# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `:authorization_code_completion` - an optional synchronous wrapper around the
  tail of an authorization-code redemption (principal construction, host
  ID-token claim construction, access- and ID-token minting, optional
  logout-session recording, access-token `jti` recording, optional generation-0
  refresh issuance, and code finalization). A host may run it inside its own
  `Repo.transaction/1` to serialize token issuance with a subject-authorization
  re-check. The continuation is bound to the callback's process and permits
  exactly one invocation; a second, cross-process, or escaped call is refused
  before anything is minted or persisted. The callback's return is verified by
  provenance rather than its outward tuple form, so a callback that never
  invokes the continuation cannot substitute a fabricated
  `{:ok, response, events}` for a real token set. The `{:ok, _}` wrapper that
  `Repo.transaction/1` places around a committed return is unwrapped instead
  of failing a request whose code is already finalized. Rollback covers only
  stores using the same Ecto Repo and enclosing transaction. Scope and resource
  resolution precede this initial authorization-code completion hook; refresh
  rotation and every other grant type bypass it. It is not a per-request
  resource-server or MCP reauthorization mechanism. An exception, throw, or
  exit after successful
  continuation emits a static, secret-free error naming the possible
  finalized-code/retry-revocation hazard, then propagates with its original
  stacktrace. Reuse detection can revoke that response's access token and the
  refresh-token family descended from that redemption, forcing the client
  through a new authorization flow; it does not revoke unrelated authorization
  grants. A success wrapper around a failed continuation is also unwrapped but
  emits a static warning because earlier writes may have committed.
- `:authorization_code_private_context` - an optional trusted issuance callback
  for host-private authorization state. It receives exactly the authorized
  `:client_id`, `:subject`, and the freshly generated authorization-grant
  provenance `:family_id` (not the separately generated refresh-rotation family
  identifier), and its return value is supplied back as `:private_context` in
  the completion callback's context. The value must be a portable JSON object
  of at most 4 KiB encoded. It is stored as plaintext JSONB, not encrypted, so
  it is for non-secret identifiers and policy epochs rather than credentials or
  token/key material. It rides with the code inside the canonical grant
  `claims` under a reserved namespaced key, and is lifted off the grant before
  principal construction so it never reaches an access token, ID Token,
  refresh token, or token-exchange input. **This feature adds no column
  migration; independent release migrations still apply.** Configuring it
  without `:authorization_code_completion` is refused at boot, and a code that
  carries private context is refused with `invalid_grant` on a node whose
  completion callback is missing, so config skew cannot silently skip the
  host's policy.
  Thanks to [@oliver-kriska](https://github.com/oliver-kriska) for the
  contribution in [#25](https://github.com/XukuLLC/attesto_phoenix/pull/25).

### Changed

- Key `attesto_authorization_codes` on `code_hash` as its PRIMARY KEY instead
  of carrying only a unique index on it. It was the one generated table without
  a primary key. Under its historical `REPLICA IDENTITY DEFAULT` setting it
  therefore has no usable identity index; if a logical-replication publication
  publishes its `UPDATE`s or `DELETE`s, those writes fail at the publisher
  until an identity is configured. `AttestoPhoenix.Schema.Authorization` now
  declares the key and maps a duplicate insert onto
  `attesto_authorization_codes_pkey`, the convention the other keyed tables
  already follow. Fresh migrations from `mix attesto_phoenix.gen.migration`
  create the keyed layout. Stored columns, single-use semantics, and the store
  API are unchanged. Thanks to
  [@jtippett](https://github.com/jtippett) for the contribution in
  [#26](https://github.com/XukuLLC/attesto_phoenix/pull/26).

### Security

- Mark `claims` `redact: true` on `AttestoPhoenix.Schema.Authorization`, hiding
  the authentication context and optional host-private state from ordinary
  struct and changeset inspection. Because `Ecto.InvalidChangesetError` renders
  raw changes and params independently of schema redaction, the bundled code
  store now replaces a failed insert changeset with a value-free one before
  raising that exception. Direct Ecto callers and custom stores remain
  responsible for equivalent exception handling.
- Retain the code store's pre-existing suppression of application SQL logging
  and Ecto query telemetry on every operation. Narrow the two reuse-detection
  reads to only the columns they report, keeping `claims` out of decoded rows as
  defence in depth, and add disclosure-focused regression coverage. Suppression
  remains unconditional; custom stores and database-server logging remain the
  host's responsibility.

### Upgrade notes

- When upgrading an existing Ecto database, apply a forward migration that
  promotes the existing unique index on `attesto_authorization_codes.code_hash`
  to the table's primary key. The application and migration may be deployed in
  either order: new application code recognizes both the historical unique
  index and the new primary-key constraint. Once migrated, either application
  version runs against the keyed layout; a duplicate `code_hash` raises
  `Ecto.ConstraintError` on the previous release and
  `Ecto.InvalidChangesetError` on this one.

  That ordering flexibility does not extend to logical replication. The
  migration must finish before this table is added to a publication that
  publishes `UPDATE` or `DELETE`. If the historical default-identity table is
  already in such a publication, the corresponding authorization-code
  conditional-update or cleanup-delete path fails at the publisher until its
  replica identity is fixed (or that operation stops being published for the
  table). PostgreSQL logical replication does not copy DDL: apply the schema
  change to the subscriber first, then to the publisher. If `REPLICA IDENTITY
  FULL` was used as a temporary publisher-side bridge, keep it until both
  sides have the primary key. The generic migration below preserves `FULL`;
  on the publisher, enable its commented reset only when `FULL` was temporary
  and the subscriber is already ready.

  The exact operation for the historical generated layout is:

  ```elixir
  defmodule MyApp.Repo.Migrations.KeyAttestoAuthorizationCodesOnCodeHash do
    use Ecto.Migration

    # Keep Ecto's default DDL transaction: SET LOCAL must cover ALTER TABLE.
    # Do not add @disable_ddl_transaction true.

    # Set this explicitly to the runtime Ecto schema prefix. Raw SQL passed to
    # execute/1 does not inherit a migrator or repository prefix option.
    @prefix nil

    def up do
      # Abort instead of waiting indefinitely for ACCESS EXCLUSIVE.
      execute "SET LOCAL lock_timeout = '5s'"

      execute """
      ALTER TABLE #{table()}
        ADD CONSTRAINT attesto_authorization_codes_pkey
        PRIMARY KEY USING INDEX attesto_authorization_codes_code_hash_index
      """

      # Publisher only: if its REPLICA IDENTITY FULL setting was temporary and
      # the subscriber already has this primary key, uncomment the reset so it
      # shares this transaction and deployment window with the promotion.
      # execute "ALTER TABLE #{table()} REPLICA IDENTITY DEFAULT"
    end

    def down do
      execute "SET LOCAL lock_timeout = '5s'"

      # Preserve REPLICA IDENTITY USING INDEX when it is active on the promoted
      # primary-key index at rollback time. The marker is LOCAL, so this
      # migration must retain Ecto's default DDL transaction.
      execute """
      DO $$
      DECLARE
        restore_identity boolean;
      BEGIN
        SELECT EXISTS (
          SELECT 1
          FROM pg_index
          WHERE indrelid = '#{table()}'::regclass
            AND indisprimary
            AND indisreplident
        ) INTO restore_identity;

        PERFORM set_config(
          'attesto_phoenix.restore_authorization_codes_replica_identity',
          CASE WHEN restore_identity THEN 'true' ELSE 'false' END,
          true
        );

        IF restore_identity THEN
          EXECUTE 'ALTER TABLE #{table()} REPLICA IDENTITY DEFAULT';
        END IF;
      END
      $$;
      """

      # Dropping the constraint drops its index, so clear the identity first
      # when that index was selected before the promotion.
      execute ~s|ALTER TABLE #{table()} DROP CONSTRAINT attesto_authorization_codes_pkey|
      create unique_index(:attesto_authorization_codes, [:code_hash], prefix: @prefix)

      execute """
      DO $$
      BEGIN
        IF current_setting(
             'attesto_phoenix.restore_authorization_codes_replica_identity',
             true
           ) = 'true' THEN
          EXECUTE 'ALTER TABLE #{table()} REPLICA IDENTITY USING INDEX #{index()}';
        END IF;
      END
      $$;
      """
    end

    defp table do
      case @prefix do
        nil -> ~s|"attesto_authorization_codes"|
        prefix -> ~s|"#{prefix}"."attesto_authorization_codes"|
      end
    end

    # PostgreSQL's REPLICA IDENTITY grammar takes an unqualified index name;
    # the schema-qualified table above determines which schema is searched.
    defp index, do: ~s|"attesto_authorization_codes_code_hash_index"|
  end
  ```

  This exact migration applies only to the historical generated layout. Run
  the [catalog preflight](guides/upgrade_3_0_schema_prefix.md#catalog-preflight)
  and proceed only when it reports `ready_for_primary_key = t`. A custom or
  renamed table/index needs a reviewed migration; a surrogate-primary-key
  layout may need no change. The same guide covers literal-prefixed 2.x tables.

  Set `@prefix` to exactly the PostgreSQL schema used by runtime Ecto queries;
  `nil` is appropriate only for the runtime's default schema. The interpolated
  raw `ALTER TABLE` does not inherit the prefix passed to `Ecto.Migrator` or the
  repository.

  When those prerequisites hold, PostgreSQL reuses and renames the existing
  index, so the forward change is metadata-only: it does not rebuild the index
  or rewrite the table and is normally fast. `ALTER TABLE` nevertheless takes
  an `ACCESS EXCLUSIVE` lock. Under live traffic, the ALTER can wait behind
  existing transactions; because an `ACCESS EXCLUSIVE` request queues ahead of
  later conflicting work, blocking of new reads and writes can begin while it
  is still waiting. Once acquired, it blocks reads and writes until the
  migration transaction commits. PostgreSQL may emit a harmless notice that it
  is renaming the reused index to match the primary-key constraint. Run the
  migration in a controlled deployment window. Keep a short `lock_timeout`
  (as above), below the application's query timeout, so contention aborts the
  attempt before waiting requests time out; then inspect blockers and retry
  during a quiet period, or drain traffic touching the table. Keep the shown
  migration transactional; `SET LOCAL lock_timeout` ends with its transaction
  and would not cover the following `ALTER TABLE` if
  `@disable_ddl_transaction true` were added. The optional FULL-to-DEFAULT
  reset is a second `ACCESS EXCLUSIVE` ALTER and belongs in this same
  transaction after the subscriber is ready.

  The `down/0` path is materially slower: it drops the primary-key index and
  rebuilds the plain unique index while the transaction retains the table's
  `ACCESS EXCLUSIVE` lock. When `REPLICA IDENTITY USING INDEX` is active on the
  promoted primary-key index at rollback time, it is restored on the rebuilt
  unique index. Treat rollback as a potentially long, blocking index build
  rather than the metadata-only inverse of `up/0`.

  Skip the migration for a database whose tables were created by this
  release's generator: it already has the key, and PostgreSQL rejects adding
  another primary-key constraint.

## [3.0.0] - 2026-08-31

### Breaking

- Replace the public 2.x host `:table_prefix` and package-level
  `config :attesto_phoenix, :table_prefix` settings, plus the
  `--table-prefix` migration-generator option, with `:schema_prefix` and
  `--schema-prefix`. In v2.14.2, the generator could prepend the value
  literally to table names in `public`, while most runtime stores queried
  canonical public tables and only `EctoCIBAStore` and `Sweeper` passed it as an
  Ecto schema prefix. The old value therefore did not identify one coherent
  runtime layout. Version 3.0 keeps canonical table names and selects one
  PostgreSQL schema through Ecto's `prefix:` option. Legacy keys and flags now
  fail closed with an upgrade message instead of being silently reinterpreted.
- Require protocol controllers to receive the validated request configuration
  in `conn.private[:attesto_phoenix_config]`. A missing or malformed request
  value no longer falls back to global application configuration; hosts must
  mount `AttestoPhoenix.Plug.PutConfig` in the route pipeline. Thanks to
  [@MuNeNiCK](https://github.com/MuNeNiCK) for reporting the request-scoping gap
  and independently proposing a fix in
  [#24](https://github.com/XukuLLC/attesto_phoenix/pull/24).
- Require a protocol config preinstalled before `AttestoPhoenix.Plug.PutConfig`
  to exactly match the protocol config derived from the same request's host
  config. Divergent private values now fail closed instead of letting metadata
  and endpoint policy disagree.
- Register the bundled Ecto sweeper under a deterministic repository/schema
  name so multiple policy profiles can coexist. `Sweeper.sweep_now/0` resolves
  that configured default; callers using an explicit custom registration name
  must continue to call `sweep_now/1`.
- Require Attesto 2.0 and its atomic refresh-store rotation contract. Custom
  refresh stores must replace the former multi-step consume/insert/successor
  callbacks with one family-serialized `rotate/4` transaction.
- Update the bundled Ecto device-code store to Attesto 2.0's full-entry lookup
  and atomic, time-aware decision callbacks. Custom device-code stores must
  adopt the corresponding Attesto 2.0 behavior contract.
- The default dynamic-registration grant catalog now includes the implemented
  OAuth token-exchange grant. Hosts that do not want to register clients for it
  must explicitly narrow `:grant_types_supported`.
- Optional CIBA, device-authorization, JWT-bearer, and pre-authorized-code
  grants are added to the default catalog only when `:grant_types_supported` is
  unset. An explicit catalog is now exact, so 2.14.2 deployments that enabled
  one of these features must add its exact grant URN before upgrading.
- Client-authentication method policy is exact in 3.0. In 2.14.2, an unset or
  empty `:token_endpoint_auth_methods_supported` value did not restrict endpoint
  authentication, so mTLS could work when its callbacks were wired. In 3.0,
  `nil` defaults to `client_secret_basic`, `client_secret_post`,
  `private_key_jwt`, and `none`; `tls_client_auth` and
  `self_signed_tls_client_auth` must be listed explicitly, with their required
  callbacks, when retained. Any non-`nil` list, including `[]`, is exact;
  wallet attestation remains conditional on trusted Wallet Provider keys.

### Security

- Retain an expired authorization-code row while its linked access token is
  still live, so replay detection and access-token revocation remain enforceable.
  Unlinked rows, malformed rows, and rows whose linked token has expired are still
  reclaimed by the sweeper.
- Suppress both Ecto Logger output and repository query telemetry for
  credential-bearing and privacy-sensitive values, including consent tokens,
  DPoP nonces, device user codes, PAR request URIs, CIBA notification tokens,
  refresh rows, and logout-session identifiers and targets.
- Bind controller actions and the standalone authentication plug to the
  validated request configuration only for bounded work, selecting its Ecto
  repository and schema prefix together and restoring state on success, halt,
  or failure.
- Enforce a lossless portable JSON boundary for persisted claim maps, including
  nested values, nulls, booleans, and I-JSON-safe integers (±9_007_199_254_740_991); incompatible
  pre-3.0 persisted maps fail closed when read.
- Recognize only exact v1/v2 encrypted refresh-successor wrappers and redact
  malformed, unknown, or tampered state conservatively no later than the parent
  token expiry.
- Enforce a DPoP nonce row's persisted expiry as well as the caller's freshness
  window, so a nonce issued with a shorter lifetime cannot be accepted after
  its stored deadline.
- Honor the validated request's configured refresh store for RFC 7009
  revocation, ahead of the compatibility-only `conn.private` override. Load a
  configured code-store module before probing its optional access-token
  revocation callback, fail closed when the module cannot load, and continue
  to require an exact boolean when that callback exists.
- Fail configuration construction when the bundled Ecto refresh store uses a
  non-zero rotation retry grace without a usable
  `:refresh_successor_secret`. The Igniter installer now adds an idempotent
  runtime setting that requires a stable secret of at least 32 bytes in
  production and provides only an explicit development/test fallback.
- Reject invalid refresh-rotation grace values, non-boolean top-level policy
  switches, and required DPoP nonce enforcement when DPoP is disabled or no
  capable nonce store is configured, instead of silently omitting requested
  security behavior.
- Reject required OID4VCI key attestation when no usable trusted verification
  key is configured, instead of silently omitting the requirement from proof
  verification.
- Require exact boolean results from security-policy callbacks and exact
  booleans for nested feature and request-object policy fields. Malformed
  public/native-client classification, sender-constraint policy, request-object
  requirements, loopback exceptions, and confirmation controls now fail loudly
  instead of being treated as enabled or disabled by truthiness.
- Enforce documented callback and store result contracts across client and
  principal lookup, grant presence, scope policy, replay and nonce handling,
  PAR, device approval, CIBA, credential issuance, introspection, and dynamic
  audience resolution. Unexpected results fail loudly with fixed, value-free
  diagnostics; post-commit notification and audit-delivery failures emit fixed
  warnings. Ordinary protocol denials retain their existing wire responses.
- Preserve the authenticated fixed retry deadline in Ecto successor records,
  reject a mismatched housekeeping deadline, and redact encrypted successor
  credentials after that deadline while retaining a deadline-only tombstone.
  The installer now supervises `AttestoPhoenix.Store.Sweeper` after the host
  repo so this cleanup actually runs.
- Preserve bounded retry compatibility for v1 encrypted successors at a
  stopped 2.14.2-to-3.0 cutover by deriving their deadline from persisted
  `consumed_at` and the configured grace, capped before token expiry. A retry
  after that window remains reuse and revokes the family.
- Require an atomic PAR `take/1` implementation when
  `require_pushed_authorization_requests: true`; fetch-only stores remain valid
  for optional PAR. Refresh-family revocation now surfaces transaction
  rollback instead of returning false success, and prebuilt application
  config structs are fully revalidated before use.
- Persist refresh-family revocation tombstones in
  `attesto_refresh_family_revocations`, separate from expirable token rows, so
  the sweeper cannot erase the decision and permit a later family resurrection.
- Bind authorization-code replay markers to the refresh family actually issued
  by the core composition API, and retain the access-token JTI linkage by code
  hash until that family is finalized. Refresh issuance is refused for
  reuse-tracking code stores that expose only the legacy family callback, rather
  than recording a token under the wrong refresh family.
- Keep asynchronous CIBA user-notification callbacks and ping delivery inside
  the validated request-local configuration, so concurrently mounted profiles
  retain their own policies and Ecto schema prefixes.
- Disable Phoenix route-dispatch parameter logging on protocol and interactive
  routes. These requests can contain redeemable codes, assertions, proofs,
  signed request objects, and encrypted responses that Phoenix's default
  substring filters do not comprehensively cover. Endpoint method/path/status
  logging remains available; hosts must apply the same rule to custom request
  and header loggers.
- Emit the documented `:refresh_reuse_detected` host event when core refresh
  reuse detection revokes a family, alongside the ordinary token-denial event.
  Refresh issuance and rotation events now include the resource-owner subject.
- Enforce Attesto 2's exact canonical authorization-code, CIBA, device-code,
  refresh-token, and refresh-successor contexts at the bundled Ecto write
  boundaries. Missing, extra, or malformed members are rejected before column
  projection, and malformed persisted confirmation data remains invalid rather
  than being interpreted as an unbound credential.

### Fixed

- Preserve explicitly empty grant-type and client-authentication catalogs in
  discovery, endpoint enforcement, and dynamic registration instead of
  widening them to package defaults. Malformed catalogs and per-client grant
  lists are rejected rather than treated as unrestricted.
- Require bundled Ecto code-store transitions and access-token linkage to
  update exactly one authorization record, and make logout-session persistence
  refusal visible instead of reporting silent success.
- Clear the refresh-family marker when an Ecto authorization code is finalized
  without issuing a refresh token. A later replay is rejected and revokes only
  the code-linked access-token JTI, never a refresh family.
- Route revocation events through the fully resolved event callback, including
  behavior-module `:event_sink` configuration, and warn without payload data
  when an event sink explicitly reports delivery failure.
- Let the installer-added sweeper child return `:ignore` when an upgraded host
  has no sweep interval, while manual supervision and invalid configured
  intervals continue to fail at startup.
- Treat replay of a legacy consumed authorization-code row with no access-token
  JTI as an idempotent no-op, so the generic `invalid_grant` path cannot become
  a 500 while still enforcing exact-one revocation for linked tokens.
- Map Attesto refresh rotation's `:temporarily_unavailable` result to OAuth
  `temporarily_unavailable` with HTTP 503. The parent token remains valid for a
  retry; logs and the denial event carry only the fixed operational code, never
  the store's internal reason.
- Run synchronous CIBA approve/deny transitions and ping endpoint resolution
  inside the passed request configuration, including for conn-free callers.
- Round-trip authorization codes through the exact nine-key Attesto 2 grant
  context: the database-only PKCE method is no longer returned as a sibling
  member, and a legacy nonce column is promoted into `:claims`. Refresh-token
  persistence now preserves duplicate scope members instead of silently
  deduplicating them.

### Upgrade notes

- Every 2.x-to-3.0 deployment, including one using the default `public`
  schema, requires a stopped cutover for all token writers. Drain 2.x nodes
  and workers, apply the refresh-generation index migration, create and
  backfill the 3.0 refresh-family tombstone table, then start 3.0 and re-enable
  traffic. Mixed 2.x/3.0 writers are unsupported because 2.x does not read or
  write the tombstones.
- A non-empty 2.x `:table_prefix` value does not identify one runtime layout.
  Before any 3.0 node starts, inventory public canonical, public
  literal-prefixed, and schema/canonical candidates for every table using
  counts, observed behavior, and backups. Stop if a logical table has split
  non-empty data; move only a verified source relation into one PostgreSQL
  schema. Never run mixed 2.x/3.0 nodes, workers, or migration commands during
  this stopped cutover; see `guides/upgrade_3_0_schema_prefix.md`. Remove every
  legacy `:table_prefix` setting, then configure `:schema_prefix` and use
  `--schema-prefix` for future fresh migrations.
- Before upgrading an existing Ecto database, apply a forward migration that
  adds the unique `(family_id, generation)` index on `attesto_refresh_tokens` if
  it is not already present. The exact operation is:

  ```elixir
  prefix = nil # Replace with your configured PostgreSQL schema name when non-default.

  create unique_index(
    :attesto_refresh_tokens,
    [:family_id, :generation],
    name: :attesto_refresh_tokens_family_id_generation_index,
    prefix: prefix
  )
  ```

  Use the runtime Ecto `prefix` (`nil` for `public`, or the configured schema).
  If creation fails because duplicate family/generation rows exist, stop,
  reconcile and revoke the affected families, then retry; never blindly delete
  duplicate rows. Do not rerun the create-table migration.
- Before deploying this release to an existing Ecto database, create the
  `attesto_refresh_family_revocations` table with the same runtime prefix and
  backfill it from every existing refresh row with `family_revoked = true`.
  This preserves already-revoked families after the sweeper removes their
  expired token rows. Qualify both source and destination tables with that
  prefix when it is non-default; do not backfill `public` accidentally. New
  installations receive the table from `mix attesto_phoenix.gen.migration`.
- Dynamic-registration clients inherit the 3.0 default grant catalog, which
  includes token exchange. Set an explicit `grant_types_supported` catalog
  before deployment when token exchange must remain unavailable. Explicit empty
  grant/auth-method catalogs remain empty rather than widening to defaults.
- Existing installations using `AttestoPhoenix.Store.EctoRefreshStore` with
  positive refresh retry grace must configure one stable
  `:refresh_successor_secret` of at least 32 bytes across every node and
  deployment. Configuration now fails at startup if it is absent or too short.
- At a stopped 2.14.2-to-3.0 cutover, an authorization-code refresh can
  preserve the configured `:authorization_grant_id_claim` using its bounded
  legacy lineage marker. Other grant types and families started while that
  feature was disabled remain excluded from the claim.
- Manual Ecto installations must supervise `AttestoPhoenix.Store.Sweeper` with
  a positive `:sweep_interval_ms`; rerunning `mix attesto_phoenix.install` adds
  the child idempotently. A custom cleanup job must explicitly redact expired
  refresh-successor ciphertext in addition to deleting expired rows.

## [2.14.2] - 2026-08-28

### Added

- Add opt-in `:authorization_grant_id_claim` configuration for a stable,
  library-owned authorization-code family claim on initial and refreshed access
  tokens. The claim reuses the 128-bit refresh `family_id`, survives rotation
  and lost-response retry while `jti` changes, is omitted from other grants, and
  remains disabled by default without requiring a migration. An authorization
  code issued without a `family_id` is permanently ineligible for the claim:
  such a grant still starts an internal refresh family, but neither its initial
  nor any refreshed access token carries the claim. Thanks to
  [@oliver-kriska](https://github.com/oliver-kriska) for the contribution in
  [#23](https://github.com/XukuLLC/attesto_phoenix/pull/23).

### Changed

- Authorization-code family identifiers are now generated with
  `Attesto.Secret.generate(16)` — 128 bits, 22 unpadded Base64URL characters —
  matching the refresh-family identifiers generated by `Attesto.RefreshToken`.
  They were previously 32 bytes (43 characters). This applies to every
  deployment, including those that leave `:authorization_grant_id_claim`
  disabled. Existing stored values are unaffected; only newly issued
  identifiers change length.

## [2.14.1] - 2026-08-27

### Security

- CIBA configurations that require signed authentication requests now fail
  when `AttestoPhoenix.Config` is constructed unless an explicit atomic
  `:replay_check` callback is configured.
  Replay identities derived from verified request-JWT `jti` values are recorded
  through that boundary until their `exp`; a repeated signed request is
  rejected as `invalid_request`. An optional signed request also fails closed
  without that callback. Plain
  requests in explicitly unsigned generic CIBA profiles remain compatible.
- CIBA replay identities are now fixed-length digests scoped to the
  authenticated client, preventing oversized store keys and cross-client
  false replay collisions.
- Configured replay callbacks are now validated during configuration
  construction for a callable two-argument function or MFA contract, rather
  than failing on the first protected request.
- CIBA `:require_signed_request` now rejects non-boolean configuration values
  during configuration construction so string or null environment values
  cannot disable request signing.

### Upgrade notes

- Do not run `2.14.0` and `2.14.1` nodes together while accepting signed CIBA
  authentication requests. Drain the `2.14.0` nodes and wait until every signed
  request JWT accepted by them has expired—conservatively 61 minutes—before
  starting `2.14.1`; the fixed replay identity introduced here is intentionally
  different from the raw key used by `2.14.0`.

## [2.14.0] - 2026-08-27

### Added

- `AttestoPhoenix.Plug.PutConfig`, a fail-closed router-pipeline bridge that
  loads the host's validated `AttestoPhoenix.Config`, derives `Attesto.Config`,
  and installs both under their documented `conn.private` keys while preserving
  correctly typed request-specific overrides.
- `principal_kinds/0` on `AttestoPhoenix.PrincipalStore` as an optional
  host-contract callback and installer scaffold for the principal-kind catalog
  required by the protocol configuration.

### Fixed

- The Igniter installer now writes `config :attesto_phoenix, otp_app: ...,
  repo: ...`, generates the config-loading router pipeline, passes it to
  `attesto_routes/1`, and repairs older installer route output that omitted the
  pipeline. Generated authorization, metadata, JWKS, and store paths therefore
  resolve the same host application instead of failing on missing config keys.
- The generated host config now includes the required access-token `:audience`
  and wires the scaffolded `principal_kinds/0` provider. Re-running the
  installer repairs both missing keys and adds only the missing callback stub
  to older scaffolded principal stores without replacing host definitions.
- Direct-TLS detection remains warning-free and functional on every supported
  Plug line, using adapter peer data when the newer SSL-data helper is absent.

### Documentation

- Document the required global OTP-app/repo pointer and config-loading pipeline,
  and add the explicit CIMD plus `localhost` loopback compatibility settings for
  native clients that publish URL metadata and bind an ephemeral callback port.

## [2.13.0] - 2026-08-13

### Added

- RFC 8705 §2 token-endpoint authentication with both `tls_client_auth` and
  `self_signed_tls_client_auth`, shared by the server's client-authentication
  service. PKI clients match one registered DN/SAN identity; self-signed
  clients match an exact registered `x5c` leaf.
- RFC 8705 metadata integration for both auth methods,
  `tls_client_certificate_bound_access_tokens`, and validated
  `mtls_endpoint_aliases`.
- Trusted-terminator certificate transport: `:forwarded_cert_der` is invoked
  only for an immediate peer in `:trusted_proxies`, while
  `:client_certificate_chain_validated?` makes PKI validation an explicit host
  assertion.

### Security

- Forwarded client-certificate headers are no longer an implicit extension of
  the generic certificate callback. The supported forwarded path is guarded by
  the trusted-proxy allowlist and tested against direct header spoofing. The
  documented deployment contract requires the terminator to overwrite the
  header and the application listener to be isolated from untrusted peers.
- The legacy `:cert_der` callback is now subject to the same trusted-proxy gate
  as `:forwarded_cert_der`. Existing deployments that used `:cert_der` to read
  a terminator header must configure `:trusted_proxies` and migrate to
  `:forwarded_cert_der`; otherwise certificate binding fails closed. Direct TLS
  certificates are read from adapter peer data and need no callback.
- Trusted-proxy decisions use `Plug.Conn.get_peer_data/1`'s socket address,
  never the middleware-rewriteable `conn.remote_ip`. A forged
  `X-Forwarded-For` therefore cannot authorize an XFCC-style certificate.
- Untrusted requests also recover direct transport and authority facts when
  standard forwarded headers have already been applied by `Plug.RewriteOn`:
  adapter SSL data controls HTTPS, the raw Host header controls authority, and
  socket peer data controls client IP. Forged forwarded headers cannot satisfy
  the HTTPS gate or redirect DPoP `htu` verification.
- Certificate-bearing public clients now remain subject to each endpoint's
  `allow_public` policy. PAR, introspection, and CIBA cannot be changed from
  authenticated-only to public-client access merely by presenting a
  certificate.
- mTLS client-metadata lookup errors and malformed callback results now fail
  authentication closed. Only an absent callback or an explicit `nil` result
  means the client has no mTLS authentication registration and may enter the
  endpoint's public-client path.
- JWS credential and signed-metadata issuance now passes keystore modules into
  core, enabling `Attesto.Signer` non-extractable custody without changing PEM
  deployments. COSE mdoc signing and verifier decryption continue to require
  direct private-key access and are outside the JWS signer contract.
- Require `attesto >= 1.15.0`; the RFC 8705 identity matcher and signer dispatch
  are runtime dependencies, so the floor is load-bearing.

## [2.12.0] - 2026-08-11

Hardening of the ID-JAG (`urn:ietf:params:oauth:grant-type:jwt-bearer`)
exchange at the token endpoint. Pairs with `attesto` 1.13.0 and now requires
it: the core release supplies the assertion-claim validation this enforcement
builds on, including the `authorization_details` rejection, which has no
equivalent on this side.

### Security

- **Signed `resource` is an audience ceiling.** The exchange previously ignored
  the assertion's `resource` claim, so a client could exchange into any other
  locally permitted audience. A request omitting `resource` now defaults to the
  signed set, and one supplying it may narrow that set but never widen it.
- **Signed `cnf.jkt` requires matching proof-of-possession.** An assertion
  carrying `cnf.jkt` is proof-of-possession authority, not a bearer credential;
  the token request must demonstrate the same DPoP key. A missing, mTLS, or
  different-key binding is now `invalid_grant` (draft §6.1, RFC 9449).
- **Scope ceilings are rechecked after host policy.** A `:authorize_scope`
  callback could previously re-add an unrequested scope or exceed the ID-JAG /
  token-exchange ceiling. The granted result is now re-validated against both
  the signed ceiling and the requested set.
- **Replay identities are fixed-size and issuer-scoped.** The store key is now
  `sha256(iss ‖ jti)` rather than the raw `jti`, so unbounded IdP input never
  becomes a database key and two trusted IdPs choosing the same identifier do
  not collide (RFC 7519 scopes `jti` uniqueness to its issuer).
- Require `attesto >= 1.13.0`, keeping the Phoenix HTTP surface on the complete
  current core hardening baseline.
- Refresh the test-only Postgrex lock past its stream-comment SQL-injection
  advisory; the driver does not enter this package's runtime closure.
- Correct `AttestoPhoenix.Store.EctoCodeStore.take/1`'s return specification
  to include consumed-code metadata and update its documentation to describe
  the atomic consume operation accurately. Thanks to
  [@h8](https://github.com/h8) for the contribution in
  [#22](https://github.com/XukuLLC/attesto_phoenix/pull/22).

### Added

- `AttestoPhoenix.AuthorizationServer.JwtBearer.prepare/3`,
  `resolve_subject/2`, and `commit_replay_claim/2`: a staged variant of
  `authorize/3` that defers the host subject callback and atomic replay claim so
  sender binding, resource, scope, and host policy can be evaluated first. A
  caller of `prepare/3` MUST resolve its verified claims and commit the returned
  `:replay_claim` before minting. `authorize/3` remains the one-call API.

### Changed

- A rejected ID-JAG exchange no longer consumes the assertion's `jti`: the
  replay claim is committed only once every check has passed, so a policy
  denial does not burn an otherwise valid assertion.
- **Host-callback ordering**: the token endpoint now invokes
  `:resolve_jwt_bearer_subject` only after sender binding, resource, scope, and
  host policy succeed, preventing invalid requests from triggering JIT
  provisioning, audit writes, or upstream lookups. Because the replay seam is
  atomically check-and-record (there is no non-consuming reservation), a validly
  signed replay can still reach the callback before replay rejection; callbacks
  with side effects should remain idempotent. Token issuance remains
  replay-protected.
- **Upgrade note**: the replay-store key format changed (see above). Entries
  written by an earlier release are not recognized after upgrade, so during a
  rolling deploy an assertion already seen by an old node could be accepted once
  by a new one. The window is bounded by the assertion's remaining lifetime
  (at most `:assertion_max_lifetime_seconds`, default 300s).

## [2.11.0] - 2026-08-10

Pairs with the `attesto` 1.12.1 wallet-surface security-hardening release and
now requires it (`>= 1.12.1`). Carries the HTTP-surface fixes from the same
6-front adversarial sweep of the EU-wallet code.

### Security

- **OID4VP `direct_post.jwt` downgrade**: the direct-post response endpoint now
  rejects a plaintext submission when the session mandated encryption (an
  ephemeral response-encryption key is attached), instead of gating only on the
  global response mode. Closes a silent per-session confidentiality downgrade of
  the vp_token to any post-TLS intermediary.
- **Credential-proof `iss` binding**: the credential endpoint now binds the
  proof's `iss` to the access token's `client_id` unconditionally (RFC 9068).
  Previously the check keyed off a `grant_type` token claim that is never
  written, so a forged/absent `iss` was accepted on the authorization_code flow.
- **`credential_response_encryption`**: a request that asks for response
  encryption is now rejected (`invalid_encryption_parameters`) rather than
  silently answered with a plaintext credential.

## [2.10.0] - 2026-08-10

Pairs with the `attesto` 1.11.0 security-hardening release and now requires it
(`>= 1.11.0`). Carries the HTTP-surface fixes from the same audit rounds.

### Security

- **JWE decompression-bomb guard on the OID4VP response endpoint.** The
  `direct_post.jwt` path (`presentation_response_controller`) rejects any JWE
  whose protected header carries a `zip` member before `JOSE.JWE.block_decrypt`,
  so a compressed response cannot inflate a tiny ciphertext into gigabytes on the
  unauthenticated endpoint.
- **Dynamic Client Registration scheme allowlist.** `redirect_uris` in the
  ordinary (authority) form must be `http`/`https`, and `post_logout_redirect_uris`
  are validated as `http`/`https` absolute URIs without a fragment — closing a
  `javascript:`/`data:`/`vbscript:` scheme-injection that reached the
  auto-executing `form_post` / logout-continuation sinks as stored XSS.
- **Server-side request forgery guard on outbound deliverers.** The
  back-channel-logout and CIBA-ping deliverers screen the target through the new
  `AttestoPhoenix.SSRFGuard` — reject any resolved special-use IP (RFC 6890) and
  pin the socket to the checked address (Mint `:hostname` keeps TLS SNI /
  certificate verification / `Host` on the real name), closing the DNS-rebinding
  window. The shared special-use-IP table gained the missing IANA IPv6 ranges
  (`100::/64`, `2001:2::/48`, `3fff::/20`, `5f00::/16`), which also hardens the
  Client ID Metadata fetcher.
- **Deferred Credential ownership contract + c_nonce single-use.** The
  credential endpoint now consumes the request's c_nonce once (after the whole
  proof batch verifies) via the store's `consume/1`, failing closed if the store
  cannot; a captured proof can no longer be replayed for another credential. The
  deferred-credential callback contract documents that it MUST bind the
  `transaction_id` to the token subject.

### Changed

- Requires `attesto >= 1.11.0`.
- A dev/test escape hatch, `config :attesto_phoenix, allow_loopback_delivery: true`,
  lets the outbound deliverers target a loopback server (off by default; keep it
  off in production).

## [2.9.0] - 2026-08-10

Pairs with the `attesto` 1.10.0 security-hardening release and now requires it
(`>= 1.10.0`). The behavioral fixes live in `attesto` core; this release carries
the matching HTTP-surface guidance.

### Security

- **Deferred Credential endpoint — documented the ownership check.** The
  endpoint authenticates the caller and passes the token's verified `subject` to
  `:build_deferred_credential`, but the callback owns binding the
  `transaction_id` to that subject. The moduledoc and the callback contract now
  state, in the strongest terms, that resolving a `transaction_id` without
  scoping to `subject` is an IDOR (any authenticated wallet could poll another's
  `transaction_id` and receive its credential) and that `transaction_id` must be
  minted with a CSPRNG.
- **Credential-offer creation guidance.** The by-reference offer controller doc
  now points hosts at `Attesto.CredentialOffer.store_by_reference/3` (which
  generates the unguessable id) instead of minting their own.

### Changed

- Requires `attesto >= 1.10.0`. `AttestoPhoenix.Verifier.presentation_result/2`
  is now single-use (it consumes the session) — a `response_code` captured from
  the browser cannot be replayed to re-read the presented claims. Read the
  result once on the completion redirect.

## [2.8.0] - 2026-08-05

### Added

- **`native_apps: [loopback_include_localhost: true]`**, an opt-in that widens
  the RFC 8252 §7.3 loopback port allowance to the bare hostname `localhost`,
  selecting `attesto`'s `:exact_allow_loopback_port_including_localhost`
  matching mode wherever `:exact_allow_loopback_port` would have been selected
  (for hosts marked native via `:client_native?`, and for CIMD clients whose
  document declares a loopback redirect URI).

  Real native clients register a portless `http://localhost/callback` in their
  client-id metadata document and bind an ephemeral port at runtime — Claude
  Code's published document is one — and no strict deployment could serve them:
  exact comparison fails on the port and the §7.3 exception is scoped to the IP
  literals. §8.3 recommends the literal over the name, but its reasons are all
  client-side (which interface the client binds, its firewall, its host-name
  resolution); a server refusing the request changes none of them.

  The opt-in threads through all three places that must agree about what
  counts as loopback: the redirect-URI match itself, the CIMD native signal
  (`AttestoPhoenix.ClientIdMetadata.loopback_redirect_uris?/2` — a
  localhost-only document now declares loopback under the widened mode), and
  the authorization endpoint's same-origin exemption (a `localhost` redirect
  is exempt exactly as the IP literals are). `loopback_redirect_uri?/1` and
  `loopback_redirect_uris?/1` gained an optional matching-mode argument,
  defaulting to the strict mode — existing callers are unaffected.

  **Off by default; no behavior change unless selected.** The flag is
  subordinate to the `loopback_redirect: false` kill switch, `localhost` never
  cross-matches `127.0.0.1` or `[::1]`, and lookalike hosts
  (`localhost.evil.example`, `sub.localhost`, `evil-localhost`) stay outside —
  the anchoring lives in `Attesto.RedirectURI` and is exercised end-to-end in
  the authorize-controller tests. Requires `attesto` 1.9.0 or later, the first
  release carrying the `:exact_allow_loopback_port_including_localhost` mode.

  Thanks to [@jtippett](https://github.com/jtippett) for the contribution in
  [#20](https://github.com/XukuLLC/attesto_phoenix/pull/20).

## [2.7.0] - 2026-08-03

### Added

- **OpenID for Verifiable Credentials (OID4VC / EU wallet) HTTP surface**,
  wiring the `attesto` 1.8.0 core to Phoenix behind feature flags. Set
  `credential_issuance: true` to mount the OID4VCI **issuer** endpoints
  (Credential, `c_nonce`, Credential Offer + `credential_offer_uri`, Deferred
  Credential, Credential Issuer Metadata incl. a signed variant); set
  `presentation: true` for the OID4VP **verifier** endpoints (request object by
  reference + `direct_post` / encrypted `direct_post.jwt` response), targeting
  the HAIP profile.
- The authorization server advertises the OID4VC surface on its metadata:
  `authorization_details_types_supported: ["openid_credential"]` when a
  credential issuer is configured, and the client-attestation signing-alg values
  when `attest_jwt_client_auth` is enabled; the token/PAR endpoints accept
  **attestation-based client authentication** (OAuth-Client-Attestation[-PoP]).
  The verifier advertises a fresh per-request response-encryption key for
  `direct_post.jwt` and supports the `x509_san_dns` / `x509_hash` client_id
  schemes.

## [2.6.0] - 2026-08-02

### Security

- The token endpoint records the namespaced DPoP replay identity `attesto`
  1.7.0's `Attesto.DPoP.verify_proof/2` now returns (`replay_key`, a
  `sha256(jkt:jti)` digest), rather than the raw `jti`, matching
  `Attesto.Plug.Authenticate`. A shared replay store therefore never holds two
  key formats, and two token-endpoint proofs that share a `jti` but are signed
  by different keys no longer collide. The raw `jti` still rides through to
  `[:attesto, :dpop, :replay_detected]` telemetry for correlation. **Requires
  attesto >= 1.7.0.**

### Fixed

- Registration scope validation no longer does a cross-product scan of the
  requested scopes against the catalogue.

### Changed

- The demo Livebook (`notebooks/attesto_phoenix_demo.livemd`) is pinned to
  `attesto_phoenix ~> 2.6` (was a stale `~> 0.6`) and its `replay_check`
  argument is named for the opaque replay identity it now receives.

## [2.5.0] - 2026-08-01

### Security

- Claim a token-endpoint DPoP proof's `jti` only after the grant has been
  validated (RFC 9449 §11.1).

  `AttestoPhoenix.AuthorizationServer.SenderConstraint.resolve/3` passed
  `:replay_check` into proof verification, so the `jti` was recorded before the
  authorization code, refresh token, device code, or subject token was looked
  at. `:replay_check` is a check-AND-record operation, and a **public client**
  (RFC 6749 §2.1) authenticates with a `client_id` and no credential — so at
  that point the caller may be anyone who knows a registered public client's
  identifier.

  Such a caller could pair a self-signed DPoP proof with a bogus authorization
  code and write one replay-store row per request, for the cost of a signature,
  without holding any grant. Against the bundled ETS cache that is unbounded
  growth; against a shared store it is unbounded writes.

  `resolve/3` now returns the claim as a deferred `pending_claim`, and every
  grant path commits it with `commit_replay_claim/2`. Replay rejection is
  unchanged: the claim is still an atomic check-and-record made before a
  response is issued.

  Placement within each grant is deliberate, because both ends are wrong. The
  code and refresh paths commit after a NON-destructive check that the grant
  exists and before it is consumed — committing after redemption meant a
  replayed proof burned a real grant (the code spent, or the parent rotated and
  a successor persisted) and only then refused the request. The device and CIBA
  paths commit on a validated grant *including* `authorization_pending` and
  `slow_down`, which are refusals but prove the caller holds the grant;
  otherwise one captured proof could poll indefinitely without ever being
  recorded.

  **Breaking for direct callers of
  `AttestoPhoenix.AuthorizationServer.SenderConstraint.resolve/3`:** it now
  returns a four-element tuple. Hosts matching the documented
  `{:ok, binding, token_type}` must add the `pending_claim` element and commit
  it. Hosts using the endpoints are unaffected.

### Security

- Mark a resolved CIMD client with the `AttestoPhoenix.ClientIdMetadata.Client`
  struct instead of a `{:cimd, metadata}` tuple.

  The host's client value is opaque by contract — the library never inspects it,
  and a host may represent a client however it likes, including as a tuple. A
  tagged tuple therefore made `{:cimd, _}` a shape a host could return from
  `:load_client` by coincidence, and every CIMD-specific decision keyed on that
  shape alone: the client would take its redirect URIs from the tuple's map
  rather than the host's callback, receive the RFC 8252 §7.3 loopback port
  allowance, and — because `client_public?/2` answers `true` for a CIMD client —
  authenticate with no secret at all.

  A struct cannot be produced by coincidence; a host that constructs one has
  named the module explicitly. This is an internal marker, not a value hosts
  were meant to build, so no host that used the documented callbacks is
  affected.

## [2.4.0] - 2026-07-28

### Security

- Hold the CIMD same-origin check to URIs on which every URL parser agrees.
  `AttestoPhoenix.ClientIdMetadata.same_origin_redirect_uri?/2` compared origins
  using Elixir's RFC 3986 parser, while the browser that receives the `Location`
  uses the WHATWG URL Standard. `https://evil.example\@client.example/cb` reads
  as host `client.example` under the first and `evil.example` under the second,
  so the check could approve a redirect URI the authorization response would not
  actually be delivered to.

  Requires `attesto` >= 1.5.0, which rejects such a URI during CIMD document
  validation so it never reaches a registered set; this predicate now refuses it
  independently, so the two are separate barriers rather than one.

- Settle the CIMD same-origin requirement before any response travels to the
  redirect URI. It previously ran only after the whole authorization request had
  validated, so a request that failed an ordinary check — a missing
  `code_challenge`, say — short-circuited ahead of the gate and carried a
  redirectable error, with the client's `state` and the issuer, to a
  cross-origin URI the gate would have refused. The payload never included a
  code or token, and the destination was one the validated document declared.

  A failed origin check now makes the error direct, exactly as an unregistered
  `redirect_uri` already was. When the check passes, ordinary validation errors
  stay redirectable as before.

### Added

- Recognize the OpenID Connect Registration §2 `application_type` member
  (`"web"` | `"native"`, defaulting to `"web"`) at the dynamic registration
  endpoint, and carry the validated value through to `:register_client` in the
  client metadata. This is the standard wire signal a client uses to declare
  itself an installed app, so a host can now answer
  `c:AttestoPhoenix.ClientStore.client_native?/1` from a registration rather than
  classifying every native client by hand — connecting dynamic registration to
  the RFC 8252 profile added in 2.2.0. An `application_type` outside the defined
  set is rejected with `invalid_client_metadata`.

  Required by the MCP 2026-07-28 authorization specification (SEP-837), which
  calls this out as the reason authorization servers reject desktop and CLI
  clients' redirect URIs.

### Security

- Serve RFC 8252 native apps that identify via a Client ID Metadata Document.
  CIMD clients were hardcoded as never-native (`client_native?` and
  `redirect_uri_matching` both short-circuited on `{:cimd, _}`) on the reasoning
  that a CIMD client "is identified by an https URL resolving to a document
  served over the network, not an installed app". That reasoning was wrong: the
  document is served over the network for *every* CIMD client — it is the
  mechanism, not a client-type signal — and it is hosted by the vendor's
  backend while the app is still installed on the user's device.

  Two defaults refused such a client, and both had to change:

    * The same-origin requirement between the `client_id` URL and the
      `redirect_uri` is now waived for a loopback redirect URI. A CIMD
      `client_id` is `https` by definition, so `http://127.0.0.1/cb` can never
      share its origin — the check was not a policy a native client failed but
      one no installed app could satisfy by construction. It is retained in
      full for `https` redirect URIs, which is where its anti-impersonation
      value lies.
    * Redirect matching for a CIMD client is now `:exact_allow_loopback_port`
      when the document itself declares a loopback redirect URI, so an
      ephemeral port bound at runtime matches a portless registration
      (RFC 8252 §7.3, whose applicability CIMD §4.2 inherits via RFC 9700
      §4.1.3). A document declaring only `https` URIs, or only the `localhost`
      name (§8.3 requires the literal IP), is unaffected.

  The signal is the document's own declared `redirect_uris`, deliberately not
  an `application_type` member: CIMD defines no such member, whether it inherits
  OpenID Connect's is an open question on the draft's tracker, real documents do
  not carry it, and the passthrough allowlist would drop it. Declared redirect
  URIs are validated document content; a claimed type would not be.

  What is given up is same-origin binding for loopback redirects — any CIMD
  document may declare one and receive a code on the user's own machine. The
  attacker must already run code on the device to hold the port, and PKCE is
  mandatory for every CIMD client, so the exposure is bounded; deployments that
  want the old posture can set
  `client_id_metadata: [require_same_origin_redirect_uri: true]` alongside
  `native_apps: [loopback_redirect: false]`, which forbids the port allowance
  server-wide.

- Stop a crashing request from destroying the ETS-backed stores. Both
  `AttestoPhoenix.Store.PAR.ETS` — the **default** `:par_store` — and
  `AttestoPhoenix.ClientIdMetadata.Cache.ETS` started their table-owner process
  with `GenServer.start_link/3` from whichever caller touched the store first.
  In a running server that is an ordinary request process, and a link carries
  abnormal exits, so any unhandled exception, timeout, or shutdown in that
  request killed the owner and destroyed its ETS table. For the PAR store that
  discarded every stored `request_uri` on the node, breaking in-flight
  authorization for every client at once, triggered by one unrelated request
  crashing. The owner is now started unlinked, and an `:already_started` pid is
  checked for liveness (a registered name can briefly outlive its process).

### Added

- `AttestoPhoenix.ClientIdMetadata.Cache` gains optional
  `c:AttestoPhoenix.ClientIdMetadata.Cache.delete/1` and
  `c:AttestoPhoenix.ClientIdMetadata.Cache.delete_all/0` callbacks, implemented
  by **both** shipped caches — the
  Postgres-backed `Cache.Ecto` (the default, where eviction is cluster-wide)
  and the per-node `Cache.ETS` — plus `Cache.evict/2` and `Cache.evict_all/1`
  which dispatch through the configured module and report
  `{:error, :not_supported}` for a custom cache that cannot evict.

  A cached CIMD document is otherwise honored until its `expires_at`, up to 24
  hours under the default `:cache_ttl_bounds`, which is the wrong behavior once
  a document is known to have rotated or be compromised: the stale copy keeps
  authorizing the client with superseded `jwks`, `redirect_uris`, and auth
  metadata. The callbacks are optional, so an existing custom `Cache`
  implementation continues to compile unchanged.

### Fixed

- Accept the canonical RFC 8252 §7.1 private-use scheme redirect URI at the
  dynamic registration endpoint. `com.example.app:/oauth2redirect` carries no
  authority, and registration required a non-empty host, so the FIRST redirect
  type RFC 8252 prescribes for a native app could be registered by hand but
  never through `POST /register` — even though `Attesto.RedirectURI` matches it
  correctly at the authorization endpoint. RFC 6749 §3.1.2's "absolute URI" does
  not require an authority (RFC 3986 §4.3).

  The authority-less form is admitted only for a client that declared
  `application_type: "native"`, and only when its scheme contains a dot and it
  carries a non-empty path. Those are necessary for the §7.1 convention (a
  reverse-ordered domain name under the app author's control, per RFC 7595
  §3.8) but not sufficient to prove that control — nothing syntactic is. What
  they do buy is keeping the authority-less door shut for web clients entirely
  and keeping out the schemes that must never be a redirect target,
  `javascript:` and `data:` among them.

- Reject a redirect URI carrying a fragment at the registration endpoint, for
  every client type. RFC 6749 §3.1.2: "The redirection endpoint URI MUST NOT
  include a fragment component."

- Reject an explicit JSON `null` `application_type` rather than reading it as
  the `"web"` default; an absent member still defaults.

## [2.3.0] - 2026-07-28

### Changed

- RFC 8252 §7.3 loopback interface redirection now follows from marking a
  client native (`:client_native?`) alone. `native_apps: [loopback_redirect:
  ...]` is no longer a gate that must be opened; it is an opt-**out**,
  defaulting to `true`.

  2.2.0 required both a server-wide flag and the per-client mark. §7.3 states
  the port allowance as a **MUST**, so refusing a native client's ephemeral
  port made the server non-conformant for a client the host had already
  declared to be an installed app.

  What keeps the profile off for an unconfigured deployment is unchanged and
  was never the flag: `:client_native?` itself defaults to `false`, so a host
  that classifies no clients has no native clients.

  Setting `loopback_redirect: false` still forbids the exception server-wide,
  as an operator kill switch or for a deployment certifying against a profile
  that mandates exact redirect-URI matching.

  `reject_embedded_user_agents` is unaffected and remains a genuine opt-in
  flag: §8.12 is a heuristic SHOULD and a server-wide posture rather than a
  per-client property.

- `:native_apps` options are now validated at config build. A non-boolean
  member value, or an unrecognized member (a typo'd `:loopbak_redirect`),
  raises `ArgumentError` instead of being silently ignored. This matters
  because `:loopback_redirect` is the switch an operator reaches for to
  *forbid* a relaxation: `native_apps: [loopback_redirect: System.get_env("X",
  "false")]` yields the string `"false"`, which must not be mistaken for
  "enabled". The predicate itself now reads strictly (`== true`), matching every
  other flag in `AttestoPhoenix.Config`; only the default differs.

### Upgrading from 2.2.0

Behavior changes only where a client is marked native — `:client_native?`
still defaults to `false`, so a deployment that classifies no clients is
entirely unaffected.

Where native clients do exist, these configuration shapes gain the §7.3
exception that 2.2.0 withheld: `:native_apps` omitted entirely; `native_apps:
[]`; `native_apps: nil`; and `native_apps: [reject_embedded_user_agents:
true]` (a host that configured the group for §8.12 only). `loopback_redirect:
true` becomes a no-op and `false` keeps its meaning, so an explicit setting
is unchanged either way.

> #### Check whether your `:client_store` exports `client_native?/1` {: .warning}
>
> 2.2.0 noted that a `:client_store` module already exporting a function of
> that name — meaning "native to our platform", "first-party" — would be read
> as the RFC 8252 classification. In 2.2.0 the consequences were *restrictions*
> (forced PKCE, refused client secrets), which a public + PKCE client would not
> have noticed. **In 2.3.0 the same accidental mark also widens redirect-URI
> matching**: any such client with a loopback redirect URI registered — a
> routine `http://127.0.0.1:3000/callback` dev entry alongside the production
> one — will accept the authorization code on *any* port on 127.0.0.1.
>
> If your client store exports `client_native?/1` for an unrelated purpose,
> rename it, or set the flat `:client_native?` config key to a function
> returning `false`, before upgrading.

## [2.2.0] - 2026-07-28

### Upgrade note

- `client_native?/1` is a new **optional** `AttestoPhoenix.ClientStore`
  callback, resolved automatically from an installed `:client_store` module the
  same way every other client callback is. If your client-store module already
  exports a function of that name meaning something else — "native to our
  platform", "first-party", and so on — it will now be read as the RFC 8252
  native-app classification, which forces PKCE for those clients and refuses
  their client secrets at every endpoint. Rename it, or set the flat
  `:client_native?` config key to a function returning `false`, before
  upgrading. Hosts with no such function are unaffected.

### Added

- RFC 8252 (BCP 212) native-app profile support, keyed on a new
  `:client_native?` client-store callback (`(client -> boolean())`, defaulting
  to `false`) and a new `:native_apps` option group. Every part of it is off
  until the host classifies its clients, so an existing deployment's behavior is
  unchanged.

  With a client marked native, two restrictions apply and need no flag:
  PKCE is required for it regardless of the global `:require_pkce` setting
  (§8.1; `S256`-only and no `plain` were already unconditional), and a client
  marked both native and public may only authenticate at the token endpoint
  with `none` — `client_secret_basic`, `client_secret_post`, and
  `private_key_jwt` are refused with the usual generic `invalid_client` (§8.4),
  because a credential shipped inside an installed binary is not confidential.
  Only a native client the host *explicitly* classifies as confidential keeps
  the secret path, that being the per-instance-credential case §8.4 carves out
  for dynamic registration. Where no `:client_public?` callback is configured
  at all, a client marked native counts as public — so wiring `:client_native?`
  alone gets §8.4 enforcement rather than silently accepting a shipped secret,
  and the same client is still admitted on `none` + PKCE. An unclassified
  *non-native* client remains confidential, unchanged.

  Two rules are additionally opt-in through `:native_apps`:

  - `loopback_redirect: true` enables RFC 8252 §7.3 loopback interface
    redirection for native clients: an `http://127.0.0.1/...` or
    `http://[::1]/...` redirect URI matches the registered one on any port, so
    an ephemeral port bound at runtime needs no registration, while scheme,
    host, path, and query still compare exactly. Nothing else is relaxed —
    `https`, private-use schemes, remote hosts, non-native clients, and the
    hostname `localhost` (forbidden by §8.3) stay byte-exact, and an unmatched
    redirect URI is still a direct, non-redirectable error. **This widens a
    check the OpenID Connect and FAPI profiles assume is exact, so enabling it
    is incompatible with certifying against them**; it requires both the
    server-wide flag and the per-client mark.
  - `reject_embedded_user_agents: true` enables the RFC 8252 §8.12 refusal of
    authorization requests that appear to come from an in-app webview, via the
    new `AttestoPhoenix.RequestContext.embedded_user_agent?/1` and
    `check_embedded_user_agent/2`. Detection is a `User-Agent` heuristic and is
    documented as defense in depth rather than a boundary, which is why it is
    opt-in; it applies to all clients, since the embedding app need not be the
    OAuth client.

  Also adds `AttestoPhoenix.AuthorizationServer.RequestPolicy.redirect_uri_matching/2`
  and `client_native?/2`, and `AttestoPhoenix.Config.native_apps/1`,
  `native_app_loopback_redirect?/1`, and `reject_embedded_user_agents?/1`.

### Security

- Bind a pushed authorization request to the client that actually authenticated
  (RFC 9126 §2.1). `AttestoPhoenix.AuthorizationServer.PAR.Request` now carries
  the identifier from `AttestoPhoenix.ClientAuthentication.Result`, and the
  stored record is bound to it whenever the optional `:client_id` callback does
  not resolve one. Previously the request body's own `client_id` was left in
  place in that case, contrary to the documented contract that it is "never
  trusted from the request body". Because the stored record is later resolved at
  the authorization endpoint *against the client named in it*, an authenticated
  client could push a request naming a different client and have the
  authorization endpoint issue a code for that client while the `redirect_uri`
  had only been validated against the pusher's registered set — a confused
  deputy reachable by any deployment that exposes no `:client_id` callback.

  Relatedly, a pushed `client_id` that disagrees with the authenticated client
  is now rejected with `invalid_request` rather than silently rewritten,
  matching how the token endpoint already treats a conflicting `client_id`. The
  check runs on the effective parameters, so one carried only inside a signed
  request object is covered. A client that pushes its own `client_id` — every
  conforming client — is unaffected.

- Verify a pushed signed request object (RFC 9101) against the bound client
  identifier rather than the host `:client_id` callback alone. A deployment
  exposing no such callback previously verified every pushed request object
  against a `nil` issuer, which `Attesto.RequestObject` treats as unverifiable,
  so PAR + JAR was rejected outright as `invalid_request_object` for those
  hosts.

- Apply the RFC 8252 §8.4 client-authentication restriction at the revocation
  endpoint too. It parses credentials itself rather than going through
  `AttestoPhoenix.ClientAuthentication`, so without this it would be a second
  authentication surface accepting a secret the token endpoint refuses. No
  effect on a deployment that exposes no `:client_native?` callback.

### Changed

- Raise the test-only Bandit floor to 1.12.1, excluding the releases affected
  by the quadratic-time WebSocket fragment-reassembly denial of service
  (EEF-CVE-2026-65623, introduced in 1.11.0). Test-only, so no published
  consumer was ever exposed.
- Require `attesto ~> 1.4`, which carries `Attesto.RedirectURI` and the
  `:redirect_uri_matching` validation option this release depends on. Against
  an older `attesto` the loopback option would be silently ignored rather than
  refused, so the floor is raised rather than left at 1.3.

## [2.1.0] - 2026-07-25

### Added

- Add `:client_auth_enforce_fapi_alg_policy` and the corresponding CIBA
  `:enforce_fapi_alg_policy` option. Omitted algorithm lists retain FAPI key
  enforcement, while an explicit list remains an intentional non-FAPI policy
  unless the host opts back into enforcement.
- Advertise RFC 9864 `Ed25519` alongside legacy `EdDSA` in the default client
  assertion and request-object algorithm metadata.
- Advertise `introspection_endpoint_auth_signing_alg_values_supported` from the
  same client-assertion policy enforced by the introspection endpoint.
- Add a minimum-version consumer smoke test without Req so optional dependency
  regressions fail CI. It covers disabled, active-default, and custom-adapter
  configurations and fails CI on any compiler warning from AttestoPhoenix
  against the minimum dependency set.

### Fixed

- Compile the bundled Back-Channel Logout and CIBA ping Req implementations
  only when the optional Req dependency is available, matching the Client ID
  Metadata fetcher. Consumers that supply their own HTTP implementations can
  now compile without adding Req. Enabled features validate the selected
  adapter module and callback at configuration time; a missing bundled Req
  adapter gets actionable dependency guidance instead of crashing on the first
  outbound request.
- Correct the CIBA ping documentation to use the top-level
  `:ciba_ping_http_client` configuration key.
- Reject CIBA `:push` delivery at configuration time because AttestoPhoenix has
  no push deliverer. Advertising an undeliverable mode could leave an approved
  request with no notification and no polling fallback.
- Reject malformed signing-algorithm lists and enforced lists that contain
  algorithms outside Attesto's FAPI set, preventing discovery metadata from
  advertising an algorithm the corresponding verifier must reject.

### Security

- Enforce the FAPI RSA modulus and Edwards-curve policy through every
  `private_key_jwt` endpoint and CIBA signed-request validation. The default
  rejects PS256 keys below 2048 bits and legacy `EdDSA` over Ed448; named and
  narrowed FAPI request-object policies retain the same checks.
- Restrict Phoenix and Plug requirements to advisory-patched releases across
  every supported minor line. This preserves the widest compatible dependency
  range without allowing a resolver to select a known-vulnerable version.
- Raise the Attesto runtime floor to 1.3.0 for key-bound FAPI enforcement and
  RFC 9864 Edwards identifiers. The floor also retains the transitive JOSE and
  Plug compatibility and security boundaries from Attesto 1.2.5. Raise the
  development/test Postgrex floor to 0.22.3.

## [2.0.2] - 2026-07-16

### Changed

- **Upgrade note:** a configured `:client_id` callback must now return exactly
  the identifier carried by the successfully verified client credentials. A
  callback that maps the authenticated client to a different canonical or
  internal identifier now fails authentication with generic `invalid_client`.
  Keep internal identifiers on the opaque client value returned by
  `:load_client`; use `:client_id` only to confirm its OAuth identifier.

### Fixed

- The introspection endpoint now recognizes access tokens minted for trusted
  RFC 8707 resource indicators. It derives the accepted audience set from the
  configured default audience plus static and signed original-token-client
  resource allowlists, while unknown resources and partially untrusted audience
  arrays remain inactive. The introspection caller remains a separate
  authorization decision.
- Token exchange now accepts trusted resource-audienced subject tokens and
  stamps the authenticated exchanger's `client_id` instead of inheriting the
  subject token's client. An omitted `resource` preserves and re-authorizes the
  complete subject audience rather than falling back to the server default.
- Every token-endpoint grant now uses one immutable, credential-carried
  `client_id` for state redemption, access and ID Tokens, refresh families, and
  audit. Host callbacks may confirm that identifier but cannot relabel an
  authenticated client, and trusted direct callers retain their legacy builder
  claim fallback.
- Invalid static resource indicators and callback configuration now fail at
  boot; malformed dynamic callback entries are ignored safely.

### Security

- Raise the direct Plug dependency floor to 1.19.5, matching Attesto core and
  excluding releases affected by multipart temp-file exhaustion,
  nested-parameter quadratic-time denial of service, and cookie
  attribute-injection advisories.

## [2.0.1] - 2026-07-16

### Security

- Raise the optional Req dependency floor to 0.6.1, the first release patched
  for EEF-CVE-2026-49755 decompression-bomb denial of service. The built-in
  Client ID Metadata, CIBA ping, and back-channel logout HTTP implementations
  can receive responses from remote endpoints and now cannot resolve with an
  affected Req release.
- Replace the test-only Bypass/Cowboy origin servers with a local Bandit-backed
  helper, removing the advisory-affected Cowlib dependency from the development
  lock and CI audit surface.

### Documentation

- Clarify that `:require_https` controls incoming request transport checks; it
  never relaxes the standards-required HTTPS issuer and advertised endpoint
  validation.

## [2.0.0] - 2026-07-15

> **Why this is a major release.** The released 1.4 public contract accepted
> absolute non-HTTPS endpoint overrides, and UserInfo did not apply the existing
> `:require_https` policy. The security and conformance corrections below can
> therefore fail a previously accepted configuration at startup or change an
> HTTP UserInfo response from success to rejection. They are incompatible
> behavior changes under this project's declared Semantic Versioning policy,
> even though the old behavior was not standards-conformant.

### Added

- `attesto_routes/1` accepts `userinfo: false` and
  `openid_configuration: false` as independent, compile-time route-mount
  controls. Both default to `true`, so existing calls retain the
  exact route table and pipeline data; OAuth-only hosts can omit the OIDC-only
  surfaces without restating the authorization-server routes. Disabling OpenID
  configuration does not remove or alter RFC 8414 authorization-server
  metadata.
- `:userinfo_endpoint` accepts `:derived` as an explicit derivation marker for
  the issuer/path-derived bundled UserInfo URL. With `userinfo: false`, only
  this derived value can be suppressed when it is route-equivalent to the
  removed local endpoint. An explicit HTTPS URL is always authoritative,
  including at the same path, so a host can replace the bundled controller
  without losing Provider Metadata; `nil` retains its released omission
  behavior. Suppression follows Phoenix/Plug dispatch semantics for prefixes,
  static and dynamic scopes, empty path segments, trailing/repeated slashes,
  percent-decoded request segments, dot segments, non-default ports, and
  forwarded router mounts. A dynamic macro `:prefix` is rejected when
  `userinfo: false` is combined with `openid_configuration: true`, because the
  retained Provider Metadata route cannot resolve that prefix; a surrounding
  dynamic Phoenix scope remains supported.
- `AttestoPhoenix.Config` accepts a `:resource_metadata_resolver` callback that
  selects an RFC 9728 protected-resource metadata URI for each request or
  returns `nil` to omit it. `AttestoPhoenix.Plug.Authenticate` and UserInfo use
  the selected URI consistently across core verification, revoked-token,
  insufficient-scope, and transport failures. The existing static
  `:resource_metadata` URL remains the backward-compatible fallback when no
  resolver is configured. Function, `{module, function}`, and
  `{module, function, extra_args}` forms are supported; extra arguments follow
  the request argument. Configuration validates MFA callbacks and their
  effective arity. Invalid runtime resolver values are safely omitted; an
  explicit per-Plug override, including `nil`, skips the resolver; and a
  resolver exception deliberately propagates and fails the request.

### Changed

- **Breaking — advertised URL validation.** `AttestoPhoenix.Config.new/1` now
  requires an HTTPS issuer with a host and no query or fragment, and requires
  explicit `:authorization_endpoint` and `:userinfo_endpoint` URLs to use HTTPS
  with a host and no fragment. Previously accepted insecure or malformed values
  now raise `ArgumentError` during configuration. Migrate production and local
  issuers/endpoints to HTTPS, remove query/fragment components from the issuer,
  and use the locally trusted certificate workflow in `guides/local_https.md`
  for development. Endpoint query components remain supported.
- **Breaking — UserInfo transport enforcement.** UserInfo now applies
  `:require_https` before token verification or claim release. A deployment that
  terminates TLS at a proxy must configure the immediate proxy in
  `:trusted_proxies` so its forwarded HTTPS scheme is trusted; do not disable
  HTTPS in production.
- **Potentially breaking — static Plug option validation.** A non-`nil`
  `resource_metadata:` option passed directly to
  `AttestoPhoenix.Plug.Authenticate` is now validated by `init/1` and raises for
  an invalid URL. Phoenix runs Plug initialization at compile time by default;
  hosts using runtime Plug initialization see the same error when the Plug is
  initialized. Fix the URL or use explicit `nil`. Invalid runtime resolver
  returns are still safely omitted, while a resolver exception deliberately
  propagates and fails the request.

### Fixed

- UserInfo now honors the configured error transport hooks on verification,
  TLS, revoked-token, and insufficient-scope failures. UserInfo also now honors
  `bearer_methods_supported` (previously it accepted header credentials only,
  regardless of configuration): a host advertising `"body"` will see UserInfo
  begin accepting RFC 6750 §2.2 form-body tokens as advertised.
- An explicit per-plug `:resource_metadata` value (including `nil`) and error
  transport hooks now take precedence consistently across core verification,
  TLS, revocation, and principal-resolution failures.
- OpenID Provider Metadata now derives the required `authorization_endpoint`
  when no override is configured, and both OAuth and OpenID metadata honor the
  same validated external override.

### Security

- Issuer and advertised endpoint validation now enforces the HTTPS requirements
  of RFC 8414 and OpenID Provider Metadata, and UserInfo no longer accepts or
  releases Bearer-token claims over an insecure transport when HTTPS is
  required. These security fixes are also the breaking changes called out
  above.

## [1.4.0] - 2026-07-15

### Added

- `attesto_routes/1` accepts `route_pipelines:` overrides for the documented
  `:metadata`, `:interactive`, and `:protocol` route classes. Each atom or
  ordered atom list replaces the legacy `pipeline:` default for that class,
  allowing browser/resource-owner support to remain separate from public
  metadata and externally submitted OAuth protocol requests. Calls without the
  new option retain the existing route table and pipeline data.

### Fixed

- `route_pipelines:` now rejects `nil` values and module-attribute pipeline
  expressions with actionable compile-time errors instead of silently treating
  `nil` as an empty pipeline list or exposing Phoenix's internal attribute AST.

## [1.3.0] - 2026-07-13

### Added

- **RFC 9728 conformance: the path-inserted protected-resource metadata URI.**
  `attesto_routes/1` grows `protected_resource_paths: ["/mcp"]`, mounting the
  RFC 9728 §3.1 path-inserted well-known form
  (`/.well-known/oauth-protected-resource/mcp`) alongside the root document.
  Clients that derive that form from the resource URL (current MCP clients
  probe it first, before the `WWW-Authenticate` `resource_metadata` fallback)
  previously missed a host serving only the root URI. The controller enforces
  RFC 9728 §3.3 fail-closed: the served `resource` member must equal the
  identifier the URI is derived from, so a mounted path that disagrees with
  the configured resource identifier raises at first request instead of
  serving a document a conformant client is required to reject. More than one
  path is a compile-time error pointing at `attesto_mcp`'s per-resource
  `attesto_mcp_protected_resource_metadata/2`.
- `attesto_routes/1` grows `protected_resource_root: false` to hand root PRM
  document ownership to `attesto_mcp`'s macro in combined AS+RS apps, so each
  PRM route has exactly one owner.

## [1.2.0] - 2026-07-08

### Added

- **OpenID Connect CIBA (Client-Initiated Backchannel Authentication) — the
  Phoenix layer.** The backchannel authentication endpoint (`/bc-authorize`),
  poll and ping token delivery, the §10.2 ping notification deliverer, and an
  Ecto-backed CIBA request store. Certified **FAPI-CIBA ID1** in both **poll**
  and **ping** delivery modes.
- **Local HTTPS for development.** `AttestoPhoenix.DevTLS.https_opts/1` wires a
  mkcert certificate into a Phoenix dev endpoint in one line, and
  `mix attesto_phoenix.gen.dev_https` generates it — so an app can develop
  against attesto's required `https` issuer with no tunnel and no downgrade. New
  `guides/local_https.md`; the installer points at it.

### Changed

- Discovery advertises `tls_client_certificate_bound_access_tokens` when mTLS is
  enabled (RFC 8705 §3.3).
- The token endpoint and the CIBA backchannel endpoint accept the issuer
  identifier, the token-endpoint URL, **or** the endpoint's own URL as a
  `private_key_jwt` client-assertion audience (RFC 7523 §3).
- The CIBA `client_notification_token` is stored as `:text` (CIBA §7.3 sets no
  length bound); requires a fresh migration via `mix attesto_phoenix.gen.migration`.
- The CIBA ping notification channel offers TLS 1.3 (FAPI transport).

### Fixed

- The UserInfo endpoint now adapts a `{module, function}` `:cert_der` callback to
  the bare function `Attesto.Plug.Authenticate` requires, so mTLS
  certificate-bound tokens are correctly enforced at the resource server (a
  presented certificate that does not match the token's `cnf.x5t#S256` is
  rejected).

## [1.1.0] - 2026-07-07

### Added

- **OpenID Connect Front-Channel Logout 1.0 (OP side).**
  - The end-session endpoint renders every front-channel-capable RP's
    registered `frontchannel_logout_uri` in a hidden iframe on the logout page
    (with `iss`/`sid` whenever the session's `sid` is known), then completes
    the RP-Initiated flow from the page itself: with a validated
    `post_logout_redirect_uri` it continues there once the iframes have loaded
    (JavaScript with a bounded timeout, plus a meta-refresh and a visible link
    as no-JS fallbacks); with no return URI the page is the logged-out page.
    The iframes and the back-channel `logout_token` POSTs are driven by the
    same atomically-taken logout-session rows, so a session is fanned out
    exactly once. A non-browser caller cannot run iframes, so front-channel
    targets are skipped (logged) and the response is unchanged.
  - The token endpoint records a logout session at ID-Token mint for any
    client that registered a `frontchannel_logout_uri` and/or a
    `backchannel_logout_uri` (previously back-channel only).
    `AttestoPhoenix.Schema.LogoutSession` / `EctoLogoutSessionStore` carry the
    new `frontchannel_logout_uri` / `frontchannel_session_required` columns,
    `backchannel_logout_uri` is now nullable, and the migration template
    reflects the new shape.
  - Client registry: new `:client_frontchannel_logout_uri` /
    `:client_frontchannel_logout_session_required` Config callbacks (and
    optional `AttestoPhoenix.ClientStore` callbacks). A non-`https`
    `frontchannel_logout_uri` is treated as absent (browsers block it as
    mixed content on the https logout page), a deliberate tightening of the
    spec's http-for-confidential-clients allowance.
  - Dynamic registration passes `frontchannel_logout_uri` (string) and
    `frontchannel_logout_session_required` (boolean) through to the host
    store (Front-Channel Logout 1.0 §2).
  - Discovery advertises `frontchannel_logout_supported` /
    `frontchannel_logout_session_supported` when logout is enabled and a
    `:logout_session_store` is wired.
- **OpenID Connect Session Management 1.0 (OP side).**
  - `session_management: [enabled: true]` turns the feature on;
    `attesto_routes(session_management: true)` mounts
    `GET /oauth/check_session`, the §3.3 `check_session_iframe` served by the
    new `AttestoPhoenix.Controller.CheckSessionController` (a static page
    whose script recomputes `session_state` with `crypto.subtle` from the
    message's `client_id`, the sender's `MessageEvent.origin`, the OP
    browser-state cookie, and the received salt, replying
    `unchanged`/`changed`/`error`).
  - Successful authorization responses carry the §2 `session_state`
    parameter, computed by `Attesto.SessionState` over the `redirect_uri`'s
    browser origin. (Deliberate deviation: the SHOULD-level `session_state` on
    authorization **error** responses is not emitted.)
  - `AttestoPhoenix.BrowserState` owns the JavaScript-readable OP
    browser-state cookie (`SameSite=None; Secure`, not `HttpOnly`): minted at
    the authorization endpoint when absent (login), expired at the
    end-session endpoint (logout), so a post-logout recomputation yields
    `changed`.
  - Discovery advertises `check_session_iframe` when the feature is enabled.

## [1.0.0] - 2026-07-04

First stable release; the public API is now under semantic versioning. No
functional change from 0.20.0. Requires `attesto ~> 1.0`.

The Phoenix/Ecto authorization-server layer drives an OpenID Provider that
passes the OpenID Foundation conformance suite for OpenID Connect Core (Basic),
FAPI 2.0 Security Profile Final, FAPI 2.0 Message Signing Final, RP-Initiated
Logout, and Back-Channel Logout.

## [0.20.0] - 2026-07-01

### Changed

- **End-session endpoint now content-negotiates its responses.** The
  browser-facing `/oauth/end_session` errors (`invalid post_logout_redirect_uri`,
  `invalid id_token_hint`, ...) and the default logged-out response rendered
  JSON to every caller; a browser (`Accept: text/html`) now gets a minimal
  human-readable HTML page instead, while non-browser callers keep the JSON
  body — matching the authorization endpoint's direct-error handling. A wired
  `:render_logged_out` callback still takes precedence.

## [0.19.1] - 2026-06-26

### Fixed

- **Authorization-endpoint direct-error HTML showed the wrong code.** A
  non-redirectable `/authorize` error rendered to a browser (`Accept:
  text/html`) hardcoded `invalid_request` in the page, while the JSON body
  correctly carried the resolved code. A browser hitting an expired/unknown PAR
  `request_uri` therefore saw `invalid_request` instead of `invalid_request_uri`
  (which a conformance check reading the rendered page rejects). The HTML page
  now renders the same resolved code as the JSON body.

## [0.19.0] - 2026-06-23

### Added

- **Dynamic-registration default scope (RFC 7591 §2).** A new
  `:registration_default_scope` config assigns a scope to a client that
  registers without one — `:scopes_supported` for the full catalog, or an
  explicit list (validated against `:scopes_supported` at boot) — echoed back in
  the §3.2.1 response so the client learns what it got. Default `nil` keeps the
  prior fail-closed behavior (a scopeless registration stays scopeless). This
  lets a scopeless DCR client (e.g. an MCP/agent client) register with a usable
  scope as protocol behavior, rather than each host's `authorize_scope` fallback
  reinventing it.

### Changed

- **Token-endpoint error diagnostics.** `POST /oauth/token` now logs the
  resolved RFC 6749 §5.2 error code + description at `:debug` at the single
  render boundary, so a host operator can tell e.g. `invalid_scope` from
  `invalid_grant` behind an otherwise-opaque 400 without reading the source. The
  level is `:debug` so a 4xx under load is never prod log noise; the structured
  `:token_denied` event still carries the same reason for hosts that want it
  louder.

## [0.18.0] - 2026-06-23

### Added

- **OpenID Connect Logout (RP-Initiated Logout 1.0 + Back-Channel Logout 1.0).**
  A `logout: true` option on `attesto_routes/1` mounts `GET`/`POST
  /oauth/end_session` (`AttestoPhoenix.Controller.EndSessionController`), gated
  by a `logout: [enabled: true]` config block. The endpoint verifies the
  `id_token_hint`, validates `post_logout_redirect_uri` against the client's
  registered set (exact match — no open redirect), and either redirects with
  `state` or hands off to the host's logged-out page.
  - The **host is the session authority**: a REQUIRED `:terminate_session`
    callback clears the browser session and returns the confirmed
    `%{sid, subject}` that scopes the Back-Channel fan-out — so a replayed or
    stolen `id_token_hint` cannot force-log-out an arbitrary session.
    `AttestoPhoenix.Config` raises at boot if logout is enabled without it (no
    fail-open logout). `:render_logged_out` is an optional page renderer.
  - Back-Channel fan-out: a `logout_token` is POSTed to every RP holding the
    terminated session, recorded at ID-Token mint
    (`AttestoPhoenix.Schema.LogoutSession` + `EctoLogoutSessionStore`, a new
    `attesto_logout_sessions` table) and taken atomically
    (`DELETE ... RETURNING`) so concurrent logouts cannot double-deliver.
    Delivery (`AttestoPhoenix.BackChannelLogout` / `.Req`) is best-effort and
    SSRF-guarded: a `backchannel_logout_uri` is honored only when it is `https`
    with no userinfo/fragment and a non-internal host (loopback / RFC 1918 /
    link-local / ULA literals are refused).
  - The authorization endpoint threads the host's `:sid` (from the authenticate
    subject map) into the ID Token, and dynamic registration accepts
    `post_logout_redirect_uris`, `backchannel_logout_uri`, and
    `backchannel_logout_session_required`. Discovery advertises
    `end_session_endpoint` + `backchannel_logout_supported` +
    `backchannel_logout_session_supported` when enabled. The sweeper reaps
    expired logout-session rows.

- Requires `attesto ~> 0.13`.

## [0.17.0] - 2026-06-23

### Added

- **RFC 8628 Device Authorization Grant.** A `device: true` option on
  `attesto_routes/1` mounts `POST /oauth/device_authorization` and the
  `GET`/`POST /oauth/device_verification` page; the token endpoint gains a
  `device_code` grant dispatch (the §3.5 polling errors render with their own
  codes, not collapsed to `invalid_grant`). A PUBLIC (`:none`) client MUST
  present a DPoP proof at the device-authorization endpoint (a device-issued
  bearer token has no PKCE/redirect backstop), and the bound RFC 8707 `resource`
  / RFC 9470 `acr`+`auth_time` thread through to the minted token. New
  `device_authorization` config block + `:device_code_store`, the
  `AttestoPhoenix.Store.EctoDeviceCodeStore` (every transition a single guarded
  atomic UPDATE) + `attesto_device_codes` table, the
  `:authenticate_device_user` / `:render_device_verification` host callbacks,
  and `device_authorization_endpoint` advertised in discovery when enabled.

### Changed

- Requires `attesto ~> 0.12`.

## [0.16.0] - 2026-06-22

### Added

- **RFC 9470 Step-Up Authentication.** The token endpoint mints the
  authentication context (`acr` / `auth_time`) onto access tokens so a resource
  server can enforce a step-up requirement: `authorization_code` mints them from
  the redeemed code's claims, and the refresh family persists and replays the
  ORIGINAL `acr` / `auth_time` (never re-stamped on rotation). A machine grant
  establishes no auth context and so fails closed against any step-up
  requirement. New `acr` / `auth_time` columns on `attesto_refresh_tokens`
  (migration generator + schema).

### Changed

- Requires `attesto ~> 0.11`.

### Fixed

- **Refresh-family revocation race (security).** `AttestoPhoenix.Store.EctoRefreshStore`
  now serializes `insert/1` and `revoke_family/1` for a given family with a
  Postgres advisory transaction lock. Previously, under `READ COMMITTED`, a
  successor insert could interleave with a concurrent family revocation and
  leave a live token in a revoked family (a `FOR UPDATE` on existing rows would
  not catch the just-inserted successor — a phantom). Sticky family revocation
  (RFC 6749 §10.4 / OAuth 2.0 Security BCP) now holds under concurrency.

## [0.15.0] - 2026-06-22

### Added

- **RFC 8707 Resource Indicators across every grant.** `client_credentials`,
  token exchange, and jwt-bearer validate (§2.1) and authorize (§2.2) the
  request-time `resource` and mint the access-token `aud` from it;
  `authorization_code` binds the resource authorized at the authorize endpoint
  and mints `aud` from it (optionally narrowed at redemption, never widened);
  `refresh_token` carries and subset-narrows it. Multiple allow-listed resources
  mint a JWT `aud` array; an unserved resource is `invalid_target`.
- Grant-agnostic `resource_indicators: [allowed_resources, allowed_resources_for]`
  config and `AttestoPhoenix.Config.allowed_resources/2` (server `:audience` +
  static list + optional per-client callback), replacing the jwt-bearer-only
  `jwt_bearer: [allowed_resources]`.
- A `resource` column persisted on the authorization-code and refresh-token
  stores (migration generator + schemas).

### Security

- Token exchange now ceilings a requested `resource` to the subject token's own
  `aud` (RFC 8693 §2.1 / RFC 8707): a token confined to resource A can no longer
  be exchanged for one audienced to a sibling resource B.

### Changed

- Requires `attesto ~> 0.10`.

## [0.14.2] - 2026-06-22

### Fixed

- `AttestoPhoenix.RequestContext` now folds an IPv4-mapped IPv6 peer address
  (`::ffff:a.b.c.d`) back to its IPv4 tuple before testing it against
  `:trusted_proxies`. A dual-stack listener bound on `::` (the common Docker /
  Kamal topology, where a TLS-terminating reverse proxy reaches the app over an
  IPv4 bridge network) surfaces the proxy peer as `::ffff:172.x.y.z`, which an
  IPv4 CIDR allowlist (e.g. `172.16.0.0/12`) never matched — so the proxy was
  treated as untrusted, `X-Forwarded-Proto: https` was ignored, and a
  legitimately TLS-terminated request to the token / protected-resource
  endpoint was misread as plain HTTP and refused with `invalid_request`
  ("TLS required"). The fold makes the forwarded-header trust gate work behind
  such a proxy without widening the allowlist to IPv6.

## [0.14.1] - 2026-06-22

### Fixed

- `AttestoPhoenix.Store.NonceStore` now calls the `Attesto.DPoP.NonceStore`
  behaviour callback `issue/1` (with an explicit TTL) on its config-free
  fallback, instead of an arity-0 `issue/0` that the behaviour does not
  guarantee. A third-party nonce store implementing the behaviour exactly
  (`issue/1` only, without an arity-0 convenience) is now dispatched correctly
  rather than crashing in the fallback. The bundled ETS and Ecto stores are
  unaffected. Doc corrected to stop referring to a non-existent `issue/0`.
- The token endpoint now rejects a request carrying more than one `DPoP` header
  outright with `invalid_dpop_proof` (RFC 9449 §4.3), rather than silently
  selecting one proof — closing a header-smuggling vector where an intermediary
  could inject an attacker's proof.
- An unparseable client certificate at the token endpoint now returns
  `invalid_request` ("invalid client certificate") rather than `invalid_client`:
  non-X.509 bytes are a malformed request parameter (there is nothing to bind a
  token to), not a client-authentication failure.
- The token-endpoint denial path no longer raises when the request body was
  never parsed (e.g. a rejected/unsupported `Content-Type` leaves `body_params`
  an `%Plug.Conn.Unfetched{}` struct). It now falls back to the action params
  instead of treating the struct as parsed params and raising on key access.

## [0.14.0] - 2026-06-22

### Security

- `AttestoPhoenix.AuthorizationServer.SenderConstraint.resolve/3` now resolves a
  client's REQUIRED sender constraint before any opportunistic binding, so a
  required constraint can no longer be satisfied by presenting a DIFFERENT
  valid one. Previously the first opportunistically-present constraint was
  bound before the client's requirement was checked: a DPoP-required client
  that presented a client certificate (and no proof) was issued an
  mTLS-bound token, and symmetrically an mTLS-required client presenting a DPoP
  proof was DPoP-bound — defeating the per-client policy. Now a DPoP-required
  client is bound only by a DPoP proof (a certificate-only request is rejected
  with `DPoP proof required`), an mTLS-required client only by a certificate (a
  proof-only request is rejected with `client certificate required`), and a
  client requiring neither keeps the existing opportunistic precedence
  (DPoP over mTLS, else Bearer).

### Fixed

- The token-endpoint and resource-server DPoP paths now accept a
  `{module, function}` / `{module, function, extra_args}` MFA `:replay_check`.
  The configured callback was passed verbatim to `Attesto.DPoP.verify_proof/2`,
  which requires a bare 2-arity function, so a host configuring an MFA replay
  store (the only form config can hold) crashed with an `ArgumentError` on every
  DPoP request. All four DPoP verify sites — token endpoint, PAR, UserInfo, and
  the `Authenticate` plug — now adapt the callback via
  `AttestoPhoenix.Callback.to_fun2/1`.
- `dpop_nonce_required: true` no longer crashes when `AttestoPhoenix.Config` is
  configured under the host's own otp_app. The DPoP paths now thread the live
  request config into nonce issuance and validation instead of letting the
  nonce store re-resolve config from a hardcoded `:attesto_phoenix` otp_app
  (which raised when the host configured the library elsewhere). A persistent
  nonce store such as `AttestoPhoenix.Store.EctoNonceStore` receives the
  resolved config and never has to guess an otp_app.

### Added

- `AttestoPhoenix.Callback.to_fun2/1` adapts any configured callback form into
  the bare 2-arity function the DPoP verifier requires for `:replay_check`.
- `AttestoPhoenix.Store.NonceStore` dispatches to the configured
  `Attesto.DPoP.NonceStore`, threading the live `%AttestoPhoenix.Config{}` to a
  store's config-aware `issue/2` / `valid?/2` entrypoints when present and
  falling back to the behaviour arities for config-free stores.

## [0.13.5] - 2026-06-21

### Added

- `:token_denied` events now carry richer audit metadata: `:client_id` when
  known, structured `:reason` as the OAuth error atom, and sender-constraint
  fields mirroring issuance events (`:token_type`, `:sender_constraint`, and
  `:cnf`).
- `AttestoPhoenix.AuthorizationServer.SenderConstraint.audit_metadata/2` exposes
  the shared sender-constraint audit classification used by token denial events.

### Changed

- `AttestoPhoenix.Controller.TokenController` now rejects token requests whose
  `Content-Type` is not `application/x-www-form-urlencoded` or
  `application/json` before client authentication. Unsupported media types
  return `400 invalid_request` naming the rejected Content-Type.

### Fixed

- Token endpoint `invalid_client` responses from `Authorization`-header client
  authentication now follow RFC 6749 §5.2: Basic/header failures return `401`
  with a matching `WWW-Authenticate` challenge, while body credentials and
  absent credentials remain `400` without a challenge.

## [0.13.4] - 2026-06-21

### Added

- `AttestoPhoenix.ConsentGrant.binding_from_params/2` builds the same canonical
  consent-grant binding as `binding/2` from raw string-keyed OAuth params, so
  consent-screen mint actions and live `/authorize` consume callbacks no longer
  need duplicate host-side binding reconstruction.

## [0.13.3] - 2026-06-21

### Added

- **Token issuance events now include sender-constraint audit metadata.**
  `:token_issued` events, plus the related `:refresh_issued` and
  `:refresh_rotated` issuance events, now preserve the mint-time sender
  constraint in `event.metadata`: `:token_type` (`"Bearer"` or `"DPoP"`),
  `:sender_constraint` (`:none`, `:dpop`, or `:mtls`), and `:cnf`
  (`%{"jkt" => thumbprint}`, `%{"x5t#S256" => thumbprint}`, or `nil`). Existing
  `:client_ip` metadata is unchanged.

## [0.13.2] - 2026-06-21

### Fixed

- **Consent grants now bind the PKCE `code_challenge_method`.**
  `AttestoPhoenix.ConsentGrant.binding/2` and `binding_hash/1` now include
  `code_challenge_method` alongside `code_challenge`, so a grant consented for
  an `S256` authorization request cannot be reused for an otherwise-identical
  `plain` request with the same challenge value. Missing PKCE fields continue to
  canonicalize as empty strings.

### Compatibility

- The consent-grant hash input changed. Any consent grant minted before this
  upgrade will not match after the upgrade. Consent grants are single-use and
  short-TTL, so the practical effect is limited to an in-flight authorization
  started across the upgrade re-prompting once.

## [0.13.1] - 2026-06-21

### Added

- **Optional OpenApiSpex token endpoint helpers.**
  `AttestoPhoenix.OpenAPI.TokenEndpoint` now exposes reusable OpenAPI values for
  `POST /oauth/token`: `operation/1`, `schemas/0`, `request_body/0`, and
  `responses/0`. The documented surface covers RFC 6749 §4.4
  `client_credentials` form requests, body client authentication,
  `private_key_jwt`, optional DPoP proof headers, Bearer and DPoP token success
  responses, OAuth error responses, and RFC 9449 `invalid_dpop_proof` /
  `use_dpop_nonce` with `DPoP-Nonce`. The `:open_api_spex` dependency is
  optional and the module compiles only when OpenApiSpex is available.

### Changed

- **Token endpoint rejects credential-bearing query strings.**
  `AttestoPhoenix.Controller.TokenController` now rejects `grant_type`,
  `client_id`, `client_secret`, or `scope` when any appears in the query string,
  before TLS validation, client authentication, or grant dispatch. The response
  is the normal RFC 6749 §5.2 `400 invalid_request` JSON envelope. The same
  fields remain accepted in the form body.

### Fixed

- **Optional `Req` dependency remains optional for consumers.**
  `AttestoPhoenix.ClientIdMetadata.Fetcher.Req` is now compile-guarded on `Req`
  being loaded, matching the existing optional dependency declaration and
  allowing a consumer that does not enable CIMD fetching to compile
  `attesto_phoenix` with `--warnings-as-errors` without depending on `:req`.

## [0.13.0] - 2026-06-21

### Changed

- **Protected-resource bearer credentials default to header-only.**
  `:bearer_methods_supported` now defaults to `["header"]`, and
  `AttestoPhoenix.Plug.Authenticate` passes that setting through to the core
  verifier. Resource servers that intentionally accept RFC 6750 §2.2 form-body
  `access_token` credentials can configure `["header", "body"]`; the runtime
  verifier and RFC 9728 metadata now use the same setting. Requires
  `attesto ~> 0.9`.

## [0.12.0] - 2026-06-21

### Added

- **Single-use, request-bound consent grants (RFC 6749 §4.1.1).** A new
  authorization-server correctness primitive that ties one consent decision to
  the *exact* authorization request the resource owner saw, so an Authorize
  click cannot approve a different client, redirect URI, scope set, or PKCE
  challenge than the one displayed. Opt-in and additive — a host that does not
  wire it is unaffected.
  - `AttestoPhoenix.ConsentGrantStore` — the store behaviour (`mint/2`,
    `consume/2`). `consume/2` is a single atomic conditional `UPDATE`, so a grant
    token works exactly once, for exactly the request it was granted for, even
    under concurrent presentation.
  - `AttestoPhoenix.ConsentGrant` — the canonical request binding
    (`subject + client_id + redirect_uri + sorted scope set + code_challenge`).
  - `AttestoPhoenix.Store.EctoConsentGrantStore` +
    `AttestoPhoenix.Schema.ConsentGrant` — the Postgres-backed implementation,
    swept by `AttestoPhoenix.Store.Sweeper`.
  - `AttestoPhoenix.Config` `:consent_grant_store` — the opt-in callback (no
    default). The host's consent UI mints a grant when the user authorizes; the
    `:consent` callback consumes it before a code is issued.
  - `mix attesto_phoenix.gen.migration` emits the `attesto_consent_grants`
    table; `mix attesto_phoenix.install` wires `EctoConsentGrantStore`.

### Fixed

- **Docs:** `AttestoPhoenix.ConsentGrantStore` referred to `consume/3` in two
  places; the callback is `consume/2`.

## [0.11.0] - 2026-06-20

### Added

- **`AttestoPhoenix.Config` `:bearer_methods_supported`** — the RFC 6750
  access-token presentation methods the resource server accepts, advertised as
  `bearer_methods_supported` in the RFC 9728 protected-resource metadata document
  (`/.well-known/oauth-protected-resource`). Previously the
  `ProtectedResourceController` hardcoded `["header", "body"]`, forcing a
  header-only deployment to advertise the form-body method (RFC 6750 §2.2) it
  rejects — a metadata-accuracy/interoperability defect, since a conformant
  client could select a rejected method (RFC 9728 §2 / RFC 6750 §3). The field is
  now configurable (a non-empty list of distinct methods, each `"header"` or
  `"body"` — exactly the surface `AttestoPhoenix.Plug.Authenticate` accepts:
  the `Authorization` header (§2.1) and a POST form-body `access_token` (§2.2);
  validated at config build), mirroring `:scopes_supported`. The §2.3 `"query"`
  method is rejected — the plug never accepts a query-presented token, so
  advertising it would be the same inaccuracy inverted (and RFC 6750 §2.3 says it
  SHOULD NOT be used). Defaults to `["header", "body"]`; a header-only resource
  server sets `["header"]`.

## [0.10.0] - 2026-06-20


### Added

- **`GET /.well-known/oauth-protected-resource` endpoint
  (`AttestoPhoenix.Controller.ProtectedResourceController`).** Serves the RFC 9728
  protected-resource metadata document (`resource`, `authorization_servers`,
  `scopes_supported`, `bearer_methods_supported`), derived from the same issuer,
  audience, and scope configuration the RFC 8414 discovery document uses. Mounted
  by `attesto_routes/1` at the host root (RFC 8615); it is the discovery target of
  the `resource_metadata` `WWW-Authenticate` challenge the protected-resource
  plugs emit, so a resource server is discovery-complete without the caller
  hand-rolling the document.

- **`AttestoPhoenix.Config` `:resource_metadata`.** Absolute URL of this
  resource's RFC 9728 protected-resource metadata document. When set,
  `AttestoPhoenix.Plug.Authenticate` and the UserInfo endpoint advertise it as a
  `resource_metadata` auth-param on every `WWW-Authenticate` challenge they
  render (RFC 9728 §5.1), so a client refused with 401/403 can discover which
  authorization server issues tokens for this resource. Configured once on the
  Config; omitted from the challenge when unset.

- **`AttestoPhoenix.Config.new/1` now validates `:audience` at boot.** It must be a non-empty **absolute https URL** with a host and no fragment, not merely present. It
  is the access-token `aud` (RFC 9068 §3), the audience the protected-resource
  verifier requires (a mismatch is `:invalid_audience`), and the RFC 9728 resource
  identifier served at `/.well-known/oauth-protected-resource` — so a nil, blank,
  or non-URL value would either fail late (every token rejected `:invalid_audience`)
  or 500 the protected-resource metadata endpoint. `new/1` now raises
  `ArgumentError` instead. With RFC 8707 resource handling the minted `aud` may
  differ per request, but `config.audience` remains the required default/fallback
  and RS verification audience.

- **Identity Assertion JWT Authorization Grant (ID-JAG / `jwt-bearer`)** — the
  resource server's half of
  `draft-ietf-oauth-identity-assertion-authz-grant-04`, the grant behind MCP
  Enterprise-Managed Authorization (EMA). A token request with
  `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and an `assertion`
  (an ID-JAG signed by a trusted enterprise IdP) is exchanged for a normal
  access token — no redirect, no consent.
  - **Off by default**, gated by `jwt_bearer: [enabled: true, ...]`. When
    enabled, `urn:ietf:params:oauth:grant-type:jwt-bearer` is advertised in
    `grant_types_supported` (both discovery documents) and accepted at the token
    endpoint; existing deployments are unaffected.
  - **Trusted issuers** (`jwt_bearer: [issuers: %{...}]`): each issuer supplies
    static `:jwks`, a cached `:jwks_uri` (fetched through the SSRF-guarded CIMD
    fetcher + cache), or a custom `:jwks_resolver`; with `:allowed_algs` and an
    optional `:audience` override. Assertions from unconfigured issuers are
    denied.
  - **Validation** via `Attesto.IdentityAssertion`: `typ=oauth-id-jag+jwt`,
    signature against the issuer JWKS, `iss`/`aud`/`exp`/`iat` (with skew), the
    required `client_id` binding to the authenticated client, and `jti` replay
    (reusing the configured `:replay_check`). Every failure is RFC 6749 §5.2
    `invalid_grant`; a missing `assertion` is `invalid_request`.
  - **Subject resolution** via a new `:resolve_jwt_bearer_subject` callback
    (also installable as `resolve_jwt_bearer_subject/1` on
    `AttestoPhoenix.PrincipalStore`): maps the validated claims to a local
    principal subject, or denies. Required at boot when the grant is enabled.
  - The grant requires client authentication (confidential clients only) and
    honours per-client `grant_types`. The assertion's `scope` claim is the
    granted-scope ceiling; `:authorize_scope` narrows from there.
  - **No refresh token is issued** for this grant: access is re-derived from a
    fresh assertion on each request (RFC 7523 §4), so it cannot outlive the
    enterprise IdP's policy/deprovisioning window.
  - **RFC 8707 `resource` indicator → access-token `aud`** (via
    `Attesto.Token.mint/3`'s `:audience` option, requiring `attesto ~> 0.8`): a
    single valid resource becomes the minted `aud` (§2.2); an absent resource
    falls back to `config.audience`. The resource is authorized fail-closed
    (§2.2) — it must be `config.audience` or an explicitly configured
    `jwt_bearer: [allowed_resources: [...]]` entry — so an authenticated client
    cannot mint a token audienced to a resource the server does not serve. An
    invalid (non-absolute-URI / fragment / bad percent-encoding), multiple, or
    unauthorized resource is rejected `invalid_target` (§2.1).
  - See [the ID-JAG guide](guides/identity_assertion_grant.md). Requires
    `attesto ~> 0.8`.

### Changed

- Made OAuth error-code resolution (RFC 6749 §5.2) total by construction. The
  `@error_*` codes in the token core, token controller, introspection
  controller, and sender-constraint module are now compile-time atoms passed
  straight to `OAuthError.new/3`, replacing a private `String.to_existing_atom/1`
  round-trip that could raise `ArgumentError` and turn a clean §5.2 error body
  into a 500 if a code string were ever emitted before its atom existed.

### Documentation

- **Documented and test-proved the DCR → `client_credentials` subject seam.**
  Dynamic Client Registration (RFC 7591 §3.2.1) issues an *unprefixed*
  `client_id`, while a minted principal's `sub` MUST carry its
  `Attesto.PrincipalKind` `sub_prefix` (`:invalid_sub` otherwise). The host's
  `:build_principal` callback is the sole seam that reconciles the two by
  namespacing `:sub`; the `:build_principal` doc on `AttestoPhoenix.Config` and
  the `c:AttestoPhoenix.PrincipalStore.build_principal/3` behaviour doc now state
  this mandate and cite the prefix as mint-time defense-in-depth. A new
  end-to-end test registers a confidential `client_credentials` client through
  the registration endpoint, issues a token with the bare DCR id, and verifies
  `sub == prefix <> client_id` and `client_id == client_id`, with a negative
  control proving a non-prefixing `:build_principal` is rejected as the
  RFC 6749 §5.2 `invalid_request`.


## [0.9.5] - 2026-06-16

### Fixed

- **Holder-of-key (DPoP) failures are now surfaced ahead of the client-auth
  error (FAPI2 `ensure-holder-of-key-required`).** A token request redeeming a
  sender-constrained (DPoP-bound) authorization code WITHOUT a DPoP proof is a
  holder-of-key failure; FAPI2 expects it reported as
  `invalid_request`/`invalid_grant`/`invalid_dpop_proof`. When such a request
  ALSO lacked client authentication, the client-auth check masked it with
  `invalid_client`. The token endpoint now reads the code (via the store's
  non-consuming `c:Attesto.CodeStore.get/1`) and, when it is DPoP-bound and no
  proof is presented, returns `invalid_request "DPoP proof required"` — even
  before the client-auth failure. The code is NOT consumed, so a legitimate
  retry is unaffected. Only DPoP-bound codes are affected; a plain (e.g. OIDC)
  code still surfaces `invalid_client`. Requires attesto 0.7.2.

### Added

- **`AttestoPhoenix.Store.EctoCodeStore.get/1`** — the non-consuming read
  (`c:Attesto.CodeStore.get/1`) for the Ecto-backed code store, a plain SELECT of
  the live (unconsumed) row.

## [0.9.4] - 2026-06-14

### Security

Adversarial-review hardening of the token, authorization, and revocation
endpoints (all found by an internal multi-agent security review).

- **Public clients can no longer run confidential-only grants.** The token
  endpoint gated grants only on the optional per-client `:client_grant_types`
  callback (unset ⇒ all grants allowed), so a public (`none`) client that proved
  possession of no credential could run `client_credentials` (RFC 6749 §4.4) or
  RFC 8693 token-exchange. The resolved client-auth method is now threaded into
  the request, and both grants reject the `:none` path with `invalid_client`,
  independent of any host policy.

- **The revocation endpoint now enforces TLS.** `RevocationController` never
  called `check_https`, so under the default `require_https: true` a plain-HTTP
  `POST /oauth/revoke` carrying the client secret + refresh token was still
  processed — leaking both over cleartext. It now gates on TLS first, like every
  other credential-bearing endpoint.

- **DPoP proofs are replay-protected at the token endpoint (RFC 9449 §11.1).**
  `SenderConstraint.bind_dpop` never wired `:replay_check`, so a captured
  token-endpoint proof's `jti` was never recorded and the proof was replayable
  within its acceptance window. The proof's `jti` is now recorded (via the same
  default `Attesto.DPoP.ReplayCache` the PAR endpoint uses).

- **The direct (non-PAR) authorization endpoint honors a signed `dpop_jkt`.** It
  read `dpop_jkt` from the raw outer query, ignoring the signed request object —
  letting a front-channel attacker strip or substitute the code's DPoP key
  binding. It now reads the value off the verified request
  (`Attesto.AuthorizationRequest.dpop_jkt`, requires attesto 0.7.1), so a signed
  request object's value is authoritative. The PAR-resolved path continues to use
  the PAR-verified thumbprint stored at the top level (a pushed request object is
  re-merged at `/authorize`, which would otherwise drop it).

- **The dynamic client registration endpoint now enforces TLS.**
  `RegistrationController.create/2` returns a freshly minted plaintext
  `client_secret` and `delete/2` reads a registration-access-token bearer
  credential; neither gated on TLS, so under the default `require_https: true`
  they served those credentials over cleartext. Both now refuse plain HTTP first,
  like every other credential-bearing endpoint. (Found by adversarial
  verification of the revocation fix — same class, uncovered sibling.)

- **The revocation endpoint equalizes client-auth timing.** A lookup failure
  skipped `verify_client_secret`, leaving a timing oracle for client-id
  enumeration. It now runs a dummy verify against an `:unknown_client` sentinel
  so the unknown-client and wrong-secret paths match in observable timing,
  matching the shared `AttestoPhoenix.ClientAuthentication` core.

- **CIMD SSRF guard covers Teredo and ORCHIDv2.** Added `2001:0000::/32` (Teredo)
  and `2001:20::/28` (ORCHIDv2) to the RFC 6890 special-use IPv6 table the
  fetcher screens against.

## [0.9.3] - 2026-06-14

### Security

- **Token exchange can no longer broaden scope (RFC 8693 §2.1).** The
  token-exchange grant validated the requested `scope` only against the host's
  `:authorize_scope` policy, which is never handed the subject token — so the
  library could not, and did not, enforce that the issued token's scope stays
  within the subject token's. A client registered for a broad scope set could
  exchange a narrowly-scoped subject token for a broader one. The token endpoint
  now rejects (`invalid_scope`) any requested scope not present in the subject
  token's scope, before delegating to `:authorize_scope` — an exchange can only
  preserve or narrow scope. (`:authorize_scope` may still narrow further.)

- **The token endpoint now enforces `grant_types_supported`.** Previously the
  only grant gate was the optional per-client `:client_grant_types` callback
  (unset ⇒ every grant allowed), while discovery advertised a hardcoded grant
  superset including token-exchange — so a host that didn't lock every client
  down had an advertised, working token-exchange grant it never opted into. The
  token endpoint now rejects (`unsupported_grant_type`) any `grant_type` outside
  the configured set, as a global backstop independent of per-client policy.

### Changed

- **`grant_types_supported` is now driven by host config, not a hardcoded list.**
  Both discovery documents (RFC 8414 and OpenID configuration) and the new token
  endpoint gate read `AttestoPhoenix.Config.grant_types_supported/1`, which
  defaults to every implemented grant (so existing deployments are unchanged) and
  is narrowed by configuring `:grant_types_supported` — dropping a grant (e.g.
  token-exchange) now disables it across discovery, the token endpoint, and
  dynamic registration at once, instead of only registration.

## [0.9.2] - 2026-06-14

### Fixed

- **A CIMD client no longer crashes a host `:authorize_scope` policy.** A Client
  ID Metadata Document need not declare a `scope` member, so the metadata map
  attesto hands the host policy callbacks carried no scope key at all. A scope
  policy written for a registered client (reading `client.scopes`) raised
  `KeyError` on it, 500-ing the token endpoint for an otherwise valid CIMD
  authorization_code exchange (observed end-to-end against the ChatGPT MCP
  connector). `host_client/1` now exposes the document's *declared* scopes — or
  an empty set when the document omits `scope` — under the atom `:scopes` key, so
  the callback reads an empty *declared* set instead of a missing key. The host
  still owns what an empty set grants (typically the resource owner's consent).

### Added

- **`AttestoPhoenix.ClientIdMetadata.scopes/1`** — the public accessor for a CIMD
  document's declared scopes (its space-delimited RFC 7591 §2 `scope` member as a
  list; `[]` when absent), alongside the existing `client_id/1`, `redirect_uris/1`,
  and `jwks/1` accessors.

## [0.9.1] - 2026-06-14

### Added

- **Boot-time discovery-document safety guard.** `AttestoPhoenix.Config.new/1`
  now validates, at config-build time (alongside the existing required-key
  checks), that the discovery documents it will serve are internally consistent —
  so a "silent discovery mismatch" (a document that omits a required endpoint or
  advertises one the router does not mount, served 200 with no error) can no
  longer ship. It raises `ArgumentError` with an actionable message for two
  classes of failure:
  - **A required discovery endpoint that would be missing or non-absolute.** The
    RFC 8414 §2 / OpenID Connect Discovery §3 endpoints the library derives —
    `issuer`, `authorization_endpoint`, `token_endpoint`, and `jwks_uri` — must
    each resolve to an absolute URL (scheme + host). The realistic trigger is an
    `:issuer` that is not an absolute https URL (e.g. `"issuer.example"`), which
    `URI.merge/2` turns into host-less, unresolvable endpoint URLs; this is the
    same class of failure as the 0.9.1 regression where the RFC 8414 document
    silently omitted `authorization_endpoint`.
  - **An `:oauth_path_prefix` vs explicit per-endpoint override mismatch.** When a
    host declares a non-default `:oauth_path_prefix` (committing every OAuth
    endpoint to one mount tree) but then sets a per-endpoint override
    (`:token_path` and friends) that escapes that prefix, discovery would
    advertise that endpoint at a path the router — which mounts every OAuth
    endpoint under one shared prefix — does not serve. That provable divergence
    now fails fast. A per-endpoint override on the default prefix, or one that
    stays under the declared prefix, remains a supported feature.

### Fixed

- **The RFC 8414 `/.well-known/oauth-authorization-server` document now advertises
  `authorization_endpoint`.** It was omitted entirely: `Attesto.Discovery` derives
  only `issuer`/`token_endpoint`, and the controller's host-member list never
  supplied `authorization_endpoint`, so the OAuth metadata silently lacked a field
  RFC 8414 §2 requires for the authorization-code flow. An OAuth client that reads
  this document rather than OpenID Discovery (e.g. the ChatGPT MCP connector)
  therefore concluded the server "does not implement OAuth." It is now derived via
  `authorize_endpoint_url/1` — the same path resolution as `token_endpoint`,
  so the two cannot diverge. (OpenID Discovery's `/.well-known/openid-configuration`
  already advertised it.)

## [0.9.0] - 2026-06-14

Requires `attesto ~> 0.7.0`.

### Added

- **Client ID Metadata Documents (CIMD,
  `draft-ietf-oauth-client-id-metadata-document-01`) — opt-in, default off.** A
  client can identify itself with no prior registration by using an HTTPS URL as
  its `client_id`; the authorization server dereferences that URL to a JSON
  client metadata document and uses it as the client. Enable with
  `client_id_metadata: [enabled: true, ...]` in the config.
  - `AttestoPhoenix.ClientIdMetadata.Fetcher` (+ the default
    `...Fetcher.Req`) — the SSRF-guarded outbound GET. It resolves the host,
    rejects any A/AAAA address that is special-use (RFC 6890: loopback, private,
    link-local, CGNAT, multicast, reserved, and every IPv6 form that embeds an
    IPv4 — IPv4-mapped, NAT64 `64:ff9b::/96` and local-use `64:ff9b:1::/48`,
    6to4, IPv4-compatible — unwrapped and re-checked), pins the connection to a
    validated IP to close the DNS-rebinding window (TLS SNI/cert stay on the
    original hostname), refuses redirects, requires `200` + JSON, and caps the
    body at 5 KB. Requires the optional `:req` dependency, or a host-supplied
    `:fetcher` (e.g. a CIMD proxy service).
  - `AttestoPhoenix.ClientIdMetadata.Cache` (default Ecto, cluster-coherent;
    ETS opt-out) — respects RFC 9111 cache headers clamped to bounds, never
    caches errors/invalid documents, re-checks expiry on read. New table
    `attesto_client_id_metadata` (`mix attesto_phoenix.gen.migration`), swept by
    `AttestoPhoenix.Store.Sweeper`.
  - `AttestoPhoenix.ClientIdMetadata.Resolver` + integration: a CIMD `client_id`
    URL resolves via the document and is wired through the authorization, PAR,
    and token endpoints as a `{:cimd, metadata}` client — PKCE forced, treated
    as a public client (or `private_key_jwt` via the document `jwks`/`jwks_uri`),
    `redirect_uri` exact-matched against the document's `redirect_uris` and (by
    default) required to be same-origin with the `client_id` URL. Opaque
    `client_id`s still resolve through `:load_client` unchanged.
  - Discovery advertises `client_id_metadata_document_supported` when enabled.

- New optional dependency `{:req, "~> 0.5", optional: true}` for the default
  CIMD fetcher (a host that never enables CIMD pays nothing).

## [0.8.0] - 2026-06-14

Requires `attesto ~> 0.6.16`.

### Added

- **`AttestoPhoenix.Store.EctoPARStore` — a Postgres-backed Pushed Authorization
  Request store (RFC 9126), closing the last per-node gap to a fully clusterable
  authorization server.** PAR was the only mutable OAuth store without an Ecto
  implementation: the default `AttestoPhoenix.Store.PAR.ETS` keeps the
  `request_uri` → params mapping in per-node memory, so a reference pushed to one
  node could not be resolved when `/authorize` landed on another — and FAPI 2.0
  *requires* PAR. The new store persists each pushed request so any node resolves
  a `request_uri` issued by any other, matching the code/refresh/nonce/replay
  Ecto stores. `fetch/1` is non-consuming (the authorization endpoint may
  re-enter after a login/consent detour); `take/1` is an atomic single-use
  `DELETE … RETURNING`.
  - New `AttestoPhoenix.Schema.PushedAuthorizationRequest` (table
    `attesto_pushed_authorization_requests`, keyed on the `request_uri` primary
    key, `params` as `jsonb`).
  - `mix attesto_phoenix.gen.migration` now creates the fifth table, and
    `mix attesto_phoenix.install` wires `par_store: …EctoPARStore` by default, so
    a by-the-docs install is cluster-safe out of the box.
  - `AttestoPhoenix.Store.Sweeper` now also reclaims expired PAR references.

- **Atomic single-use of the PAR `request_uri` at completion.** The
  authorization endpoint now claims the pushed reference with the store's atomic
  `take/1` *before* issuing the code (it was previously consumed after issuance,
  with the result ignored), so two concurrent completions — on one node or
  across a cluster — can no longer each mint a code from one pushed request:
  exactly one wins the claim; the loser is redirected `invalid_request_uri` and
  issues nothing. Resolution still uses the non-consuming `fetch/1`, so a host
  may establish login/consent and re-enter `/authorize` with the same reference.

### Changed

- README documents the clustering story end-to-end and the PAR caveat; the
  `:par_store` config doc points at `EctoPARStore` for clustered/FAPI
  deployments. The default `par_store` is unchanged (single-node ETS), so
  existing single-node hosts are unaffected.

## [0.7.7] - 2026-06-13

Requires `attesto ~> 0.6.16`.

### Fixed

- **Token endpoint finalizes the authorization code only after the full
  response is built.** The `authorization_code` grant now calls
  `Attesto.AuthorizationCode.finalize/3` (new in attesto 0.6.16) once the access
  token, optional refresh token, and id_token have all been minted and recorded
  successfully. Previously the reuse marker was set the moment the code
  validated, so any later failure in the same request (a refresh-store write
  error, an id_token mint fault, a host `build_principal` callback returning the
  subject under the wrong key) left the code spent AND flagged as a successful
  redemption — turning a legitimate client retry into a false reuse attack that
  revoked the whole refresh-token family. A redemption that validates but fails
  downstream is now a clean `invalid_grant` on replay.

## [0.7.6] - 2026-06-12

Requires `attesto ~> 0.6.13`.

### Fixed

- The token endpoint no longer short-circuits a missing PKCE `code_verifier` as
  `invalid_request`. PKCE enforcement is challenge-based:
  `Token.fetch_code_verifier/3` passes the verifier through to
  `Attesto.AuthorizationCode.redeem/4`, which requires a matching verifier for a
  challenge-bound code and collapses a missing OR mismatched verifier to a single
  `invalid_grant` (RFC 7636 §4.6). The authorization/PAR endpoint still requires a
  `code_challenge` for clients that must use PKCE (`RequestPolicy.require_pkce?/2`),
  so a challenge-bound code is always issued. Matches the FAPI
  ensure-pkce-code-verifier-required test (it expects `invalid_grant`).

## [0.7.5] - 2026-06-10

Requires `attesto ~> 0.6.13`.

### Security

- **PAR `request_uri` is now single-use (RFC 9126 §2.2 / FAPI 2.0).** The
  reference is consumed once an authorization code is issued (not on the
  non-consuming `fetch` that lets the host establish login/consent and
  re-enter), so a completed flow cannot be replayed within the remaining TTL.
  An already-consumed reference is rejected as `invalid_request_uri`. (Flips the
  conformance `PARAttemptReuseRequestUri` warning to a clean pass.)
- **UserInfo derives the DPoP `htu` via `RequestContext.canonical_url`**, like
  every other endpoint — honouring a configured `:htu` but otherwise gating
  `X-Forwarded-*`/Host on the trusted-proxy allowlist. Previously it fell back
  to the raw request Host when `:htu` was unset (its default), the one endpoint
  that bypassed the host-header trust boundary.

### Fixed

- **Sender-constrained (DPoP/mTLS) clients now require PKCE.** A FAPI 2.0 client
  is sender-constrained, and FAPI 2.0 Security Profile §5.3.1.2 / RFC 9700
  §2.1.1 mandate PKCE for it even though it authenticates confidentially (e.g.
  `private_key_jwt`). `RequestPolicy.require_pkce?/2` now forces PKCE whenever
  `client_requires_dpop?`/`client_requires_mtls?` is true, regardless of the
  global `:require_pkce` flag, and the token endpoint enforces the matching
  `code_verifier` through that same predicate (one source of truth, so the
  authorization and token endpoints cannot drift). A plain confidential
  Basic-profile client still follows the global flag. (Flips the conformance
  `EnsurePKCERequired` test to a pass.)

## [0.7.4] - 2026-06-04

Requires `attesto ~> 0.6.13`.

### Security / FAPI 2.0 conformance

Closes four conformance gaps found by auditing the OpenID FAPI 2.0 test suite
source against the implementation:

- **PAR `request_uri` is bound to the client.** The authorization endpoint now
  rejects a front-channel `client_id` that does not match the client the
  `request_uri` was issued to (RFC 9126 §2.2 / `PAREnsureRequestUriIsBoundToClient`)
  instead of silently using the stored client.
- **Unknown/expired PAR `request_uri` → `invalid_request_uri`.** A
  `urn:ietf:params:oauth:request_uri:` reference not in the store now returns the
  correct `invalid_request_uri` error rather than falling through to
  `request_uri_not_supported`/`invalid_request` (RFC 9126 §2.2 /
  `PARAttemptToUseExpiredRequestUri`). External (non-PAR) references still report
  `request_uri_not_supported`.
- **PAR rejects a `request_uri` parameter.** The PAR endpoint rejects a request
  carrying `request_uri` (RFC 9126 §2.1 step 2), checked on the raw parameters so
  it cannot be masked by a `request` object replacing the set.
- **Client-assertion audience is issuer-only.** `private_key_jwt` assertions at
  the token, PAR, and introspection endpoints must be audienced to the issuer
  identifier (FAPI 2.0 §5.3.2.1); the concrete endpoint URL is no longer accepted
  as `aud`, closing a confused-deputy gap (`PAREndpointAsAudienceFails`).

### Changed

- `:authorization_response_iss` now defaults to **`true`** (RFC 9207
  authorization-server mix-up defense, mandated by FAPI 2.0). Set `false` to opt
  out. Discovery advertises `authorization_response_iss_parameter_supported`
  accordingly.
- Internal: `mix dialyzer` is clean again. `token.ex` resolves `:principal_kinds`
  by reading the struct field directly (its type admits a list, unlike the
  `callback() | nil` reader), and two fail-closed grant-pipeline clauses are
  documented in `.dialyzer_ignore.exs`. No behaviour change.

## [0.7.3] - 2026-06-04

The FAPI 2.0 Message Signing endpoints on the Phoenix layer: signed
authorization responses (JARM), the RFC 7662 / RFC 9701 introspection endpoint,
and PAR/JAR hardening. Requires `attesto ~> 0.6.13`.

### Added

- `POST /oauth/introspect` — OAuth 2.0 Token Introspection (RFC 7662) with the
  RFC 9701 signed-JWT response (FAPI 2.0 Message Signing §5.5). Authenticates
  the caller through the shared `AttestoPhoenix.ClientAuthentication` core
  (`client_secret_basic`/`client_secret_post`/`private_key_jwt`), introspects
  via the conn-free `Attesto.Introspection`, and negotiates by `Accept` between
  the plain JSON response and `application/token-introspection+jwt`.
- `:introspection_authorize` Config callback `(caller_client_id, response ->
  boolean)` — authorizes the authenticated introspection caller against the
  token (RFC 7662 §4 / RFC 9701 §5). Consulted only for an active response;
  a non-`true` return (or a raise) downgrades the response to
  `%{"active" => false}` so a caller not entitled to the token learns nothing
  about it. Optional — when unset, every authenticated caller may introspect
  any token (the single-trust-domain default).
- The authorization endpoint emits JARM (§5.4) responses for the JARM
  `response_mode`s (`jwt`/`query.jwt`/`fragment.jwt`/`form_post.jwt`), and the
  discovery documents advertise the supported `response_modes_supported`,
  `authorization_signing_alg_values_supported`, the introspection endpoint, and
  its signing-algorithm metadata.

### Changed

- The PAR endpoint now validates the pushed request as an authorization request
  at push time (RFC 9126 §2.1 step 3): the request `redirect_uri` must exactly
  match one of the client's registered URIs (RFC 6749 §3.1.2.3), and the
  `response_type`/PKCE/`response_mode` must be valid, so an invalid request is
  refused early rather than only when the `request_uri` is later resolved at
  `/authorize`. The redirect-URI/PKCE/nonce policy is resolved by the new
  conn-free `AttestoPhoenix.AuthorizationServer.RequestPolicy`, shared with the
  authorization endpoint so both validate identically. **A host that mounts the
  PAR endpoint must configure `:client_redirect_uris`** (the authorization
  endpoint already required it).
- `AttestoPhoenix.ClientAuthentication.Result.client_id` falls back to the
  presented credential identifier so the signed-introspection audience (and the
  PAR/token client identity) resolves without a separate `:client_id` callback.
- OpenID Provider Metadata derives `request_parameter_supported` (and only then
  advertises `request_object_signing_alg_values_supported`) from actual
  request-object capability — whether the host can resolve a client's trusted
  JWKS (a `:client_jwks` callback or an installed `:client_store`). An install
  without that capability now advertises `request_parameter_supported: false`
  instead of a JAR support it cannot honour.
- The OAuth 2.0 Authorization Server Metadata document (RFC 8414) now advertises
  the signed-request-object metadata (`require_signed_request_object` and
  `request_object_signing_alg_values_supported`, RFC 9101 §10.5), matching the
  OpenID Provider Metadata document so a FAPI client reading either sees
  identical JAR support. Both documents derive it from the new conn-free
  `AttestoPhoenix.AuthorizationServer.RequestObjectMetadata` (no more split,
  drift-prone assembly).
- `AttestoPhoenix.Config` now rejects at boot a `:request_object_policy` that
  requires a signed request object (e.g. `Policy.fapi_message_signing/0`) when
  no `:client_jwks` capability is configured. Such a config is unsatisfiable
  (every authorization request would be rejected) and would otherwise advertise
  the incoherent pair `request_parameter_supported: false` +
  `require_signed_request_object: true`. Pair the policy with `:client_jwks`
  (or an installed `:client_store`).

## [0.7.2] - 2026-06-03

### Added

- `:request_object_policy` Config key (an `Attesto.RequestObject.Policy`,
  default `%Policy{}` = generic OpenID Connect §6.1). It is enforced at BOTH
  the PAR endpoint and `/authorize`: a signed request object pushed to `/par`
  is verified there (rejected with `invalid_request_object` if it fails the
  policy), and re-verified at `/authorize` (RFC 9101). On success the PAR store
  holds the VERIFIED request-object parameters, never the unsigned body values
  beside them (RFC 9101 §6.3). A non-`%Attesto.RequestObject.Policy{}` value is
  rejected at boot. Set
  `Attesto.RequestObject.Policy.fapi_message_signing()` for the FAPI 2.0
  Message Signing §5.3.1 profile (`nbf`/`exp` required and bounded to 60
  minutes, `typ` = `"oauth-authz-req+jwt"`). Behaviour is unchanged unless a
  host opts in. Requires `attesto ~> 0.6.12`.

## [0.7.1] - 2026-06-03

### Added

- `:client_auth_signing_algs` Config key — the JOSE algorithms accepted for
  `private_key_jwt` client-assertion signatures, threaded into
  `Attesto.ClientAssertion.verify/5` (via its `:accepted_algs` opt) and also
  rendered as `token_endpoint_auth_signing_alg_values_supported` in discovery.
  Defaults to `Attesto.SigningAlg.fapi_algs/0` (PS256, ES256, EdDSA), so
  behaviour is unchanged unless a host overrides it. Verification and the
  advertised metadata now read this one value and cannot drift. Requires
  `attesto ~> 0.6.11`.

## [0.7.0] - 2026-06-03

A structural refactor of the token/PAR controllers into a reusable
authorization-server core, plus a behaviour-module install surface and several
correctness fixes. Pre-1.0 minor bump because it carries breaking changes to
the host-callback contract (see **BREAKING** below).

### Added

- Behaviour-module install for host callbacks. The Config keys `:client_store`,
  `:principal_store`, `:consent_policy`, `:scope_policy`, `:event_sink`,
  `:registration`, and `:claims_provider` each resolve their callbacks from a
  single installed module. Precedence is fixed: an explicit flat callback key
  wins; else the installed behaviour module if it exports the callback; else
  `nil`. The required capabilities (`load_client`, `verify_client_secret`,
  `load_principal`) are validated by *resolution* at boot, so a
  behaviour-module-only install works. Boot-time conformance validation fails
  fast on a typo'd or partial module.
- `AttestoPhoenix.ClaimsProvider` behaviour — the host UserInfo/ID-Token claim
  source (`build_userinfo_claims/3`, `build_id_token_claims/4`).
- `AttestoPhoenix.Callback` — one callback dispatcher (function / `{m,f}` /
  `{m,f,extra}`), replacing ~10 duplicated private `invoke/2` helpers.
- `AttestoPhoenix.ClientAuthentication` and
  `AttestoPhoenix.AuthorizationServer.{SenderConstraint, Token, PAR}` — conn-free
  core modules. The token and PAR controllers are now thin adapters that lift
  conn facts into data, call the core, and render; the core returns data and
  audit events rather than writing the conn or emitting events.

### Changed

- **BREAKING:** the ID-Token extra-claims source is now the separate
  `:build_id_token_claims` callback (`(client, subject, granted_scopes,
  requested_claims -> map)`, and it MUST NOT carry `sub`). Previously the
  4-arity form of `:build_userinfo_claims` doubled as the ID-Token source;
  `:build_userinfo_claims` is now the 3-arity UserInfo source only. Hosts that
  wired a 4-arity `:build_userinfo_claims` must move it to
  `:build_id_token_claims`.
- **BREAKING:** `AttestoPhoenix.ClaimsProvider` no longer declares
  `build_principal/3`; principal building stays solely on
  `AttestoPhoenix.PrincipalStore`. Claim sourcing and principal loading are
  separate concerns.
- Client-assertion `aud` now accepts the issuer **or** the concrete token/PAR
  endpoint URL (RFC 7523 / OIDC Core §9), widened from issuer-only. The endpoint
  URL is derived from trusted Config (issuer + path), never the request Host.
  Still FAPI 2 valid (the issuer remains accepted).
- Client authentication (RFC 6749 §2.3.1): a request-body `client_id` presented
  alongside HTTP Basic is accepted as identification when it matches the Basic
  userid, and rejected as `invalid_request` when it conflicts. Only a second
  *credential* (body `client_secret` or `client_assertion`) is treated as a
  competing authentication method. The token and PAR endpoints now share one
  client-authentication implementation, so they no longer diverge.
- PAR stores the resolved authenticated `client_id`; when no `:client_id`
  callback is configured it leaves the request's presented `client_id` intact
  rather than clobbering it. The opaque-struct `client[:id]`/`client["id"]`
  fallback is removed.

## [0.6.23] - 2026-06-02

### Changed

- Require the client-authentication assertion `aud` to be the issuer identifier
  at both the token and PAR endpoints (FAPI 2). The endpoint URL is no longer
  accepted as an audience. Requires `attesto ~> 0.6.10`.

## [0.6.22] - 2026-06-02

### Changed

- Advertise only the FAPI 2 client-authentication signing algorithms
  (`PS256`, `ES256`, `EdDSA`) in `token_endpoint_auth_signing_alg_values_supported`,
  matching the underlying enforcement in attesto 0.6.9 which rejects RS256
  client assertions. Requires `attesto ~> 0.6.9`.

## [0.6.21] - 2026-06-02

### Fixed

- Return the standard OAuth token endpoint error `invalid_request` when a
  client that requires DPoP omits the proof entirely. Presented-but-invalid
  proofs still return `invalid_dpop_proof`; the omitted-proof case now matches
  FAPI's expected token endpoint error classification.

## [0.6.20] - 2026-06-02

### Added

- Add `:refresh_token_rotation_grace_seconds` to `AttestoPhoenix.Config` and
  pass it through to `Attesto.RefreshToken.rotate/3`. The default is now a
  FAPI retry-compatible 60-second idempotency window for retrying a
  just-rotated refresh token when the client did not receive or persist the
  first rotation response; set `0` for strict immediate reuse revocation.

## [0.6.19] - 2026-06-02

### Fixed

- Bind refresh tokens to the DPoP proof key only for public clients, as
  required by RFC 9449. Confidential clients keep refresh tokens bound to the
  authenticated client, allowing a later refresh request to use a fresh DPoP
  proof key while still minting the returned access token as DPoP-bound to that
  current proof.

## [0.6.18] - 2026-06-02

### Added

- Add `:client_requires_dpop?` as a host callback so deployments can mark a
  client as requiring DPoP-bound token issuance. When such a client calls the
  token endpoint without a DPoP proof, the controller now rejects the request
  with `invalid_dpop_proof` rather than silently issuing an unbound Bearer
  token.

## [0.6.17] - 2026-06-02

### Fixed

- Treat a resolved PAR `request_uri` as the complete authorization request, so
  front-channel parameters outside the pushed request object do not augment the
  request. In particular, a `state` query parameter that was not included in the
  pushed request is no longer echoed in the authorization response.

## [0.6.16] - 2026-06-02

### Fixed

- Allow PAR requests to carry an explicit `dpop_jkt` without also requiring a
  DPoP proof on the PAR request itself. If a PAR DPoP proof is present, an
  explicit `dpop_jkt` must still match that proof; otherwise the stored
  thumbprint is later enforced when the authorization code is redeemed.

## [0.6.15] - 2026-06-02

### Fixed

- Carry the DPoP JWK thumbprint from a pushed authorization request into the
  issued authorization code. A token request that redeems the code with a
  different DPoP proof key is now rejected instead of minting a token bound to
  the later key.

## [0.6.14] - 2026-06-01

### Fixed

- Verify DPoP proofs at the PAR endpoint and bind stored pushed
  authorization requests to the verified proof key. If a PAR request includes
  an explicit `dpop_jkt`, it must match the verified proof JWK thumbprint;
  mismatches now return `invalid_dpop_proof` instead of issuing a
  `request_uri`.

## [0.6.13] - 2026-06-01

### Fixed

- Accept `private_key_jwt` client assertions whose `aud` is the issuer at the
  token endpoint and PAR endpoint, while continuing to accept endpoint-specific
  audiences and reject unrelated audiences. This matches FAPI conformance suite
  client-authentication behavior without relaxing signature, `iss`/`sub`, `jti`,
  or replay checks.

## [0.6.12] - 2026-06-01

### Security

- Reject replayed `private_key_jwt` client assertions at the token endpoint and
  PAR endpoint by recording assertion `jti` values through the configured
  replay check.
- Enforce per-client registered grant types when a host provides
  `:client_grant_types`, preventing a client registered for one grant from
  minting tokens through another.
- Bind PAR `request_uri` authorization requests to the authenticated pushed
  request client and store that authenticated client id, rather than trusting a
  front-channel or body-supplied `client_id`.

### Fixed

- Preserve keystore-provided per-key `alg` metadata in the JWKS endpoint. This
  keeps FAPI deployments that sign ID tokens with `PS256` from advertising the
  same key as `RS256`.
- Add the zero-arity `issue/0` entrypoint to the Ecto DPoP nonce store so
  server-issued DPoP nonces work when the store is configured directly as a
  behaviour module.
- Decode form-encoded client id and secret values in revocation endpoint Basic
  authentication, matching the token endpoint.
- Make the default ETS PAR store tolerate concurrent first-use table creation.

## [0.6.11] - 2026-06-01

### Fixed

- Resolve PAR `request_uri` references non-destructively at the authorization
  endpoint, so host login or consent re-entry can complete without consuming the
  pushed request before authorization-code issuance.

### Changed

- Add a `fetch` callback to `AttestoPhoenix.PARStore` for authorization-endpoint
  resolution. Existing custom stores that only implement `take/1` still work
  through a compatibility fallback, but new stores should implement `fetch/1`.

## [0.6.10] - 2026-06-01

### Fixed

- Treat an explicit `nil` `:par_store` config value as unset when applying the
  default ETS PAR store. This prevents PAR from calling `nil.put/3` when hosts
  enable pushed authorization requests without overriding the development PAR
  store.
- Apply the same nil-aware defaulting to authorization-endpoint PAR resolution.

## [0.6.9] - 2026-06-01

### Added

- Advertise FAPI-required discovery metadata when configured:
  `authorization_response_iss_parameter_supported: true` when RFC 9207
  authorization-response `iss` is enabled, and
  `token_endpoint_auth_signing_alg_values_supported` from Attesto's asymmetric
  signing algorithm set for `private_key_jwt` clients.

## [0.6.8] - 2026-06-01

### Added

- Add host-configurable FAPI-oriented authorization-server controls:
  `:require_pushed_authorization_requests` rejects direct front-channel
  authorization requests unless they arrive through a PAR `request_uri`, and
  `:authorization_response_iss` includes the RFC 9207 `iss` parameter on
  successful and error authorization responses.
- Allow hosts to configure the advertised and accepted token endpoint client
  authentication methods. The token endpoint and PAR endpoint now enforce
  `:token_endpoint_auth_methods_supported` when set, so deployments can expose
  stricter profiles such as `private_key_jwt` only.
- Advertise configured token endpoint authentication methods and PAR-required
  policy in OAuth/OIDC metadata.

## [0.6.7] - 2026-06-01

### Added

- Mount `POST /oauth/authorize` alongside `GET /oauth/authorize`, matching
  OpenID Connect Core's requirement that the Authorization Endpoint support both
  methods.
- Extend the Ecto authorization-code store with successful-consumption markers
  and issued-access-token tracking. When a successfully redeemed authorization
  code is replayed, the token endpoint still returns `invalid_grant` and now
  revokes the access token minted by the original code redemption when the Ecto
  store is configured.

## [0.6.6] - 2026-06-01

### Fixed

- Dynamic client registration now preserves inline `jwks` metadata (RFC 7591
  §2) and hands it to the host `:register_client` callback. Hosts can then
  return those keys through `:client_jwks` for request-object and
  `private_key_jwt` verification.

## [0.6.5] - 2026-06-01

### Fixed

- Return a clean `request_uri_not_supported` authorization response for
  unsupported OIDC `request_uri` references when no PAR store is configured,
  instead of calling a nil PAR store.

## [0.6.4] - 2026-05-31

### Changed

- Replace the direct `jason` dependency with Elixir's built-in `JSON` module.

### Added

- Add a test-only `req_dpop` compatibility check proving that
  `AttestoPhoenix.Plug.Authenticate` accepts RFC 9449 DPoP proofs generated by
  an external Req client plugin. `req_dpop` is not a runtime dependency.
- Document `req_dpop` as an optional Req client companion for tests and
  internal tooling.

## [0.6.3] - 2026-05-31

### Added

- `mix attesto_phoenix.install`, an upgrade-aware Igniter installer. It is
  idempotent and re-runnable: it adds the `AttestoPhoenix.Config` config skeleton
  (issuer, keystore, repo, the Ecto-backed token stores, a chosen
  `:oauth_path_prefix`, and neutral defaults) to the host config, mounts
  `attesto_routes/1` at the chosen prefix into the host router, scaffolds host
  callback modules implementing the recommended behaviours (`ClientStore`,
  `PrincipalStore`, `ScopePolicy`, `ConsentPolicy`, `RegistrationStore`,
  `EventSink`) with documented stub callbacks, and points the host at
  `mix attesto_phoenix.gen.migration` for the Ecto tables. `igniter` is declared
  as an optional dependency, so the runtime package never forces it on consumers;
  the task is available to a host that opts into running it. Options:
  `--oauth-path-prefix` and `--callbacks-module`.

- Configurable OAuth endpoint paths. `AttestoPhoenix.Config` now accepts an
  `:oauth_path_prefix` (default `"/oauth"`, reproducing the historic surface)
  plus explicit per-endpoint overrides (`:authorize_path`, `:token_path`,
  `:par_path`, `:revocation_path`, `:registration_path`, `:userinfo_path`) that
  win when set. Resolver helpers (`token_endpoint_url/1`, `par_endpoint_url/1`,
  `revocation_endpoint_url/1`, `registration_endpoint_url/1`,
  `userinfo_endpoint_url/1`, `authorize_endpoint_url/1`, `jwks_uri/1`,
  `registration_client_uri/2`, and the `*_path/1` helpers) build absolute URLs
  from the issuer and the resolved path. The discovery (RFC 8414),
  OpenID-configuration (OpenID Connect Discovery), and registration (RFC 7591 /
  RFC 7592) controllers read every advertised URL from these resolvers instead
  of hardcoding `/oauth/*`, and `to_attesto_config/2` passes the resolved token
  path to the core builder automatically so the DPoP `htu` follows the mount.
  A host that mounts under `/mcp/oauth` now advertises correct URLs.
- Named host-contract behaviours documenting the full callback contract with
  the governing RFC for each callback, as the recommended production shape:
  `AttestoPhoenix.ClientStore`, `AttestoPhoenix.PrincipalStore`,
  `AttestoPhoenix.ScopePolicy`, `AttestoPhoenix.ConsentPolicy`,
  `AttestoPhoenix.RegistrationStore`, and `AttestoPhoenix.EventSink`. Wiring is
  unchanged: pass an anonymous function, a `{module, function}` pair, or a
  `{module, function, extra_args}` triple per `AttestoPhoenix.Config` key.
- Dynamic registration metadata passthrough (RFC 7591 §2). The registration
  endpoint now validates and carries the known client-identity members
  (`client_name`, `client_uri`, `logo_uri`, `contacts`, `policy_uri`,
  `tos_uri`, and related software/JWKS members) through to `:register_client`
  so consent screens keep the client's identity. Unknown members are dropped
  and never promoted to trusted policy; known members are merged under the
  validated protocol-critical members so they cannot override them.
- Actionable `AttestoPhoenix.Config.new/1` validation errors that name the
  callback/store/path to add for each enabled feature, and absolute-path
  validation for `:oauth_path_prefix` and the per-endpoint overrides.
- Operations guides wired into the published docs: `replay_nonce_production.md`,
  `proxy_canonical_host.md`, `error_envelope.md`, `consumer_migration.md`, and
  `examples.md`.

## [0.6.2]

- Advertise `response_modes_supported: ["query"]` from the RFC 8414 OAuth
  Authorization Server Metadata endpoint, matching the authorization-code
  redirect response mode already used by the Phoenix authorization endpoint.

## [0.6.1]

- Emit `:token_denied` audit/telemetry events for token endpoint failures,
  including OAuth error, status, client/grant/scope context when available, and
  sender-constraint presence.
- Normalize Phoenix callback specs before handing `:cert_der` to core Attesto
  protected-resource verification, so function captures, `{Module, function}`,
  and `{Module, function, extra_args}` all work consistently.

## [0.6.0]

Initial release: a Phoenix/Ecto OAuth 2.0 / OIDC authorization server layer
over [attesto](https://hex.pm/packages/attesto).

### Added

- `AttestoPhoenix.Config`: centralized, validated configuration with neutral
  host callbacks (`:load_client`, `:verify_client_secret`, `:load_principal`,
  `:authorize_scope`, `:on_event`, and others), deriving the `Attesto.Config`
  the protocol layer consumes.
- `AttestoPhoenix.Router`: the `attesto_routes/1` macro mounting the token,
  revocation, discovery, JWKS, and optional dynamic-registration endpoints.
- Controllers for the token endpoint (`authorization_code`, `refresh_token`,
  and `client_credentials` grants), revocation (RFC 7009), discovery
  (RFC 8414), JWKS (RFC 7517), and optional dynamic client registration
  (RFC 7591).
- `AttestoPhoenix.Plug.Authenticate` and `AttestoPhoenix.Plug.RequireScopes`
  protected-resource plugs with DPoP and mTLS sender-constraint enforcement.
- Ecto-backed implementations of the attesto store behaviours: code store,
  refresh store (rotation with reuse detection), DPoP nonce store, and DPoP
  `jti` replay check, plus an optional TTL sweeper.
- `mix attesto_phoenix.gen.migration` to generate the operational tables.
- Pushed Authorization Requests (PAR, RFC 9126), `private_key_jwt` client
  authentication, signed request object validation, token exchange, UserInfo,
  registration management cleanup, and Phoenix resource-server plugs.
