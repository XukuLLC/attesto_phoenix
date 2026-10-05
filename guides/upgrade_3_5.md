# Upgrading to 3.5

Version 3.5 adds explicit migration policies while retaining the security
defaults introduced in 3.4.1. It requires Attesto 2.2.2 or later within 2.x.
Apply the existing 3.4 database migration before deploying any 3.4 or 3.5
writer. No additional database columns are required by 3.5.

## Registration profiles and native redirects

Registration defaults an absent `application_type` to `"web"`. A host that
intentionally operates a native registration profile can select:

```elixir
config :my_app, AttestoPhoenix,
  registration_default_application_type: "native",
  native_apps: [loopback_redirect: true, loopback_include_localhost: true]
```

This applies only when the request omits the member. Explicit `"web"` and
`"native"` values retain their meaning, and JSON `null` is invalid. The native
profile permits configured loopback HTTP redirects; external HTTP redirects
remain invalid. `loopback_redirect: false` disables that exception at
registration too. The localhost option is separate and defaults to false.
An IP loopback redirect remains preferable under RFC 8252.

The loopback matching mode changes only the port comparison for a registered
loopback HTTP URI. Private-use callbacks and other non-loopback URIs still
match exactly, including their scheme, authority, path, and query. Enabling
loopback registration therefore does not relax matching for a native client
whose registered callbacks contain no loopback URI. A request cannot substitute
a loopback URI for that client's private-use callback.

The standards registration default is `"web"`. Select that default for OIDC
conformance and ordinary web registration. Use a separate configuration profile
when a host deliberately provides native defaults.

## Migrating a single-issuer refresh store

By default, a refresh family without its persisted issuer binding is refused.
A store that has always belonged to exactly one issuer can be migrated through
an explicit administrative assertion. Do not use this procedure for shared or
uncertain historical issuer provenance. It supports the bundled
`AttestoPhoenix.Store.EctoRefreshStore` and explicitly declared wrappers backed
by that store.

Starting in 3.5.1, a wrapper implementing `Attesto.RefreshStore` can declare its
persistence backend:

```elixir
config :my_app, AttestoPhoenix,
  refresh_store: MyApp.RefreshStore,
  refresh_store_backend: AttestoPhoenix.Store.EctoRefreshStore,
  bind_unbound_refresh_families: :configured_issuer
```

The direct Ecto store is recognized without the declaration. Undeclared custom
stores cannot enable this migration. The declaration is a trusted operator
assertion: callback validation cannot prove delegation. The wrapper must
delegate Ecto operations under the same request configuration, repository, and
schema prefix. Token operations retain the configured wrapper. Positive retry
grace still requires the stable successor secret and configured cleanup used
by the direct Ecto store.

A cached retry can recover a successor through the wrapper's `get/1` without
calling `rotate/4` again. Policies that must apply to recovered successors
therefore need enforcement on reads or through `:build_refresh_principal`;
a rotation-only policy does not cover that existing retry path. Administrative
backfill changes issuer bindings directly in the trusted Ecto persistence
scope and does not issue tokens or evaluate per-request wrapper policy.

Audit with the configured application, repository, prefix, and stable
refresh-successor encryption secret:

```bash
mix attesto_phoenix.backfill_refresh_issuer \
  --issuer https://issuer.example --assert-single-issuer
```

The default is a dry run. Add `--apply` to persist changes. The issuer must
exactly equal the normalized configured issuer. `--repo`, `--schema-prefix`,
`--otp-app`, and `--batch-size` select explicit administrative contexts.
Each family is locked and updated atomically, including authenticated retry
contexts. A conflicting issuer, unreadable retry state, or oversized family
stops that family without partial writes. Previously committed families remain
bound; the operation is idempotent. Output contains aggregate counts only.

Production releases can use the same API from a release console without Mix.
Load the application's trusted configuration and audit first:

```elixir
alias AttestoPhoenix.Config
alias AttestoPhoenix.Store.EctoRefreshStore

config = Config.from_otp_app(:my_app)

Config.with_request_config(config, fn ->
  EctoRefreshStore.backfill_issuer(config.issuer,
    assert_single_issuer: true,
    dry_run: true,
    batch_size: 100
  )
end)
```

Review the aggregate counts, then use `dry_run: false` in that same trusted
context to apply the backfill. The explicit single-issuer assertion is required
for both audit and apply. Keep strict rejection unless the temporary rolling
migration policy is deliberately enabled; this administrative operation does
not enable it automatically.

Migration emits `[:attesto_phoenix, :refresh_token, :issuer_migration]` with
`%{count: n}` and bounded outcome/reason metadata only. Outcomes are `:audited`,
`:bound`, and `:rejected`; no issuer, family, client identifier, or token is
included. Watch configured-single-issuer binding activity while retiring older
writers and returning to strict policy.

A one-time backfill is sufficient only with quiescent token writers. For a
rolling deployment within an asserted single-issuer store:

1. Apply the 3.4 schema migration and audit the historical store. Backfill with
   `--apply` before introducing new token endpoints.
2. Temporarily configure new nodes with
   `bind_unbound_refresh_families: :configured_issuer`. This policy binds legacy
   issuance and repairs authenticated retry contexts created by older writers.
3. Drain all older token endpoints and writers. Until they are gone, keep new
   absolute family deadlines and attested refresh issuance disabled: old nodes
   do not enforce those bindings or issuer isolation.
4. Audit and backfill again after old writers drain, then deploy
   `bind_unbound_refresh_families: :reject` everywhere.

The compatibility policy obtains issuer provenance from the server
configuration, never from presented credentials. It refuses existing different
bindings. It does not reset revocation, extend lifetime, or add a missing
Client Instance Key. Pre-3.4 attested refresh families still require
reauthorization, even after issuer backfill. Multi-issuer stores must retain
strict rejection and reauthorize legacy families through their original issuer.

## Registered-method diagnostics

Continue providing trusted registration data through `:client_auth_method` or
`ClientStore.client_auth_method/1`. Enable `client_auth_method_validation: :boot`
to reject startup when Basic or POST is advertised without that callback.
The default `:runtime` policy retains runtime refusal of missing method data.

Mismatches emit
`[:attesto_phoenix, :client_authentication, :method_mismatch]` with `%{count: 1}`.
Metadata contains only known registered/presented methods, a bounded reason,
and `:rejected` or `:observed` outcome. It contains no client identifier or
credential. An observed mismatch still requires successful credential checks.

`client_secret_auth_method_policy: :strict` remains the default. A temporary
`:observe` policy permits Basic/POST transport differences only when the
client is registered for one of those shared-secret methods and the presented
method is server-supported. It never permits a secret to replace private-key
JWT, mTLS, attestation, or public authentication. Correct registrations or
client transports, then restore `:strict`. Keep strict matching for conformance.

## Enforcing raw-body analysis

Install the duplicate-parameter reader before the router:

```elixir
plug Plug.Parsers,
  parsers: [:urlencoded, :multipart, :json],
  pass: ["*/*"],
  json_decoder: Phoenix.json_library(),
  body_reader: {AttestoPhoenix.DuplicateParameterGuard, :read_body, []}
```

The default `oauth_body_guard: :observe` emits
`[:attesto_phoenix, :oauth_body_guard, :missing_analysis]` when a protocol
form/JSON request has no raw-body analysis. Measurements are `%{count: 1}`;
metadata contains the HTTP method and body format only. After every endpoint
uses the reader, select `oauth_body_guard: :required` to refuse those requests
with HTTP 400. Multipart protocol bodies also emit this event and are rejected
under `:required`, because Plug's multipart parser bypasses the body reader.
Host upload routes can keep their existing multipart parsing.
Duplicate query/header checks remain automatic, and completed
body analysis is enforced under either policy. Custom readers can be wrapped
as described in `AttestoPhoenix.DuplicateParameterGuard`.

Protocol tests must exercise the encoded body when testing the reader or using
`:required`. Passing a params map directly to `Phoenix.ConnTest.post/3` bypasses
body reading. Encode JSON and set its content type instead:

```elixir
conn
|> Plug.Conn.put_req_header("content-type", "application/json")
|> Phoenix.ConnTest.post("/register", Jason.encode!(registration))
```

Use `URI.encode_query/1` with `application/x-www-form-urlencoded` for form
requests. In 3.5.1, clean JSON bodies record completed analysis; malformed JSON
also records that the reader ran and remains subject to the parser's normal
JSON decoding error.

## Dependencies and generated rollback

IDNA 6.1.x and 7.x are supported with canonical hostname checks. The lower
dependency line still rejects empty DNS labels and label loss during UTS #46
mapping. No dependency override is needed to select either supported line.

Newly generated 3.4 migrations resolve explicit, migrator, and repository
prefixes consistently. Their rollback locks the refresh table and drops the
new columns only if every row has NULL `family_expires_at` and
`attestation_jkt`. Any stored value prevents rollback, including on expired or
revoked rows. Review revocation and retention before deleting affected rows;
do not clear security fields to force a downgrade. The CIBA notification-token
column remains TEXT to preserve stored values. Existing migration files are
not rewritten automatically.
