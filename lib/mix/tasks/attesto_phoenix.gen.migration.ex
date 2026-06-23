defmodule Mix.Tasks.AttestoPhoenix.Gen.Migration do
  @shortdoc "Generates the Ecto migration backing the AttestoPhoenix stores"

  @moduledoc """
  Generates an Ecto migration that creates the persistence backing the
  Ecto-based stores ship with `attesto_phoenix`.

  The migration creates seven tables, named to match the runtime schemas
  exactly so a by-the-docs deploy installs tables the Ecto-backed stores can
  use without modification:

    * `attesto_authorization_codes` - the authorization code grant store
      (`AttestoPhoenix.Schema.Authorization`). Holds one row per issued
      authorization code (RFC 6749, section 4.1) plus the PKCE binding
      (RFC 7636), the optional `cnf` key binding (RFC 7800), the OIDC `nonce`,
      mapped `claims`, the descendant `family_id`, consumed markers, and the
      access-token `jti` issued from a successful redemption so code reuse can
      revoke it. Keyed on `code_hash` (no surrogate id); consulted exactly once
      at the token endpoint.

    * `attesto_refresh_tokens` - the refresh token store
      (`AttestoPhoenix.Schema.RefreshToken`, RFC 6749, section 6). Each row
      carries the rotation `family_id` and `generation` it belongs to, the
      `consumed`/`consumed_at` idempotency markers, `successor` retry payload,
      `family_revoked` sticky revocation flag, the `cnf` key binding, mapped
      `claims`, and the diagnostic `parent_hash`, so that reuse of a rotated
      token can be detected and the whole family revoked (RFC 6819, section
      5.2.2.3 - refresh token rotation / replay detection).

    * `attesto_device_codes` - the device authorization grant store
      (`AttestoPhoenix.Schema.DeviceCode`, RFC 8628). One row per device code,
      keyed on `device_code_hash` (the poll key) and `user_code` (the
      verification key), carrying the bound `scope`/`resource`/`dpop_jkt`, the
      `status` state machine (pending → approved|denied → consumed), the
      approved `subject`/`granted_scope`/`granted_claims`, and `last_polled_at`
      for the section 3.5 poll-interval guard.

    * `dpop_nonces` - server-issued DPoP nonces
      (`AttestoPhoenix.Schema.DPoPNonce`, RFC 9449, section 8). Each row is a
      single-use nonce carrying `issued_at`, `expires_at`, and the `used_at`
      consumption marker.

    * `dpop_replays` - the DPoP proof replay cache keyed by the proof's `jti`
      as its PRIMARY KEY (`AttestoPhoenix.Schema.DPoPReplay`, RFC 9449,
      section 11.1). A row is the record that a given proof JWT has already been
      seen within its acceptance window.

    * `attesto_pushed_authorization_requests` - the Pushed Authorization Request
      store (`AttestoPhoenix.Schema.PushedAuthorizationRequest`, RFC 9126). Each
      row maps a one-time `request_uri` reference (the PRIMARY KEY) to the stored,
      validated authorization request `params` and the reference `expires_at`, so
      a `request_uri` pushed to one node is resolvable on every node (FAPI 2.0
      requires PAR).

    * `attesto_client_id_metadata` - the Client ID Metadata Document cache
      (`AttestoPhoenix.Schema.ClientIdMetadata`,
      `draft-ietf-oauth-client-id-metadata-document-01`). Each row caches one
      *validated* CIMD document under its `client_id` URL (the PRIMARY KEY), as a
      jsonb `metadata` map plus the `expires_at` derived from the response's HTTP
      freshness directives (RFC 9111). Keeps every authorization request from
      re-fetching the URL and, being shared, makes the cache coherent across a
      cluster and bounds the outbound fetch fan-out.

    * `attesto_consent_grants` - the single-use, request-bound consent grant
      store (`AttestoPhoenix.Schema.ConsentGrant` / `EctoConsentGrantStore`,
      RFC 6749 §4.1.1). Each row records one consent decision keyed on an
      unguessable `token` (the PRIMARY KEY), with a `binding_hash` over the exact
      request the user saw and a short `expires_at`; `consumed_at` marks single
      use. The host consent screen mints a row; the host's `:consent` callback
      consumes it before a code is issued, so one consent click cannot approve a
      different client/redirect/scope/challenge.

  ## Usage

      mix attesto_phoenix.gen.migration --repo MyApp.Repo

  ## Options

    * `--repo` - the Ecto repo module the migration is generated for. May be
      given more than once to target several repos. When omitted the repos
      configured for the host application are used (the same resolution
      `mix ecto.gen.migration` performs).

    * `--table-prefix` - an optional prefix applied to every generated table
      name (for example `--table-prefix oauth_` yields
      `oauth_attesto_authorization_codes`).
      Defaults to no prefix. When omitted, the prefix configured for the host
      (`:table_prefix` on the `AttestoPhoenix.Config` keyword the host puts in
      its application environment) is used so the generated tables match the
      prefix the Ecto stores read at runtime; the task never invents a prefix.

    * `--migrations-path` - directory the migration file is written to. Defaults
      to the repo's `priv/<repo>/migrations` directory, the same location
      `mix ecto.gen.migration` uses.

    * `--otp-app` - the host application whose environment holds the
      `AttestoPhoenix.Config` keyword to read `:table_prefix` from when
      `--table-prefix` is omitted. Optional; without it the default (no prefix)
      is used.

    * `--config-key` - the application environment key the host stores its
      `AttestoPhoenix.Config` keyword under. Defaults to `AttestoPhoenix.Config`,
      matching `AttestoPhoenix.Config.from_otp_app/2`. Only consulted together
      with `--otp-app`.

  The generated migration is reversible: `up` creates the tables and indexes and
  `down` drops them.
  """

  use Mix.Task

  import Mix.Ecto, only: [parse_repo: 1, ensure_repo: 2]
  import Mix.Generator

  # Column byte-lengths. Hashes are stored, never the secrets themselves: the
  # caller hashes the authorization code / refresh token / nonce before it
  # reaches the store, so these columns hold opaque digests rather than the
  # token material (RFC 6749, section 10.3 - the store never sees plaintext
  # credentials at rest). SHA-256 hex is 64 chars; the columns are sized to hold
  # that with room for alternative encodings.
  @hash_column_size 88
  @jti_column_size 255
  @nonce_column_size 255
  @identifier_column_size 255

  @switches [
    repo: [:keep],
    table_prefix: :string,
    migrations_path: :string,
    otp_app: :string,
    config_key: :string
  ]

  # The application environment key the host stores its AttestoPhoenix.Config
  # keyword under, mirroring AttestoPhoenix.Config.from_otp_app/2's default.
  @default_config_key AttestoPhoenix.Config

  @impl Mix.Task
  def run(args) do
    # Reading any host configuration (table prefix, the repo set) goes through
    # AttestoPhoenix.Config rather than being hardcoded here: the task is policy
    # free and only renders what the host has declared.
    repos = parse_repo(args)

    {opts, _, _} = OptionParser.parse(args, switches: @switches)

    prefix = table_prefix(opts)
    validate_prefix!(prefix)

    repos
    |> resolve_repos!()
    |> Enum.each(&generate_for_repo(&1, opts, prefix))
  end

  defp resolve_repos!([]) do
    Mix.raise("""
    no Ecto repos available.

    Pass one explicitly with --repo, e.g.

        mix attesto_phoenix.gen.migration --repo MyApp.Repo

    or configure :ecto_repos for your application.
    """)
  end

  defp resolve_repos!(repos), do: repos

  defp table_prefix(opts) do
    # An explicit --table-prefix always wins; otherwise defer to the prefix the
    # host configured for the runtime stores so the schema and the migration
    # agree. The neutral identity default (no host config, no flag) is the empty
    # string: no prefix. The task never invents a prefix of its own.
    case Keyword.fetch(opts, :table_prefix) do
      {:ok, prefix} -> prefix
      :error -> configured_table_prefix(opts)
    end
  end

  # Reads :table_prefix from the host's AttestoPhoenix.Config keyword in the
  # application environment, without building (and thus validating) the full
  # config: the generator must run before the host's other required keys (issuer,
  # keystore, ...) are necessarily present. Returns "" (no prefix) when no host
  # app is identified or no prefix is configured.
  defp configured_table_prefix(opts) do
    case Keyword.fetch(opts, :otp_app) do
      {:ok, otp_app} ->
        key = opts |> Keyword.get(:config_key) |> config_key()

        otp_app
        |> String.to_atom()
        |> Application.get_env(key, [])
        |> Keyword.get(:table_prefix)
        |> normalize_configured_prefix()

      :error ->
        ""
    end
  end

  defp config_key(nil), do: @default_config_key
  defp config_key(key) when is_binary(key), do: Module.concat([key])

  defp normalize_configured_prefix(nil), do: ""
  defp normalize_configured_prefix(prefix) when is_binary(prefix), do: prefix

  # Table names are emitted into the migration source verbatim, so a prefix that
  # is not a bare identifier fragment would either break the generated module or
  # allow injection. Fail closed (no silent normalization) per a strict
  # identifier grammar: letters, digits and underscores only.
  defp validate_prefix!(prefix) when is_binary(prefix) do
    if prefix == "" or Regex.match?(~r/\A[a-z_][a-z0-9_]*\z/, prefix) do
      :ok
    else
      Mix.raise(
        "invalid --table-prefix #{inspect(prefix)}: " <>
          "expected an empty string or a lowercase identifier matching /[a-z_][a-z0-9_]*/"
      )
    end
  end

  defp validate_prefix!(other) do
    Mix.raise("invalid table prefix #{inspect(other)}: expected a string")
  end

  defp generate_for_repo(repo, opts, prefix) do
    ensure_repo(repo, [])

    path = migrations_path(repo, opts)
    create_directory(path)

    base_name = "create_attesto_phoenix_tables"
    file = Path.join(path, "#{timestamp()}_#{base_name}.exs")

    if !Enum.empty?(Path.wildcard(Path.join(path, "*_#{base_name}.exs"))) do
      Mix.raise(
        "migration #{inspect(base_name)} already exists in #{path}; " <>
          "remove it before regenerating to avoid duplicate tables"
      )
    end

    # The base table names are fixed by the runtime schemas and MUST match them
    # exactly, or a by-the-docs deploy installs tables the stores cannot use:
    #
    #   * AttestoPhoenix.Schema.Authorization               -> "attesto_authorization_codes"
    #   * AttestoPhoenix.Schema.RefreshToken                -> "attesto_refresh_tokens"
    #   * AttestoPhoenix.Schema.DPoPReplay                  -> "dpop_replays"
    #   * AttestoPhoenix.Schema.DPoPNonce                   -> "dpop_nonces"
    #   * AttestoPhoenix.Schema.PushedAuthorizationRequest  -> "attesto_pushed_authorization_requests"
    #   * AttestoPhoenix.Schema.ClientIdMetadata            -> "attesto_client_id_metadata"
    #   * AttestoPhoenix.Schema.ConsentGrant                -> "attesto_consent_grants"
    #
    # The optional --table-prefix is the only thing the host may vary; the base
    # names are not host-configurable because the schemas hardcode them.
    assigns = [
      module: migration_module(repo, base_name),
      prefix: prefix,
      authorization_codes: table_name(prefix, "attesto_authorization_codes"),
      refresh_tokens: table_name(prefix, "attesto_refresh_tokens"),
      device_codes: table_name(prefix, "attesto_device_codes"),
      dpop_nonces: table_name(prefix, "dpop_nonces"),
      dpop_replays: table_name(prefix, "dpop_replays"),
      pushed_authorization_requests: table_name(prefix, "attesto_pushed_authorization_requests"),
      client_id_metadata: table_name(prefix, "attesto_client_id_metadata"),
      consent_grants: table_name(prefix, "attesto_consent_grants"),
      hash_size: @hash_column_size,
      jti_size: @jti_column_size,
      nonce_size: @nonce_column_size,
      identifier_size: @identifier_column_size
    ]

    create_file(file, migration_template(assigns))
    file
  end

  defp migrations_path(repo, opts) do
    case Keyword.fetch(opts, :migrations_path) do
      {:ok, path} -> path
      :error -> default_migrations_path(repo)
    end
  end

  # Mirrors how `mix ecto.gen.migration` locates a repo's migrations: the repo's
  # configured :priv (defaulting to priv/<repo>) resolved against the host
  # application source root. Tests always pass --migrations-path, so this is the
  # real-use default rather than a code path under test.
  defp default_migrations_path(repo) do
    config = repo.config()
    priv = config[:priv] || "priv/#{repo |> Module.split() |> List.last() |> Macro.underscore()}"
    Path.join([File.cwd!(), priv, "migrations"])
  end

  defp migration_module(repo, base_name) do
    Module.concat([repo, Migrations, Macro.camelize(base_name)])
  end

  defp table_name(prefix, name), do: prefix <> name

  # UTC timestamp identifier, matching the format mix ecto.gen.migration uses so
  # the generated file sorts correctly against hand-written migrations.
  defp timestamp do
    {{y, m, d}, {hh, mm, ss}} = :calendar.universal_time()

    [y, m, d, hh, mm, ss]
    |> Enum.map_join(&pad/1)
  end

  defp pad(i) when i < 10, do: "0" <> Integer.to_string(i)
  defp pad(i), do: Integer.to_string(i)

  embed_template(:migration, """
  defmodule <%= inspect @module %> do
    @moduledoc false

    # Generated by `mix attesto_phoenix.gen.migration`.
    #
    # Backing tables for the Ecto-based attesto_phoenix stores. See the task
    # moduledoc for the RFC each table implements.

    use Ecto.Migration

    def up do
      # Authorization code grant store (RFC 6749, section 4.1), backing
      # AttestoPhoenix.Schema.Authorization / AttestoPhoenix.Store.EctoCodeStore.
      # One row per issued code. Only the hash of the code is stored (RFC 6749,
      # section 10.3); the unique index on it is the single-use lookup key
      # (EctoCodeStore.take/1 deletes by code_hash). The schema declares
      # `@primary_key false` and keys on :code_hash, so there is no surrogate id.
      create table(:<%= @authorization_codes %>, primary_key: false) do
        add :code_hash, :string, size: <%= @hash_size %>, null: false
        add :client_id, :string, size: <%= @identifier_size %>, null: false
        add :subject, :string, size: <%= @identifier_size %>, null: false
        add :scope, {:array, :string}, null: false, default: []
        # RFC 8707 resource indicator(s) bound at authorization time; the token
        # endpoint mints the access token `aud` from this set.
        add :resource, {:array, :string}, null: false, default: []
        add :redirect_uri, :text, null: false
        # PKCE binding (RFC 7636, section 4.3). Stored so the token endpoint can
        # verify the code_verifier presented at redemption.
        add :code_challenge, :string, size: <%= @identifier_size %>
        add :code_challenge_method, :string, size: 16
        # RFC 7800 confirmation (DPoP key thumbprint, RFC 9449 section 6, or mTLS
        # thumbprint, RFC 8705 section 3.1). NULL for an unbound code.
        add :cnf, :map
        # OIDC request nonce (OpenID Connect Core, section 3.1.2.1).
        add :nonce, :string, size: <%= @nonce_size %>
        # Opaque request claims round-tripped to redemption.
        add :claims, :map, null: false, default: %{}
        # Grant family linking this authorization code to descendants that must
        # be revoked if the code is replayed.
        add :family_id, :string, size: <%= @identifier_size %>
        # The access token minted by a successful redemption; used only for
        # revocation after authorization-code reuse.
        add :access_token_jti, :string, size: <%= @jti_size %>
        add :access_token_expires_at, :utc_datetime
        add :access_token_revoked_at, :utc_datetime
        add :expires_at, :utc_datetime, null: false
        # consumed_at is set by the atomic claim. consumed_success is set only
        # after redemption validation passes, letting later re-presentation revoke
        # descendants while a failed first presentation remains plain invalid_grant.
        add :consumed_at, :utc_datetime
        add :consumed_success, :boolean, null: false, default: false
        # The schema carries an explicit :inserted_at (no :updated_at).
        add :inserted_at, :utc_datetime, null: false
      end

      # Single-use redemption is enforced at the database: the code hash is
      # globally unique. The default index name attesto_authorization_codes_code_hash_index
      # matches the schema's unique_constraint(:code_hash, name: ...).
      create unique_index(:<%= @authorization_codes %>, [:code_hash])
      # Expiry sweeps scan by expiry (AttestoPhoenix.Store.Sweeper).
      create index(:<%= @authorization_codes %>, [:expires_at])
      create index(:<%= @authorization_codes %>, [:family_id])
      create index(:<%= @authorization_codes %>, [:access_token_jti])

      # Refresh token store (RFC 6749, section 6), backing
      # AttestoPhoenix.Schema.RefreshToken / AttestoPhoenix.Store.EctoRefreshStore.
      # Rotation with reuse detection (RFC 6819, section 5.2.2.3): every rotation
      # issues a new row in the same family; presenting a consumed token revokes
      # the family. consumed/family_revoked are the booleans the atomic claim and
      # sticky revocation flip.
      create table(:<%= @refresh_tokens %>, primary_key: false) do
        add :id, :binary_id, primary_key: true
        add :token_hash, :string, size: <%= @hash_size %>, null: false
        add :family_id, :string, size: <%= @identifier_size %>, null: false
        add :generation, :integer, null: false, default: 0
        add :client_id, :string, size: <%= @identifier_size %>
        add :subject, :string, size: <%= @identifier_size %>, null: false
        add :scope, {:array, :string}, null: false, default: []
        # RFC 8707 resource indicator(s) bound to the grant; carried through
        # rotation (subset-only narrowing) so the refreshed token's `aud` matches.
        add :resource, {:array, :string}, null: false, default: []
        # RFC 9470 / OIDC Core: original authentication context, carried across
        # rotation so a refreshed access token reports the real auth event
        # (auth_time is never re-stamped). auth_time is unix seconds.
        add :acr, :string
        add :auth_time, :bigint
        add :cnf, :map
        add :claims, :map, null: false, default: %{}
        # consumed is flipped false -> true by the atomic rotation claim
        # (UPDATE ... WHERE consumed = false); a missed update with the row still
        # present is the reuse signal.
        add :consumed, :boolean, null: false, default: false
        # consumed_at and successor support a short idempotency window for an
        # honest retry whose successful rotation response was lost.
        add :consumed_at, :utc_datetime
        add :successor, :map
        # family_revoked is sticky: a revoked family refuses every later insert.
        add :family_revoked, :boolean, null: false, default: false
        add :expires_at, :utc_datetime, null: false
        # Diagnostic lineage: the predecessor's token_hash, or NULL for the first
        # token in a family. Never a lookup key.
        add :parent_hash, :string, size: <%= @hash_size %>

        # The schema declares timestamps(updated_at: false): an :inserted_at, no
        # :updated_at.
        timestamps(updated_at: false, type: :utc_datetime)
      end

      # Token presentation looks up by hash; it must be unique to keep lookup and
      # rotation atomic. The default index name attesto_refresh_tokens_token_hash_index
      # matches the schema's unique_constraint(:token_hash, name: ...).
      create unique_index(:<%= @refresh_tokens %>, [:token_hash])
      # Family-wide revocation scans by family_id.
      create index(:<%= @refresh_tokens %>, [:family_id])
      create index(:<%= @refresh_tokens %>, [:expires_at])

      # Device authorization grant (RFC 8628), backing
      # AttestoPhoenix.Schema.DeviceCode / AttestoPhoenix.Store.EctoDeviceCodeStore.
      # A device code is a mutable row moving pending -> approved|denied ->
      # consumed; each transition is one guarded atomic UPDATE in the store. Only
      # the device_code hash is stored; user_code is the normalized verification
      # key. last_polled_at enforces the section 3.5 minimum poll interval.
      create table(:<%= @device_codes %>, primary_key: false) do
        add :id, :binary_id, primary_key: true
        add :device_code_hash, :string, size: <%= @hash_size %>, null: false
        add :user_code, :string, size: <%= @identifier_size %>, null: false
        add :client_id, :string, size: <%= @identifier_size %>, null: false
        add :scope, {:array, :string}, null: false, default: []
        # RFC 8707 resource indicator(s) bound at the device-authorization endpoint.
        add :resource, {:array, :string}, null: false, default: []
        # RFC 9449 section 10 DPoP holder-of-key pre-binding (NULL for unbound).
        add :dpop_jkt, :string, size: <%= @identifier_size %>
        # pending | approved | denied | consumed (the state machine).
        add :status, :string, size: 16, null: false, default: "pending"
        # Bound at approval (NULL until the user authorizes).
        add :subject, :string, size: <%= @identifier_size %>
        add :granted_scope, {:array, :string}
        add :granted_claims, :map
        # Unix-second-truncated timestamp of the last accepted poll (NULL before
        # the first); the atomic slow_down guard compares against it.
        add :last_polled_at, :utc_datetime
        add :expires_at, :utc_datetime, null: false

        timestamps(updated_at: false, type: :utc_datetime)
      end

      # The device polls by device_code_hash and the verification page resolves by
      # user_code; both are unique single-use lookup keys.
      create unique_index(:<%= @device_codes %>, [:device_code_hash])
      create unique_index(:<%= @device_codes %>, [:user_code])
      create index(:<%= @device_codes %>, [:expires_at])

      # Server-issued DPoP nonces (RFC 9449, section 8), backing
      # AttestoPhoenix.Schema.DPoPNonce / AttestoPhoenix.Store.EctoNonceStore.
      # Each nonce is single-use: issued_at + the consume cutoff bound freshness,
      # and used_at (NULL while unused) is stamped exactly once.
      create table(:<%= @dpop_nonces %>, primary_key: false) do
        add :id, :binary_id, primary_key: true
        add :nonce, :string, size: <%= @nonce_size %>, null: false
        add :issued_at, :utc_datetime, null: false
        add :expires_at, :utc_datetime, null: false
        add :used_at, :utc_datetime
      end

      # The default index name dpop_nonces_nonce_index matches the schema's
      # unique_constraint(:nonce) (which uses Ecto's default name).
      create unique_index(:<%= @dpop_nonces %>, [:nonce])
      # Partial index over still-unused rows keeps the conditional consume fast.
      create index(:<%= @dpop_nonces %>, [:used_at],
               where: "used_at IS NULL",
               name: :<%= @dpop_nonces %>_unused_index
             )

      # DPoP proof replay cache (RFC 9449, section 11.1), backing
      # AttestoPhoenix.Schema.DPoPReplay / AttestoPhoenix.Store.EctoReplayCheck.
      # The proof's jti (RFC 9449 section 4.2, RFC 7519 section 4.1.7) is the
      # PRIMARY KEY, so the atomic record-and-check is INSERT ... ON CONFLICT DO
      # NOTHING and the conflicting constraint is the primary key dpop_replays_pkey
      # the schema's unique_constraint(:jti, name: :dpop_replays_pkey) names.
      create table(:<%= @dpop_replays %>, primary_key: false) do
        add :jti, :string, size: <%= @jti_size %>, primary_key: true, null: false
        add :expires_at, :utc_datetime_usec, null: false
        add :inserted_at, :utc_datetime_usec, null: false
      end

      # Expiry sweeps scan by expires_at; replay decisions hit the primary key.
      create index(:<%= @dpop_replays %>, [:expires_at])

      # Pushed Authorization Request store (RFC 9126), backing
      # AttestoPhoenix.Schema.PushedAuthorizationRequest /
      # AttestoPhoenix.Store.EctoPARStore. The one-time request_uri reference is
      # the PRIMARY KEY, so resolution at /authorize (and the optional single-use
      # take/1 = DELETE ... RETURNING) hits the primary key. The stored, validated
      # request params live in a jsonb column; expires_at bounds the reference's
      # life (RFC 9126 section 2.2) and is re-checked on read.
      create table(:<%= @pushed_authorization_requests %>, primary_key: false) do
        add :request_uri, :string, size: <%= @identifier_size %>, primary_key: true, null: false
        add :params, :map, null: false
        add :expires_at, :utc_datetime, null: false
        add :inserted_at, :utc_datetime, null: false
      end

      # Expiry sweeps scan by expires_at; resolution hits the primary key.
      create index(:<%= @pushed_authorization_requests %>, [:expires_at])

      # Client ID Metadata Document cache
      # (draft-ietf-oauth-client-id-metadata-document-01), backing
      # AttestoPhoenix.Schema.ClientIdMetadata /
      # AttestoPhoenix.ClientIdMetadata.Cache.Ecto. The CIMD client_id URL is the
      # PRIMARY KEY, so the cache lookup (get/1) hits the primary key and a
      # re-fetch upserts the single row. The validated document lives in a jsonb
      # metadata column; expires_at is the freshness derived from the response's
      # Cache-Control/Expires (RFC 9111), re-checked on read and indexed for
      # sweeps. Only validated documents are ever written here.
      create table(:<%= @client_id_metadata %>, primary_key: false) do
        add :url, :string, size: <%= @identifier_size %>, primary_key: true, null: false
        add :metadata, :map, null: false
        add :expires_at, :utc_datetime, null: false
        add :inserted_at, :utc_datetime, null: false
      end

      # Expiry sweeps scan by expires_at; lookups hit the primary key.
      create index(:<%= @client_id_metadata %>, [:expires_at])

      # Single-use, request-bound consent grants (RFC 6749 section 4.1.1),
      # backing AttestoPhoenix.Schema.ConsentGrant /
      # AttestoPhoenix.Store.EctoConsentGrantStore. One row per consent decision,
      # keyed on an unguessable token (the PRIMARY KEY) so the conditional consume
      # UPDATE and the disambiguation read both hit the primary key. binding_hash
      # ties the grant to the exact request the user saw; consumed_at marks single
      # use; expires_at bounds the short consent window and is re-checked on
      # consume. The default index name attesto_consent_grants_pkey matches the
      # schema's unique_constraint(:token, name: :attesto_consent_grants_pkey).
      create table(:<%= @consent_grants %>, primary_key: false) do
        add :token, :string, size: <%= @identifier_size %>, primary_key: true, null: false
        add :binding_hash, :string, size: <%= @hash_size %>, null: false
        add :subject, :string, size: <%= @identifier_size %>, null: false
        add :consumed_at, :utc_datetime_usec
        add :expires_at, :utc_datetime_usec, null: false

        timestamps(type: :utc_datetime_usec)
      end

      # Expiry sweeps scan by expires_at; consume hits the primary key.
      create index(:<%= @consent_grants %>, [:expires_at])
    end

    def down do
      drop table(:<%= @consent_grants %>)
      drop table(:<%= @client_id_metadata %>)
      drop table(:<%= @pushed_authorization_requests %>)
      drop table(:<%= @dpop_replays %>)
      drop table(:<%= @dpop_nonces %>)
      drop table(:<%= @refresh_tokens %>)
      drop table(:<%= @authorization_codes %>)
    end
  end
  """)
end
