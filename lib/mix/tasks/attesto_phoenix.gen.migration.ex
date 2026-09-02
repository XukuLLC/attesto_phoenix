defmodule Mix.Tasks.AttestoPhoenix.Gen.Migration do
  @shortdoc "Generates the Ecto migration backing the AttestoPhoenix stores"

  @moduledoc """
  Generates an Ecto migration that creates the persistence backing the
  Ecto-based stores ship with `attesto_phoenix`.

  The migration creates eleven tables, named to match the runtime schemas
  exactly so a by-the-docs deploy installs tables the Ecto-backed stores can
  use without modification:

    * `attesto_authorization_codes` - the authorization code grant store
      (`AttestoPhoenix.Schema.Authorization`). Holds one row per issued
      authorization code (RFC 6749, section 4.1) plus the PKCE binding
      (RFC 7636), the optional `cnf` key binding (RFC 7800), the OIDC `nonce`,
      mapped `claims`, the descendant `family_id`, consumed markers, and the
      access-token `jti` issued from a successful redemption so code reuse can
      revoke it. Keyed on `code_hash` as its PRIMARY KEY (no surrogate id);
      consulted exactly once at the token endpoint.

    * `attesto_refresh_tokens` - the refresh token store
      (`AttestoPhoenix.Schema.RefreshToken`, RFC 6749, section 6). Each row
      carries the rotation `family_id` and `generation` it belongs to, the
      `consumed`/`consumed_at` idempotency markers, `successor` retry payload,
      `family_revoked` sticky revocation flag, the `cnf` key binding, mapped
      `claims`, and the diagnostic `parent_hash`, so that reuse of a rotated
      token can be detected and the whole family revoked (RFC 6819, section
      5.2.2.3 - refresh token rotation / replay detection).

    * `attesto_refresh_family_revocations` - durable refresh-family revocation
      tombstones. Refresh-token rows are eligible for expiry cleanup, so this
      separate table preserves a revocation after every row in the family has
      been swept. Existing installations upgrading to a release that uses
      this table must apply a forward migration before starting the new code;
      see the upgrade notes in the README and CHANGELOG.

    * `attesto_device_codes` - the device authorization grant store
      (`AttestoPhoenix.Schema.DeviceCode`, RFC 8628). One row per device code,
      keyed on `device_code_hash` (the poll key) and `user_code` (the
      verification key), carrying the bound `scope`/`resource`/`dpop_jkt`, the
      `status` state machine (pending → approved|denied → consumed), the
      approved `subject`/`granted_scope`/`granted_claims`, and `last_polled_at`
      for the section 3.5 poll-interval guard.

    * `attesto_ciba_requests` - the OpenID Connect CIBA authentication-request
      store (`AttestoPhoenix.Schema.CIBARequest` / `EctoCIBAStore`, CIBA Core
      1.0). One row per `auth_req_id`, keyed on `auth_req_id_hash`, carrying the
      bound `scope`/`resource`/`dpop_jkt`, the `delivery_mode`, the ping
      `client_notification_token`, the hint-resolved `hint_subject`, the
      `status` state machine (pending → approved|denied → consumed), the
      approved `subject`/`acr`/`auth_time`/`granted_scope`/`granted_claims`, the
      frozen poll `interval`, and `last_polled_at` for the §7.3 poll-interval
      guard.

    * `attesto_logout_sessions` - the logout session store
      (`AttestoPhoenix.Schema.LogoutSession`, OpenID Connect Back-Channel Logout
      1.0 + Front-Channel Logout 1.0). One row per `(session, Relying Party)`
      pair, recorded at ID-Token mint and read at the end-session endpoint to
      deliver a `logout_token` and/or render the RP's `frontchannel_logout_uri`.
      Upserted on `(sid, client_id)`; carries the `subject`, the RP's
      `backchannel_logout_uri`/`session_required` and
      `frontchannel_logout_uri`/`frontchannel_session_required`, and the
      `expires_at` that bounds an abandoned session.

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

    * `--schema-prefix` - an optional PostgreSQL schema selected by Ecto's
      `prefix:` option for every generated table and index (for example
      `--schema-prefix oauth` creates `attesto_authorization_codes` in schema
      `oauth`). Runtime Ecto queries use the same `prefix:` option; the table
      names themselves remain canonical. Defaults to no prefix. When omitted,
      the prefix configured for the host (`:schema_prefix` on the
      `AttestoPhoenix.Config` the host puts in its application environment) is
      used so the generated schema matches the prefix the Ecto stores read at
      runtime; the task never invents a prefix. The 2.x `--table-prefix` option
      is rejected because it controlled literal names in generated migrations,
      not one coherent runtime layout: most 2.x stores queried canonical tables
      in `public`, while only the CIBA store and sweeper treated the value as an
      Ecto schema prefix. Inventory an existing database before choosing a 3.0
      schema; this task is for fresh migrations only.

    * `--migrations-path` - directory the migration file is written to. Defaults
      to the repo's `priv/<repo>/migrations` directory, the same location
      `mix ecto.gen.migration` uses.

    * `--otp-app` - the host application whose environment holds the
      `AttestoPhoenix.Config` keyword or struct to read `:schema_prefix` from
      when `--schema-prefix` is omitted. Optional; when omitted, the task first uses
      `config :attesto_phoenix, otp_app: ...` and then the current Mix
      project's `:app`. If neither application has a configured prefix, the
      default is no prefix.

    * `--config-key` - the application environment key the host stores its
      `AttestoPhoenix.Config` keyword under. Defaults to `AttestoPhoenix.Config`,
      matching `AttestoPhoenix.Config.from_otp_app/2`.

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
  @max_schema_prefix_bytes 63

  @switches [
    repo: [:keep],
    schema_prefix: :string,
    migrations_path: :string,
    otp_app: :string,
    config_key: :string
  ]

  # The application environment key the host stores its AttestoPhoenix.Config
  # keyword under, mirroring AttestoPhoenix.Config.from_otp_app/2's default.
  @default_config_key AttestoPhoenix.Config

  @impl Mix.Task
  def run(args) do
    reject_legacy_table_prefix_arg!(args)
    reject_legacy_global_table_prefix!()

    # Reading any host configuration (schema prefix, the repo set) goes through
    # AttestoPhoenix.Config rather than being hardcoded here: the task is policy
    # free and only renders what the host has declared.
    {opts, positional, invalid} = OptionParser.parse(args, strict: @switches)
    reject_invalid_args!(positional, invalid)

    repos = parse_repo(args)

    prefix = schema_prefix(opts)
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

  defp schema_prefix(opts) do
    # An explicit --schema-prefix always wins; otherwise defer to the prefix the
    # host configured for the runtime stores so the schema and the migration
    # agree. The neutral identity default (no host config, no flag) is nil: no
    # prefix. The task never invents a prefix of its own.
    case Keyword.fetch(opts, :schema_prefix) do
      {:ok, prefix} -> prefix
      :error -> configured_schema_prefix(opts)
    end
  end

  # Reads :schema_prefix from the host's AttestoPhoenix.Config keyword or
  # already-built struct in the application environment, without requiring the
  # host's other required keys (issuer, keystore, ...) to be present.
  defp configured_schema_prefix(opts) do
    key = opts |> Keyword.get(:config_key) |> config_key()

    case configured_otp_app(opts) do
      nil -> nil
      otp_app -> otp_configured_schema_prefix(otp_app, key)
    end
  end

  # Keep the no-flag command useful from a host application's project root.
  # The explicit library pointer wins because it is the same source used by
  # runtime config resolution; the Mix project app is the safe fallback for a
  # host that stores its config directly under its own application.
  defp configured_otp_app(opts) do
    case Keyword.fetch(opts, :otp_app) do
      {:ok, otp_app} ->
        normalize_otp_app!(otp_app)

      :error ->
        case Application.get_env(:attesto_phoenix, :otp_app) do
          nil ->
            Mix.Project.config()[:app]

          otp_app when is_atom(otp_app) ->
            otp_app

          other ->
            Mix.raise("invalid config :attesto_phoenix, :otp_app: expected an application atom, got #{inspect(other)}")
        end
    end
  end

  defp normalize_otp_app!(otp_app) when is_binary(otp_app) and otp_app != "" do
    String.to_existing_atom(otp_app)
  rescue
    ArgumentError ->
      Mix.raise("invalid --otp-app: application #{inspect(otp_app)} is not loaded")
  end

  defp normalize_otp_app!(otp_app) when is_atom(otp_app), do: otp_app

  defp normalize_otp_app!(other) do
    Mix.raise("invalid --otp-app: expected an application name, got #{inspect(other)}")
  end

  defp otp_configured_schema_prefix(otp_app, key) do
    case Application.get_env(otp_app, key, []) do
      %AttestoPhoenix.Config{schema_prefix: prefix} = config ->
        reject_malformed_prefix_keys!(config)
        reject_legacy_table_prefix_config!(config)
        normalize_configured_prefix(prefix)

      opts when is_list(opts) ->
        reject_legacy_table_prefix_config!(opts)
        opts |> Keyword.get(:schema_prefix) |> normalize_configured_prefix()

      opts when is_map(opts) ->
        reject_malformed_prefix_keys!(opts)
        reject_legacy_table_prefix_config!(opts)
        opts |> Map.get(:schema_prefix) |> normalize_configured_prefix()

      other ->
        Mix.raise(
          "invalid config #{inspect(key)} for #{inspect(otp_app)}: expected " <>
            "a keyword list, map, or AttestoPhoenix.Config struct; got #{inspect(other)}"
        )
    end
  end

  defp reject_legacy_table_prefix_config!(opts) when is_map(opts) do
    if Map.has_key?(opts, :table_prefix) do
      Mix.raise(
        "legacy :table_prefix configuration detected. Version 3.0 uses " <>
          ":schema_prefix for a PostgreSQL schema. In 2.x this value did not " <>
          "identify one runtime layout: generated migrations could create " <>
          "literal-prefixed public tables, most stores queried canonical public " <>
          "tables, and only the CIBA store and sweeper used it as an Ecto schema " <>
          "prefix. Remove the key only after inventorying and migrating verified " <>
          "sources in the existing database."
      )
    end
  end

  defp reject_legacy_table_prefix_config!(opts) when is_list(opts) do
    reject_malformed_prefix_keys!(opts)

    if Keyword.has_key?(opts, :table_prefix) do
      reject_legacy_table_prefix_config!(Map.new(opts))
    end
  end

  defp reject_malformed_prefix_keys!(opts) when is_map(opts) do
    cond do
      Map.has_key?(opts, "schema_prefix") ->
        Mix.raise(
          "invalid config: string key \"schema_prefix\" is not supported; use " <>
            "the atom key :schema_prefix in the host keyword list or map"
        )

      Map.has_key?(opts, "table_prefix") ->
        Mix.raise(
          "legacy config: string key \"table_prefix\" was removed in 3.0; " <>
            "remove it and use the atom key :schema_prefix after the table cutover"
        )

      true ->
        :ok
    end
  end

  defp reject_malformed_prefix_keys!(opts) when is_list(opts) do
    cond do
      Enum.any?(opts, fn
        {"schema_prefix", _value} -> true
        _other -> false
      end) ->
        reject_malformed_prefix_keys!(Map.new(opts))

      Enum.any?(opts, fn
        {"table_prefix", _value} -> true
        _other -> false
      end) ->
        reject_malformed_prefix_keys!(Map.new(opts))

      true ->
        :ok
    end
  end

  defp reject_legacy_table_prefix_arg!(args) do
    if Enum.any?(args, &legacy_table_prefix_arg?/1) do
      Mix.raise(
        "--table-prefix was removed in 3.0. In 2.x it controlled literal names " <>
          "in generated migrations but did not identify one runtime layout: most " <>
          "stores queried canonical public tables, while only the CIBA store and " <>
          "sweeper used it as an Ecto schema prefix. Use --schema-prefix for a " <>
          "fresh migration; inventory and migrate verified existing sources before " <>
          "deploying."
      )
    end
  end

  defp reject_legacy_global_table_prefix! do
    if Keyword.has_key?(Application.get_all_env(:attesto_phoenix), :table_prefix) do
      Mix.raise(
        "legacy config :attesto_phoenix, :table_prefix detected. Version 3.0 " <>
          "uses :schema_prefix for a PostgreSQL schema. The 2.x value did not " <>
          "identify one runtime layout; inventory and complete the 3.0 table " <>
          "cutover before generating a migration."
      )
    end
  end

  defp legacy_table_prefix_arg?("--table-prefix"), do: true
  defp legacy_table_prefix_arg?(arg) when is_binary(arg), do: String.starts_with?(arg, "--table-prefix=")
  defp legacy_table_prefix_arg?(_arg), do: false

  defp config_key(nil), do: @default_config_key
  defp config_key(key) when is_binary(key), do: Module.concat([key])

  defp normalize_configured_prefix(nil), do: nil
  # Preserve an explicitly configured empty value so `validate_prefix!/1` can
  # reject it just like `AttestoPhoenix.Config.new/1`; it is not equivalent to
  # the neutral `nil` prefix.
  defp normalize_configured_prefix(""), do: ""
  defp normalize_configured_prefix(prefix) when is_binary(prefix), do: prefix

  defp normalize_configured_prefix(other) do
    Mix.raise(
      "invalid configured :schema_prefix: expected nil or a lowercase PostgreSQL " <>
        "schema identifier, got #{inspect(other)}"
    )
  end

  defp reject_invalid_args!([], []), do: :ok

  defp reject_invalid_args!(positional, invalid) do
    Mix.raise(
      "invalid migration-generator arguments; use --schema-prefix for a " <>
        "PostgreSQL schema and --repo RepoModule. " <>
        "Unexpected positional arguments: #{inspect(positional)}; invalid options: #{inspect(invalid)}"
    )
  end

  # Prefixes are emitted into the migration source as Ecto schema options, so
  # validate the same conservative
  # PostgreSQL identifier accepted by AttestoPhoenix.Config. Fail closed (no
  # silent normalization).
  defp validate_prefix!(nil), do: :ok

  defp validate_prefix!(prefix) when is_binary(prefix) do
    cond do
      prefix == "" ->
        Mix.raise("invalid --schema-prefix: expected a non-empty lowercase PostgreSQL schema identifier")

      byte_size(prefix) > @max_schema_prefix_bytes ->
        Mix.raise("invalid --schema-prefix: expected at most 63 bytes")

      prefix == "information_schema" or String.starts_with?(prefix, "pg_") ->
        Mix.raise(
          "invalid --schema-prefix: #{inspect(prefix)} is a reserved PostgreSQL " <>
            "system schema; choose an application-owned schema"
        )

      Regex.match?(~r/\A[a-z_][a-z0-9_]*\z/, prefix) ->
        :ok

      true ->
        Mix.raise("invalid --schema-prefix: expected a lowercase PostgreSQL schema identifier")
    end
  end

  defp validate_prefix!(_other) do
    Mix.raise("invalid --schema-prefix: expected nil or a lowercase PostgreSQL schema identifier")
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
    # The optional --schema-prefix is the only thing the host may vary; the base
    # names are not host-configurable because the schemas hardcode them.
    assigns = [
      module: migration_module(repo, base_name),
      prefix: normalize_configured_prefix(prefix),
      authorization_codes: "attesto_authorization_codes",
      refresh_tokens: "attesto_refresh_tokens",
      refresh_family_revocations: "attesto_refresh_family_revocations",
      device_codes: "attesto_device_codes",
      ciba_requests: "attesto_ciba_requests",
      logout_sessions: "attesto_logout_sessions",
      dpop_nonces: "dpop_nonces",
      dpop_replays: "dpop_replays",
      pushed_authorization_requests: "attesto_pushed_authorization_requests",
      client_id_metadata: "attesto_client_id_metadata",
      consent_grants: "attesto_consent_grants",
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
      prefix = <%= inspect @prefix %>

      # A non-default runtime prefix is a PostgreSQL schema, not a table-name
      # fragment. Create it if needed, but leave it in place on rollback: it
      # may be shared by other application tables or migrations.
      <%= if @prefix do %>
      execute(~s|CREATE SCHEMA IF NOT EXISTS "\#{prefix}"|)
      <% end %>

      # Authorization code grant store (RFC 6749, section 4.1), backing
      # AttestoPhoenix.Schema.Authorization / AttestoPhoenix.Store.EctoCodeStore.
      # One row per issued code. Only the hash of the code is stored (RFC 6749,
      # section 10.3); it is the PRIMARY KEY and the single-use lookup key
      # (EctoCodeStore.take/1 deletes by code_hash). The schema keys on
      # :code_hash, so there is no surrogate id. A primary key, not merely a
      # unique index, also gives the table a default REPLICA IDENTITY, which
      # PostgreSQL logical replication needs to replicate UPDATE and DELETE.
      create table(:<%= @authorization_codes %>, primary_key: false, prefix: prefix) do
        add :code_hash, :string, size: <%= @hash_size %>, primary_key: true, null: false
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

      # Single-use redemption is enforced at the database by the primary key. A
      # duplicate code hash violates attesto_authorization_codes_pkey, the name
      # the schema's unique_constraint(:code_hash, name: ...) maps onto the
      # changeset.
      # Expiry sweeps scan by expiry (AttestoPhoenix.Store.Sweeper).
      create index(:<%= @authorization_codes %>, [:expires_at], prefix: prefix)
      create index(:<%= @authorization_codes %>, [:family_id], prefix: prefix)
      create index(:<%= @authorization_codes %>, [:access_token_jti], prefix: prefix)

      # Refresh token store (RFC 6749, section 6), backing
      # AttestoPhoenix.Schema.RefreshToken / AttestoPhoenix.Store.EctoRefreshStore.
      # Rotation with reuse detection (RFC 6819, section 5.2.2.3): every rotation
      # issues a new row in the same family; presenting a consumed token revokes
      # the family. consumed/family_revoked are the booleans the atomic claim and
      # sticky revocation flip.
      create table(:<%= @refresh_tokens %>, primary_key: false, prefix: prefix) do
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
      create unique_index(:<%= @refresh_tokens %>, [:token_hash], prefix: prefix)
      # One generation per family prevents a concurrent or corrupted rotation
      # from creating two sibling successors.
      # Keep this name aligned with Schema.RefreshToken's unique_constraint/3.
      create unique_index(
        :<%= @refresh_tokens %>,
        [:family_id, :generation],
        name: :attesto_refresh_tokens_family_id_generation_index,
        prefix: prefix
      )
      # Family-wide revocation scans by family_id.
      create index(:<%= @refresh_tokens %>, [:family_id], prefix: prefix)
      create index(:<%= @refresh_tokens %>, [:expires_at], prefix: prefix)

      # Durable family revocation tombstones. This table is deliberately
      # separate from refresh-token rows because the sweeper may delete every
      # expired row in a family. The primary key makes revoke idempotent and
      # keeps marker lookups/insert checks cheap.
      create table(:<%= @refresh_family_revocations %>, primary_key: false, prefix: prefix) do
        add :family_id, :string, size: <%= @identifier_size %>, primary_key: true, null: false
        add :revoked_at, :utc_datetime, null: false
      end

      # Device authorization grant (RFC 8628), backing
      # AttestoPhoenix.Schema.DeviceCode / AttestoPhoenix.Store.EctoDeviceCodeStore.
      # A device code is a mutable row moving pending -> approved|denied ->
      # consumed; each transition is one guarded atomic UPDATE in the store. Only
      # the device_code hash is stored; user_code is the normalized verification
      # key. last_polled_at enforces the section 3.5 minimum poll interval.
      create table(:<%= @device_codes %>, primary_key: false, prefix: prefix) do
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
      create unique_index(:<%= @device_codes %>, [:device_code_hash], prefix: prefix)
      create unique_index(:<%= @device_codes %>, [:user_code], prefix: prefix)
      create index(:<%= @device_codes %>, [:expires_at], prefix: prefix)

      # OpenID Connect CIBA authentication requests (CIBA Core 1.0), backing
      # AttestoPhoenix.Schema.CIBARequest / AttestoPhoenix.Store.EctoCIBAStore. A
      # CIBA request is a mutable row moving pending -> approved|denied ->
      # consumed; each transition is one guarded atomic UPDATE in the store. Only
      # the auth_req_id hash is stored. The §7.3 poll interval is frozen into the
      # `interval` column at issue (it is the value the client was told).
      create table(:<%= @ciba_requests %>, primary_key: false, prefix: prefix) do
        add :id, :binary_id, primary_key: true
        add :auth_req_id_hash, :string, size: <%= @hash_size %>, null: false
        add :client_id, :string, size: <%= @identifier_size %>, null: false
        # poll | ping | push (FAPI-CIBA forbids push).
        add :delivery_mode, :string, size: 16, null: false
        add :scope, {:array, :string}, null: false, default: []
        add :acr_values, {:array, :string}, null: false, default: []
        add :binding_message, :string
        # Ping/push only: the client-generated bearer secret the notification POST
        # carries (NULL for poll). A single-flow-scoped, short-lived secret.
        # `:text`, not `:string(255)`: CIBA Core §7.3 sets no length bound and a
        # client may present a long high-entropy token (the conformance client does).
        add :client_notification_token, :text
        # The hint-resolved end-user the OP set out to authenticate (CIBA §7.1:
        # identified BEFORE the auth_req_id is issued). Bound at issue.
        add :hint_subject, :string, size: <%= @identifier_size %>, null: false
        # RFC 8707 resource indicator(s) bound at the backchannel endpoint.
        add :resource, {:array, :string}, null: false, default: []
        # RFC 9449 §10 DPoP holder-of-key pre-binding (NULL for unbound).
        add :dpop_jkt, :string, size: <%= @identifier_size %>
        # pending | approved | denied | consumed (the state machine).
        add :status, :string, size: 16, null: false, default: "pending"
        # Bound at approval (NULL until the user authenticates).
        add :subject, :string, size: <%= @identifier_size %>
        add :acr, :string
        add :auth_time, :utc_datetime
        add :granted_scope, {:array, :string}
        add :granted_claims, :map
        # The §7.3 minimum seconds between accepted polls, frozen at issue.
        add :interval, :integer, null: false, default: 0
        add :last_polled_at, :utc_datetime
        add :expires_at, :utc_datetime, null: false

        timestamps(updated_at: false, type: :utc_datetime)
      end

      # The token endpoint redeems by auth_req_id_hash (the single-use poll key).
      create unique_index(:<%= @ciba_requests %>, [:auth_req_id_hash], prefix: prefix)
      create index(:<%= @ciba_requests %>, [:expires_at], prefix: prefix)

      # Logout session store (OpenID Connect Back-Channel Logout 1.0 +
      # Front-Channel Logout 1.0), backing AttestoPhoenix.Schema.LogoutSession /
      # AttestoPhoenix.Store.EctoLogoutSessionStore. One row per (session, RP)
      # pair, recorded at ID-Token mint and enumerated at the end-session
      # endpoint to deliver a logout_token (back-channel) and/or render the RP's
      # frontchannel_logout_uri in an iframe (front-channel); at least one of the
      # two URIs is present. Upserted on (sid, client_id); read by sid
      # (session-scoped logout) or subject (all the subject's sessions).
      create table(:<%= @logout_sessions %>, primary_key: false, prefix: prefix) do
        add :id, :binary_id, primary_key: true
        add :sid, :string, size: <%= @identifier_size %>, null: false
        add :subject, :string, size: <%= @identifier_size %>, null: false
        add :client_id, :string, size: <%= @identifier_size %>, null: false
        add :backchannel_logout_uri, :text
        # The RP's backchannel_logout_session_required: whether its logout token
        # MUST carry sid (Back-Channel Logout 1.0 section 2.2).
        add :session_required, :boolean, null: false, default: false
        add :frontchannel_logout_uri, :text
        # The RP's frontchannel_logout_session_required: whether the rendered
        # logout URI must carry iss/sid (Front-Channel Logout 1.0 section 2).
        add :frontchannel_session_required, :boolean, null: false, default: false
        add :expires_at, :utc_datetime, null: false

        timestamps(updated_at: false, type: :utc_datetime)
      end

      # Upsert key: re-issuing an ID Token for a session the RP already holds
      # refreshes the row rather than duplicating it. The default index name
      # attesto_logout_sessions_sid_client_id_index matches the schema's
      # unique_constraint([:sid, :client_id], name: ...).
      create unique_index(:<%= @logout_sessions %>, [:sid, :client_id], prefix: prefix)
      # Fan-out reads by sid or subject; sweeps scan by expires_at.
      create index(:<%= @logout_sessions %>, [:subject], prefix: prefix)
      create index(:<%= @logout_sessions %>, [:expires_at], prefix: prefix)

      # Server-issued DPoP nonces (RFC 9449, section 8), backing
      # AttestoPhoenix.Schema.DPoPNonce / AttestoPhoenix.Store.EctoNonceStore.
      # Each nonce is single-use: issued_at + the consume cutoff bound freshness,
      # and used_at (NULL while unused) is stamped exactly once.
      create table(:<%= @dpop_nonces %>, primary_key: false, prefix: prefix) do
        add :id, :binary_id, primary_key: true
        add :nonce, :string, size: <%= @nonce_size %>, null: false
        add :issued_at, :utc_datetime, null: false
        add :expires_at, :utc_datetime, null: false
        add :used_at, :utc_datetime
      end

      # The default index name dpop_nonces_nonce_index matches the schema's
      # unique_constraint(:nonce) (which uses Ecto's default name).
      create unique_index(:<%= @dpop_nonces %>, [:nonce], prefix: prefix)
      # Partial index over still-unused rows keeps the conditional consume fast.
      create index(:<%= @dpop_nonces %>, [:used_at],
               where: "used_at IS NULL",
               name: :<%= @dpop_nonces %>_unused_index,
               prefix: prefix
             )

      # DPoP proof replay cache (RFC 9449, section 11.1), backing
      # AttestoPhoenix.Schema.DPoPReplay / AttestoPhoenix.Store.EctoReplayCheck.
      # The proof's jti (RFC 9449 section 4.2, RFC 7519 section 4.1.7) is the
      # PRIMARY KEY, so the atomic record-and-check is INSERT ... ON CONFLICT DO
      # NOTHING and the conflicting constraint is the primary key dpop_replays_pkey
      # the schema's unique_constraint(:jti, name: :dpop_replays_pkey) names.
      create table(:<%= @dpop_replays %>, primary_key: false, prefix: prefix) do
        add :jti, :string, size: <%= @jti_size %>, primary_key: true, null: false
        add :expires_at, :utc_datetime_usec, null: false
        add :inserted_at, :utc_datetime_usec, null: false
      end

      # Expiry sweeps scan by expires_at; replay decisions hit the primary key.
      create index(:<%= @dpop_replays %>, [:expires_at], prefix: prefix)

      # Pushed Authorization Request store (RFC 9126), backing
      # AttestoPhoenix.Schema.PushedAuthorizationRequest /
      # AttestoPhoenix.Store.EctoPARStore. The one-time request_uri reference is
      # the PRIMARY KEY, so resolution at /authorize (and the optional single-use
      # take/1 = DELETE ... RETURNING) hits the primary key. The stored, validated
      # request params live in a jsonb column; expires_at bounds the reference's
      # life (RFC 9126 section 2.2) and is re-checked on read.
      create table(:<%= @pushed_authorization_requests %>, primary_key: false, prefix: prefix) do
        add :request_uri, :string, size: <%= @identifier_size %>, primary_key: true, null: false
        add :params, :map, null: false
        add :expires_at, :utc_datetime, null: false
        add :inserted_at, :utc_datetime, null: false
      end

      # Expiry sweeps scan by expires_at; resolution hits the primary key.
      create index(:<%= @pushed_authorization_requests %>, [:expires_at], prefix: prefix)

      # Client ID Metadata Document cache
      # (draft-ietf-oauth-client-id-metadata-document-01), backing
      # AttestoPhoenix.Schema.ClientIdMetadata /
      # AttestoPhoenix.ClientIdMetadata.Cache.Ecto. The CIMD client_id URL is the
      # PRIMARY KEY, so the cache lookup (get/1) hits the primary key and a
      # re-fetch upserts the single row. The validated document lives in a jsonb
      # metadata column; expires_at is the freshness derived from the response's
      # Cache-Control/Expires (RFC 9111), re-checked on read and indexed for
      # sweeps. Only validated documents are ever written here.
      create table(:<%= @client_id_metadata %>, primary_key: false, prefix: prefix) do
        add :url, :string, size: <%= @identifier_size %>, primary_key: true, null: false
        add :metadata, :map, null: false
        add :expires_at, :utc_datetime, null: false
        add :inserted_at, :utc_datetime, null: false
      end

      # Expiry sweeps scan by expires_at; lookups hit the primary key.
      create index(:<%= @client_id_metadata %>, [:expires_at], prefix: prefix)

      # Single-use, request-bound consent grants (RFC 6749 section 4.1.1),
      # backing AttestoPhoenix.Schema.ConsentGrant /
      # AttestoPhoenix.Store.EctoConsentGrantStore. One row per consent decision,
      # keyed on an unguessable token (the PRIMARY KEY) so the conditional consume
      # UPDATE and the disambiguation read both hit the primary key. binding_hash
      # ties the grant to the exact request the user saw; consumed_at marks single
      # use; expires_at bounds the short consent window and is re-checked on
      # consume. The default index name attesto_consent_grants_pkey matches the
      # schema's unique_constraint(:token, name: :attesto_consent_grants_pkey).
      create table(:<%= @consent_grants %>, primary_key: false, prefix: prefix) do
        add :token, :string, size: <%= @identifier_size %>, primary_key: true, null: false
        add :binding_hash, :string, size: <%= @hash_size %>, null: false
        add :subject, :string, size: <%= @identifier_size %>, null: false
        add :consumed_at, :utc_datetime_usec
        add :expires_at, :utc_datetime_usec, null: false

        timestamps(type: :utc_datetime_usec)
      end

      # Expiry sweeps scan by expires_at; consume hits the primary key.
      create index(:<%= @consent_grants %>, [:expires_at], prefix: prefix)
    end

    def down do
      prefix = <%= inspect @prefix %>
      drop table(:<%= @consent_grants %>, prefix: prefix)
      drop table(:<%= @client_id_metadata %>, prefix: prefix)
      drop table(:<%= @pushed_authorization_requests %>, prefix: prefix)
      drop table(:<%= @dpop_replays %>, prefix: prefix)
      drop table(:<%= @dpop_nonces %>, prefix: prefix)
      drop table(:<%= @logout_sessions %>, prefix: prefix)
      drop table(:<%= @ciba_requests %>, prefix: prefix)
      drop table(:<%= @device_codes %>, prefix: prefix)
      drop table(:<%= @refresh_family_revocations %>, prefix: prefix)
      drop table(:<%= @refresh_tokens %>, prefix: prefix)
      drop table(:<%= @authorization_codes %>, prefix: prefix)
    end
  end
  """)
end
