defmodule Mix.Tasks.AttestoPhoenix.Gen.Migration do
  @shortdoc "Generates the Ecto migration backing the AttestoPhoenix stores"

  @moduledoc """
  Generates an Ecto migration that creates the persistence backing the
  Ecto-based stores shipped with `attesto_phoenix`.

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

      # Fresh installation:
      mix attesto_phoenix.gen.migration --repo MyApp.Repo

      # Upgrading an existing database to 3.0:
      mix attesto_phoenix.gen.migration --upgrade 3.0 --repo MyApp.Repo

      # Promoting the historical authorization-code unique index to its
      # primary key (run after the 3.0 migration when upgrading 2.x):
      mix attesto_phoenix.gen.migration --upgrade 3.1 --repo MyApp.Repo

  ## Options

    * `--upgrade` - generate a migration to upgrade an existing database rather
      than creating fresh tables. Supported values: `3.0`/`3.0.0` and
      `3.1`/`3.1.0`. The 3.0 migration adopts or creates the exact unique index
      on `attesto_refresh_tokens(family_id, generation)`, creates or adopts the
      `attesto_refresh_family_revocations` table, and safely backfills every
      currently-revoked refresh-token family. The 3.1 migration promotes the
      historical unique index on `attesto_authorization_codes(code_hash)` to
      the primary key required by current schemas. Run both, in order, for a
      2.x database. Each upgrade validates any pre-existing object before
      backfilling or changing it; malformed collisions fail the migration
      transaction rather than being silently accepted.

    * `--repo`, `-r` - the Ecto repo module the migration is generated for. May
      be given more than once to target several repos. When omitted the repos
      configured for the host application are used (the same resolution
      `mix ecto.gen.migration` performs).

    * `--schema-prefix` - an optional PostgreSQL schema selected by Ecto's
      `prefix:` option for every generated table and index (for example
      `--schema-prefix oauth` creates `attesto_authorization_codes` in schema
      `oauth`). Runtime Ecto queries use the same `prefix:` option; the table
      names themselves remain canonical. When omitted, the prefix configured
      for the host (`:schema_prefix` on the
      `AttestoPhoenix.Config` the host puts in its application environment) is
      used so the generated schema matches the prefix the Ecto stores read at
      runtime. If the host has no configured prefix, the generated migration
      defers to the migrator or repo default at execution time. The task never
      invents a prefix. The 2.x `--table-prefix` option is rejected because it
      controlled literal names in generated migrations, not one coherent
      runtime layout: most 2.x stores queried canonical tables in `public`,
      while only the CIBA store and sweeper treated the value as an Ecto schema
      prefix. Inventory an existing database before choosing a 3.0 schema;
      without `--upgrade`, this task is for fresh migrations only.

    * `--migrations-path` - directory the migration file is written to. Defaults
      to the repo's `priv/<repo>/migrations` directory, the same location
      `mix ecto.gen.migration` uses.

    * `--otp-app` - the host application whose environment holds the
      `AttestoPhoenix.Config` keyword or struct to read `:schema_prefix` from
      when `--schema-prefix` is omitted. Optional; when omitted, the task first uses
      `config :attesto_phoenix, otp_app: ...` and then the current Mix
      project's `:app`. If neither application has a configured prefix, the
      task embeds no explicit prefix and the migration uses the migrator or
      repo default at execution time (normally `public`). Keep a custom
      migration default aligned with the runtime database connection's search
      path, or pass `--schema-prefix` explicitly.

    * `--config-key` - the application environment key the host stores its
      `AttestoPhoenix.Config` keyword under. Defaults to `AttestoPhoenix.Config`,
      matching `AttestoPhoenix.Config.from_otp_app/2`.

  Fresh-install migrations are reversible. The 3.0 upgrade migration has a
  guarded rollback that refuses to discard revocations which 2.x cannot
  represent. An application downgrade also requires stopped writers and a
  drain of active 3.x refresh-retry deadlines because 2.x cannot recover 3.x
  successor envelopes.
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
  @max_migration_version 99_999_999_999_999
  @switches [
    repo: [:keep],
    schema_prefix: :string,
    migrations_path: :string,
    otp_app: :string,
    config_key: :string,
    upgrade: :string
  ]

  @aliases [
    r: :repo
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
    {opts, positional, invalid} = OptionParser.parse(args, strict: @switches, aliases: @aliases)
    reject_invalid_args!(positional, invalid)

    upgrade_version = parse_upgrade_version!(opts)

    repos = parse_repo(args)

    configured_prefix =
      if Keyword.has_key?(opts, :schema_prefix) do
        # An explicit 3.x schema wins over a current :schema_prefix value, but
        # it must not bypass detection of the retired 2.x key: that key does
        # not identify one database layout and requires an inventory first.
        reject_configured_legacy_prefix!(opts)
        nil
      else
        configured_schema_prefix(opts)
      end

    prefix = schema_prefix(opts, configured_prefix)
    validate_prefix!(prefix)

    repos
    |> resolve_repos!()
    |> Enum.uniq()
    |> Enum.each(&generate_for_repo(&1, opts, prefix, upgrade_version))
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

  defp schema_prefix(opts, configured_prefix) do
    # An explicit --schema-prefix always wins; otherwise defer to the prefix the
    # host configured for the runtime stores so the schema and the migration
    # agree. The neutral identity default (no host config, no flag) is nil: no
    # prefix. The task never invents a prefix of its own.
    case Keyword.fetch(opts, :schema_prefix) do
      {:ok, prefix} -> prefix
      :error -> configured_prefix
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

  defp reject_configured_legacy_prefix!(opts) do
    key = opts |> Keyword.get(:config_key) |> config_key()

    case configured_otp_app(opts) do
      nil -> :ok
      otp_app -> reject_configured_legacy_prefix_value!(Application.get_env(otp_app, key, []))
    end
  end

  defp reject_configured_legacy_prefix_value!(opts) when is_map(opts) do
    cond do
      Map.has_key?(opts, :table_prefix) -> reject_legacy_table_prefix_config!(opts)
      Map.has_key?(opts, "table_prefix") -> reject_malformed_prefix_keys!(opts)
      true -> :ok
    end
  end

  defp reject_configured_legacy_prefix_value!(opts) when is_list(opts) do
    cond do
      Enum.any?(opts, fn
        {:table_prefix, _value} -> true
        _other -> false
      end) ->
        reject_legacy_table_prefix_config!(%{table_prefix: :configured})

      Enum.any?(opts, fn
        {"table_prefix", _value} -> true
        _other -> false
      end) ->
        reject_malformed_prefix_keys!(opts)

      true ->
        :ok
    end
  end

  defp reject_configured_legacy_prefix_value!(_other), do: :ok

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

  defp parse_upgrade_version!(opts) do
    case Keyword.fetch(opts, :upgrade) do
      {:ok, version} when version in ["3.0", "3.0.0"] ->
        "3.0"

      {:ok, version} when version in ["3.1", "3.1.0"] ->
        "3.1"

      {:ok, version} ->
        Mix.raise(
          ~s|unsupported --upgrade version #{inspect(version)}; currently supported upgrade versions: "3.0", "3.1"|
        )

      :error ->
        nil
    end
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

  defp generate_for_repo(repo, opts, prefix, upgrade_version) do
    case upgrade_version do
      "3.0" -> generate_upgrade_3_0_for_repo(repo, opts, prefix)
      "3.1" -> generate_upgrade_3_1_for_repo(repo, opts, prefix)
      nil -> generate_fresh_for_repo(repo, opts, prefix)
    end
  end

  defp generate_fresh_for_repo(repo, opts, prefix) do
    ensure_repo(repo, [])

    path = migrations_path(repo, opts)
    create_directory(path)

    base_name = "create_attesto_phoenix_tables"

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

    create_migration_file(path, base_name, migration_template(assigns), :fresh)
  end

  defp generate_upgrade_3_0_for_repo(repo, opts, prefix) do
    ensure_repo(repo, [])

    path = migrations_path(repo, opts)
    create_directory(path)

    base_name = "upgrade_attesto_phoenix_to_3_0"
    normalized_prefix = normalize_configured_prefix(prefix)

    assigns = [
      module: migration_module(repo, base_name),
      prefix: normalized_prefix,
      refresh_tokens: "attesto_refresh_tokens",
      refresh_family_revocations: "attesto_refresh_family_revocations",
      identifier_size: @identifier_column_size
    ]

    create_migration_file(path, base_name, upgrade_migration_template(assigns), :upgrade_3_0)
  end

  defp generate_upgrade_3_1_for_repo(repo, opts, prefix) do
    ensure_repo(repo, [])

    path = migrations_path(repo, opts)
    create_directory(path)

    base_name = "upgrade_attesto_phoenix_to_3_1"
    normalized_prefix = normalize_configured_prefix(prefix)

    assigns = [
      module: migration_module(repo, base_name),
      prefix: normalized_prefix,
      authorization_codes: "attesto_authorization_codes",
      authorization_code_hash_index: "attesto_authorization_codes_code_hash_index",
      # PostgreSQL stores varchar(n)'s typmod as n plus its four-byte varlena
      # header. Keep the catalog contract tied to the generator's hash size.
      authorization_code_hash_typmod: @hash_column_size + 4
    ]

    create_migration_file(
      path,
      base_name,
      authorization_code_upgrade_migration_template(assigns),
      :upgrade_3_1
    )
  end

  defp migrations_path(repo, opts) do
    case Keyword.fetch(opts, :migrations_path) do
      {:ok, path} -> path
      :error -> default_migrations_path(repo)
    end
  end

  # Mirrors how `mix ecto.gen.migration` locates a repo's migrations: the repo's
  # configured :priv resolved via Mix.EctoSQL.source_repo_priv/1 so umbrella repos
  # and absolute :priv paths work.
  defp default_migrations_path(repo) do
    priv = repo_priv(repo)
    Path.join(priv, "migrations")
  end

  defp repo_priv(repo) do
    config = repo.config()

    case config[:priv] do
      priv when is_binary(priv) ->
        if Path.type(priv) == :absolute do
          priv
        else
          Mix.EctoSQL.source_repo_priv(repo)
        end

      _ ->
        Mix.EctoSQL.source_repo_priv(repo)
    end
  end

  defp migration_module(repo, base_name) do
    Module.concat([repo, Migrations, Macro.camelize(base_name)])
  end

  defp with_migration_generation_lock(path, fun) do
    lock_path = Path.join(path, ".attesto_phoenix_migration.lock")

    case acquire_migration_generation_lock(lock_path) do
      {:ok, owner_token} ->
        result =
          try do
            {:ok, fun.()}
          catch
            kind, reason -> {:raised, kind, reason, __STACKTRACE__}
          end

        release_result = release_migration_generation_lock(lock_path, owner_token)

        case {result, release_result} do
          {{:ok, value}, :ok} ->
            value

          {{:ok, _value}, {:error, reason}} ->
            Mix.raise("could not release migrations directory lock #{lock_path}: #{inspect(reason)}")

          {{:raised, kind, reason, stacktrace}, _release_error} ->
            :erlang.raise(kind, reason, stacktrace)
        end

      {:error, reason} ->
        Mix.raise(migration_generation_lock_error(path, lock_path, reason))
    end
  end

  defp acquire_migration_generation_lock(lock_path) do
    case File.mkdir(lock_path) do
      :ok ->
        owner_token = migration_generation_owner_token()
        owner_path = Path.join(lock_path, "owner")

        case File.write(owner_path, owner_token, [:write, :exclusive, :binary]) do
          :ok ->
            {:ok, owner_token}

          {:error, reason} ->
            File.rm(owner_path)
            File.rmdir(lock_path)
            {:error, {:owner_token_could_not_be_written, reason}}
        end

      {:error, :eexist} ->
        # A lock directory can survive a crashed generator. Do not reclaim it
        # from its age: a paused live generator could otherwise be interrupted
        # and have its cleanup remove a newer owner's lock. The caller reports
        # the path so an operator can verify ownership before removing it.
        {:error, :generation_in_progress}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp migration_generation_owner_token do
    16
    |> :crypto.strong_rand_bytes()
    |> Base.encode16(case: :lower)
  end

  defp release_migration_generation_lock(lock_path, owner_token) do
    owner_path = Path.join(lock_path, "owner")

    case File.read(owner_path) do
      {:ok, ^owner_token} ->
        remove_owned_migration_generation_lock(lock_path, owner_path)

      {:ok, _other_token} ->
        {:error, :lock_ownership_lost}

      {:error, :enoent} ->
        {:error, :lock_owner_missing}

      {:error, reason} ->
        {:error, {:lock_owner_could_not_be_read, reason}}
    end
  end

  defp remove_owned_migration_generation_lock(lock_path, owner_path) do
    case File.rm(owner_path) do
      :ok ->
        case File.rmdir(lock_path) do
          :ok -> :ok
          {:error, reason} -> {:error, {:lock_directory_could_not_be_removed, reason}}
        end

      {:error, reason} ->
        {:error, {:owner_token_could_not_be_removed, reason}}
    end
  end

  defp migration_generation_lock_error(path, lock_path, :generation_in_progress) do
    "could not safely reserve migrations directory #{path}: lock #{lock_path} exists; " <>
      "another generator may be active, or a previous generator may have crashed; " <>
      "verify no generator is active, remove the lock directory, and retry"
  end

  defp migration_generation_lock_error(path, lock_path, reason) do
    "could not safely reserve migrations directory #{path}: lock #{lock_path}: #{inspect(reason)}"
  end

  defp create_migration_file(path, base_name, contents, kind) do
    with_migration_generation_lock(path, fn ->
      ensure_migration_kind_available!(path, base_name, kind)

      version = next_migration_version(path)
      file = Path.join(path, "#{version}_#{base_name}.exs")

      # The directory lock covers the full scan-and-write operation, so another
      # invocation cannot select a different version for the same migration
      # kind (or invert the requested upgrade order) while this one runs.
      ensure_migration_version_available!(path, version)
      write_migration_file!(file, contents)
      ensure_single_migration_kind!(path, file, base_name)
      ensure_single_migration_version!(path, file, version)
      Mix.shell().info("* creating #{file}")
      file
    end)
  end

  defp ensure_migration_kind_available!(path, base_name, :fresh) do
    if !Enum.empty?(migration_kind_files(path, base_name)) do
      Mix.raise(
        "migration #{inspect(base_name)} already exists in #{path}; " <>
          "remove it before regenerating to avoid duplicate tables"
      )
    end

    upgrade_files =
      migration_kind_files(path, "upgrade_attesto_phoenix_to_3_0") ++
        migration_kind_files(path, "upgrade_attesto_phoenix_to_3_1")

    if upgrade_files != [] do
      file_names =
        upgrade_files
        |> Enum.map(&Path.basename/1)
        |> Enum.sort()
        |> Enum.join(", ")

      Mix.raise(
        "#{path} already contains attesto_phoenix upgrade migrations (#{file_names}); " <>
          "the fresh-install migration is only for a new database and must not be added " <>
          "to an upgraded database's migration history"
      )
    end
  end

  defp ensure_migration_kind_available!(path, base_name, :upgrade_3_0) do
    case migration_kind_files(path, base_name) do
      [] ->
        if migration_kind_files(path, "upgrade_attesto_phoenix_to_3_1") == [] do
          :ok
        else
          Mix.raise(
            "cannot generate migration version 3.0 after the 3.1 migration already " <>
              "exists in #{path}; remove the 3.1 migration and retry in order"
          )
        end

      [_existing_file] ->
        Mix.raise(
          "migration #{inspect(base_name)} already exists in #{path}; " <>
            "remove it before regenerating"
        )

      multiple ->
        Mix.raise("multiple #{inspect(base_name)} migrations exist in #{path}: #{inspect(multiple)}")
    end
  end

  defp ensure_migration_kind_available!(path, base_name, :upgrade_3_1) do
    case migration_kind_files(path, base_name) do
      [] ->
        :ok

      [_existing_file] ->
        Mix.raise(
          "migration #{inspect(base_name)} already exists in #{path}; " <>
            "remove it before regenerating"
        )

      multiple ->
        Mix.raise("multiple #{inspect(base_name)} migrations exist in #{path}: #{inspect(multiple)}")
    end
  end

  defp next_migration_version(path) do
    case migration_versions(path) do
      [] ->
        timestamp()

      versions ->
        current = timestamp()
        latest = Enum.max(versions)

        if latest < String.to_integer(current) do
          current
        else
          latest
          |> Kernel.+(1)
          |> format_migration_version!()
        end
    end
  end

  defp format_migration_version!(version) when version <= @max_migration_version do
    version
    |> Integer.to_string()
    |> String.pad_leading(14, "0")
  end

  defp format_migration_version!(version) do
    Mix.raise(
      "cannot allocate a 14-digit migration version at or after the existing " <>
        "latest version #{version - 1}"
    )
  end

  defp migration_versions(path) do
    path
    |> migration_files()
    |> Enum.flat_map(fn file ->
      case Integer.parse(Path.rootname(Path.basename(file))) do
        {version, "_" <> _name} -> [version]
        _ -> []
      end
    end)
  end

  defp migration_files(path) do
    case File.ls(path) do
      {:ok, _entries} ->
        Path.join(path, "**/*.{ex,exs}")
        |> Path.wildcard()

      {:error, reason} ->
        Mix.raise("could not inspect migrations directory #{path}: #{inspect(reason)}")
    end
  end

  defp migration_kind_files(path, base_name) do
    Path.join(path, "**/*_#{base_name}.exs")
    |> Path.wildcard()
  end

  defp ensure_single_migration_kind!(path, file, base_name) do
    if length(migration_kind_files(path, base_name)) != 1 do
      File.rm(file)

      Mix.raise(
        "migration #{inspect(base_name)} collided with another file in #{path}; " <>
          "refusing to leave duplicate migration kinds"
      )
    end
  end

  defp ensure_migration_version_available!(path, version) do
    versions = migration_versions(path)

    if Enum.any?(versions, &(&1 >= String.to_integer(version))) do
      Mix.raise(
        "migration version #{version} is no longer available in #{path}; " <>
          "another migration was created concurrently; retry"
      )
    end
  end

  defp write_migration_file!(file, contents) do
    case File.open(file, [:write, :exclusive, :binary]) do
      {:ok, io} ->
        result = IO.binwrite(io, contents)
        close_result = File.close(io)

        case {result, close_result} do
          {:ok, :ok} ->
            :ok

          _ ->
            File.rm(file)

            Mix.raise("could not write migration file #{file}: #{inspect({result, close_result})}")
        end

      {:error, :eexist} ->
        Mix.raise("migration file #{file} was created concurrently; refusing to overwrite it")

      {:error, reason} ->
        Mix.raise("could not create migration file #{file}: #{inspect(reason)}")
    end
  end

  defp ensure_single_migration_version!(path, file, version) do
    duplicate_count =
      path
      |> migration_files()
      |> Enum.count(fn candidate ->
        case Integer.parse(Path.rootname(Path.basename(candidate))) do
          {candidate_version, "_" <> _name} -> candidate_version == String.to_integer(version)
          _ -> false
        end
      end)

    if duplicate_count != 1 do
      File.rm(file)

      Mix.raise(
        "migration version #{version} collided with another file in #{path}; " <>
          "refusing to leave duplicate Ecto versions"
      )
    end
  end

  # Fourteen-digit sortable migration version seeded from the current UTC
  # second. Allocations after an existing version are sequence values rather
  # than literal UTC timestamps, so the directory remains strictly ordered.
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
      # (EctoCodeStore.take/1 claims it with a conditional UPDATE by code_hash).
      # The schema keys on :code_hash, so there is no surrogate id. A primary
      # key, not merely a unique index, also supplies the usable index selected
      # by REPLICA IDENTITY DEFAULT. A logical-replication publication needs
      # that identity when it includes this table's UPDATE or DELETE operations.
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

      # A duplicate code hash violates attesto_authorization_codes_pkey, the
      # primary-key name the schema maps onto the changeset alongside the legacy
      # unique-index name for rolling upgrades. Single-use redemption is
      # enforced by take/1's conditional UPDATE of consumed_at.
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

  embed_template(:upgrade_migration, """
  defmodule <%= inspect @module %> do
    @moduledoc false

    # Generated by `mix attesto_phoenix.gen.migration --upgrade 3.0`.
    #
    # Upgrades the Ecto-based attesto_phoenix stores from 2.14.x to 3.0.
    # This migration owns the exact generation index and durable tombstone table
    # after it succeeds. It may adopt either object when it already exists, but
    # it validates the complete PostgreSQL catalog definition before it performs
    # the backfill. A malformed object with one of these canonical names aborts
    # the transaction; it is never silently accepted or replaced.
    #   * Adds or adopts the unique index on
    #     attesto_refresh_tokens(family_id, generation)
    #   * Creates or adopts the attesto_refresh_family_revocations table
    #   * Safely backfills already-revoked families from attesto_refresh_tokens
    #
    # Contention & Retry:
    #   A short transaction-local lock timeout (5s) is applied before creating
    #   the unique index. If migration fails due to lock contention on
    #   attesto_refresh_tokens (PostgreSQL error 55P03: lock_not_available),
    #   identify and wait for or terminate long-running queries holding locks on
    #   the table, stop all token writers, and retry `mix ecto.migrate`.
    #
    # Downgrade limitation:
    #   Rollback is guarded. Every tombstoned family must still have at least
    #   one legacy attesto_refresh_tokens row, and every remaining row in that
    #   family must have family_revoked = true. Missing rows or a mixed true/
    #   false family abort rollback so 2.x cannot resurrect a usable token.
    #   Keep every 3.x token writer stopped during rollback. Before starting
    #   2.x, wait out the longest active refresh retry deadline (or accept that
    #   an honest retry may be treated as reuse), because 2.x cannot recover a
    #   3.x successor envelope.

    use Ecto.Migration

    def up do
      prefix = effective_prefix(<%= inspect @prefix %>)
      source_table = qualify_table("<%= @refresh_tokens %>", prefix)
      target_table = qualify_table("<%= @refresh_family_revocations %>", prefix)

      repo().query!("SET LOCAL lock_timeout = '5s'", [], log: false)
      repo().query!("SET LOCAL row_security = off", [], log: false)

      create_if_not_exists table(:<%= @refresh_family_revocations %>, primary_key: false, prefix: prefix) do
        add :family_id, :string, size: <%= @identifier_size %>, primary_key: true, null: false
        add :revoked_at, :utc_datetime, null: false
      end

      # Ecto queues migration DDL. Materialize the tombstone table first, then
      # lock both tables in runtime revocation order. CREATE TABLE IF NOT EXISTS
      # does not lock a pre-existing relation when it skips creation, so these
      # explicit locks close the validation/backfill race for adopted objects.
      flush()
      repo().query!("LOCK TABLE \#{target_table} IN ACCESS EXCLUSIVE MODE", [], log: false)
      repo().query!("LOCK TABLE \#{source_table} IN ACCESS EXCLUSIVE MODE", [], log: false)

      create_if_not_exists unique_index(
        :<%= @refresh_tokens %>,
        [:family_id, :generation],
        name: :attesto_refresh_tokens_family_id_generation_index,
        prefix: prefix
      )

      # Flush the conditional index before checking the catalog. A validation
      # error rolls back every create and the entire migration transaction.
      flush()
      validate_generation_index!(
        source_table,
        qualify_table("attesto_refresh_tokens_family_id_generation_index", prefix),
        :apply
      )

      validate_revocation_table!(target_table, :apply)

      repo().query!(\"""
      INSERT INTO \#{target_table} (family_id, revoked_at)
      SELECT DISTINCT family_id, CURRENT_TIMESTAMP AT TIME ZONE 'UTC'
      FROM \#{source_table}
      WHERE family_revoked = true
      ON CONFLICT (family_id) DO NOTHING
      \""", [], log: false)

      validate_revocation_backfill!(source_table, target_table)
    end

    defp validate_generation_index!(source_table, index_table, operation) do
      %{rows: [[ready, failure_reasons]]} =
        repo().query!(\"\"\"
        WITH target AS (
          SELECT pg_catalog.to_regclass($1)::pg_catalog.oid AS table_oid,
                 pg_catalog.to_regclass($2)::pg_catalog.oid AS index_oid
        ), attrs AS (
          SELECT target.*,
                 family.attnum AS family_attnum,
                 family.atttypid AS family_type,
                 family.atttypmod AS family_typmod,
                 family.attnotnull AS family_not_null,
                 family.attcollation AS family_collation,
                 generation.attnum AS generation_attnum,
                 generation.atttypid AS generation_type,
                 generation.attnotnull AS generation_not_null,
                 generation.attcollation AS generation_collation
          FROM target
          LEFT JOIN pg_catalog.pg_attribute AS family
            ON family.attrelid = target.table_oid
           AND family.attname = 'family_id'
           AND family.attnum > 0
           AND NOT family.attisdropped
          LEFT JOIN pg_catalog.pg_attribute AS generation
            ON generation.attrelid = target.table_oid
           AND generation.attname = 'generation'
           AND generation.attnum > 0
           AND NOT generation.attisdropped
        ), catalog AS (
          SELECT attrs.*,
                 table_rel.relkind AS table_kind,
                 table_rel.relpersistence AS table_persistence,
                 table_rel.relispartition AS table_is_partition,
                 EXISTS (
                   SELECT 1
                   FROM pg_catalog.pg_inherits AS inheritance
                   WHERE inheritance.inhrelid = attrs.table_oid
                      OR inheritance.inhparent = attrs.table_oid
                 ) AS table_has_inheritance,
                 index_rel.relkind AS index_kind,
                 access_method.amname,
                 index_info.indisunique,
                 index_info.indisvalid,
                 index_info.indisready,
                 index_info.indislive,
                 index_info.indimmediate,
                 index_info.indisreplident,
                 index_info.indnatts,
                 index_info.indnkeyatts,
                 index_info.indkey,
                 index_info.indcollation,
                 index_info.indclass,
                 index_info.indoption,
                 index_info.indpred,
                 index_info.indexprs,
                 COALESCE(
                   (pg_catalog.to_jsonb(index_info) ->> 'indnullsnotdistinct')::pg_catalog.bool,
                   false
                 )
                   AS nulls_not_distinct,
                 EXISTS (
                   SELECT 1 FROM pg_catalog.pg_constraint AS constraint_info
                   WHERE constraint_info.conindid = attrs.index_oid
                 ) AS constraint_backed
          FROM attrs
          LEFT JOIN pg_catalog.pg_class AS table_rel ON table_rel.oid = attrs.table_oid
          LEFT JOIN pg_catalog.pg_class AS index_rel ON index_rel.oid = attrs.index_oid
          LEFT JOIN pg_catalog.pg_index AS index_info
            ON index_info.indexrelid = attrs.index_oid
           AND index_info.indrelid = attrs.table_oid
          LEFT JOIN pg_catalog.pg_am AS access_method ON access_method.oid = index_rel.relam
        ), checks AS (
          SELECT table_oid IS NOT NULL AS table_exists,
                 index_oid IS NOT NULL AS index_exists,
                 table_kind = 'r' AS ordinary_table,
                 table_persistence = 'p' AS permanent_table,
                 NOT COALESCE(table_is_partition, false) AND NOT table_has_inheritance
                   AS standalone_table,
                 index_kind = 'i' AND amname = 'btree' AS btree_index,
                 COALESCE(indisunique, false) AS unique_index,
                 COALESCE(indisvalid AND indisready AND indislive AND indimmediate, false)
                   AS index_valid_ready_live,
                 COALESCE(
                   indnatts = 2 AND indnkeyatts = 2 AND
                   indkey[0] = family_attnum AND indkey[1] = generation_attnum,
                   false
                 ) AS exact_columns,
                 COALESCE(
                   family_type = '1043'::pg_catalog.regtype::pg_catalog.oid AND
                     family_typmod = 259,
                   false
                 )
                   AS family_type_exact,
                 COALESCE(generation_type = '23'::pg_catalog.regtype::pg_catalog.oid, false)
                   AS generation_type_exact,
                 COALESCE(family_not_null, false) AS family_not_null,
                 COALESCE(generation_not_null, false) AS generation_not_null,
                 COALESCE(
                   indcollation[0] = family_collation AND
                     indcollation[1] = generation_collation AND
                     family_collation = (
                       SELECT oid FROM pg_catalog.pg_collation
                       WHERE collname = 'default'
                         AND collnamespace = 'pg_catalog'::pg_catalog.regnamespace
                     ) AND
                     generation_collation = 0,
                   false
                 )
                   AS default_collation,
                 NOT nulls_not_distinct AS default_null_treatment,
                 COALESCE(
                   (SELECT opcdefault FROM pg_catalog.pg_opclass WHERE oid = indclass[0]) AND
                   (SELECT opcdefault FROM pg_catalog.pg_opclass WHERE oid = indclass[1]) AND
                   (SELECT opcintype = family_type OR EXISTS (
                      SELECT 1 FROM pg_catalog.pg_cast
                      WHERE castsource = family_type
                        AND casttarget = opcintype
                        AND castcontext = 'i'
                    ) FROM pg_catalog.pg_opclass WHERE oid = indclass[0]) AND
                   (SELECT opcintype = generation_type
                    FROM pg_catalog.pg_opclass
                    WHERE oid = indclass[1]),
                   false
                 ) AS default_operator_classes,
                 COALESCE(indoption[0] = 0 AND indoption[1] = 0, false)
                   AS default_ordering,
                 indpred IS NULL AS no_predicate,
                 indexprs IS NULL AS no_expressions,
                 NOT constraint_backed AS not_constraint_backed,
                 NOT COALESCE(indisreplident, false) AS not_replica_identity_index
          FROM catalog
        ), failures AS (
          SELECT checks.*,
                 pg_catalog.array_remove(ARRAY[
                   CASE WHEN NOT table_exists THEN 'table_missing' END,
                   CASE WHEN NOT index_exists THEN 'index_missing' END,
                   CASE WHEN NOT ordinary_table THEN 'table_not_ordinary' END,
                   CASE WHEN NOT permanent_table THEN 'table_not_permanent' END,
                   CASE WHEN NOT standalone_table THEN 'table_partitioned_or_inherited' END,
                   CASE WHEN NOT btree_index THEN 'index_not_btree' END,
                   CASE WHEN NOT unique_index THEN 'index_not_unique' END,
                   CASE WHEN NOT index_valid_ready_live THEN 'index_invalid_not_ready_or_not_live' END,
                   CASE WHEN NOT exact_columns THEN 'index_columns_or_include_columns_mismatch' END,
                   CASE WHEN NOT family_type_exact THEN 'family_id_type_mismatch' END,
                   CASE WHEN NOT generation_type_exact THEN 'generation_type_mismatch' END,
                   CASE WHEN NOT family_not_null THEN 'family_id_nullable_or_missing' END,
                   CASE WHEN NOT generation_not_null THEN 'generation_nullable_or_missing' END,
                   CASE WHEN NOT default_collation THEN 'non_default_collation' END,
                   CASE WHEN NOT default_null_treatment THEN 'index_nulls_not_distinct' END,
                   CASE WHEN NOT default_operator_classes THEN 'non_default_operator_class' END,
                   CASE WHEN NOT default_ordering THEN 'non_default_ordering' END,
                   CASE WHEN NOT no_predicate THEN 'partial_index' END,
                   CASE WHEN NOT no_expressions THEN 'expression_index' END,
                   CASE WHEN NOT not_constraint_backed THEN 'index_backs_constraint' END,
                   CASE WHEN NOT not_replica_identity_index THEN 'index_is_replica_identity' END
                 ], NULL) AS failure_reasons
          FROM checks
        )
        SELECT pg_catalog.cardinality(failure_reasons) = 0 AS ready_for_generation_index,
               failure_reasons
        FROM failures
        \"\"\", [source_table, index_table], log: false)

      unless ready do
        raise "Cannot safely \#{operation} 3.0 migration: the canonical generation index " <>
                "does not have the exact expected definition. Catalog failures: " <>
                inspect(failure_reasons)
      end
    end

    defp validate_revocation_table!(target_table, operation) do
      %{rows: [[ready, failure_reasons]]} =
        repo().query!(\"\"\"
        WITH target AS (
          SELECT pg_catalog.to_regclass($1)::pg_catalog.oid AS table_oid
        ), columns AS (
          SELECT target.*,
                 pg_catalog.count(attribute.attnum) FILTER (
                   WHERE attribute.attnum > 0 AND NOT attribute.attisdropped
                 ) AS column_count,
                 pg_catalog.count(attribute.attnum) FILTER (
                   WHERE attribute.attname = 'family_id'
                     AND attribute.atttypid = '1043'::pg_catalog.regtype::pg_catalog.oid
                     AND attribute.atttypmod = 259
                     AND attribute.attnotnull
                     AND attribute.attcollation = (
                       SELECT oid FROM pg_catalog.pg_collation
                       WHERE collname = 'default'
                         AND collnamespace = 'pg_catalog'::pg_catalog.regnamespace
                     )
                     AND NOT attribute.atthasdef
                     AND attribute.attidentity = ''
                     AND attribute.attgenerated = ''
                 ) AS family_column_count,
                 pg_catalog.count(attribute.attnum) FILTER (
                   WHERE attribute.attname = 'revoked_at'
                     AND attribute.atttypid = '1114'::pg_catalog.regtype::pg_catalog.oid
                     AND attribute.atttypmod = 0
                     AND attribute.attnotnull
                     AND attribute.attcollation = 0
                     AND NOT attribute.atthasdef
                     AND attribute.attidentity = ''
                     AND attribute.attgenerated = ''
                 ) AS revoked_at_column_count,
                 pg_catalog.max(attribute.attnum) FILTER (WHERE attribute.attname = 'family_id')
                   AS family_attnum
          FROM target
          LEFT JOIN pg_catalog.pg_attribute AS attribute
            ON attribute.attrelid = target.table_oid
           AND attribute.attnum > 0
           AND NOT attribute.attisdropped
          GROUP BY target.table_oid
        ), constraints AS (
          SELECT columns.*,
                 relation.relkind AS table_kind,
                 relation.relpersistence,
                 relation.relispartition,
                 relation.relrowsecurity,
                 relation.relforcerowsecurity,
                 EXISTS (
                   SELECT 1
                   FROM pg_catalog.pg_inherits AS inheritance
                   WHERE inheritance.inhrelid = columns.table_oid
                      OR inheritance.inhparent = columns.table_oid
                 ) AS table_has_inheritance,
                 pg_catalog.count(constraint_info.oid) FILTER (WHERE constraint_info.contype = 'p')
                   AS primary_key_count,
                 pg_catalog.count(constraint_info.oid) FILTER (WHERE constraint_info.contype <> 'n')
                   AS constraint_count,
                 pg_catalog.max(constraint_info.conname) FILTER (WHERE constraint_info.contype = 'p')
                   AS primary_key_name,
                 COALESCE(pg_catalog.bool_or(
                   constraint_info.contype = 'p' AND
                     NOT constraint_info.condeferrable AND
                     NOT constraint_info.condeferred AND
                     constraint_info.convalidated
                 ), false) AS primary_key_contract_exact,
                 (pg_catalog.array_agg(constraint_info.conindid)
                   FILTER (WHERE constraint_info.contype = 'p'))[1]
                   AS primary_index_oid,
                 pg_catalog.count(constraint_info.oid) FILTER (
                   WHERE constraint_info.contype = 'p'
                     AND constraint_info.conkey::pg_catalog.int2[] =
                       ARRAY[columns.family_attnum]::pg_catalog.int2[]
                 ) AS family_primary_key_count
          FROM columns
          LEFT JOIN pg_catalog.pg_class AS relation ON relation.oid = columns.table_oid
          LEFT JOIN pg_catalog.pg_constraint AS constraint_info
            ON constraint_info.conrelid = columns.table_oid
          GROUP BY columns.table_oid, columns.column_count,
                   columns.family_column_count, columns.revoked_at_column_count,
                   columns.family_attnum, relation.relkind, relation.relpersistence,
                   relation.relispartition, relation.relrowsecurity,
                   relation.relforcerowsecurity
        ), catalog AS (
          SELECT constraints.*,
                 primary_index_rel.relkind AS primary_index_kind,
                 primary_access_method.amname AS primary_index_access_method,
                 primary_index.indisunique AS primary_index_unique,
                 primary_index.indisvalid AS primary_index_valid,
                 primary_index.indisready AS primary_index_ready,
                 primary_index.indislive AS primary_index_live,
                 primary_index.indimmediate AS primary_index_immediate,
                 primary_index.indnatts AS primary_index_nattrs,
                 primary_index.indnkeyatts AS primary_index_nkeyattrs,
                 primary_index.indkey AS primary_index_key,
                 primary_index.indcollation AS primary_index_collation,
                 primary_index.indclass AS primary_index_class,
                 primary_index.indoption AS primary_index_options,
                 primary_index.indpred AS primary_index_predicate,
                 primary_index.indexprs AS primary_index_expressions,
                 COALESCE(
                   (pg_catalog.to_jsonb(primary_index) ->> 'indnullsnotdistinct')::pg_catalog.bool,
                   false
                 )
                   AS primary_index_nulls_not_distinct,
                 (SELECT pg_catalog.count(*) FROM pg_catalog.pg_index AS table_index
                  WHERE table_index.indrelid = constraints.table_oid) AS table_index_count,
                 EXISTS (
                   SELECT 1 FROM pg_catalog.pg_trigger AS trigger_info
                   WHERE trigger_info.tgrelid = constraints.table_oid
                     AND NOT trigger_info.tgisinternal
                 ) AS has_user_triggers,
                 EXISTS (
                   SELECT 1 FROM pg_catalog.pg_rewrite AS rewrite_info
                   WHERE rewrite_info.ev_class = constraints.table_oid
                 ) AS has_rewrite_rules,
                 EXISTS (
                   SELECT 1 FROM pg_catalog.pg_policy AS policy_info
                   WHERE policy_info.polrelid = constraints.table_oid
                 ) AS has_row_policies,
                 (SELECT opcdefault FROM pg_catalog.pg_opclass
                  WHERE oid = primary_index.indclass[0]) AS primary_index_default_opclass,
                 (SELECT opcintype FROM pg_catalog.pg_opclass
                  WHERE oid = primary_index.indclass[0]) AS primary_index_opclass_type
          FROM constraints
          LEFT JOIN pg_catalog.pg_class AS primary_index_rel
            ON primary_index_rel.oid = constraints.primary_index_oid
          LEFT JOIN pg_catalog.pg_index AS primary_index
            ON primary_index.indexrelid = constraints.primary_index_oid
          LEFT JOIN pg_catalog.pg_am AS primary_access_method
            ON primary_access_method.oid = primary_index_rel.relam
        ), failures AS (
          SELECT catalog.*,
                 pg_catalog.array_remove(ARRAY[
                   CASE WHEN table_oid IS NULL THEN 'table_missing' END,
                   CASE WHEN table_kind <> 'r' THEN 'table_not_ordinary' END,
                   CASE WHEN relpersistence <> 'p' THEN 'table_not_permanent' END,
                   CASE WHEN relispartition OR table_has_inheritance
                        THEN 'table_partitioned_or_inherited' END,
                   CASE WHEN COALESCE(relrowsecurity, false)
                        THEN 'row_level_security_enabled' END,
                   CASE WHEN COALESCE(relforcerowsecurity, false)
                        THEN 'force_row_level_security_enabled' END,
                   CASE WHEN has_user_triggers THEN 'user_triggers_present' END,
                   CASE WHEN has_rewrite_rules THEN 'rewrite_rules_present' END,
                   CASE WHEN has_row_policies THEN 'row_policies_present' END,
                   CASE WHEN column_count <> 2 THEN 'unexpected_columns' END,
                   CASE WHEN family_column_count <> 1 THEN 'family_id_definition_mismatch' END,
                   CASE WHEN revoked_at_column_count <> 1 THEN 'revoked_at_definition_mismatch' END,
                   CASE WHEN constraint_count <> 1 OR primary_key_count <> 1 OR
                              family_primary_key_count <> 1 OR
                              primary_key_name <> 'attesto_refresh_family_revocations_pkey' OR
                              NOT primary_key_contract_exact
                        THEN 'primary_key_definition_mismatch' END,
                   CASE WHEN table_index_count <> 1 THEN 'unexpected_indexes' END,
                   CASE WHEN primary_index_kind <> 'i' OR primary_index_access_method <> 'btree'
                        THEN 'primary_key_index_not_btree' END,
                   CASE WHEN NOT COALESCE(primary_index_unique, false) OR
                              NOT COALESCE(primary_index_valid AND primary_index_ready AND
                                primary_index_live AND primary_index_immediate, false)
                        THEN 'primary_key_index_not_valid_ready_unique' END,
                   CASE WHEN NOT COALESCE(primary_index_nattrs = 1 AND
                              primary_index_nkeyattrs = 1 AND
                              primary_index_key[0] = family_attnum, false)
                        THEN 'primary_key_index_columns_mismatch' END,
                   CASE WHEN NOT COALESCE(primary_index_collation[0] = (
                              SELECT oid FROM pg_catalog.pg_collation
                              WHERE collname = 'default'
                                AND collnamespace = 'pg_catalog'::pg_catalog.regnamespace
                            ), false)
                        THEN 'primary_key_index_collation_mismatch' END,
                   CASE WHEN NOT COALESCE(primary_index_default_opclass AND
                              (primary_index_opclass_type =
                                 '1043'::pg_catalog.regtype::pg_catalog.oid OR EXISTS (
                                SELECT 1 FROM pg_catalog.pg_cast
                                WHERE castsource = '1043'::pg_catalog.regtype::pg_catalog.oid
                                  AND casttarget = primary_index_opclass_type
                                  AND castcontext = 'i'
                              )), false)
                        THEN 'primary_key_index_operator_class_mismatch' END,
                   CASE WHEN NOT COALESCE(primary_index_options[0] = 0, false)
                        THEN 'primary_key_index_ordering_mismatch' END,
                   CASE WHEN primary_index_predicate IS NOT NULL
                              OR primary_index_expressions IS NOT NULL
                        THEN 'primary_key_index_expression_or_predicate' END,
                   CASE WHEN primary_index_nulls_not_distinct
                        THEN 'primary_key_index_nulls_not_distinct' END
                 ], NULL) AS failure_reasons
          FROM catalog
        )
        SELECT pg_catalog.cardinality(failure_reasons) = 0 AS ready_for_revocation_table,
               failure_reasons
        FROM failures
        \"\"\", [target_table], log: false)

      unless ready do
        raise "Cannot safely \#{operation} 3.0 migration: the canonical family-revocation " <>
                "table does not have the exact expected definition. Catalog failures: " <>
                inspect(failure_reasons)
      end
    end

    defp validate_revocation_backfill!(source_table, target_table) do
      %{rows: [[complete]]} =
        repo().query!(\"""
        SELECT NOT EXISTS (
          SELECT 1
          FROM \#{source_table} AS source
          WHERE source.family_revoked = true
            AND NOT EXISTS (
              SELECT 1
              FROM \#{target_table} AS target
              WHERE target.family_id = source.family_id
            )
        )
        \""", [], log: false)

      unless complete do
        raise "Cannot safely apply 3.0 migration: the durable family-revocation " <>
                "backfill did not preserve every revoked refresh-token family"
      end
    end

    def down do
      prefix = effective_prefix(<%= inspect @prefix %>)
      source_table = qualify_table("<%= @refresh_tokens %>", prefix)
      target_table = qualify_table("<%= @refresh_family_revocations %>", prefix)

      # These calls execute immediately inside Ecto's migration transaction;
      # queued execute/1 commands would run only after this callback returns.
      # Lock in runtime revocation order (tombstones, then refresh rows) so no
      # revocation or sweep can cross the guard-and-drop boundary.
      repo().query!("SET LOCAL lock_timeout = '5s'", [], log: false)
      repo().query!("SET LOCAL row_security = off", [], log: false)
      repo().query!("LOCK TABLE \#{target_table} IN ACCESS EXCLUSIVE MODE", [], log: false)
      repo().query!("LOCK TABLE \#{source_table} IN ACCESS EXCLUSIVE MODE", [], log: false)

      # A successful up/0 owns these exact canonical objects, but a later host
      # migration may have replaced or extended them. Revalidate under the
      # table locks before any destructive rollback operation.
      validate_generation_index!(
        source_table,
        qualify_table("attesto_refresh_tokens_family_id_generation_index", prefix),
        :rollback
      )

      validate_revocation_table!(target_table, :rollback)

      %{rows: unsafe_rows} =
        repo().query!(\"""
        SELECT 1
        FROM \#{target_table} t
        WHERE
          NOT EXISTS (
            SELECT 1
            FROM \#{source_table} r
            WHERE r.family_id = t.family_id
              AND r.family_revoked = true
          )
          OR EXISTS (
            SELECT 1
            FROM \#{source_table} r
            WHERE r.family_id = t.family_id
              AND r.family_revoked IS DISTINCT FROM true
          )
        LIMIT 1
        \""", [], log: false)

      if unsafe_rows != [] do
        raise "Cannot safely rollback 3.0 migration: a durable family revocation tombstone " <>
                "has no complete legacy representation. Every tombstoned family must retain " <>
                "at least one attesto_refresh_tokens row, and every remaining row in that " <>
                "family must have family_revoked = true. Rolling back would discard durable revocations " <>
                "and resurrect revoked refresh tokens on 2.x."
      end

      drop table(:<%= @refresh_family_revocations %>, prefix: prefix)

      drop index(
        :<%= @refresh_tokens %>,
        [:family_id, :generation],
        name: :attesto_refresh_tokens_family_id_generation_index,
        prefix: prefix
      )
    end

    defp effective_prefix(explicit_prefix) do
      cond do
        is_binary(explicit_prefix) and byte_size(explicit_prefix) > 0 ->
          explicit_prefix

        is_atom(explicit_prefix) and not is_nil(explicit_prefix) ->
          Atom.to_string(explicit_prefix)

        migrator_prefix = Ecto.Migration.prefix() ->
          to_string(migrator_prefix)

        repo_default = repo_migration_default_prefix() ->
          to_string(repo_default)

        true ->
          nil
      end
    end

    defp repo_migration_default_prefix do
      case Ecto.Migration.repo() do
        repo when is_atom(repo) and not is_nil(repo) ->
          repo.config()[:migration_default_prefix]

        _ ->
          nil
      end
    end

    defp qualify_table(table, nil), do: quote_identifier(table)
    defp qualify_table(table, ""), do: quote_identifier(table)
    defp qualify_table(table, prefix), do: quote_identifier(prefix) <> "." <> quote_identifier(table)

    defp quote_identifier(identifier) do
      "\\"" <> String.replace(to_string(identifier), "\\"", "\\"\\"") <> "\\""
    end
  end
  """)

  embed_template(:authorization_code_upgrade_migration, """
  defmodule <%= inspect @module %> do
    @moduledoc false

    # This migration promotes the historical unique index on
    # attesto_authorization_codes(code_hash) to the primary key expected by
    # current AttestoPhoenix schemas. It is for an existing 2.x database and
    # runs after the --upgrade 3.0 migration.
    #
    # This migration owns the canonical attesto_authorization_codes_pkey layout
    # after it succeeds: an exact historical index is adopted and a later
    # rollback recreates that historical unique index. It validates the table,
    # column, index, collation, operator class, ordering, and primary-key
    # catalog definitions before changing anything. A renamed, custom,
    # malformed, or otherwise ambiguous layout fails inside the migration
    # transaction and needs a reviewed host-specific migration. Fresh
    # migrations already create the primary key and must not run this migration.

    # Generated by `mix attesto_phoenix.gen.migration --upgrade 3.1`.
    use Ecto.Migration

    def up do
      prefix = effective_prefix(<%= inspect @prefix %>)
      table = qualify_table("<%= @authorization_codes %>", prefix)
      index = qualify_table("<%= @authorization_code_hash_index %>", prefix)

      repo().query!("SET LOCAL lock_timeout = '5s'", [], log: false)
      repo().query!("LOCK TABLE \#{table} IN ACCESS EXCLUSIVE MODE", [], log: false)

      case authorization_code_state(table, index) do
        :promoted ->
          :ok

        :historical ->
          # PostgreSQL reuses and renames the existing unique index; it does
          # not rebuild the table or index. The table lock is still ACCESS
          # EXCLUSIVE, so run this migration in a controlled window.
          repo().query!(
            "ALTER TABLE \#{table} ADD CONSTRAINT attesto_authorization_codes_pkey " <>
              "PRIMARY KEY USING INDEX \#{quote_identifier(\"<%= @authorization_code_hash_index %>\")}",
            [],
            log: false
          )

        {:invalid, failure_reasons} ->
          raise "Cannot safely apply 3.1 migration: attesto_authorization_codes " <>
                  "does not have the exact historical or already-promoted layout. " <>
                  "Catalog failures: \#{inspect(failure_reasons)}." <>
                  authorization_code_remediation(failure_reasons)
      end
    end

    def down do
      prefix = effective_prefix(<%= inspect @prefix %>)
      table = qualify_table("<%= @authorization_codes %>", prefix)
      index = qualify_table("<%= @authorization_code_hash_index %>", prefix)

      repo().query!("SET LOCAL lock_timeout = '5s'", [], log: false)
      repo().query!("LOCK TABLE \#{table} IN ACCESS EXCLUSIVE MODE", [], log: false)

      case authorization_code_state(table, index) do
        # A migration generated against an already-promoted database has no
        # historical index to undo. Treat a manually reverted state as a
        # no-op, while still refusing a custom or ambiguous definition.
        :historical ->
          :ok

        :promoted ->
          %{rows: [[restore_replica_identity]]} =
            repo().query!(
              \"\"\"
              SELECT EXISTS (
                SELECT 1
                FROM pg_catalog.pg_constraint AS primary_constraint
                JOIN pg_catalog.pg_index AS primary_index
                  ON primary_index.indexrelid = primary_constraint.conindid
                WHERE primary_constraint.conrelid = pg_catalog.to_regclass($1)
                  AND primary_constraint.contype = 'p'
                  AND primary_constraint.conname = 'attesto_authorization_codes_pkey'
                  AND primary_index.indisreplident
              )
              \"\"\",
              [table],
              log: false
            )

          # Dropping the primary key also drops its index. If that index is
          # currently selected for REPLICA IDENTITY, temporarily switch to the
          # default and restore INDEX after rebuilding the historical unique
          # index. FULL and DEFAULT are left untouched.
          if restore_replica_identity do
            repo().query!(
              "ALTER TABLE \#{table} REPLICA IDENTITY DEFAULT",
              [],
              log: false
            )
          end

          repo().query!(
            "ALTER TABLE \#{table} DROP CONSTRAINT attesto_authorization_codes_pkey",
            [],
            log: false
          )

          create unique_index(
            :<%= @authorization_codes %>,
            [:code_hash],
            name: :<%= @authorization_code_hash_index %>,
            prefix: prefix
          )
          flush()

          if restore_replica_identity do
            repo().query!(
              "ALTER TABLE \#{table} REPLICA IDENTITY USING INDEX \#{quote_identifier(\"<%= @authorization_code_hash_index %>\")}",
              [],
              log: false
            )
          end

        {:invalid, failure_reasons} ->
          raise "Cannot safely rollback 3.1 migration: attesto_authorization_codes " <>
                  "does not have the exact promoted layout. Catalog failures: " <>
                  "\#{inspect(failure_reasons)}." <>
                  authorization_code_remediation(failure_reasons)
      end
    end

    defp authorization_code_remediation(failure_reasons) do
      if "historical_index_coexists_with_primary_key" in failure_reasons do
        " Confirm the primary key is the live constraint and drop the leftover " <>
          "attesto_authorization_codes_code_hash_index, then rerun."
      else
        ""
      end
    end

    # Returns :historical for the exact generated 2.x layout, :promoted for the
    # exact current primary-key layout, and a failure list for every other
    # catalog definition. The JSON access keeps this query executable on
    # PostgreSQL versions before 15, where pg_index gained indnullsnotdistinct.
    defp authorization_code_state(table, index) do
      %{rows: [[state, failure_reasons]]} =
        repo().query!(\"\"\"
        WITH target AS (
          SELECT pg_catalog.to_regclass($1)::pg_catalog.oid AS table_oid,
                 pg_catalog.to_regclass($2)::pg_catalog.oid AS index_oid
        ), attrs AS (
          SELECT target.*,
                 table_rel.relkind AS table_kind,
                 code_hash.attnum AS code_hash_attnum,
                 code_hash.atttypid AS code_hash_type,
                 code_hash.atttypmod AS code_hash_typmod,
                 code_hash.attnotnull AS code_hash_not_null,
                 code_hash.attcollation AS code_hash_collation,
                 code_hash.atthasdef AS code_hash_has_default,
                 code_hash.attidentity AS code_hash_identity,
                 code_hash.attgenerated AS code_hash_generated,
                 table_rel.relpersistence AS table_persistence,
                 table_rel.relispartition AS table_is_partition,
                 EXISTS (
                   SELECT 1
                   FROM pg_catalog.pg_inherits AS inheritance
                   WHERE inheritance.inhrelid = target.table_oid
                      OR inheritance.inhparent = target.table_oid
                 ) AS table_has_inheritance,
                 default_collation.oid AS database_default_collation
          FROM target
          LEFT JOIN pg_catalog.pg_class AS table_rel ON table_rel.oid = target.table_oid
          LEFT JOIN pg_catalog.pg_attribute AS code_hash
            ON code_hash.attrelid = target.table_oid
           AND code_hash.attname = 'code_hash'
           AND code_hash.attnum > 0
           AND NOT code_hash.attisdropped
          LEFT JOIN pg_catalog.pg_collation AS default_collation
            ON default_collation.collnamespace = 'pg_catalog'::pg_catalog.regnamespace
           AND default_collation.collname = 'default'
        ), primary_key AS (
          SELECT attrs.*,
                 pg_catalog.count(constraint_info.oid) FILTER (WHERE constraint_info.contype = 'p')
                   AS primary_key_count,
                 pg_catalog.max(constraint_info.conname) FILTER (WHERE constraint_info.contype = 'p')
                   AS primary_key_name,
                 COALESCE(pg_catalog.bool_or(
                   constraint_info.contype = 'p' AND
                     NOT constraint_info.condeferrable AND
                     NOT constraint_info.condeferred AND
                     constraint_info.convalidated
                 ), false) AS primary_key_contract_exact,
                 pg_catalog.bool_or(
                   constraint_info.contype = 'p' AND
                     constraint_info.conkey::pg_catalog.int2[] =
                       ARRAY[attrs.code_hash_attnum]::pg_catalog.int2[]
                 ) AS primary_key_columns_exact
          FROM attrs
          LEFT JOIN pg_catalog.pg_constraint AS constraint_info
            ON constraint_info.conrelid = attrs.table_oid
          GROUP BY attrs.table_oid, attrs.index_oid, attrs.table_kind,
                   attrs.code_hash_attnum, attrs.code_hash_type,
                   attrs.code_hash_typmod, attrs.code_hash_not_null,
                   attrs.code_hash_collation, attrs.code_hash_has_default,
                   attrs.code_hash_identity, attrs.code_hash_generated,
                   attrs.table_persistence, attrs.table_is_partition,
                   attrs.table_has_inheritance, attrs.database_default_collation
        ), catalog AS (
          SELECT primary_key.*,
                 index_rel.relkind AS index_kind,
                 access_method.amname,
                 index_info.indisunique,
                 index_info.indisvalid,
                 index_info.indisready,
                 index_info.indislive,
                 index_info.indisreplident,
                 index_info.indimmediate,
                 index_info.indnatts,
                 index_info.indnkeyatts,
                 index_info.indkey,
                 index_info.indcollation,
                 index_info.indclass,
                 index_info.indoption,
                 index_info.indpred,
                 index_info.indexprs,
                 COALESCE(
                   (pg_catalog.to_jsonb(index_info) ->> 'indnullsnotdistinct')::pg_catalog.bool,
                   false
                 )
                   AS nulls_not_distinct,
                 EXISTS (
                   SELECT 1 FROM pg_catalog.pg_constraint AS index_constraint
                   WHERE index_constraint.conindid = primary_key.index_oid
                 ) AS index_constraint_backed,
                 EXISTS (
                   SELECT 1
                   FROM pg_catalog.pg_constraint AS primary_constraint
                   JOIN pg_catalog.pg_index AS primary_index
                     ON primary_index.indexrelid = primary_constraint.conindid
                    AND primary_index.indrelid = primary_key.table_oid
                   JOIN pg_catalog.pg_class AS primary_index_rel
                     ON primary_index_rel.oid = primary_index.indexrelid
                   JOIN pg_catalog.pg_am AS primary_access_method
                     ON primary_access_method.oid = primary_index_rel.relam
                   WHERE primary_constraint.conrelid = primary_key.table_oid
                     AND primary_constraint.contype = 'p'
                     AND primary_constraint.conname = 'attesto_authorization_codes_pkey'
                     AND primary_constraint.conkey::pg_catalog.int2[] =
                       ARRAY[primary_key.code_hash_attnum]::pg_catalog.int2[]
                     AND primary_index.indisunique
                     AND primary_index.indisvalid
                     AND primary_index.indisready
                     AND primary_index.indislive
                     AND primary_index.indimmediate
                     AND primary_index.indnatts = 1
                     AND primary_index.indnkeyatts = 1
                     AND primary_index.indkey[0] = primary_key.code_hash_attnum
                     AND primary_access_method.amname = 'btree'
                     AND primary_index.indcollation[0] = primary_key.database_default_collation
                     AND NOT COALESCE(
                       (pg_catalog.to_jsonb(primary_index) ->>
                         'indnullsnotdistinct')::pg_catalog.bool,
                       false
                     )
                     AND primary_index.indoption[0] = 0
                     AND primary_index.indpred IS NULL
                     AND primary_index.indexprs IS NULL
                     AND (SELECT opcdefault
                          FROM pg_catalog.pg_opclass
                          WHERE oid = primary_index.indclass[0])
                     AND (SELECT opcintype = primary_key.code_hash_type OR EXISTS (
                       SELECT 1 FROM pg_catalog.pg_cast
                       WHERE castsource = primary_key.code_hash_type
                         AND casttarget = opcintype
                         AND castcontext = 'i'
                     ) FROM pg_catalog.pg_opclass WHERE oid = primary_index.indclass[0])
                 ) AS primary_index_exact
          FROM primary_key
          LEFT JOIN pg_catalog.pg_class AS index_rel ON index_rel.oid = primary_key.index_oid
          LEFT JOIN pg_catalog.pg_index AS index_info
            ON index_info.indexrelid = primary_key.index_oid
           AND index_info.indrelid = primary_key.table_oid
          LEFT JOIN pg_catalog.pg_am AS access_method ON access_method.oid = index_rel.relam
        ), checks AS (
          SELECT table_oid IS NOT NULL AS table_exists,
                 index_oid IS NOT NULL AS index_exists,
                 table_kind = 'r' AS ordinary_table,
                 table_persistence = 'p' AS permanent_table,
                 NOT COALESCE(table_is_partition, false) AND NOT table_has_inheritance
                   AS standalone_table,
                 code_hash_attnum IS NOT NULL AS code_hash_exists,
                 code_hash_type = '1043'::pg_catalog.regtype::pg_catalog.oid AND
                   code_hash_typmod = <%= @authorization_code_hash_typmod %>
                   AS code_hash_definition,
                 COALESCE(code_hash_not_null, false) AS code_hash_not_null,
                 NOT COALESCE(code_hash_has_default, false) AS code_hash_without_default,
                 COALESCE(code_hash_identity = '', false) AS code_hash_not_identity,
                 COALESCE(code_hash_generated = '', false) AS code_hash_not_generated,
                 COALESCE(
                   code_hash_collation = database_default_collation,
                   false
                 ) AS code_hash_default_collation,
                 index_kind = 'i' AND amname = 'btree' AS btree_index,
                 COALESCE(indisunique, false) AS unique_index,
                 COALESCE(indisvalid AND indisready AND indislive AND indimmediate, false)
                   AS index_valid_ready_live,
                 COALESCE(indnatts = 1 AND indnkeyatts = 1 AND indkey[0] = code_hash_attnum, false)
                   AS exact_index_columns,
                 COALESCE(indcollation[0] = database_default_collation, false)
                   AS index_default_collation,
                 NOT nulls_not_distinct AS default_null_treatment,
                 COALESCE(
                   (SELECT opcdefault FROM pg_catalog.pg_opclass WHERE oid = indclass[0]) AND
                   (SELECT opcintype = code_hash_type OR EXISTS (
                     SELECT 1 FROM pg_catalog.pg_cast
                     WHERE castsource = code_hash_type
                       AND casttarget = opcintype
                       AND castcontext = 'i'
                   ) FROM pg_catalog.pg_opclass WHERE oid = indclass[0]),
                   false
                 ) AS default_operator_class,
                 COALESCE(indoption[0] = 0, false) AS default_ordering,
                 indpred IS NULL AS no_predicate,
                 indexprs IS NULL AS no_expressions,
                 NOT index_constraint_backed AS not_constraint_backed,
                 primary_key_count,
                 primary_key_name,
                 primary_key_contract_exact,
                 primary_key_columns_exact,
                 code_hash_attnum,
                 primary_index_exact
          FROM catalog
        ), classified_keys AS (
          SELECT *,
                 primary_key_count = 1 AND
                   primary_key_name = 'attesto_authorization_codes_pkey' AND
                   primary_key_contract_exact AND
                   COALESCE(primary_key_columns_exact, false) AND
                   table_exists AND ordinary_table AND permanent_table AND standalone_table AND
                   code_hash_exists AND
                   code_hash_definition AND code_hash_not_null AND
                   code_hash_without_default AND code_hash_not_identity AND
                   code_hash_not_generated AND code_hash_default_collation AND primary_index_exact
                   AS primary_key_exact
          FROM checks
        ), classified AS (
          SELECT *,
                 primary_key_exact AND NOT index_exists
                   AS exact_primary_key,
                 index_exists AND table_exists AND ordinary_table AND permanent_table AND
                   standalone_table AND code_hash_exists AND
                   code_hash_definition AND code_hash_not_null AND btree_index AND
                   code_hash_without_default AND code_hash_not_identity AND
                   code_hash_not_generated AND
                   unique_index AND index_valid_ready_live AND exact_index_columns AND
                   index_default_collation AND code_hash_default_collation AND
                   default_null_treatment AND default_operator_class AND
                   default_ordering AND no_predicate AND no_expressions AND
                   not_constraint_backed AND primary_key_count = 0
                   AS exact_historical_index
          FROM classified_keys
        ), failures AS (
          SELECT classified.*,
                 pg_catalog.array_remove(ARRAY[
                   CASE WHEN NOT table_exists THEN 'table_missing' END,
                   CASE WHEN NOT ordinary_table THEN 'table_not_ordinary' END,
                   CASE WHEN NOT permanent_table THEN 'table_not_permanent' END,
                   CASE WHEN NOT standalone_table THEN 'table_partitioned_or_inherited' END,
                   CASE WHEN NOT code_hash_exists THEN 'code_hash_missing' END,
                   CASE WHEN NOT code_hash_definition THEN 'code_hash_definition_mismatch' END,
                   CASE WHEN NOT code_hash_not_null THEN 'code_hash_nullable' END,
                   CASE WHEN NOT code_hash_without_default THEN 'code_hash_has_default' END,
                   CASE WHEN NOT code_hash_not_identity THEN 'code_hash_is_identity' END,
                   CASE WHEN NOT code_hash_not_generated THEN 'code_hash_is_generated' END,
                   CASE WHEN NOT code_hash_default_collation THEN 'code_hash_non_default_collation' END,
                   CASE WHEN NOT index_exists AND NOT exact_primary_key THEN 'index_missing' END,
                   CASE WHEN NOT btree_index AND NOT exact_primary_key THEN 'index_not_btree' END,
                   CASE WHEN NOT unique_index AND NOT exact_primary_key THEN 'index_not_unique' END,
                   CASE WHEN NOT index_valid_ready_live AND NOT exact_primary_key THEN 'index_invalid_not_ready_or_not_live' END,
                   CASE WHEN NOT exact_index_columns AND NOT exact_primary_key THEN 'index_columns_or_include_columns_mismatch' END,
                   CASE WHEN NOT index_default_collation AND NOT exact_primary_key THEN 'index_non_default_collation' END,
                   CASE WHEN NOT default_null_treatment AND NOT exact_primary_key THEN 'index_nulls_not_distinct' END,
                   CASE WHEN NOT default_operator_class AND NOT exact_primary_key THEN 'index_non_default_operator_class' END,
                   CASE WHEN NOT default_ordering AND NOT exact_primary_key THEN 'index_non_default_ordering' END,
                   CASE WHEN NOT no_predicate AND NOT exact_primary_key THEN 'partial_index' END,
                   CASE WHEN NOT no_expressions AND NOT exact_primary_key THEN 'expression_index' END,
                   CASE WHEN NOT not_constraint_backed AND NOT exact_primary_key THEN 'index_backs_constraint' END,
                   CASE WHEN primary_key_exact AND index_exists THEN 'historical_index_coexists_with_primary_key' END,
                   CASE WHEN primary_key_count <> 0 AND NOT primary_key_exact
                        THEN 'primary_key_definition_mismatch' END
                 ], NULL) AS failure_reasons
          FROM classified
        )
        SELECT CASE
                 WHEN exact_primary_key THEN 'promoted'
                 WHEN exact_historical_index THEN 'historical'
                 ELSE 'invalid'
               END AS state,
               failure_reasons
        FROM failures
        \"\"\", [table, index], log: false)

      case state do
        "promoted" -> :promoted
        "historical" -> :historical
        _ -> {:invalid, failure_reasons}
      end
    end

    defp effective_prefix(explicit_prefix) do
      cond do
        is_binary(explicit_prefix) and byte_size(explicit_prefix) > 0 ->
          explicit_prefix

        is_atom(explicit_prefix) and not is_nil(explicit_prefix) ->
          Atom.to_string(explicit_prefix)

        migrator_prefix = Ecto.Migration.prefix() ->
          to_string(migrator_prefix)

        repo_default = repo_migration_default_prefix() ->
          to_string(repo_default)

        true ->
          nil
      end
    end

    defp repo_migration_default_prefix do
      case Ecto.Migration.repo() do
        repo when is_atom(repo) and not is_nil(repo) ->
          repo.config()[:migration_default_prefix]

        _ ->
          nil
      end
    end

    defp qualify_table(table, nil), do: quote_identifier(table)
    defp qualify_table(table, ""), do: quote_identifier(table)
    defp qualify_table(table, prefix), do: quote_identifier(prefix) <> "." <> quote_identifier(table)

    defp quote_identifier(identifier) do
      "\\\"" <> String.replace(to_string(identifier), "\\\"", "\\\"\\\"") <> "\\\""
    end
  end
  """)
end
