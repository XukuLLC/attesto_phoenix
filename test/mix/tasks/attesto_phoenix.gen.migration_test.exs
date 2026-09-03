defmodule Mix.Tasks.AttestoPhoenix.Gen.MigrationTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias AttestoPhoenix.AppEnvSnapshot
  alias AttestoPhoenix.Config
  alias Mix.Tasks.AttestoPhoenix.Gen.Migration
  alias Mix.Tasks.Format

  @moduletag :tmp_dir

  # A throwaway Ecto repo module so the task can resolve a repo from --repo
  # without standing up a real database connection. The migration path is always
  # given explicitly via --migrations-path in these tests, so config/0 only has
  # to satisfy Mix.Ecto.ensure_repo/2.
  defmodule TestRepo do
    def __adapter__, do: Ecto.Adapters.Postgres

    def config do
      Keyword.merge([otp_app: :attesto_phoenix], Application.get_env(:attesto_phoenix, __MODULE__, []))
    end
  end

  defp migrations_dir(tmp_dir), do: Path.join(tmp_dir, "migrations")

  defp migration_version(file) do
    file
    |> Path.basename()
    |> String.split("_", parts: 2)
    |> hd()
  end

  defp run!(args, tmp_dir) do
    # inspect/1 renders the module without the "Elixir." prefix, which is the
    # spelling Mix.Ecto.parse_repo/1 expects for --repo.
    Migration.run(["--repo", inspect(TestRepo), "--migrations-path", migrations_dir(tmp_dir)] ++ args)
  end

  defp generated_migration(tmp_dir) do
    files =
      Path.wildcard(Path.join(migrations_dir(tmp_dir), "*_create_attesto_phoenix_tables.exs"))

    assert [file] = files
    File.read!(file)
  end

  describe "run/1" do
    setup do
      AppEnvSnapshot.ensure_unset!([
        {:attesto_phoenix, :otp_app},
        {:attesto_phoenix, AttestoPhoenix.Config},
        {:attesto_phoenix, :table_prefix}
      ])

      :ok
    end

    test "generates a migration creating all bundled tables", %{tmp_dir: tmp_dir} do
      run!([], tmp_dir)
      source = generated_migration(tmp_dir)

      # Table names MUST match the runtime schemas' table names exactly, or a
      # by-the-docs deploy installs tables the stores cannot use:
      #   * AttestoPhoenix.Schema.Authorization               -> attesto_authorization_codes
      #   * AttestoPhoenix.Schema.RefreshToken                -> attesto_refresh_tokens
      #   * AttestoPhoenix.Schema.RefreshFamilyRevocation    -> attesto_refresh_family_revocations
      #   * AttestoPhoenix.Schema.DeviceCode                  -> attesto_device_codes
      #   * AttestoPhoenix.Schema.CIBARequest                 -> attesto_ciba_requests
      #   * AttestoPhoenix.Schema.LogoutSession               -> attesto_logout_sessions
      #   * AttestoPhoenix.Schema.DPoPNonce                   -> dpop_nonces
      #   * AttestoPhoenix.Schema.DPoPReplay                  -> dpop_replays
      #   * AttestoPhoenix.Schema.PushedAuthorizationRequest  -> attesto_pushed_authorization_requests
      #   * AttestoPhoenix.Schema.ClientIdMetadata            -> attesto_client_id_metadata
      #   * AttestoPhoenix.Schema.ConsentGrant                -> attesto_consent_grants
      assert source =~ ~s|use Ecto.Migration|
      assert source =~ ~s|create table(:attesto_authorization_codes|
      assert source =~ ~s|create table(:attesto_refresh_tokens|
      assert source =~ ~s|create table(:attesto_refresh_family_revocations|
      assert source =~ ~s|create table(:attesto_device_codes|
      assert source =~ ~s|create table(:attesto_ciba_requests|
      assert source =~ ~s|create table(:attesto_logout_sessions|
      assert source =~ ~s|create table(:dpop_nonces|
      assert source =~ ~s|create table(:dpop_replays|
      assert source =~ ~s|create table(:attesto_pushed_authorization_requests|
      assert source =~ ~s|create table(:attesto_client_id_metadata|
      assert source =~ ~s|create table(:attesto_consent_grants|
    end

    test "client_id_metadata keys on url as PK with a jsonb metadata column", %{tmp_dir: tmp_dir} do
      run!([], tmp_dir)
      source = generated_migration(tmp_dir)

      # ClientIdMetadata declares @primary_key {:url, :string}, so url is the
      # PRIMARY KEY; metadata is jsonb (:map); expires_at is indexed for sweeps.
      assert source =~ ~s|add :url, :string, size: 255, primary_key: true, null: false|
      assert source =~ ~s|add :metadata, :map, null: false|

      assert source =~
               ~s|create index(:attesto_client_id_metadata, [:expires_at], prefix: prefix)|
    end

    test "pushed_authorization_requests keys on request_uri as PK with a jsonb params column", %{
      tmp_dir: tmp_dir
    } do
      run!([], tmp_dir)
      source = generated_migration(tmp_dir)

      # PushedAuthorizationRequest declares @primary_key {:request_uri, :string},
      # so request_uri is the PRIMARY KEY; params is jsonb (:map); expires_at is
      # indexed for sweeps.
      assert source =~ ~s|add :request_uri, :string, size: 255, primary_key: true, null: false|
      assert source =~ ~s|add :params, :map, null: false|

      assert source =~
               ~s|create index(:attesto_pushed_authorization_requests, [:expires_at], prefix: prefix)|
    end

    test "creates the unique constraints the schemas name", %{tmp_dir: tmp_dir} do
      run!([], tmp_dir)
      source = generated_migration(tmp_dir)

      # Each unique index's Postgres default name (<table>_<col>_index) must be
      # the name the schema's unique_constraint relies on:
      #   * RefreshToken:  attesto_refresh_tokens_token_hash_index
      #   * DPoPNonce:     dpop_nonces_nonce_index (Ecto default)
      assert source =~
               ~s|create unique_index(:attesto_refresh_tokens, [:token_hash], prefix: prefix)|

      assert source =~ ~s|create unique_index(:dpop_nonces, [:nonce], prefix: prefix)|

      assert source =~
               "name: :attesto_refresh_tokens_family_id_generation_index"
    end

    test "keys dpop_replays on jti so the conflict is dpop_replays_pkey", %{tmp_dir: tmp_dir} do
      run!([], tmp_dir)
      source = generated_migration(tmp_dir)

      # DPoPReplay declares @primary_key {:jti, ...} and
      # unique_constraint(:jti, name: :dpop_replays_pkey). jti must therefore be
      # the table's PRIMARY KEY (its constraint name is then dpop_replays_pkey),
      # not a separate unique index, so INSERT ... ON CONFLICT DO NOTHING fires
      # on the primary key.
      assert source =~ ~s|add :jti, :string, size: 255, primary_key: true, null: false|
      refute source =~ ~s|create unique_index(:dpop_replays, [:jti])|
      assert source =~ ~s|add :inserted_at, :utc_datetime_usec, null: false|
    end

    test "keys authorization_codes on code_hash so the conflict is attesto_authorization_codes_pkey",
         %{tmp_dir: tmp_dir} do
      run!([], tmp_dir)
      source = generated_migration(tmp_dir)

      # Authorization declares @primary_key {:code_hash, ...} and
      # unique_constraint(:code_hash, name: :attesto_authorization_codes_pkey).
      # code_hash must therefore be the table's PRIMARY KEY, not a separate
      # unique index. Under REPLICA IDENTITY DEFAULT, a table without a primary
      # key has no usable identity index, so its UPDATE/DELETE paths fail when
      # they are included in a logical-replication publication.
      assert source =~ ~s|add :code_hash, :string, size: 88, primary_key: true, null: false|
      refute source =~ ~s|create unique_index(:attesto_authorization_codes, [:code_hash]|
    end

    test "authorization_codes carries the columns the store reads/writes", %{tmp_dir: tmp_dir} do
      run!([], tmp_dir)
      source = generated_migration(tmp_dir)

      # The drifted columns that broke a by-the-docs deploy: PKCE method, DPoP
      # cnf, mapped claims, OIDC nonce, and the single-use marker.
      assert source =~ ~s|add :code_hash, :string, size: 88, primary_key: true, null: false|
      assert source =~ ~s|add :code_challenge, :string, size: 255|
      assert source =~ ~s|add :code_challenge_method, :string, size: 16|
      refute source =~ ~s|add :code_challenge, :string, size: 255, null: false|
      refute source =~ ~s|add :code_challenge_method, :string, size: 16, null: false|
      assert source =~ ~s|add :cnf, :map|
      assert source =~ ~s|add :claims, :map, null: false, default: %{}|
      assert source =~ ~s|add :consumed_at, :utc_datetime|
      # The schema keys on code_hash (no surrogate id): the table is created
      # primary_key: false so that code_hash itself is the primary key.
      assert source =~
               ~s|create table(:attesto_authorization_codes, primary_key: false, prefix: prefix) do|
    end

    test "refresh_tokens carries the rotation/reuse columns", %{tmp_dir: tmp_dir} do
      run!([], tmp_dir)
      source = generated_migration(tmp_dir)

      assert source =~ ~s|add :token_hash, :string, size: 88, null: false|
      assert source =~ ~s|add :family_id, :string, size: 255, null: false|
      assert source =~ ~s|add :generation, :integer, null: false, default: 0|
      assert source =~ ~s|add :consumed, :boolean, null: false, default: false|
      assert source =~ ~s|add :consumed_at, :utc_datetime|
      assert source =~ ~s|add :successor, :map|
      assert source =~ ~s|add :family_revoked, :boolean, null: false, default: false|
      assert source =~ ~s|add :parent_hash, :string, size: 88|
      assert source =~ ~s|create index(:attesto_refresh_tokens, [:family_id], prefix: prefix)|
    end

    test "dpop_nonces carries issued_at/used_at", %{tmp_dir: tmp_dir} do
      run!([], tmp_dir)
      source = generated_migration(tmp_dir)

      assert source =~ ~s|add :issued_at, :utc_datetime, null: false|
      assert source =~ ~s|add :used_at, :utc_datetime|
    end

    test "creates expires_at indexes on the ttl tables", %{tmp_dir: tmp_dir} do
      run!([], tmp_dir)
      source = generated_migration(tmp_dir)

      assert source =~
               ~s|create index(:attesto_authorization_codes, [:expires_at], prefix: prefix)|

      assert source =~ ~s|create index(:attesto_refresh_tokens, [:expires_at], prefix: prefix)|
      assert source =~ ~s|create index(:dpop_replays, [:expires_at], prefix: prefix)|
    end

    test "is reversible", %{tmp_dir: tmp_dir} do
      run!([], tmp_dir)
      source = generated_migration(tmp_dir)

      assert source =~ ~s|def up do|
      assert source =~ ~s|def down do|
      # down drops every table the up created.
      for table <-
            ~w(
              attesto_authorization_codes
              attesto_refresh_tokens
              attesto_refresh_family_revocations
              attesto_device_codes
              attesto_ciba_requests
              attesto_logout_sessions
              dpop_nonces
              dpop_replays
              attesto_pushed_authorization_requests
              attesto_client_id_metadata
              attesto_consent_grants
            ) do
        assert source =~ ~s|drop table(:#{table}, prefix: prefix)|
      end
    end

    test "applies an explicit --schema-prefix to every table", %{tmp_dir: tmp_dir} do
      run!(["--schema-prefix", "oauth_"], tmp_dir)
      source = generated_migration(tmp_dir)

      assert source =~ ~s|prefix = "oauth_"|

      assert source =~
               ~s|create table(:attesto_authorization_codes, primary_key: false, prefix: prefix)|

      assert source =~
               ~s|create table(:attesto_refresh_tokens, primary_key: false, prefix: prefix)|

      assert source =~ ~s|create table(:dpop_nonces, primary_key: false, prefix: prefix)|
      assert source =~ ~s|create table(:dpop_replays, primary_key: false, prefix: prefix)|

      assert source =~ ~s|add :code_hash, :string, size: 88, primary_key: true, null: false|

      assert source =~ "name: :attesto_refresh_tokens_family_id_generation_index"
      assert source =~ "prefix: prefix"

      refute source =~ "oauth_attesto_authorization_codes"
    end

    test "reads a prebuilt Config struct from the selected otp_app", %{tmp_dir: tmp_dir} do
      host_app = :attesto_phoenix_generator_config_test
      previous = Application.get_env(host_app, Config, :missing)
      Application.put_env(host_app, Config, struct(Config, schema_prefix: "tenant_schema"))

      on_exit(fn ->
        case previous do
          :missing -> Application.delete_env(host_app, Config)
          value -> Application.put_env(host_app, Config, value)
        end
      end)

      run!(["--otp-app", Atom.to_string(host_app)], tmp_dir)
      source = generated_migration(tmp_dir)

      assert source =~ ~s|prefix = "tenant_schema"|

      assert source =~
               ~s|create table(:attesto_authorization_codes, primary_key: false, prefix: prefix)|
    end

    test "reads the configured otp_app when --otp-app is omitted", %{tmp_dir: tmp_dir} do
      host_app = :attesto_phoenix_generator_no_flag_config_test
      previous_pointer = Application.get_env(:attesto_phoenix, :otp_app, :missing)
      previous_config = Application.get_env(host_app, Config, :missing)

      Application.put_env(:attesto_phoenix, :otp_app, host_app)
      Application.put_env(host_app, Config, schema_prefix: "tenant_schema")

      on_exit(fn ->
        case previous_pointer do
          :missing -> Application.delete_env(:attesto_phoenix, :otp_app)
          value -> Application.put_env(:attesto_phoenix, :otp_app, value)
        end

        case previous_config do
          :missing -> Application.delete_env(host_app, Config)
          value -> Application.put_env(host_app, Config, value)
        end
      end)

      run!([], tmp_dir)
      source = generated_migration(tmp_dir)

      assert source =~ ~s|prefix = "tenant_schema"|
    end

    test "rejects an empty explicit schema prefix", %{tmp_dir: tmp_dir} do
      assert_raise Mix.Error, ~r/invalid --schema-prefix.*non-empty/, fn ->
        run!(["--schema-prefix", ""], tmp_dir)
      end

      assert Path.wildcard(Path.join(migrations_dir(tmp_dir), "*.exs")) == []
    end

    test "rejects an empty configured schema prefix", %{tmp_dir: tmp_dir} do
      host_app = :attesto_phoenix_generator_empty_prefix_test
      previous = Application.get_env(host_app, Config, :missing)
      Application.put_env(host_app, Config, schema_prefix: "")

      on_exit(fn ->
        case previous do
          :missing -> Application.delete_env(host_app, Config)
          value -> Application.put_env(host_app, Config, value)
        end
      end)

      assert_raise Mix.Error, ~r/invalid --schema-prefix.*non-empty/, fn ->
        run!(["--otp-app", Atom.to_string(host_app)], tmp_dir)
      end

      assert Path.wildcard(Path.join(migrations_dir(tmp_dir), "*.exs")) == []
    end

    test "rejects a schema prefix over PostgreSQL's 63-byte bound", %{tmp_dir: tmp_dir} do
      assert_raise Mix.Error, ~r/at most 63 bytes/, fn ->
        run!(["--schema-prefix", String.duplicate("a", 64)], tmp_dir)
      end

      assert Path.wildcard(Path.join(migrations_dir(tmp_dir), "*.exs")) == []
    end

    test "rejects an invalid schema prefix (fail closed)", %{tmp_dir: tmp_dir} do
      assert_raise Mix.Error, ~r/invalid --schema-prefix/, fn ->
        run!(["--schema-prefix", "bad-prefix;"], tmp_dir)
      end

      assert Path.wildcard(Path.join(migrations_dir(tmp_dir), "*.exs")) == []
    end

    test "rejects PostgreSQL system schemas", %{tmp_dir: tmp_dir} do
      for prefix <- ["pg_catalog", "information_schema"] do
        assert_raise Mix.Error, ~r/reserved PostgreSQL system schema/, fn ->
          run!(["--schema-prefix", prefix], tmp_dir)
        end
      end

      assert Path.wildcard(Path.join(migrations_dir(tmp_dir), "*.exs")) == []
    end

    test "rejects string-key configured prefix maps", %{tmp_dir: tmp_dir} do
      host_app = :attesto_phoenix_generator_string_prefix_test
      previous = Application.get_env(host_app, Config, :missing)
      Application.put_env(host_app, Config, %{"schema_prefix" => "tenant_schema"})

      on_exit(fn ->
        case previous do
          :missing -> Application.delete_env(host_app, Config)
          value -> Application.put_env(host_app, Config, value)
        end
      end)

      assert_raise Mix.Error, ~r/string key "schema_prefix".*atom key :schema_prefix/, fn ->
        run!(["--otp-app", Atom.to_string(host_app)], tmp_dir)
      end

      assert Path.wildcard(Path.join(migrations_dir(tmp_dir), "*.exs")) == []
    end

    test "rejects the removed 2.x table-prefix flag", %{tmp_dir: tmp_dir} do
      assert_raise Mix.Error, ~r/--table-prefix was removed.*one runtime layout.*--schema-prefix/, fn ->
        run!(["--table-prefix", "oauth_"], tmp_dir)
      end

      assert Path.wildcard(Path.join(migrations_dir(tmp_dir), "*.exs")) == []
    end

    test "rejects a legacy configured table prefix", %{tmp_dir: tmp_dir} do
      host_app = :attesto_phoenix_generator_legacy_prefix_test
      previous = Application.get_env(host_app, Config, :missing)
      Application.put_env(host_app, Config, table_prefix: "oauth_")

      on_exit(fn ->
        case previous do
          :missing -> Application.delete_env(host_app, Config)
          value -> Application.put_env(host_app, Config, value)
        end
      end)

      assert_raise Mix.Error, ~r/legacy :table_prefix configuration detected.*:schema_prefix.*one runtime layout/, fn ->
        run!(["--otp-app", Atom.to_string(host_app)], tmp_dir)
      end
    end

    test "rejects a legacy configured table prefix even with an explicit schema prefix", %{tmp_dir: tmp_dir} do
      host_app = :attesto_phoenix_generator_explicit_legacy_prefix_test
      previous = Application.get_env(host_app, Config, :missing)
      Application.put_env(host_app, Config, table_prefix: "oauth_")

      on_exit(fn ->
        case previous do
          :missing -> Application.delete_env(host_app, Config)
          value -> Application.put_env(host_app, Config, value)
        end
      end)

      assert_raise Mix.Error, ~r/legacy :table_prefix configuration detected/, fn ->
        run!(
          ["--otp-app", Atom.to_string(host_app), "--schema-prefix", "oauth", "--upgrade", "3.0"],
          tmp_dir
        )
      end

      assert Path.wildcard(Path.join(migrations_dir(tmp_dir), "*.exs")) == []
    end

    test "rejects a legacy prefix in a malformed list even with an explicit schema prefix", %{
      tmp_dir: tmp_dir
    } do
      host_app = :attesto_phoenix_generator_malformed_legacy_prefix_test
      previous = Application.get_env(host_app, Config, :missing)
      Application.put_env(host_app, Config, [{:table_prefix, "oauth_"}, :malformed])

      on_exit(fn ->
        case previous do
          :missing -> Application.delete_env(host_app, Config)
          value -> Application.put_env(host_app, Config, value)
        end
      end)

      assert_raise Mix.Error, ~r/legacy :table_prefix configuration detected/, fn ->
        run!(
          ["--otp-app", Atom.to_string(host_app), "--schema-prefix", "oauth", "--upgrade", "3.0"],
          tmp_dir
        )
      end

      assert Path.wildcard(Path.join(migrations_dir(tmp_dir), "*.exs")) == []
    end

    test "rejects a stale package-level table prefix", %{tmp_dir: tmp_dir} do
      previous = Application.get_env(:attesto_phoenix, :table_prefix, :missing)
      Application.put_env(:attesto_phoenix, :table_prefix, nil)

      on_exit(fn ->
        case previous do
          :missing -> Application.delete_env(:attesto_phoenix, :table_prefix)
          value -> Application.put_env(:attesto_phoenix, :table_prefix, value)
        end
      end)

      assert_raise Mix.Error, ~r/legacy config :attesto_phoenix, :table_prefix detected.*:schema_prefix/, fn ->
        run!(["--schema-prefix", "oauth"], tmp_dir)
      end
    end

    test "rejects malformed configured schema prefixes instead of using public", %{tmp_dir: tmp_dir} do
      host_app = :attesto_phoenix_generator_malformed_prefix_test
      previous = Application.get_env(host_app, Config, :missing)
      Application.put_env(host_app, Config, schema_prefix: 42)

      on_exit(fn ->
        case previous do
          :missing -> Application.delete_env(host_app, Config)
          value -> Application.put_env(host_app, Config, value)
        end
      end)

      assert_raise Mix.Error, ~r/invalid configured :schema_prefix/, fn ->
        run!(["--otp-app", Atom.to_string(host_app)], tmp_dir)
      end

      assert Path.wildcard(Path.join(migrations_dir(tmp_dir), "*.exs")) == []
    end

    test "an explicit schema prefix overrides a malformed current schema value", %{tmp_dir: tmp_dir} do
      host_app = :attesto_phoenix_generator_explicit_prefix_override_test
      previous = Application.get_env(host_app, Config, :missing)
      Application.put_env(host_app, Config, schema_prefix: 42)

      on_exit(fn ->
        case previous do
          :missing -> Application.delete_env(host_app, Config)
          value -> Application.put_env(host_app, Config, value)
        end
      end)

      run!(
        [
          "--otp-app",
          Atom.to_string(host_app),
          "--schema-prefix",
          "oauth",
          "--upgrade",
          "3.0"
        ],
        tmp_dir
      )

      [file] =
        Path.wildcard(Path.join(migrations_dir(tmp_dir), "*_upgrade_attesto_phoenix_to_3_0.exs"))

      migration = File.read!(file)
      assert migration =~ ~s|prefix = effective_prefix("oauth")|
    end

    test "rejects unknown options and positional arguments", %{tmp_dir: tmp_dir} do
      assert_raise Mix.Error, ~r/invalid migration-generator arguments/, fn ->
        run!(["--schema-prefix", "oauth", "--bogus"], tmp_dir)
      end

      assert_raise Mix.Error, ~r/invalid migration-generator arguments/, fn ->
        run!(["unexpected"], tmp_dir)
      end
    end

    test "refuses to regenerate over an existing migration", %{tmp_dir: tmp_dir} do
      run!([], tmp_dir)

      assert_raise Mix.Error, ~r/already exists/, fn ->
        run!([], tmp_dir)
      end
    end

    test "refuses fresh migration generation when 3.0 upgrade migration already exists", %{tmp_dir: tmp_dir} do
      run!(["--upgrade", "3.0"], tmp_dir)

      assert_raise Mix.Error, ~r/already contains attesto_phoenix upgrade migrations/, fn ->
        run!([], tmp_dir)
      end

      assert Path.wildcard(Path.join(migrations_dir(tmp_dir), "*_create_attesto_phoenix_tables.exs")) == []
    end

    test "refuses fresh migration generation when 3.0 and 3.1 upgrade migrations already exist", %{tmp_dir: tmp_dir} do
      run!(["--upgrade", "3.0"], tmp_dir)
      run!(["--upgrade", "3.1"], tmp_dir)

      assert_raise Mix.Error, ~r/already contains attesto_phoenix upgrade migrations/, fn ->
        run!([], tmp_dir)
      end

      assert Path.wildcard(Path.join(migrations_dir(tmp_dir), "*_create_attesto_phoenix_tables.exs")) == []
    end

    test "formats every generated migration with the project's formatter configuration", %{
      tmp_dir: tmp_dir
    } do
      fresh_dir = Path.join(tmp_dir, "fresh")
      upgrade_dir = Path.join(tmp_dir, "upgrade")

      Migration.run(["--repo", inspect(TestRepo), "--migrations-path", Path.join(fresh_dir, "migrations")])

      Migration.run([
        "--repo",
        inspect(TestRepo),
        "--migrations-path",
        Path.join(upgrade_dir, "migrations"),
        "--upgrade",
        "3.0"
      ])

      Migration.run([
        "--repo",
        inspect(TestRepo),
        "--migrations-path",
        Path.join(upgrade_dir, "migrations"),
        "--upgrade",
        "3.1"
      ])

      files = Path.wildcard(Path.join(tmp_dir, "*/migrations/*.exs"))
      assert length(files) == 3

      # The project's .formatter.exs (plugins included) is what a host's own
      # `mix format --check-formatted` enforces on the generated file.
      for file <- files do
        assert :ok = Format.run(["--check-formatted", file])
      end
    end

    test "requires at least one repo", %{tmp_dir: tmp_dir} do
      # Mix.Ecto warns before our task raises its actionable "pass --repo"
      # message. Capture that expected stderr so the test suite itself stays
      # warning-free.
      capture_io(:stderr, fn ->
        assert_raise Mix.Error, ~r/no Ecto repos/, fn ->
          Migration.run(["--migrations-path", migrations_dir(tmp_dir)])
        end
      end)
    end

    test "generates a 3.0 upgrade migration with the unique index, tombstone table, and backfill", %{
      tmp_dir: tmp_dir
    } do
      run!(["--upgrade", "3.0"], tmp_dir)

      [file] = Path.wildcard(Path.join(migrations_dir(tmp_dir), "*_upgrade_attesto_phoenix_to_3_0.exs"))
      content = File.read!(file)

      assert content =~ "Migrations.UpgradeAttestoPhoenixTo30 do"
      assert content =~ ~s|repo().query!("SET LOCAL lock_timeout = '5s'", [], log: false)|
      assert content =~ ~s|repo().query!("SET LOCAL row_security = off", [], log: false)|
      assert content =~ "create_if_not_exists unique_index("
      assert content =~ ":attesto_refresh_tokens"
      assert content =~ "[:family_id, :generation]"
      assert content =~ "name: :attesto_refresh_tokens_family_id_generation_index"

      assert content =~ "create_if_not_exists table(:attesto_refresh_family_revocations, primary_key: false"
      assert content =~ "add :family_id, :string, size: 255, primary_key: true, null: false"
      assert content =~ "add :revoked_at, :utc_datetime, null: false"

      assert content =~ ~s|INSERT INTO \#{target_table} (family_id, revoked_at)|
      assert content =~ "SELECT DISTINCT family_id, CURRENT_TIMESTAMP AT TIME ZONE 'UTC'"
      assert content =~ ~s|FROM \#{source_table}|
      assert content =~ "WHERE family_revoked = true"
      assert content =~ "family_revoked IS DISTINCT FROM true"
      assert content =~ "ON CONFLICT (family_id) DO NOTHING"
      assert content =~ "pg_catalog.to_regclass"
      assert content =~ "pg_catalog.pg_class"
      assert content =~ "pg_catalog.pg_trigger"
      assert content =~ "pg_catalog.pg_rewrite"
      assert content =~ "pg_catalog.pg_policy"
      assert content =~ "table_not_permanent"
      assert content =~ "table_partitioned_or_inherited"
      assert content =~ "row_level_security_enabled"
      assert content =~ "force_row_level_security_enabled"
      assert content =~ "user_triggers_present"
      assert content =~ "rewrite_rules_present"
      assert content =~ "row_policies_present"
      assert content =~ "validate_revocation_backfill!(source_table, target_table)"

      # Down migration is guarded against discarding durable revocations
      assert content =~ "Cannot safely rollback 3.0 migration"
      assert content =~ "drop table(:attesto_refresh_family_revocations, prefix: prefix)"
      assert content =~ "drop index("
      refute content =~ "drop_if_exists index("

      # Never creates schema
      refute content =~ "CREATE SCHEMA"
    end

    test "applies an explicit --schema-prefix to the 3.0 upgrade migration", %{tmp_dir: tmp_dir} do
      run!(["--upgrade", "3.0", "--schema-prefix", "oauth"], tmp_dir)

      [file] = Path.wildcard(Path.join(migrations_dir(tmp_dir), "*_upgrade_attesto_phoenix_to_3_0.exs"))
      content = File.read!(file)

      assert content =~ ~s|prefix = effective_prefix("oauth")|
      refute content =~ "CREATE SCHEMA"
      assert content =~ ~s|INSERT INTO \#{target_table} (family_id, revoked_at)|
      assert content =~ ~s|FROM \#{source_table}|
    end

    test "fails closed when upgrade migration already exists and leaves user-edited content unchanged", %{
      tmp_dir: tmp_dir
    } do
      run!(["--upgrade", "3.0"], tmp_dir)

      [first_file] =
        Path.wildcard(Path.join(migrations_dir(tmp_dir), "*_upgrade_attesto_phoenix_to_3_0.exs"))

      custom_content = "# User edited migration content\ndefmodule Custom do end"
      File.write!(first_file, custom_content)

      assert_raise Mix.Error, ~r/migration "upgrade_attesto_phoenix_to_3_0" already exists/, fn ->
        run!(["--upgrade", "3.0"], tmp_dir)
      end

      # User content must be preserved byte-for-byte
      assert File.read!(first_file) == custom_content
    end

    test "generated down/0 enforces strict lock -> revalidation -> guard -> drop ordering", %{tmp_dir: tmp_dir} do
      run!(["--upgrade", "3.0"], tmp_dir)

      [file] = Path.wildcard(Path.join(migrations_dir(tmp_dir), "*_upgrade_attesto_phoenix_to_3_0.exs"))
      content = File.read!(file)

      # Extract down callback body
      assert [_, down_body] = String.split(content, "def down do")

      # Find index positions of all operations in the rollback
      idx_lock_timeout =
        :binary.match(down_body, ~s|repo().query!("SET LOCAL lock_timeout = '5s'", [], log: false)|)

      idx_row_security =
        :binary.match(down_body, ~s|repo().query!("SET LOCAL row_security = off", [], log: false)|)

      idx_lock_target =
        :binary.match(
          down_body,
          ~s|repo().query!("LOCK TABLE \#{target_table} IN ACCESS EXCLUSIVE MODE", [], log: false)|
        )

      idx_lock_source =
        :binary.match(
          down_body,
          ~s|repo().query!("LOCK TABLE \#{source_table} IN ACCESS EXCLUSIVE MODE", [], log: false)|
        )

      idx_validate_index = :binary.match(down_body, "validate_generation_index!(")
      idx_validate_table = :binary.match(down_body, "validate_revocation_table!(target_table, :rollback)")
      idx_guard_query = :binary.match(down_body, "NOT EXISTS (")
      idx_guard_raise = :binary.match(down_body, "raise \"Cannot safely rollback 3.0 migration")
      idx_drop_table = :binary.match(down_body, "drop table(:attesto_refresh_family_revocations")
      idx_drop_index = :binary.match(down_body, "drop index(")

      # Ensure all operations exist
      refute idx_lock_timeout == :nomatch
      refute idx_row_security == :nomatch
      refute idx_lock_target == :nomatch
      refute idx_lock_source == :nomatch
      refute idx_validate_index == :nomatch
      refute idx_validate_table == :nomatch
      refute idx_guard_query == :nomatch
      refute idx_guard_raise == :nomatch
      refute idx_drop_table == :nomatch
      refute idx_drop_index == :nomatch
      refute down_body =~ "drop_if_exists index("
      refute down_body =~ ~s|execute("LOCK TABLE|

      # Strict execution ordering:
      # 1. lock timeout before table locks
      # 2. lock tombstone table before tokens table
      # 3. lock tables before revalidating both canonical objects
      # 4. revalidate before the durable-revocation guard
      # 5. guard query before guard raise
      # 6. guard raise before dropping tombstone table
      # 7. drop tombstone table before dropping unique index
      {pos_lock_timeout, _} = idx_lock_timeout
      {pos_row_security, _} = idx_row_security
      {pos_lock_target, _} = idx_lock_target
      {pos_lock_source, _} = idx_lock_source
      {pos_validate_index, _} = idx_validate_index
      {pos_validate_table, _} = idx_validate_table
      {pos_guard_query, _} = idx_guard_query
      {pos_guard_raise, _} = idx_guard_raise
      {pos_drop_table, _} = idx_drop_table
      {pos_drop_index, _} = idx_drop_index

      assert pos_lock_timeout < pos_lock_target
      assert pos_row_security < pos_lock_target
      assert pos_lock_target < pos_lock_source
      assert pos_lock_source < pos_validate_index
      assert pos_validate_index < pos_validate_table
      assert pos_validate_table < pos_guard_query
      assert pos_guard_query < pos_guard_raise
      assert pos_guard_raise < pos_drop_table
      assert pos_drop_table < pos_drop_index
    end

    test "supports -r as an alias for --repo", %{tmp_dir: tmp_dir} do
      Migration.run(["-r", inspect(TestRepo), "--migrations-path", migrations_dir(tmp_dir), "--upgrade", "3.0"])

      files = Path.wildcard(Path.join(migrations_dir(tmp_dir), "*_upgrade_attesto_phoenix_to_3_0.exs"))
      assert length(files) == 1
    end

    test "generates the separate 3.1 authorization-code primary-key migration", %{tmp_dir: tmp_dir} do
      run!(["--upgrade", "3.1"], tmp_dir)

      [file] =
        Path.wildcard(Path.join(migrations_dir(tmp_dir), "*_upgrade_attesto_phoenix_to_3_1.exs"))

      content = File.read!(file)

      assert content =~ "--upgrade 3.1"
      assert content =~ "attesto_authorization_codes_code_hash_index"
      assert content =~ "attesto_authorization_codes_pkey"
      assert content =~ "PRIMARY KEY USING INDEX"
      assert content =~ "REPLICA IDENTITY USING INDEX"
      assert content =~ "to_jsonb(index_info)"
      assert content =~ "exact_historical_index"
      assert content =~ "exact_primary_key"
      assert content =~ "primary_key_exact"
      assert content =~ "historical_index_coexists_with_primary_key"
      assert content =~ "drop the leftover"
      assert content =~ "condeferrable"
      assert content =~ "condeferred"
      assert content =~ "convalidated"
      assert content =~ "code_hash_typmod = 92"
      assert content =~ "code_hash_default_collation"
      assert content =~ "code_hash_without_default"
      assert content =~ ~s|repo().query!("LOCK TABLE \#{table} IN ACCESS EXCLUSIVE MODE"|
      assert content =~ "pg_catalog.to_regclass"
      assert content =~ "pg_catalog.pg_class"
      assert content =~ "table_not_permanent"
      assert content =~ "table_partitioned_or_inherited"
      assert content =~ "Catalog failures"
      refute content =~ "attesto_refresh_family_revocations"
    end

    test "assigns strictly ordered versions to back-to-back upgrades", %{tmp_dir: tmp_dir} do
      run!(["--upgrade", "3.0"], tmp_dir)
      run!(["--upgrade", "3.1"], tmp_dir)

      [upgrade_3_0] =
        Path.wildcard(Path.join(migrations_dir(tmp_dir), "*_upgrade_attesto_phoenix_to_3_0.exs"))

      [upgrade_3_1] =
        Path.wildcard(Path.join(migrations_dir(tmp_dir), "*_upgrade_attesto_phoenix_to_3_1.exs"))

      version_3_0 = migration_version(upgrade_3_0)
      version_3_1 = migration_version(upgrade_3_1)

      assert byte_size(version_3_0) == 14
      assert byte_size(version_3_1) == 14
      assert version_3_0 < version_3_1
    end

    test "allows only one concurrent generation of the same migration kind", %{
      tmp_dir: tmp_dir
    } do
      tasks =
        for _attempt <- 1..2 do
          Task.async(fn ->
            try do
              {:ok, run!(["--upgrade", "3.0"], tmp_dir)}
            rescue
              exception -> {:error, exception}
            end
          end)
        end

      results = Enum.map(tasks, &Task.await(&1, 5_000))

      assert Enum.count(results, &match?({:ok, _file}, &1)) == 1
      assert Enum.count(results, &match?({:error, %Mix.Error{}}, &1)) == 1
      assert length(Path.wildcard(Path.join(migrations_dir(tmp_dir), "*.exs"))) == 1
    end

    test "fails closed on generation-lock residue until it is explicitly removed", %{
      tmp_dir: tmp_dir
    } do
      lock_path = Path.join(migrations_dir(tmp_dir), ".attesto_phoenix_migration.lock")
      File.mkdir_p!(migrations_dir(tmp_dir))
      File.mkdir!(lock_path)
      File.write!(Path.join(lock_path, "owner"), "crashed-generator-token")

      assert_raise Mix.Error, ~r/verify no generator is active, remove the lock directory/, fn ->
        run!(["--upgrade", "3.0"], tmp_dir)
      end

      assert File.dir?(lock_path)
      File.rm!(Path.join(lock_path, "owner"))
      File.rmdir!(lock_path)

      assert :ok = run!(["--upgrade", "3.0"], tmp_dir)
    end

    test "keeps concurrent upgrade kinds ordered by requiring a retry", %{tmp_dir: tmp_dir} do
      tasks =
        for version <- ["3.0", "3.1"] do
          Task.async(fn ->
            try do
              {:ok, run!(["--upgrade", version], tmp_dir)}
            rescue
              exception -> {:error, exception}
            end
          end)
        end

      results = Enum.map(tasks, &Task.await(&1, 5_000))
      assert Enum.count(results, &match?({:ok, _file}, &1)) in [1, 2]

      case Path.wildcard(Path.join(migrations_dir(tmp_dir), "*_upgrade_attesto_phoenix_to_3_0.exs")) do
        [_upgrade_3_0] ->
          if Path.wildcard(Path.join(migrations_dir(tmp_dir), "*_upgrade_attesto_phoenix_to_3_1.exs")) == [] do
            run!(["--upgrade", "3.1"], tmp_dir)
          end

          [upgrade_3_1] =
            Path.wildcard(Path.join(migrations_dir(tmp_dir), "*_upgrade_attesto_phoenix_to_3_1.exs"))

          [upgrade_3_0] =
            Path.wildcard(Path.join(migrations_dir(tmp_dir), "*_upgrade_attesto_phoenix_to_3_0.exs"))

          assert migration_version(upgrade_3_0) < migration_version(upgrade_3_1)

        [] ->
          [_upgrade_3_1] =
            Path.wildcard(Path.join(migrations_dir(tmp_dir), "*_upgrade_attesto_phoenix_to_3_1.exs"))

          assert_raise Mix.Error, ~r/migration version/, fn ->
            run!(["--upgrade", "3.0"], tmp_dir)
          end
      end
    end

    test "allocates after a future-dated migration version", %{tmp_dir: tmp_dir} do
      future = Path.join(migrations_dir(tmp_dir), "29991231235959_existing_migration.exs")
      File.mkdir_p!(migrations_dir(tmp_dir))
      File.write!(future, "# Existing migration\n")

      run!(["--upgrade", "3.0"], tmp_dir)

      [file] =
        Path.wildcard(Path.join(migrations_dir(tmp_dir), "*_upgrade_attesto_phoenix_to_3_0.exs"))

      assert migration_version(file) == "29991231235960"
    end

    test "fails closed when no 14-digit version remains", %{tmp_dir: tmp_dir} do
      existing = Path.join(migrations_dir(tmp_dir), "99999999999999_existing_migration.exs")
      File.mkdir_p!(migrations_dir(tmp_dir))
      File.write!(existing, "# Existing migration\n")

      assert_raise Mix.Error, ~r/cannot allocate a 14-digit migration version/, fn ->
        run!(["--upgrade", "3.0"], tmp_dir)
      end

      assert File.read!(existing) == "# Existing migration\n"
      assert Path.wildcard(Path.join(migrations_dir(tmp_dir), "*_upgrade_attesto_phoenix_to_3_0.exs")) == []
    end

    test "accepts the 3.1.0 spelling and applies the schema prefix", %{tmp_dir: tmp_dir} do
      run!(["--upgrade", "3.1.0", "--schema-prefix", "oauth"], tmp_dir)

      [file] =
        Path.wildcard(Path.join(migrations_dir(tmp_dir), "*_upgrade_attesto_phoenix_to_3_1.exs"))

      content = File.read!(file)
      assert content =~ "effective_prefix(\"oauth\")"
      assert content =~ "prefix: prefix"
      refute content =~ "pg_catalog.set_config"
      refute content =~ "pg_catalog.quote_ident"
      refute content =~ "SET LOCAL search_path"
    end

    test "does not conflate the 3.0 upgrade with the 3.1 primary-key promotion", %{
      tmp_dir: tmp_dir
    } do
      run!(["--upgrade", "3.0"], tmp_dir)

      [file] =
        Path.wildcard(Path.join(migrations_dir(tmp_dir), "*_upgrade_attesto_phoenix_to_3_0.exs"))

      content = File.read!(file)
      refute content =~ "PRIMARY KEY USING INDEX"
      refute content =~ "attesto_authorization_codes_pkey"
    end

    test "writes to the repo's absolute priv path when --migrations-path is omitted", %{
      tmp_dir: tmp_dir
    } do
      abs_priv = Path.join(tmp_dir, "custom_abs_priv")
      Application.put_env(:attesto_phoenix, TestRepo, priv: abs_priv)

      on_exit(fn ->
        Application.delete_env(:attesto_phoenix, TestRepo)
      end)

      Migration.run(["--repo", inspect(TestRepo), "--upgrade", "3.0"])

      assert [_file] =
               Path.wildcard(Path.join([abs_priv, "migrations", "*_upgrade_attesto_phoenix_to_3_0.exs"]))
    end

    test "rejects unsupported --upgrade versions", %{tmp_dir: tmp_dir} do
      assert_raise Mix.Error, ~r/unsupported --upgrade version "2\.0"/, fn ->
        run!(["--upgrade", "2.0"], tmp_dir)
      end

      assert_raise Mix.Error, ~r/unsupported --upgrade version "4\.0"/, fn ->
        run!(["--upgrade", "4.0"], tmp_dir)
      end
    end
  end
end
