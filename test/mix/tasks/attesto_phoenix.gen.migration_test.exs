defmodule Mix.Tasks.AttestoPhoenix.Gen.MigrationTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias AttestoPhoenix.Config
  alias Mix.Tasks.AttestoPhoenix.Gen.Migration

  @moduletag :tmp_dir

  # A throwaway Ecto repo module so the task can resolve a repo from --repo
  # without standing up a real database connection. The migration path is always
  # given explicitly via --migrations-path in these tests, so config/0 only has
  # to satisfy Mix.Ecto.ensure_repo/2.
  defmodule TestRepo do
    def __adapter__, do: Ecto.Adapters.Postgres
    def config, do: [otp_app: :attesto_phoenix]
  end

  defp migrations_dir(tmp_dir), do: Path.join(tmp_dir, "migrations")

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
      # unique index. A table without a primary key has no default REPLICA
      # IDENTITY, so PostgreSQL logical replication (blue/green deployments,
      # major-version upgrades, CDC) cannot replicate its UPDATE/DELETE.
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
  end
end
