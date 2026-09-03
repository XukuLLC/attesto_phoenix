defmodule Mix.Tasks.AttestoPhoenix.Gen.MigrationIntegrationTest do
  @moduledoc """
  Applies the generated migration against PostgreSQL and drives every bundled
  Ecto store through the resulting non-default schema.

  The source-level generator tests catch drift in the rendered migration. This
  test catches the runtime failure that would otherwise be hidden by a table
  name prefix: Ecto's `prefix:` option must select one PostgreSQL schema for
  every store operation, including the migration's indexes and rollback.
  """

  use AttestoPhoenix.DataCase, async: false

  alias AttestoPhoenix.AppEnvSnapshot
  alias AttestoPhoenix.ClientIdMetadata.Cache.Ecto, as: ClientIdMetadataCache
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Store.EctoCIBAStore
  alias AttestoPhoenix.Store.EctoCodeStore
  alias AttestoPhoenix.Store.EctoConsentGrantStore
  alias AttestoPhoenix.Store.EctoDeviceCodeStore
  alias AttestoPhoenix.Store.EctoLogoutSessionStore
  alias AttestoPhoenix.Store.EctoNonceStore
  alias AttestoPhoenix.Store.EctoPARStore
  alias AttestoPhoenix.Store.EctoRefreshStore
  alias AttestoPhoenix.Store.EctoReplayCheck
  alias AttestoPhoenix.Store.Sweeper
  alias AttestoPhoenix.TestRepo
  alias AttestoPhoenix.TestRepo.Migrations.CreateAttestoPhoenixTables
  alias AttestoPhoenix.TestRepo.Migrations.UpgradeAttestoPhoenixTo30
  alias AttestoPhoenix.TestRepo.Migrations.UpgradeAttestoPhoenixTo31
  alias Ecto.Adapters.SQL.Sandbox
  alias Mix.Tasks.AttestoPhoenix.Gen.Migration

  @moduletag :ecto
  @moduletag :tmp_dir

  setup do
    AppEnvSnapshot.ensure_unset!([
      {:attesto_phoenix, AttestoPhoenix.Config},
      {:attesto_phoenix, :table_prefix}
    ])

    :ok
  end

  defmodule Keystore do
    @moduledoc false
  end

  defp migrations_dir(tmp_dir), do: Path.join(tmp_dir, "migrations")

  defp next_migration_version do
    # Keep ad-hoc migration versions above any versions left by an earlier
    # focused test run in the shared database. Ecto treats a lower version as
    # already applied when the schema_migrations table is reused.
    System.os_time(:microsecond)
  end

  defp create_legacy_refresh_table(prefix) do
    TestRepo.query!("""
    CREATE TABLE "#{prefix}"."attesto_refresh_tokens" (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      token_hash varchar(255) NOT NULL UNIQUE,
      family_id varchar(255) NOT NULL,
      generation integer NOT NULL,
      client_id varchar(255) NOT NULL,
      subject varchar(255) NOT NULL,
      scope varchar(255)[] NOT NULL,
      resource varchar(255)[] NOT NULL,
      claims jsonb NOT NULL,
      family_revoked boolean NOT NULL DEFAULT false,
      expires_at timestamp(0) without time zone NOT NULL
    )
    """)
  end

  defp create_legacy_authorization_table(prefix) do
    # Match the historical generator, not the test repo's deliberately broad
    # support migration: every released generator used varchar(88) for hashes.
    TestRepo.query!("""
    CREATE TABLE "#{prefix}"."attesto_authorization_codes" (
      code_hash varchar(88) NOT NULL,
      client_id varchar(255) NOT NULL
    )
    """)
  end

  defp create_authorization_code_index(prefix) do
    TestRepo.query!(
      "CREATE UNIQUE INDEX \"attesto_authorization_codes_code_hash_index\" " <>
        "ON \"#{prefix}\".\"attesto_authorization_codes\" (code_hash)"
    )
  end

  defp with_schema_search_path(prefix, fun) do
    TestRepo.transaction(fn ->
      TestRepo.query!("SET LOCAL search_path = \"#{prefix}\", public")
      fun.()
    end)
  end

  defp create_generation_index(prefix) do
    TestRepo.query!(
      "CREATE UNIQUE INDEX \"attesto_refresh_tokens_family_id_generation_index\" " <>
        "ON \"#{prefix}\".\"attesto_refresh_tokens\" (family_id, generation)"
    )
  end

  defp create_revocation_table(prefix, extra_sql \\ "") do
    TestRepo.query!("""
    CREATE TABLE "#{prefix}"."attesto_refresh_family_revocations" (
      family_id varchar(255) PRIMARY KEY NOT NULL,
      revoked_at timestamp(0) without time zone NOT NULL
      #{extra_sql}
    )
    """)
  end

  defp assert_tombstone_upgrade_objects(prefix, row_security, force_row_security) do
    assert %{rows: [[true, true, ^row_security, ^force_row_security]]} =
             TestRepo.query!(
               """
               SELECT
                 pg_catalog.to_regclass($1) IS NOT NULL,
                 pg_catalog.to_regclass($2) IS NOT NULL,
                 relation.relrowsecurity,
                 relation.relforcerowsecurity
               FROM pg_catalog.pg_class AS relation
               WHERE relation.oid = pg_catalog.to_regclass($1)
               """,
               [
                 "#{prefix}.attesto_refresh_family_revocations",
                 "#{prefix}.attesto_refresh_tokens_family_id_generation_index"
               ]
             )
  end

  defp compile_generated_upgrade(tmp_dir, prefix, version, module) do
    upgrade = if version == "3.0", do: "3_0", else: "3_1"
    generated_tmp_dir = Path.join(tmp_dir, "generated-#{System.unique_integer([:positive])}")
    generated_migrations_dir = migrations_dir(generated_tmp_dir)

    Migration.run([
      "--repo",
      inspect(TestRepo),
      "--migrations-path",
      generated_migrations_dir,
      "--schema-prefix",
      prefix,
      "--upgrade",
      version
    ])

    [migration_file] =
      Path.wildcard(Path.join(generated_migrations_dir, "*_upgrade_attesto_phoenix_to_#{upgrade}.exs"))

    compile_migration(migration_file, module)
  end

  defp generated_upgrade(tmp_dir, prefix, version, module) do
    compile_generated_upgrade(tmp_dir, prefix, version, module)
    version_number = next_migration_version()
    assert :ok = Ecto.Migrator.up(TestRepo, version_number, module, log: false)
    {module, version_number}
  end

  defp compile_migration(file, module) do
    :code.purge(module)
    :code.delete(module)
    [{^module, _binary}] = Code.compile_file(file)
    module
  end

  defp prefix_config(prefix) do
    Config.new(
      issuer: "https://issuer.example",
      audience: "https://resource.example",
      keystore: Keystore,
      repo: TestRepo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      schema_prefix: prefix
    )
  end

  test "applies the generated schema prefix and routes every Ecto store through it", %{
    tmp_dir: tmp_dir
  } do
    prefix = "attesto_generated_#{System.unique_integer([:positive])}"

    # Ecto.Migrator runs migration callbacks in a supervised process. Let that
    # process check out its own connection; the store assertions below are
    # likewise committed and the schema is removed by the cleanup callback.
    Sandbox.mode(TestRepo, :auto)
    on_exit(fn -> Sandbox.mode(TestRepo, :manual) end)

    on_exit(fn ->
      TestRepo.query!(~s|DROP SCHEMA IF EXISTS "#{prefix}" CASCADE|)
    end)

    Migration.run([
      "--repo",
      inspect(TestRepo),
      "--migrations-path",
      migrations_dir(tmp_dir),
      "--schema-prefix",
      prefix
    ])

    [migration_file] = Path.wildcard(Path.join(migrations_dir(tmp_dir), "*.exs"))

    migration =
      compile_migration(
        migration_file,
        CreateAttestoPhoenixTables
      )

    version = next_migration_version()

    assert :ok = Ecto.Migrator.up(TestRepo, version, migration, log: false)

    config = prefix_config(prefix)
    assert :ok = Sweeper.register_cleanup_worker(config, self())

    Config.with_request_config(config, fn ->
      now = System.system_time(:second)

      assert :ok =
               EctoCodeStore.put(%{
                 code_hash: "generated-code-#{now}",
                 data: %{
                   client_id: "client-1",
                   subject: "subject-1",
                   scope: ["openid"],
                   resource: [],
                   redirect_uri: "https://rp.example/cb",
                   code_challenge: nil,
                   dpop_jkt: nil,
                   family_id: nil,
                   claims: %{}
                 },
                 expires_at: now + 600
               })

      assert {:ok, _} = EctoCodeStore.get("generated-code-#{now}")

      par_uri = "urn:ietf:params:oauth:request_uri:generated-#{now}"
      assert :ok = EctoPARStore.put(par_uri, %{"client_id" => "client-1"}, 600)
      assert {:ok, %{"client_id" => "client-1"}} = EctoPARStore.fetch(par_uri)

      binding = %{
        subject: "subject-1",
        client_id: "client-1",
        redirect_uri: "https://rp.example/cb",
        scope: ["openid"],
        code_challenge: nil,
        code_challenge_method: nil
      }

      assert {:ok, consent_token} = EctoConsentGrantStore.mint(binding, 600)
      assert :ok = EctoConsentGrantStore.consume(consent_token, binding)

      nonce = EctoNonceStore.issue(60)
      assert EctoNonceStore.valid?(nonce)
      assert :ok = EctoNonceStore.accept(nonce, 60)

      assert :ok = EctoReplayCheck.check_and_record("generated-jti-#{now}", 60)

      metadata_url = "https://client.example/generated-#{now}.json"

      assert :ok =
               ClientIdMetadataCache.put(
                 metadata_url,
                 %{"client_id" => metadata_url},
                 DateTime.add(DateTime.utc_now(), 600, :second)
               )

      assert {:ok, %{"client_id" => ^metadata_url}} = ClientIdMetadataCache.get(metadata_url)

      ciba = %{
        auth_req_id_hash: "generated-ciba-#{now}",
        data: %{
          acr_values: [],
          binding_message: nil,
          client_id: "client-1",
          client_notification_token: nil,
          delivery_mode: :poll,
          dpop_jkt: nil,
          resource: [],
          scope: ["openid"],
          subject: "subject-1"
        },
        status: :pending,
        interval: 0,
        expires_at: now + 600,
        last_polled_at: nil
      }

      assert :ok = EctoCIBAStore.put(ciba)
      assert {:ok, _} = EctoCIBAStore.lookup(ciba.auth_req_id_hash)

      device = %{
        device_code_hash: "generated-device-#{now}",
        user_code: "BCDFGHJK",
        data: %{client_id: "client-1", scope: ["openid"], resource: [], dpop_jkt: nil},
        status: :pending,
        expires_at: now + 600,
        last_polled_at: nil
      }

      assert :ok = EctoDeviceCodeStore.put(device)
      assert {:ok, _} = EctoDeviceCodeStore.get(device.device_code_hash)

      logout = %{
        sid: "generated-sid-#{now}",
        subject: "subject-1",
        client_id: "client-1",
        backchannel_logout_uri: "https://rp.example/logout",
        expires_at: now + 600
      }

      assert :ok = EctoLogoutSessionStore.record(logout)
      assert [%{client_id: "client-1"}] = EctoLogoutSessionStore.targets(%{sid: logout.sid})

      refresh = %{
        token_hash: "generated-refresh-#{now}",
        family_id: "generated-family-#{now}",
        generation: 0,
        data: %{
          subject: "subject-1",
          scope: ["openid"],
          resource: [],
          acr: nil,
          auth_time: nil,
          client_id: "client-1",
          dpop_jkt: nil,
          claims: %{}
        },
        expires_at: now + 600,
        consumed: false
      }

      assert :ok = EctoRefreshStore.insert(refresh)
      assert {:ok, _} = EctoRefreshStore.get(refresh.token_hash)
      assert :ok = EctoRefreshStore.revoke_family(refresh.family_id)
      assert :error = EctoRefreshStore.get(refresh.token_hash)
    end)

    assert :ok = Ecto.Migrator.down(TestRepo, version, migration, log: false)

    assert %{rows: [[true]]} =
             TestRepo.query!(
               "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)",
               [prefix]
             )

    assert %{rows: [[nil]]} =
             TestRepo.query!(
               "SELECT to_regclass($1)",
               ["#{prefix}.attesto_authorization_codes"]
             )
  end

  test "upgrades a 2.14-era database to 3.0: creates index, table, and backfills revocations", %{
    tmp_dir: tmp_dir
  } do
    prefix = "attesto_upgrade_#{System.unique_integer([:positive])}"

    Sandbox.mode(TestRepo, :auto)
    on_exit(fn -> Sandbox.mode(TestRepo, :manual) end)

    on_exit(fn ->
      TestRepo.query!(~s|DROP SCHEMA IF EXISTS "#{prefix}" CASCADE|)
    end)

    # 1. Create a 2.14.x schema layout with attesto_refresh_tokens (no generation index, no tombstone table)
    TestRepo.query!(~s|CREATE SCHEMA IF NOT EXISTS "#{prefix}"|)

    TestRepo.query!("""
    CREATE TABLE "#{prefix}"."attesto_refresh_tokens" (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      token_hash varchar(255) NOT NULL UNIQUE,
      family_id varchar(255) NOT NULL,
      generation integer NOT NULL,
      client_id varchar(255) NOT NULL,
      subject varchar(255) NOT NULL,
      scope varchar(255)[] NOT NULL,
      resource varchar(255)[] NOT NULL,
      acr varchar(255),
      auth_time timestamp(0) without time zone,
      cnf jsonb,
      claims jsonb NOT NULL,
      consumed boolean NOT NULL DEFAULT false,
      consumed_at timestamp(0) without time zone,
      successor jsonb,
      family_revoked boolean NOT NULL DEFAULT false,
      expires_at timestamp(0) without time zone NOT NULL,
      parent_hash varchar(255),
      inserted_at timestamp(0) without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # 2. Seed 2.14.x rows: active family, and revoked families (including multiple rows for one revoked family)
    expires_at = DateTime.utc_now() |> DateTime.add(3600, :second) |> DateTime.truncate(:second)

    TestRepo.query!(
      """
      INSERT INTO "#{prefix}"."attesto_refresh_tokens"
        (token_hash, family_id, generation, client_id, subject, scope, resource, claims, family_revoked, expires_at)
      VALUES
        ('hash-active-0', 'fam-active', 0, 'client-1', 'sub-1', ARRAY['openid'], ARRAY[]::varchar[], '{}', false, $1),
        ('hash-rev-1-gen-0', 'fam-revoked-1', 0, 'client-1', 'sub-1', ARRAY['openid'], ARRAY[]::varchar[], '{}', true, $1),
        ('hash-rev-1-gen-1', 'fam-revoked-1', 1, 'client-1', 'sub-1', ARRAY['openid'], ARRAY[]::varchar[], '{}', true, $1),
        ('hash-rev-2-gen-0', 'fam-revoked-2', 0, 'client-1', 'sub-1', ARRAY['openid'], ARRAY[]::varchar[], '{}', true, $1)
      """,
      [expires_at]
    )

    # 3. Generate 3.0 upgrade migration
    Migration.run([
      "--repo",
      inspect(TestRepo),
      "--migrations-path",
      migrations_dir(tmp_dir),
      "--schema-prefix",
      prefix,
      "--upgrade",
      "3.0"
    ])

    [migration_file] =
      Path.wildcard(Path.join(migrations_dir(tmp_dir), "*_upgrade_attesto_phoenix_to_3_0.exs"))

    migration =
      compile_migration(
        migration_file,
        UpgradeAttestoPhoenixTo30
      )

    version = next_migration_version()

    # 4. Migrate up
    assert :ok = Ecto.Migrator.up(TestRepo, version, migration, log: false)

    # 5. Verify the revocations table exists and contains exactly the backfilled families
    %{rows: rows} =
      TestRepo.query!(~s|SELECT family_id FROM "#{prefix}"."attesto_refresh_family_revocations" ORDER BY family_id|)

    assert rows == [["fam-revoked-1"], ["fam-revoked-2"]]

    # Verify public was never written to
    assert %{rows: []} =
             TestRepo.query!(
               "SELECT 1 FROM public.attesto_refresh_family_revocations WHERE family_id IN ('fam-revoked-1', 'fam-revoked-2')"
             )

    # 6. Verify generation index enforces uniqueness on (family_id, generation)
    assert_raise Postgrex.Error, ~r/unique_violation/, fn ->
      TestRepo.query!(
        """
        INSERT INTO "#{prefix}"."attesto_refresh_tokens"
          (token_hash, family_id, generation, client_id, subject, scope, resource, claims, family_revoked, expires_at)
        VALUES
        ('hash-collision', 'fam-active', 0, 'client-1', 'sub-1', ARRAY['openid'], ARRAY[]::varchar[], '{}', false, $1)
        """,
        [expires_at]
      )
    end

    # 7. Verify EctoRefreshStore runtime integration
    config = prefix_config(prefix)

    Config.with_request_config(config, fn ->
      assert {:ok, %{family_id: "fam-active"}} = EctoRefreshStore.get("hash-active-0")
      assert :error = EctoRefreshStore.get("hash-rev-1-gen-0")
      assert :error = EctoRefreshStore.get("hash-rev-1-gen-1")
      assert :error = EctoRefreshStore.get("hash-rev-2-gen-0")
    end)

    # 8. Test guarded rollback: an actual runtime revocation without a 2.x
    # legacy row must abort rollback. This exercises the same EctoRefreshStore
    # path that creates tombstones in a live 3.x deployment.
    Config.with_request_config(config, fn ->
      assert :ok = EctoRefreshStore.revoke_family("fam-post-3-0")
    end)

    assert_raise RuntimeError, ~r/Cannot safely rollback 3\.0 migration/, fn ->
      Ecto.Migrator.down(TestRepo, version, migration, log: false)
    end

    # Verify schema state was preserved
    assert %{rows: [[_]]} =
             TestRepo.query!(
               "SELECT to_regclass($1)",
               ["#{prefix}.attesto_refresh_family_revocations"]
             )

    # Clean up orphan post-3.0 tombstone
    TestRepo.query!(~s|DELETE FROM "#{prefix}"."attesto_refresh_family_revocations" WHERE family_id = 'fam-post-3-0'|)

    # A single revoked row is not enough when another legacy row in the same
    # family remains usable. Rolling back that mixed family would let 2.x load
    # the false row after the durable tombstone disappears.
    TestRepo.query!(
      """
      INSERT INTO "#{prefix}"."attesto_refresh_tokens"
        (token_hash, family_id, generation, client_id, subject, scope, resource, claims, family_revoked, expires_at)
      VALUES
        ('hash-rev-1-mixed', 'fam-revoked-1', 2, 'client-1', 'sub-1', ARRAY['openid'], ARRAY[]::varchar[], '{}', false, $1)
      """,
      [expires_at]
    )

    assert_raise RuntimeError, ~r/Cannot safely rollback 3\.0 migration/, fn ->
      Ecto.Migrator.down(TestRepo, version, migration, log: false)
    end

    TestRepo.query!(~s|DELETE FROM "#{prefix}"."attesto_refresh_tokens" WHERE token_hash = 'hash-rev-1-mixed'|)

    # 9. Migrate down cleanly now that every tombstoned family's 2.x rows are
    # all marked revoked.
    assert :ok = Ecto.Migrator.down(TestRepo, version, migration, log: false)

    # Revocation table dropped
    assert %{rows: [[nil]]} =
             TestRepo.query!(
               "SELECT to_regclass($1)",
               ["#{prefix}.attesto_refresh_family_revocations"]
             )

    # Generation index dropped: duplicate generation insert now succeeds
    assert %{num_rows: 1} =
             TestRepo.query!(
               """
               INSERT INTO "#{prefix}"."attesto_refresh_tokens"
                 (token_hash, family_id, generation, client_id, subject, scope, resource, claims, family_revoked, expires_at)
               VALUES
                 ('hash-collision-allowed', 'fam-active', 0, 'client-1', 'sub-1', ARRAY['openid'], ARRAY[]::varchar[], '{}', false, $1)
               """,
               [expires_at]
             )
  end

  test "3.0 adopts exact pre-existing index and tombstone objects in every partial state", %{
    tmp_dir: tmp_dir
  } do
    Sandbox.mode(TestRepo, :auto)
    on_exit(fn -> Sandbox.mode(TestRepo, :manual) end)

    for existing <- [:index, :table, :both] do
      prefix = "attesto_adopt_#{existing}_#{System.unique_integer([:positive])}"
      TestRepo.query!(~s|CREATE SCHEMA "#{prefix}"|)
      create_legacy_refresh_table(prefix)

      on_exit(fn -> TestRepo.query!(~s|DROP SCHEMA IF EXISTS "#{prefix}" CASCADE|) end)

      expires_at = DateTime.utc_now() |> DateTime.add(600, :second) |> DateTime.truncate(:second)

      TestRepo.query!(
        """
        INSERT INTO "#{prefix}"."attesto_refresh_tokens"
          (token_hash, family_id, generation, client_id, subject, scope, resource, claims, family_revoked, expires_at)
        VALUES ('adopt-#{existing}', 'adopt-family-#{existing}', 0, 'client', 'subject', ARRAY['openid'], ARRAY[]::varchar[], '{}', true, $1)
        """,
        [expires_at]
      )

      if existing in [:index, :both], do: create_generation_index(prefix)
      if existing in [:table, :both], do: create_revocation_table(prefix)

      {_migration, version} = generated_upgrade(tmp_dir, prefix, "3.0", UpgradeAttestoPhoenixTo30)

      assert %{rows: [[true]]} =
               TestRepo.query!(
                 "SELECT EXISTS (SELECT 1 FROM pg_class WHERE oid = to_regclass($1))",
                 ["#{prefix}.attesto_refresh_tokens_family_id_generation_index"]
               )

      expected_family = "adopt-family-#{existing}"

      assert %{rows: [[^expected_family]]} =
               TestRepo.query!(~s|SELECT family_id FROM "#{prefix}"."attesto_refresh_family_revocations"|)

      # The successful migration owns adopted objects too; its guarded down
      # removes both objects after preserving the legacy revocation row.
      assert :ok = Ecto.Migrator.down(TestRepo, version, UpgradeAttestoPhoenixTo30, log: false)

      assert %{rows: [[nil]]} =
               TestRepo.query!(
                 "SELECT to_regclass($1)",
                 ["#{prefix}.attesto_refresh_family_revocations"]
               )

      assert %{rows: [[nil]]} =
               TestRepo.query!(
                 "SELECT to_regclass($1)",
                 ["#{prefix}.attesto_refresh_tokens_family_id_generation_index"]
               )
    end
  end

  test "3.0 rejects malformed canonical objects before mutation and rolls back new DDL", %{
    tmp_dir: tmp_dir
  } do
    Sandbox.mode(TestRepo, :auto)
    on_exit(fn -> Sandbox.mode(TestRepo, :manual) end)

    malformed_index_prefix = "attesto_bad_index_#{System.unique_integer([:positive])}"
    TestRepo.query!(~s|CREATE SCHEMA "#{malformed_index_prefix}"|)
    create_legacy_refresh_table(malformed_index_prefix)
    on_exit(fn -> TestRepo.query!(~s|DROP SCHEMA IF EXISTS "#{malformed_index_prefix}" CASCADE|) end)

    TestRepo.query!(
      "CREATE UNIQUE INDEX \"attesto_refresh_tokens_family_id_generation_index\" " <>
        "ON \"#{malformed_index_prefix}\".\"attesto_refresh_tokens\" (generation)"
    )

    migration = compile_generated_upgrade(tmp_dir, malformed_index_prefix, "3.0", UpgradeAttestoPhoenixTo30)

    assert_raise RuntimeError, ~r/exact expected definition/, fn ->
      Ecto.Migrator.up(TestRepo, next_migration_version(), migration, log: false)
    end

    assert %{rows: [[nil]]} =
             TestRepo.query!(
               "SELECT to_regclass($1)",
               ["#{malformed_index_prefix}.attesto_refresh_family_revocations"]
             )

    assert %{rows: [[true]]} =
             TestRepo.query!(
               "SELECT to_regclass($1) IS NOT NULL",
               ["#{malformed_index_prefix}.attesto_refresh_tokens_family_id_generation_index"]
             )

    malformed_table_prefix = "attesto_bad_table_#{System.unique_integer([:positive])}"
    TestRepo.query!(~s|CREATE SCHEMA "#{malformed_table_prefix}"|)
    create_legacy_refresh_table(malformed_table_prefix)
    on_exit(fn -> TestRepo.query!(~s|DROP SCHEMA IF EXISTS "#{malformed_table_prefix}" CASCADE|) end)
    create_revocation_table(malformed_table_prefix, ", extra text")

    migration = compile_generated_upgrade(tmp_dir, malformed_table_prefix, "3.0", UpgradeAttestoPhoenixTo30)

    assert_raise RuntimeError, ~r/exact expected definition/, fn ->
      Ecto.Migrator.up(TestRepo, next_migration_version(), migration, log: false)
    end

    assert %{rows: [[nil]]} =
             TestRepo.query!(
               "SELECT to_regclass($1)",
               ["#{malformed_table_prefix}.attesto_refresh_tokens_family_id_generation_index"]
             )

    assert %{rows: [[true]]} =
             TestRepo.query!(
               "SELECT to_regclass($1) IS NOT NULL",
               ["#{malformed_table_prefix}.attesto_refresh_family_revocations"]
             )
  end

  test "3.0 rejects an adopted tombstone table whose trigger can suppress the backfill", %{
    tmp_dir: tmp_dir
  } do
    prefix = "attesto_triggered_tombstone_#{System.unique_integer([:positive])}"
    Sandbox.mode(TestRepo, :auto)
    on_exit(fn -> Sandbox.mode(TestRepo, :manual) end)
    on_exit(fn -> TestRepo.query!(~s|DROP SCHEMA IF EXISTS "#{prefix}" CASCADE|) end)
    TestRepo.query!(~s|CREATE SCHEMA "#{prefix}"|)
    create_legacy_refresh_table(prefix)
    create_revocation_table(prefix)

    expires_at = DateTime.utc_now() |> DateTime.add(600, :second) |> DateTime.truncate(:second)

    TestRepo.query!(
      """
      INSERT INTO "#{prefix}"."attesto_refresh_tokens"
        (token_hash, family_id, generation, client_id, subject, scope, resource, claims, family_revoked, expires_at)
      VALUES ('triggered-adoption', 'triggered-family', 0, 'client', 'subject', ARRAY['openid'], ARRAY[]::varchar[], '{}', true, $1)
      """,
      [expires_at]
    )

    TestRepo.query!("""
    CREATE FUNCTION "#{prefix}".suppress_tombstone_insert()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $function$
    BEGIN
      RETURN NULL;
    END
    $function$
    """)

    TestRepo.query!(
      ~s|CREATE TRIGGER suppress_tombstone_insert BEFORE INSERT ON "#{prefix}"."attesto_refresh_family_revocations" FOR EACH ROW EXECUTE FUNCTION "#{prefix}".suppress_tombstone_insert()|
    )

    migration = compile_generated_upgrade(tmp_dir, prefix, "3.0", UpgradeAttestoPhoenixTo30)

    assert_raise RuntimeError, ~r/user_triggers_present/, fn ->
      Ecto.Migrator.up(TestRepo, next_migration_version(), migration, log: false)
    end

    assert %{rows: [[nil]]} =
             TestRepo.query!(
               "SELECT to_regclass($1)",
               ["#{prefix}.attesto_refresh_tokens_family_id_generation_index"]
             )

    assert %{rows: [[0]]} =
             TestRepo.query!(~s|SELECT count(*) FROM "#{prefix}"."attesto_refresh_family_revocations"|)
  end

  test "3.0 rollback preserves objects when tombstone behavior has drifted", %{tmp_dir: tmp_dir} do
    prefix = "attesto_tombstone_drift_#{System.unique_integer([:positive])}"
    Sandbox.mode(TestRepo, :auto)
    on_exit(fn -> Sandbox.mode(TestRepo, :manual) end)
    on_exit(fn -> TestRepo.query!(~s|DROP SCHEMA IF EXISTS "#{prefix}" CASCADE|) end)
    TestRepo.query!(~s|CREATE SCHEMA "#{prefix}"|)
    create_legacy_refresh_table(prefix)

    expires_at = DateTime.utc_now() |> DateTime.add(600, :second) |> DateTime.truncate(:second)

    TestRepo.query!(
      """
      INSERT INTO "#{prefix}"."attesto_refresh_tokens"
        (token_hash, family_id, generation, client_id, subject, scope, resource, claims, family_revoked, expires_at)
      VALUES ('rollback-drift', 'rollback-drift-family', 0, 'client', 'subject', ARRAY['openid'], ARRAY[]::varchar[], '{}', true, $1)
      """,
      [expires_at]
    )

    {_migration, version} = generated_upgrade(tmp_dir, prefix, "3.0", UpgradeAttestoPhoenixTo30)

    table = ~s|"#{prefix}"."attesto_refresh_family_revocations"|

    # FORCE is an independent catalog flag and PostgreSQL permits it while RLS
    # itself is disabled. Pin that state so validation cannot accidentally
    # collapse the two checks.
    TestRepo.query!("ALTER TABLE #{table} FORCE ROW LEVEL SECURITY")

    assert_raise RuntimeError, ~r/force_row_level_security_enabled/, fn ->
      Ecto.Migrator.down(TestRepo, version, UpgradeAttestoPhoenixTo30, log: false)
    end

    assert_tombstone_upgrade_objects(prefix, false, true)
    TestRepo.query!("ALTER TABLE #{table} NO FORCE ROW LEVEL SECURITY")

    TestRepo.query!("ALTER TABLE #{table} ENABLE ROW LEVEL SECURITY")

    assert_raise RuntimeError, ~r/row_level_security_enabled/, fn ->
      Ecto.Migrator.down(TestRepo, version, UpgradeAttestoPhoenixTo30, log: false)
    end

    assert_tombstone_upgrade_objects(prefix, true, false)
    TestRepo.query!("ALTER TABLE #{table} DISABLE ROW LEVEL SECURITY")

    # A dormant policy still belongs to the host and would be silently lost if
    # rollback dropped the table, so reject it even while RLS is disabled.
    TestRepo.query!("CREATE POLICY preserve_known_families ON #{table} USING (family_id <> '')")

    assert_raise RuntimeError, ~r/row_policies_present/, fn ->
      Ecto.Migrator.down(TestRepo, version, UpgradeAttestoPhoenixTo30, log: false)
    end

    assert_tombstone_upgrade_objects(prefix, false, false)
    TestRepo.query!("DROP POLICY preserve_known_families ON #{table}")

    TestRepo.query!("""
    CREATE FUNCTION "#{prefix}".accept_tombstone_insert()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $function$
    BEGIN
      RETURN NEW;
    END
    $function$
    """)

    TestRepo.query!(
      ~s|CREATE TRIGGER accept_tombstone_insert BEFORE INSERT ON "#{prefix}"."attesto_refresh_family_revocations" FOR EACH ROW EXECUTE FUNCTION "#{prefix}".accept_tombstone_insert()|
    )

    TestRepo.query!(
      ~s|CREATE RULE preserve_tombstones AS ON DELETE TO "#{prefix}"."attesto_refresh_family_revocations" DO INSTEAD NOTHING|
    )

    assert_raise RuntimeError,
                 ~r/user_triggers_present.*rewrite_rules_present/s,
                 fn ->
                   Ecto.Migrator.down(TestRepo, version, UpgradeAttestoPhoenixTo30, log: false)
                 end

    assert_tombstone_upgrade_objects(prefix, false, false)
    TestRepo.query!("DROP TRIGGER accept_tombstone_insert ON #{table}")
    TestRepo.query!("DROP RULE preserve_tombstones ON #{table}")
    TestRepo.query!(~s|DROP FUNCTION "#{prefix}".accept_tombstone_insert()|)

    assert :ok = Ecto.Migrator.down(TestRepo, version, UpgradeAttestoPhoenixTo30, log: false)
  end

  test "3.0 refuses an unlogged source table and rolls back its new objects", %{tmp_dir: tmp_dir} do
    prefix = "attesto_unlogged_refresh_#{System.unique_integer([:positive])}"
    Sandbox.mode(TestRepo, :auto)
    on_exit(fn -> Sandbox.mode(TestRepo, :manual) end)
    on_exit(fn -> TestRepo.query!(~s|DROP SCHEMA IF EXISTS "#{prefix}" CASCADE|) end)
    TestRepo.query!(~s|CREATE SCHEMA "#{prefix}"|)
    create_legacy_refresh_table(prefix)
    TestRepo.query!(~s|ALTER TABLE "#{prefix}"."attesto_refresh_tokens" SET UNLOGGED|)

    migration = compile_generated_upgrade(tmp_dir, prefix, "3.0", UpgradeAttestoPhoenixTo30)

    assert_raise RuntimeError, ~r/table_not_permanent/, fn ->
      Ecto.Migrator.up(TestRepo, next_migration_version(), migration, log: false)
    end

    assert %{rows: [[nil]]} =
             TestRepo.query!(
               "SELECT to_regclass($1)",
               ["#{prefix}.attesto_refresh_tokens_family_id_generation_index"]
             )

    assert %{rows: [[nil]]} =
             TestRepo.query!(
               "SELECT to_regclass($1)",
               ["#{prefix}.attesto_refresh_family_revocations"]
             )
  end

  test "3.0 duplicate family generations abort atomically before creating the tombstone", %{
    tmp_dir: tmp_dir
  } do
    prefix = "attesto_duplicate_generation_#{System.unique_integer([:positive])}"
    Sandbox.mode(TestRepo, :auto)
    on_exit(fn -> Sandbox.mode(TestRepo, :manual) end)
    on_exit(fn -> TestRepo.query!(~s|DROP SCHEMA IF EXISTS "#{prefix}" CASCADE|) end)
    TestRepo.query!(~s|CREATE SCHEMA "#{prefix}"|)
    create_legacy_refresh_table(prefix)

    expires_at = DateTime.utc_now() |> DateTime.add(600, :second) |> DateTime.truncate(:second)

    TestRepo.query!(
      """
      INSERT INTO "#{prefix}"."attesto_refresh_tokens"
        (token_hash, family_id, generation, client_id, subject, scope, resource, claims, family_revoked, expires_at)
      VALUES
        ('duplicate-one', 'duplicate-family', 0, 'client', 'subject', ARRAY['openid'], ARRAY[]::varchar[], '{}', false, $1),
        ('duplicate-two', 'duplicate-family', 0, 'client', 'subject', ARRAY['openid'], ARRAY[]::varchar[], '{}', false, $1)
      """,
      [expires_at]
    )

    migration = compile_generated_upgrade(tmp_dir, prefix, "3.0", UpgradeAttestoPhoenixTo30)

    assert_raise Postgrex.Error, ~r/unique_violation/, fn ->
      Ecto.Migrator.up(TestRepo, next_migration_version(), migration, log: false)
    end

    assert %{rows: [[nil]]} =
             TestRepo.query!(
               "SELECT to_regclass($1)",
               ["#{prefix}.attesto_refresh_tokens_family_id_generation_index"]
             )

    assert %{rows: [[nil]]} =
             TestRepo.query!(
               "SELECT to_regclass($1)",
               ["#{prefix}.attesto_refresh_family_revocations"]
             )

    assert %{rows: [[2]]} =
             TestRepo.query!(~s|SELECT count(*) FROM "#{prefix}"."attesto_refresh_tokens"|)
  end

  test "3.0 rollback refuses canonical objects changed after the forward migration", %{tmp_dir: tmp_dir} do
    prefix = "attesto_rollback_drift_#{System.unique_integer([:positive])}"
    Sandbox.mode(TestRepo, :auto)
    on_exit(fn -> Sandbox.mode(TestRepo, :manual) end)
    on_exit(fn -> TestRepo.query!(~s|DROP SCHEMA IF EXISTS "#{prefix}" CASCADE|) end)
    TestRepo.query!(~s|CREATE SCHEMA "#{prefix}"|)
    create_legacy_refresh_table(prefix)

    {_migration, version} = generated_upgrade(tmp_dir, prefix, "3.0", UpgradeAttestoPhoenixTo30)

    TestRepo.query!(
      "CREATE INDEX \"unexpected_revocation_time_index\" " <>
        "ON \"#{prefix}\".\"attesto_refresh_family_revocations\" (revoked_at)"
    )

    assert_raise RuntimeError, ~r/Cannot safely rollback 3\.0 migration.*family-revocation/s, fn ->
      Ecto.Migrator.down(TestRepo, version, UpgradeAttestoPhoenixTo30, log: false)
    end

    TestRepo.query!(~s|DROP INDEX "#{prefix}"."unexpected_revocation_time_index"|)

    TestRepo.query!(~s|DROP INDEX "#{prefix}"."attesto_refresh_tokens_family_id_generation_index"|)

    TestRepo.query!(
      "CREATE UNIQUE INDEX \"attesto_refresh_tokens_family_id_generation_index\" " <>
        "ON \"#{prefix}\".\"attesto_refresh_tokens\" (generation)"
    )

    assert_raise RuntimeError, ~r/Cannot safely rollback 3\.0 migration.*generation index/s, fn ->
      Ecto.Migrator.down(TestRepo, version, UpgradeAttestoPhoenixTo30, log: false)
    end

    TestRepo.query!(~s|DROP INDEX "#{prefix}"."attesto_refresh_tokens_family_id_generation_index"|)

    create_generation_index(prefix)
    assert :ok = Ecto.Migrator.down(TestRepo, version, UpgradeAttestoPhoenixTo30, log: false)
  end

  test "3.1 promotes the historical authorization-code index and reverses it", %{tmp_dir: tmp_dir} do
    prefix = "attesto_code_promote_#{System.unique_integer([:positive])}"
    Sandbox.mode(TestRepo, :auto)
    on_exit(fn -> Sandbox.mode(TestRepo, :manual) end)
    on_exit(fn -> TestRepo.query!(~s|DROP SCHEMA IF EXISTS "#{prefix}" CASCADE|) end)
    TestRepo.query!(~s|CREATE SCHEMA "#{prefix}"|)
    create_legacy_authorization_table(prefix)
    create_authorization_code_index(prefix)

    assert %{rows: [[92]]} =
             TestRepo.query!(
               "SELECT atttypmod FROM pg_attribute " <>
                 "WHERE attrelid = to_regclass($1) AND attname = 'code_hash'",
               ["#{prefix}.attesto_authorization_codes"]
             )

    # PostgreSQL resolves the unqualified USING INDEX name in the qualified
    # target table's own schema; the migration does not alter search_path.
    {_migration, version} =
      generated_upgrade(tmp_dir, prefix, "3.1", UpgradeAttestoPhoenixTo31)

    assert %{rows: [[1]]} =
             TestRepo.query!(
               "SELECT count(*) FROM pg_constraint WHERE conrelid = to_regclass($1) " <>
                 "AND conname = 'attesto_authorization_codes_pkey' AND contype = 'p'",
               ["#{prefix}.attesto_authorization_codes"]
             )

    assert %{rows: [[nil]]} =
             TestRepo.query!(
               "SELECT to_regclass($1)",
               ["#{prefix}.attesto_authorization_codes_code_hash_index"]
             )

    promoted_index = "#{prefix}.attesto_authorization_codes_pkey"

    assert %{rows: [[^promoted_index]]} =
             TestRepo.query!(
               "SELECT to_regclass($1)::text",
               ["#{prefix}.attesto_authorization_codes_pkey"]
             )

    assert :ok = Ecto.Migrator.down(TestRepo, version, UpgradeAttestoPhoenixTo31, log: false)

    assert %{rows: [[nil]]} =
             TestRepo.query!(
               "SELECT to_regclass($1)",
               ["#{prefix}.attesto_authorization_codes_pkey"]
             )

    assert %{rows: [[true]]} =
             TestRepo.query!(
               "SELECT to_regclass($1) IS NOT NULL",
               ["#{prefix}.attesto_authorization_codes_code_hash_index"]
             )
  end

  test "3.1 preserves replica identity using the promoted primary-key index", %{
    tmp_dir: tmp_dir
  } do
    prefix = "attesto_code_identity_#{System.unique_integer([:positive])}"
    Sandbox.mode(TestRepo, :auto)
    on_exit(fn -> Sandbox.mode(TestRepo, :manual) end)
    on_exit(fn -> TestRepo.query!(~s|DROP SCHEMA IF EXISTS "#{prefix}" CASCADE|) end)
    TestRepo.query!(~s|CREATE SCHEMA "#{prefix}"|)
    create_legacy_authorization_table(prefix)
    create_authorization_code_index(prefix)

    with_schema_search_path(prefix, fn ->
      TestRepo.query!(
        ~s|ALTER TABLE "#{prefix}"."attesto_authorization_codes" | <>
          ~s|REPLICA IDENTITY USING INDEX "attesto_authorization_codes_code_hash_index"|
      )
    end)

    {_migration, version} =
      generated_upgrade(tmp_dir, prefix, "3.1", UpgradeAttestoPhoenixTo31)

    assert %{rows: [["i"]]} =
             TestRepo.query!(
               "SELECT relreplident::text FROM pg_class WHERE oid = to_regclass($1)",
               ["#{prefix}.attesto_authorization_codes"]
             )

    assert %{rows: [[true]]} =
             TestRepo.query!(
               "SELECT indisreplident FROM pg_index WHERE indexrelid = to_regclass($1)",
               ["#{prefix}.attesto_authorization_codes_pkey"]
             )

    assert :ok = Ecto.Migrator.down(TestRepo, version, UpgradeAttestoPhoenixTo31, log: false)

    assert %{rows: [["i"]]} =
             TestRepo.query!(
               "SELECT relreplident::text FROM pg_class WHERE oid = to_regclass($1)",
               ["#{prefix}.attesto_authorization_codes"]
             )

    assert %{rows: [[true]]} =
             TestRepo.query!(
               "SELECT indisreplident FROM pg_index WHERE indexrelid = to_regclass($1)",
               ["#{prefix}.attesto_authorization_codes_code_hash_index"]
             )
  end

  test "3.1 leaves another replica-identity index selected during rollback", %{tmp_dir: tmp_dir} do
    prefix = "attesto_code_other_identity_#{System.unique_integer([:positive])}"
    Sandbox.mode(TestRepo, :auto)
    on_exit(fn -> Sandbox.mode(TestRepo, :manual) end)
    on_exit(fn -> TestRepo.query!(~s|DROP SCHEMA IF EXISTS "#{prefix}" CASCADE|) end)
    TestRepo.query!(~s|CREATE SCHEMA "#{prefix}"|)
    create_legacy_authorization_table(prefix)
    create_authorization_code_index(prefix)

    TestRepo.query!(
      "CREATE UNIQUE INDEX \"authorization_codes_client_index\" " <>
        "ON \"#{prefix}\".\"attesto_authorization_codes\" (client_id, code_hash)"
    )

    with_schema_search_path(prefix, fn ->
      TestRepo.query!(
        ~s|ALTER TABLE "#{prefix}"."attesto_authorization_codes" | <>
          ~s|REPLICA IDENTITY USING INDEX "authorization_codes_client_index"|
      )
    end)

    {_migration, version} =
      generated_upgrade(tmp_dir, prefix, "3.1", UpgradeAttestoPhoenixTo31)

    assert :ok = Ecto.Migrator.down(TestRepo, version, UpgradeAttestoPhoenixTo31, log: false)

    assert %{rows: [["i"]]} =
             TestRepo.query!(
               "SELECT relreplident::text FROM pg_class WHERE oid = to_regclass($1)",
               ["#{prefix}.attesto_authorization_codes"]
             )

    assert %{rows: [[true]]} =
             TestRepo.query!(
               "SELECT indisreplident FROM pg_index WHERE indexrelid = to_regclass($1)",
               ["#{prefix}.authorization_codes_client_index"]
             )
  end

  test "3.1 safely adopts an exact already-promoted primary key", %{tmp_dir: tmp_dir} do
    prefix = "attesto_code_already_promoted_#{System.unique_integer([:positive])}"
    Sandbox.mode(TestRepo, :auto)
    on_exit(fn -> Sandbox.mode(TestRepo, :manual) end)
    on_exit(fn -> TestRepo.query!(~s|DROP SCHEMA IF EXISTS "#{prefix}" CASCADE|) end)
    TestRepo.query!(~s|CREATE SCHEMA "#{prefix}"|)
    create_legacy_authorization_table(prefix)

    TestRepo.query!(
      ~s|ALTER TABLE "#{prefix}"."attesto_authorization_codes" | <>
        "ADD CONSTRAINT attesto_authorization_codes_pkey PRIMARY KEY (code_hash)"
    )

    {_migration, _version} =
      generated_upgrade(tmp_dir, prefix, "3.1", UpgradeAttestoPhoenixTo31)

    assert %{rows: [[1]]} =
             TestRepo.query!(
               "SELECT count(*) FROM pg_constraint WHERE conrelid = to_regclass($1) " <>
                 "AND conname = 'attesto_authorization_codes_pkey' AND contype = 'p'",
               ["#{prefix}.attesto_authorization_codes"]
             )
  end

  test "3.1 reports coexisting historical index obstacle when promoted primary key already exists", %{
    tmp_dir: tmp_dir
  } do
    prefix = "attesto_code_coexisting_#{System.unique_integer([:positive])}"
    Sandbox.mode(TestRepo, :auto)
    on_exit(fn -> Sandbox.mode(TestRepo, :manual) end)
    on_exit(fn -> TestRepo.query!(~s|DROP SCHEMA IF EXISTS "#{prefix}" CASCADE|) end)
    TestRepo.query!(~s|CREATE SCHEMA "#{prefix}"|)
    create_legacy_authorization_table(prefix)

    TestRepo.query!(
      ~s|ALTER TABLE "#{prefix}"."attesto_authorization_codes" | <>
        "ADD CONSTRAINT attesto_authorization_codes_pkey PRIMARY KEY (code_hash)"
    )

    TestRepo.query!(
      "CREATE UNIQUE INDEX attesto_authorization_codes_code_hash_index " <>
        ~s|ON "#{prefix}"."attesto_authorization_codes" (code_hash)|
    )

    migration = compile_generated_upgrade(tmp_dir, prefix, "3.1", UpgradeAttestoPhoenixTo31)

    error =
      assert_raise RuntimeError, fn ->
        Ecto.Migrator.up(TestRepo, next_migration_version(), migration, log: false)
      end

    assert error.message =~ "historical_index_coexists_with_primary_key"
    refute error.message =~ "primary_key_definition_mismatch"
    assert error.message =~ "drop the leftover attesto_authorization_codes_code_hash_index"
  end

  test "3.1 rejects an already-promoted key whose code-hash column uses a custom collation", %{
    tmp_dir: tmp_dir
  } do
    prefix = "attesto_code_bad_collation_#{System.unique_integer([:positive])}"
    Sandbox.mode(TestRepo, :auto)
    on_exit(fn -> Sandbox.mode(TestRepo, :manual) end)
    on_exit(fn -> TestRepo.query!(~s|DROP SCHEMA IF EXISTS "#{prefix}" CASCADE|) end)
    TestRepo.query!(~s|CREATE SCHEMA "#{prefix}"|)
    create_legacy_authorization_table(prefix)

    TestRepo.query!(
      ~s|ALTER TABLE "#{prefix}"."attesto_authorization_codes" | <>
        ~s|ALTER COLUMN code_hash TYPE varchar(88) COLLATE "C"|
    )

    TestRepo.query!(
      ~s|ALTER TABLE "#{prefix}"."attesto_authorization_codes" | <>
        "ADD CONSTRAINT attesto_authorization_codes_pkey PRIMARY KEY (code_hash)"
    )

    migration = compile_generated_upgrade(tmp_dir, prefix, "3.1", UpgradeAttestoPhoenixTo31)

    assert_raise RuntimeError, ~r/exact historical or already-promoted layout/, fn ->
      Ecto.Migrator.up(TestRepo, next_migration_version(), migration, log: false)
    end

    assert %{rows: [[1]]} =
             TestRepo.query!(
               "SELECT count(*) FROM pg_constraint WHERE conrelid = to_regclass($1) " <>
                 "AND conname = 'attesto_authorization_codes_pkey' AND contype = 'p'",
               ["#{prefix}.attesto_authorization_codes"]
             )
  end

  test "3.1 rejects a canonical index with the wrong definition before promotion", %{
    tmp_dir: tmp_dir
  } do
    prefix = "attesto_code_bad_index_#{System.unique_integer([:positive])}"
    Sandbox.mode(TestRepo, :auto)
    on_exit(fn -> Sandbox.mode(TestRepo, :manual) end)
    on_exit(fn -> TestRepo.query!(~s|DROP SCHEMA IF EXISTS "#{prefix}" CASCADE|) end)
    TestRepo.query!(~s|CREATE SCHEMA "#{prefix}"|)
    create_legacy_authorization_table(prefix)

    TestRepo.query!(
      "CREATE UNIQUE INDEX \"attesto_authorization_codes_code_hash_index\" " <>
        "ON \"#{prefix}\".\"attesto_authorization_codes\" (client_id)"
    )

    migration = compile_generated_upgrade(tmp_dir, prefix, "3.1", UpgradeAttestoPhoenixTo31)

    assert_raise RuntimeError, ~r/exact historical or already-promoted layout/, fn ->
      Ecto.Migrator.up(TestRepo, next_migration_version(), migration, log: false)
    end

    assert %{rows: [[0]]} =
             TestRepo.query!(
               "SELECT count(*) FROM pg_constraint WHERE conrelid = to_regclass($1) AND contype = 'p'",
               ["#{prefix}.attesto_authorization_codes"]
             )

    assert %{rows: [[true]]} =
             TestRepo.query!(
               "SELECT to_regclass($1) IS NOT NULL",
               ["#{prefix}.attesto_authorization_codes_code_hash_index"]
             )
  end

  test "3.1 rejects a canonical code-hash column with a default", %{tmp_dir: tmp_dir} do
    prefix = "attesto_code_default_#{System.unique_integer([:positive])}"
    Sandbox.mode(TestRepo, :auto)
    on_exit(fn -> Sandbox.mode(TestRepo, :manual) end)
    on_exit(fn -> TestRepo.query!(~s|DROP SCHEMA IF EXISTS "#{prefix}" CASCADE|) end)
    TestRepo.query!(~s|CREATE SCHEMA "#{prefix}"|)
    create_legacy_authorization_table(prefix)

    TestRepo.query!(
      ~s|ALTER TABLE "#{prefix}"."attesto_authorization_codes" | <>
        "ALTER COLUMN code_hash SET DEFAULT 'unexpected'"
    )

    create_authorization_code_index(prefix)
    migration = compile_generated_upgrade(tmp_dir, prefix, "3.1", UpgradeAttestoPhoenixTo31)

    assert_raise RuntimeError, ~r/code_hash_has_default/, fn ->
      Ecto.Migrator.up(TestRepo, next_migration_version(), migration, log: false)
    end
  end

  test "3.1 refuses unlogged and inherited authorization-code tables", %{tmp_dir: tmp_dir} do
    Sandbox.mode(TestRepo, :auto)
    on_exit(fn -> Sandbox.mode(TestRepo, :manual) end)

    unlogged_prefix = "attesto_code_unlogged_#{System.unique_integer([:positive])}"
    TestRepo.query!(~s|CREATE SCHEMA "#{unlogged_prefix}"|)
    on_exit(fn -> TestRepo.query!(~s|DROP SCHEMA IF EXISTS "#{unlogged_prefix}" CASCADE|) end)
    create_legacy_authorization_table(unlogged_prefix)
    create_authorization_code_index(unlogged_prefix)
    TestRepo.query!(~s|ALTER TABLE "#{unlogged_prefix}"."attesto_authorization_codes" SET UNLOGGED|)

    unlogged_migration =
      compile_generated_upgrade(tmp_dir, unlogged_prefix, "3.1", UpgradeAttestoPhoenixTo31)

    assert_raise RuntimeError, ~r/table_not_permanent/, fn ->
      Ecto.Migrator.up(TestRepo, next_migration_version(), unlogged_migration, log: false)
    end

    inherited_prefix = "attesto_code_inherited_#{System.unique_integer([:positive])}"
    TestRepo.query!(~s|CREATE SCHEMA "#{inherited_prefix}"|)
    on_exit(fn -> TestRepo.query!(~s|DROP SCHEMA IF EXISTS "#{inherited_prefix}" CASCADE|) end)
    create_legacy_authorization_table(inherited_prefix)
    create_authorization_code_index(inherited_prefix)

    TestRepo.query!("""
    CREATE TABLE "#{inherited_prefix}"."authorization_code_parent" (
      code_hash varchar(88) NOT NULL,
      client_id varchar(255) NOT NULL
    )
    """)

    TestRepo.query!(
      ~s|ALTER TABLE "#{inherited_prefix}"."attesto_authorization_codes" | <>
        ~s|INHERIT "#{inherited_prefix}"."authorization_code_parent"|
    )

    inherited_migration =
      compile_generated_upgrade(tmp_dir, inherited_prefix, "3.1", UpgradeAttestoPhoenixTo31)

    assert_raise RuntimeError, ~r/table_partitioned_or_inherited/, fn ->
      Ecto.Migrator.up(TestRepo, next_migration_version(), inherited_migration, log: false)
    end
  end

  test "upgrade migration with generated nil prefix uses Ecto.Migrator runtime prefix", %{
    tmp_dir: tmp_dir
  } do
    prefix = "attesto_mig_rt_#{System.unique_integer([:positive])}"

    Sandbox.mode(TestRepo, :auto)
    on_exit(fn -> Sandbox.mode(TestRepo, :manual) end)

    on_exit(fn ->
      TestRepo.query!(~s|DROP SCHEMA IF EXISTS "#{prefix}" CASCADE|)
    end)

    TestRepo.query!(~s|CREATE SCHEMA IF NOT EXISTS "#{prefix}"|)

    TestRepo.query!("""
    CREATE TABLE "#{prefix}"."attesto_refresh_tokens" (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      token_hash varchar(255) NOT NULL UNIQUE,
      family_id varchar(255) NOT NULL,
      generation integer NOT NULL,
      client_id varchar(255) NOT NULL,
      subject varchar(255) NOT NULL,
      scope varchar(255)[] NOT NULL,
      resource varchar(255)[] NOT NULL,
      claims jsonb NOT NULL,
      family_revoked boolean NOT NULL DEFAULT false,
      expires_at timestamp(0) without time zone NOT NULL
    )
    """)

    expires_at = DateTime.utc_now() |> DateTime.add(3600, :second) |> DateTime.truncate(:second)

    TestRepo.query!(
      """
      INSERT INTO "#{prefix}"."attesto_refresh_tokens"
        (token_hash, family_id, generation, client_id, subject, scope, resource, claims, family_revoked, expires_at)
      VALUES
        ('hash-rev-runtime', 'fam-revoked-runtime', 0, 'c-1', 's-1', ARRAY['openid'], ARRAY[]::varchar[], '{}', true, $1)
      """,
      [expires_at]
    )

    # Generate with prefix: nil
    Migration.run([
      "--repo",
      inspect(TestRepo),
      "--migrations-path",
      migrations_dir(tmp_dir),
      "--upgrade",
      "3.0"
    ])

    [migration_file] =
      Path.wildcard(Path.join(migrations_dir(tmp_dir), "*_upgrade_attesto_phoenix_to_3_0.exs"))

    migration =
      compile_migration(
        migration_file,
        UpgradeAttestoPhoenixTo30
      )

    version = next_migration_version()

    # Run with Ecto.Migrator prefix: option
    assert :ok = Ecto.Migrator.up(TestRepo, version, migration, prefix: prefix, log: false)

    # Target schema has the tombstone
    %{rows: rows} =
      TestRepo.query!(~s|SELECT family_id FROM "#{prefix}"."attesto_refresh_family_revocations"|)

    assert rows == [["fam-revoked-runtime"]]

    # Public was never written to
    assert %{rows: []} =
             TestRepo.query!(
               "SELECT 1 FROM public.attesto_refresh_family_revocations WHERE family_id = 'fam-revoked-runtime'"
             )

    # Down with prefix: prefix
    assert :ok = Ecto.Migrator.down(TestRepo, version, migration, prefix: prefix, log: false)

    assert %{rows: [[nil]]} =
             TestRepo.query!("SELECT to_regclass($1)", ["#{prefix}.attesto_refresh_family_revocations"])
  end

  test "upgrade migration with generated nil prefix uses repo migration_default_prefix", %{
    tmp_dir: tmp_dir
  } do
    prefix = "attesto_repo_dp_#{System.unique_integer([:positive])}"

    Sandbox.mode(TestRepo, :auto)
    on_exit(fn -> Sandbox.mode(TestRepo, :manual) end)

    previous_repo_config = Application.fetch_env!(:attesto_phoenix, TestRepo)

    on_exit(fn ->
      TestRepo.query!(~s|DROP SCHEMA IF EXISTS "#{prefix}" CASCADE|)
      Application.put_env(:attesto_phoenix, TestRepo, previous_repo_config)
    end)

    Application.put_env(
      :attesto_phoenix,
      TestRepo,
      Keyword.put(previous_repo_config, :migration_default_prefix, prefix)
    )

    TestRepo.query!(~s|CREATE SCHEMA IF NOT EXISTS "#{prefix}"|)

    TestRepo.query!("""
    CREATE TABLE "#{prefix}"."attesto_refresh_tokens" (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      token_hash varchar(255) NOT NULL UNIQUE,
      family_id varchar(255) NOT NULL,
      generation integer NOT NULL,
      client_id varchar(255) NOT NULL,
      subject varchar(255) NOT NULL,
      scope varchar(255)[] NOT NULL,
      resource varchar(255)[] NOT NULL,
      claims jsonb NOT NULL,
      family_revoked boolean NOT NULL DEFAULT false,
      expires_at timestamp(0) without time zone NOT NULL
    )
    """)

    expires_at = DateTime.utc_now() |> DateTime.add(3600, :second) |> DateTime.truncate(:second)

    TestRepo.query!(
      """
      INSERT INTO "#{prefix}"."attesto_refresh_tokens"
        (token_hash, family_id, generation, client_id, subject, scope, resource, claims, family_revoked, expires_at)
      VALUES
        ('hash-rev-default', 'fam-revoked-default', 0, 'c-1', 's-1', ARRAY['openid'], ARRAY[]::varchar[], '{}', true, $1)
      """,
      [expires_at]
    )

    # Generate with prefix: nil
    Migration.run([
      "--repo",
      inspect(TestRepo),
      "--migrations-path",
      migrations_dir(tmp_dir),
      "--upgrade",
      "3.0"
    ])

    [migration_file] =
      Path.wildcard(Path.join(migrations_dir(tmp_dir), "*_upgrade_attesto_phoenix_to_3_0.exs"))

    migration =
      compile_migration(
        migration_file,
        UpgradeAttestoPhoenixTo30
      )

    version = next_migration_version()

    # Run without migrator prefix: option (inherits repo migration_default_prefix)
    assert :ok = Ecto.Migrator.up(TestRepo, version, migration, log: false)

    # Target schema has the tombstone
    %{rows: rows} =
      TestRepo.query!(~s|SELECT family_id FROM "#{prefix}"."attesto_refresh_family_revocations"|)

    assert rows == [["fam-revoked-default"]]

    # Public was never written to
    assert %{rows: []} =
             TestRepo.query!(
               "SELECT 1 FROM public.attesto_refresh_family_revocations WHERE family_id = 'fam-revoked-default'"
             )

    # Down cleanly
    assert :ok = Ecto.Migrator.down(TestRepo, version, migration, log: false)

    assert %{rows: [[nil]]} =
             TestRepo.query!("SELECT to_regclass($1)", ["#{prefix}.attesto_refresh_family_revocations"])
  end
end
