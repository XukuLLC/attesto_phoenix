defmodule AttestoPhoenix.Store.CodeStoreMigrationTest do
  use ExUnit.Case, async: false

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Legacy418.EctoCodeStore, as: Old
  alias AttestoPhoenix.Store.EctoCodeStore, as: New
  alias AttestoPhoenix.TestRepo
  alias AttestoPhoenix.TestRepo.Migrations.Baseline418
  alias Ecto.Adapters.SQL.Sandbox
  alias Mix.Tasks.AttestoPhoenix.Gen.Migration

  @moduletag :ecto
  @moduletag :tmp_dir

  setup %{tmp_dir: tmp_dir} do
    Sandbox.mode(TestRepo, :auto)
    prefix = "code_upgrade_#{System.unique_integer([:positive])}"
    TestRepo.query!(~s|CREATE SCHEMA "#{prefix}"|)

    on_exit(fn ->
      TestRepo.query!(~s|DROP SCHEMA IF EXISTS "#{prefix}" CASCADE|)
      Sandbox.mode(TestRepo, :manual)
    end)

    # Execute frozen 4.18.0 generated DDL, changing only the target prefix.
    source = File.read!("test/support/fixtures/baseline_4_18.exs")
    Code.compile_string(String.replace(source, "prefix = nil", "prefix = #{inspect(prefix)}"))
    assert :ok = Ecto.Migrator.up(TestRepo, System.os_time(:microsecond), Baseline418, log: false)

    config =
      struct!(Config, issuer: "https://issuer.example", keystore: __MODULE__, repo: TestRepo, schema_prefix: prefix)

    %{prefix: prefix, config: config, tmp_dir: tmp_dir}
  end

  defp record do
    %{
      code_hash: "migration-code",
      expires_at: System.system_time(:second) + 600,
      data: %{
        client_id: "client",
        redirect_uri: "https://client.example/cb",
        subject: "subject",
        scope: [],
        resource: [],
        claims: %{},
        code_challenge: nil,
        dpop_jkt: nil,
        family_id: "original"
      }
    }
  end

  test "generated additive upgrade preserves old rows and installs no triggers or rules", context do
    Config.with_request_config(context.config, fn -> Old.put(record()) end)

    Migration.run([
      "--repo",
      inspect(TestRepo),
      "--migrations-path",
      context.tmp_dir,
      "--schema-prefix",
      context.prefix,
      "--upgrade",
      "4.19"
    ])

    [file] = Path.wildcard(Path.join(context.tmp_dir, "*_upgrade_attesto_phoenix_to_4_19.exs"))
    [{migration, _}] = Code.compile_file(file)
    version = System.os_time(:microsecond)
    assert :ok = Ecto.Migrator.up(TestRepo, version, migration, log: false)

    Config.with_request_config(context.config, fn ->
      assert {:ok, %{state: :live, data: %{family_id: "original"}}} = New.read("migration-code")
      assert {:ok, _} = Old.take("migration-code")
      assert :ok = Old.mark_consumed("migration-code", %{family_id: "issued", replay_retain_until: nil})
      assert {:ok, %{state: :redeemed, redemption: %{family_id: "issued"}}} = New.read("migration-code")
      assert {:error, :consumed, %{family_id: "issued"}} = Old.take("migration-code")
    end)

    table = context.prefix <> ".attesto_authorization_codes"

    assert %{rows: [[0]]} =
             TestRepo.query!(
               "SELECT count(*) FROM pg_trigger WHERE tgrelid = $1::text::regclass AND NOT tgisinternal",
               [table]
             )

    assert %{rows: [[0]]} =
             TestRepo.query!("SELECT count(*) FROM pg_rewrite WHERE ev_class = $1::text::regclass", [table])

    assert %{rows: [[nil]]} = TestRepo.query!("SELECT authorization_family_id FROM #{table}")

    assert %{rows: [[1]]} =
             TestRepo.query!(
               "SELECT count(*) FROM information_schema.columns WHERE table_schema = $1 AND table_name = 'attesto_authorization_codes' AND column_name = ANY($2)",
               [context.prefix, ["authorization_family_id", "redemption_subject", "replay_detected", "grant_revoked"]]
             )

    assert :ok = Ecto.Migrator.down(TestRepo, version, migration, log: false)

    assert %{rows: [[0]]} =
             TestRepo.query!(
               "SELECT count(*) FROM information_schema.columns WHERE table_schema = $1 AND table_name = 'attesto_authorization_codes' AND column_name = 'authorization_family_id'",
               [context.prefix]
             )
  end
end
