defmodule AttestoPhoenix.Store.AuthorizationCodePrimaryKeyUpgradeTest do
  @moduledoc """
  Runs the forward migration documented in the CHANGELOG upgrade notes
  against a real PostgreSQL `attesto_authorization_codes` table laid out the
  way earlier releases created it (unique index on `code_hash`, no primary
  key), and checks the resulting catalog state.

  Tagged `:ecto` so the suite is excluded by default and runs only when a SQL
  backend is available (see `test/test_helper.exs`).
  """

  use ExUnit.Case, async: false

  alias AttestoPhoenix.TestRepo
  alias Ecto.Adapters.SQL
  alias Ecto.Adapters.SQL.Sandbox

  @moduletag :ecto

  # Isolated PostgreSQL schema so the upgrade runs against a table with the
  # old layout without touching the suite's own attesto_authorization_codes.
  @schema "attesto_upgrade_test"
  @table "attesto_authorization_codes"

  # The CHANGELOG snippet, with the prefix set to the scratch schema.
  defmodule Migration do
    use Ecto.Migration

    @prefix "attesto_upgrade_test"

    def up do
      execute("SET LOCAL lock_timeout = '5s'")

      execute("""
      ALTER TABLE #{table()}
        ADD CONSTRAINT attesto_authorization_codes_pkey
        PRIMARY KEY USING INDEX attesto_authorization_codes_code_hash_index
      """)
    end

    def down do
      execute("SET LOCAL lock_timeout = '5s'")
      execute(~s|ALTER TABLE #{table()} DROP CONSTRAINT attesto_authorization_codes_pkey|)
      create(unique_index(:attesto_authorization_codes, [:code_hash], prefix: @prefix))
    end

    defp table do
      case @prefix do
        nil -> ~s|"attesto_authorization_codes"|
        prefix -> ~s|"#{prefix}"."attesto_authorization_codes"|
      end
    end
  end

  setup do
    # DDL must commit, so this test runs outside the sandbox transaction; and
    # Ecto.Migrator runs each migration in its own process, so the connection
    # is shared rather than owned. Both are undone on exit (async: false).
    :ok = Sandbox.checkout(TestRepo, sandbox: false)
    Sandbox.mode(TestRepo, {:shared, self()})
    on_exit(fn -> Sandbox.mode(TestRepo, :manual) end)

    sql!(~s|DROP SCHEMA IF EXISTS "#{@schema}" CASCADE|)
    sql!(~s|CREATE SCHEMA "#{@schema}"|)

    # The pre-upgrade layout: unique index on code_hash, no primary key.
    sql!(~s|CREATE TABLE "#{@schema}"."#{@table}" (code_hash varchar(88) NOT NULL, expires_at timestamp NOT NULL)|)

    sql!(~s|CREATE UNIQUE INDEX "#{@table}_code_hash_index" ON "#{@schema}"."#{@table}" (code_hash)|)

    :ok
  end

  test "promotes the unique index to the primary key in place, reversibly" do
    refute primary_key?()
    assert index_names() == ["#{@table}_code_hash_index"]
    original_index_oid = index_oid("#{@table}_code_hash_index")

    # Up: the existing index becomes the primary key under the name the schema
    # maps duplicate inserts onto; nothing is rebuilt.
    migrate(:up, 1)
    assert primary_key?()
    assert index_names() == ["#{@table}_pkey"]
    assert index_oid("#{@table}_pkey") == original_index_oid
    # "d" = default: the primary key is the replica identity logical
    # replication uses for UPDATE/DELETE.
    assert replica_identity() == "d"

    # Down restores the previous layout.
    migrate(:down, 1)
    refute primary_key?()
    assert index_names() == ["#{@table}_code_hash_index"]
  end

  # migration_lock: false because the lock's transaction and the migration
  # itself run in different processes, which cannot share one sandbox
  # connection at the same time.
  defp migrate(direction, version) do
    opts = [prefix: @schema, log: false, migration_lock: false]
    apply(Ecto.Migrator, direction, [TestRepo, version, Migration, opts])
  end

  defp primary_key? do
    %{rows: [[count]]} =
      sql!(~s|SELECT count(*) FROM pg_index WHERE indrelid = '"#{@schema}"."#{@table}"'::regclass AND indisprimary|)

    count == 1
  end

  defp index_names do
    %{rows: rows} =
      sql!(~s|SELECT indexname FROM pg_indexes WHERE schemaname = '#{@schema}' AND tablename = '#{@table}' ORDER BY 1|)

    List.flatten(rows)
  end

  defp index_oid(name) do
    %{rows: [[oid]]} = sql!(~s|SELECT '"#{@schema}"."#{name}"'::regclass::oid|)
    oid
  end

  defp replica_identity do
    %{rows: [[identity]]} =
      sql!(~s|SELECT relreplident::text FROM pg_class WHERE oid = '"#{@schema}"."#{@table}"'::regclass|)

    identity
  end

  defp sql!(statement), do: SQL.query!(TestRepo, statement, [])
end
