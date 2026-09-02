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

      # Preserve REPLICA IDENTITY USING INDEX when it is active on the promoted
      # primary-key index at rollback time. The marker is LOCAL, so this
      # migration must retain Ecto's default DDL transaction.
      execute("""
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
      """)

      execute(~s|ALTER TABLE #{table()} DROP CONSTRAINT attesto_authorization_codes_pkey|)
      create(unique_index(:attesto_authorization_codes, [:code_hash], prefix: @prefix))

      execute("""
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
      """)
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

  setup do
    # DDL must commit, so this test runs outside the sandbox transaction; and
    # Ecto.Migrator runs each migration in its own process, so the connection
    # is shared rather than owned. Both are undone on exit (async: false).
    :ok = Sandbox.checkout(TestRepo, sandbox: false)
    Sandbox.mode(TestRepo, {:shared, self()})
    on_exit(fn -> Sandbox.mode(TestRepo, :manual) end)

    on_exit(fn ->
      # ExUnit runs cleanup after the test's sandbox owner has exited, so the
      # callback needs its own committed connection.
      :ok = Sandbox.checkout(TestRepo, sandbox: false)

      try do
        sql!(~s|DROP SCHEMA IF EXISTS "#{@schema}" CASCADE|)
      after
        Sandbox.checkin(TestRepo)
      end
    end)

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
    assert effective_replica_identity_index_oid() == nil
    original_index_oid = index_oid("#{@table}_code_hash_index")

    # Up: the existing index becomes the primary key under the name the schema
    # maps duplicate inserts onto; nothing is rebuilt.
    migrate(:up, 1)
    assert primary_key?()
    assert index_names() == ["#{@table}_pkey"]
    assert index_oid("#{@table}_pkey") == original_index_oid
    assert replica_identity() == "d"
    assert effective_replica_identity_index_oid() == index_oid("#{@table}_pkey")

    # Down restores the previous layout.
    migrate(:down, 1)
    refute primary_key?()
    assert index_names() == ["#{@table}_code_hash_index"]
    assert replica_identity() == "d"
    assert effective_replica_identity_index_oid() == nil
  end

  test "down preserves an explicit identity active on the promoted index" do
    sql!(~s|ALTER TABLE "#{@schema}"."#{@table}" REPLICA IDENTITY USING INDEX "#{@table}_code_hash_index"|)
    original_index_oid = index_oid("#{@table}_code_hash_index")

    migrate(:up, 1)
    assert replica_identity() == "i"
    assert effective_replica_identity_index_oid() == original_index_oid

    migrate(:down, 1)
    refute primary_key?()
    assert replica_identity() == "i"
    assert index_names() == ["#{@table}_code_hash_index"]
    assert effective_replica_identity_index_oid() == index_oid("#{@table}_code_hash_index")
  end

  test "down preserves FULL replica identity" do
    sql!(~s|ALTER TABLE "#{@schema}"."#{@table}" REPLICA IDENTITY FULL|)

    migrate(:up, 1)
    assert replica_identity() == "f"

    migrate(:down, 1)
    refute primary_key?()
    assert replica_identity() == "f"
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

  # Resolve the index PostgreSQL can actually use for the table's current
  # replica-identity mode. A plain unique index does not count under DEFAULT;
  # DEFAULT needs a usable primary-key index, while INDEX needs the explicitly
  # selected replica-identity index.
  defp effective_replica_identity_index_oid do
    %{rows: [[oid]]} =
      sql!("""
      SELECT identity.indexrelid
      FROM pg_class AS relation
      LEFT JOIN LATERAL (
        SELECT candidate.indexrelid
        FROM pg_index AS candidate
        WHERE candidate.indrelid = relation.oid
          AND candidate.indisunique
          AND candidate.indimmediate
          AND candidate.indisvalid
          AND candidate.indisready
          AND candidate.indislive
          AND candidate.indpred IS NULL
          AND (
            (relation.relreplident = 'd' AND candidate.indisprimary) OR
            (relation.relreplident = 'i' AND candidate.indisreplident)
          )
        LIMIT 1
      ) AS identity ON true
      WHERE relation.oid = '"#{@schema}"."#{@table}"'::regclass
      """)

    oid
  end

  defp sql!(statement), do: SQL.query!(TestRepo, statement, [])
end
