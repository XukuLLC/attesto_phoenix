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

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Schema.Authorization
  alias AttestoPhoenix.Store.EctoCodeStore
  alias AttestoPhoenix.TestRepo
  alias Ecto.Adapters.SQL
  alias Ecto.Adapters.SQL.Sandbox

  @moduletag :ecto

  # Isolated PostgreSQL schema so the upgrade runs against a table with the
  # old layout without touching the suite's own attesto_authorization_codes.
  @schema "attesto_upgrade_test"
  @table "attesto_authorization_codes"

  defmodule Keystore do
    @moduledoc false
  end

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

    # The pre-upgrade layout: all historical columns, a unique index on
    # code_hash, and no primary key. LIKE INCLUDING DEFAULTS copies columns
    # without copying the current release's primary key or secondary indexes.
    sql!(~s|CREATE TABLE "#{@schema}"."#{@table}" (LIKE public."#{@table}" INCLUDING DEFAULTS)|)

    sql!(~s|CREATE UNIQUE INDEX "#{@table}_code_hash_index" ON "#{@schema}"."#{@table}" (code_hash)|)

    :ok
  end

  test "catalog preflight accepts the historical generated layout" do
    assert %{ready_for_primary_key: true, failure_reasons: []} = preflight()
  end

  test "catalog preflight rejects NULLS NOT DISTINCT indexes" do
    if postgres_version_num() >= 150_000 do
      sql!(~s|DROP INDEX "#{@schema}"."#{@table}_code_hash_index"|)

      sql!(
        ~s|CREATE UNIQUE INDEX "#{@table}_code_hash_index" ON "#{@schema}"."#{@table}" (code_hash) NULLS NOT DISTINCT|
      )

      assert %{ready_for_primary_key: false, failure_reasons: reasons} = preflight()
      assert "index_nulls_not_distinct" in reasons
    end
  end

  test "catalog preflight rejects a custom column and matching index collation" do
    collation = non_default_collation()
    sql!(~s|DROP INDEX "#{@schema}"."#{@table}_code_hash_index"|)

    sql!(~s|ALTER TABLE "#{@schema}"."#{@table}" ALTER COLUMN code_hash TYPE varchar(88) COLLATE #{collation}|)

    sql!(
      ~s|CREATE UNIQUE INDEX "#{@table}_code_hash_index" ON "#{@schema}"."#{@table}" (code_hash COLLATE #{collation})|
    )

    assert %{ready_for_primary_key: false, failure_reasons: reasons} = preflight()
    assert "non_default_collation" in reasons
  end

  test "catalog preflight rejects a custom index collation" do
    collation = non_default_collation()
    sql!(~s|DROP INDEX "#{@schema}"."#{@table}_code_hash_index"|)

    sql!(
      ~s|CREATE UNIQUE INDEX "#{@table}_code_hash_index" ON "#{@schema}"."#{@table}" (code_hash COLLATE #{collation})|
    )

    assert %{ready_for_primary_key: false, failure_reasons: reasons} = preflight()
    assert "non_default_collation" in reasons
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

  test "sanitizes duplicate inserts before and after primary-key promotion" do
    Config.with_request_config(prefix_config(), fn ->
      assert_sanitized_duplicate("old-layout-hash", "old-layout-private-marker")

      migrate(:up, 2)

      assert_sanitized_duplicate("new-layout-hash", "new-layout-private-marker")
    end)
  end

  test "the combined schema has one redacted primary key and both constraints" do
    assert Authorization.__schema__(:primary_key) == [:code_hash]
    assert Enum.count(Authorization.__schema__(:fields), &(&1 == :code_hash)) == 1
    assert :claims in Authorization.__schema__(:redact_fields)

    constraints =
      Authorization.from_record(entry("schema-check-hash", %{"safe" => true}))
      |> Ecto.Changeset.constraints()

    assert Enum.any?(constraints, &(&1.constraint == "attesto_authorization_codes_code_hash_index"))
    assert Enum.any?(constraints, &(&1.constraint == "attesto_authorization_codes_pkey"))
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

  defp postgres_version_num do
    %{rows: [[version]]} = sql!("SHOW server_version_num")
    String.to_integer(version)
  end

  defp non_default_collation do
    %{rows: rows} =
      sql!("""
      SELECT quote_ident(candidate.collname)
      FROM pg_collation AS candidate
      JOIN pg_namespace AS namespace ON namespace.oid = candidate.collnamespace
      WHERE namespace.nspname = 'pg_catalog'
        AND candidate.collname <> 'default'
        AND candidate.oid <> (
          SELECT database_default.oid
          FROM pg_collation AS database_default
          JOIN pg_namespace AS default_namespace
            ON default_namespace.oid = database_default.collnamespace
          WHERE default_namespace.nspname = 'pg_catalog'
            AND database_default.collname = 'default'
        )
      ORDER BY CASE candidate.collname
                 WHEN 'C' THEN 0
                 WHEN 'C.utf8' THEN 1
                 WHEN 'POSIX' THEN 2
                 ELSE 3
               END,
               candidate.oid
      LIMIT 1
      """)

    case rows do
      [[collation]] -> collation
      [] -> flunk("the PostgreSQL test database has no non-default catalog collation")
    end
  end

  # Keep this query in lockstep with the pasteable catalog preflight in
  # guides/upgrade_3_0_schema_prefix.md. The JSON access to
  # indnullsnotdistinct is intentional: PostgreSQL added that pg_index column
  # in 15, while this query remains executable on earlier servers.
  defp preflight do
    %{columns: columns, rows: [values]} =
      sql!("""
      WITH target AS (
        SELECT to_regclass('#{@schema}.#{@table}') AS table_oid,
               to_regclass('#{@schema}.#{@table}_code_hash_index') AS index_oid
      ), catalog AS (
        SELECT target.*,
               table_rel.relkind AS table_kind,
               index_rel.relkind AS index_kind,
               access_method.amname,
               index_info.indisunique,
               index_info.indisvalid,
               index_info.indisready,
               index_info.indislive,
               index_info.indnatts,
               index_info.indnkeyatts,
               index_info.indkey,
               index_info.indcollation[0] AS index_collation,
               index_info.indoption[0] AS index_options,
               COALESCE((to_jsonb(index_info) ->> 'indnullsnotdistinct')::boolean, false)
                 AS nulls_not_distinct,
               index_info.indpred,
               index_info.indexprs,
               code_hash.attnum AS code_hash_attnum,
               code_hash.atttypid AS code_hash_type,
               code_hash.attnotnull AS code_hash_not_null,
               code_hash.attcollation AS code_hash_collation,
               default_collation.oid AS database_default_collation,
               operator_class.opcdefault AS operator_class_default,
               operator_class.opcintype AS operator_class_type,
               constraint_info.constraint_name,
               COALESCE(primary_key_info.table_has_primary_key, false) AS table_has_primary_key
        FROM target
        LEFT JOIN pg_class AS table_rel ON table_rel.oid = target.table_oid
        LEFT JOIN pg_class AS index_rel ON index_rel.oid = target.index_oid
        LEFT JOIN pg_index AS index_info
          ON index_info.indexrelid = target.index_oid
         AND index_info.indrelid = target.table_oid
        LEFT JOIN pg_am AS access_method ON access_method.oid = index_rel.relam
        LEFT JOIN pg_attribute AS code_hash
          ON code_hash.attrelid = target.table_oid
         AND code_hash.attname = 'code_hash'
         AND code_hash.attnum > 0
        LEFT JOIN pg_collation AS default_collation
          ON default_collation.collnamespace = 'pg_catalog'::regnamespace
         AND default_collation.collname = 'default'
        LEFT JOIN pg_opclass AS operator_class
          ON operator_class.oid = index_info.indclass[0]
        LEFT JOIN LATERAL (
          SELECT c.conname AS constraint_name
          FROM pg_constraint AS c
          WHERE c.conindid = target.index_oid
          ORDER BY c.oid
          LIMIT 1
        ) AS constraint_info ON true
        LEFT JOIN LATERAL (
          SELECT bool_or(indisprimary) AS table_has_primary_key
          FROM pg_index
          WHERE indrelid = target.table_oid
        ) AS primary_key_info ON true
      ), checks AS (
        SELECT table_oid IS NOT NULL AS table_exists,
               index_oid IS NOT NULL AS index_exists,
               table_kind = 'r' AS ordinary_table,
               index_kind = 'i' AND amname = 'btree' AS btree_index,
               COALESCE(indisunique, false) AS unique_index,
               COALESCE(indisvalid AND indisready AND indislive, false) AS index_valid_ready_live,
               COALESCE(indnatts = 1 AND indnkeyatts = 1 AND indkey[0] = code_hash_attnum, false) AS only_code_hash,
               COALESCE(code_hash_not_null, false) AS code_hash_not_null,
               COALESCE(
                 code_hash_collation = database_default_collation AND
                   index_collation = database_default_collation,
                 false
               ) AS default_collation,
               NOT nulls_not_distinct AS default_null_treatment,
               COALESCE(
                 operator_class_default AND
                   (operator_class_type = code_hash_type OR EXISTS (
                     SELECT 1 FROM pg_cast
                     WHERE castsource = code_hash_type
                       AND casttarget = operator_class_type
                       AND castcontext = 'i'
                   )), false
               ) AS default_operator_class,
               COALESCE(index_options = 0, false) AS default_ordering,
               indpred IS NULL AS no_predicate,
               indexprs IS NULL AS no_expressions,
               constraint_name IS NOT NULL AS constraint_backed,
               table_has_primary_key
        FROM catalog
      ), failures AS (
        SELECT checks.*,
               array_remove(ARRAY[
                 CASE WHEN NOT table_exists THEN 'table_missing' END,
                 CASE WHEN NOT index_exists THEN 'index_missing' END,
                 CASE WHEN NOT ordinary_table THEN 'table_not_ordinary' END,
                 CASE WHEN NOT btree_index THEN 'index_not_btree' END,
                 CASE WHEN NOT unique_index THEN 'index_not_unique' END,
                 CASE WHEN NOT index_valid_ready_live THEN 'index_invalid_not_ready_or_not_live' END,
                 CASE WHEN NOT only_code_hash THEN 'index_is_multicolumn_or_has_include_columns' END,
                 CASE WHEN NOT code_hash_not_null THEN 'code_hash_nullable_or_missing' END,
                 CASE WHEN NOT default_collation THEN 'non_default_collation' END,
                 CASE WHEN NOT default_null_treatment THEN 'index_nulls_not_distinct' END,
                 CASE WHEN NOT default_operator_class THEN 'non_default_operator_class' END,
                 CASE WHEN NOT default_ordering THEN 'non_default_ordering' END,
                 CASE WHEN NOT no_predicate THEN 'partial_index' END,
                 CASE WHEN NOT no_expressions THEN 'expression_index' END,
                 CASE WHEN constraint_backed THEN 'index_backs_constraint' END,
                 CASE WHEN table_has_primary_key THEN 'table_already_has_primary_key' END
               ], NULL) AS failure_reasons
        FROM checks
      )
      SELECT cardinality(failure_reasons) = 0 AS ready_for_primary_key,
             failure_reasons
      FROM failures
      """)

    Map.new(Enum.zip(columns, values), fn {column, value} ->
      {String.to_existing_atom(column), value}
    end)
  end

  defp assert_sanitized_duplicate(code_hash, sentinel) do
    assert :ok = EctoCodeStore.put(entry(code_hash, %{"safe" => true}))

    error =
      assert_raise Ecto.InvalidChangesetError, fn ->
        EctoCodeStore.put(entry(code_hash, %{"private_marker" => sentinel}))
      end

    refute Exception.message(error) =~ sentinel
    refute inspect(error) =~ sentinel
  end

  defp entry(code_hash, claims) do
    %{
      code_hash: code_hash,
      data: %{
        client_id: "client-1",
        subject: "subject-1",
        scope: ["openid"],
        resource: [],
        redirect_uri: "https://client.example/callback",
        code_challenge: nil,
        dpop_jkt: nil,
        family_id: nil,
        claims: claims
      },
      expires_at: System.system_time(:second) + 600
    }
  end

  defp prefix_config do
    Config.new(
      issuer: "https://issuer.example",
      audience: "https://resource.example",
      keystore: Keystore,
      repo: TestRepo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      schema_prefix: @schema
    )
  end

  defp sql!(statement), do: SQL.query!(TestRepo, statement, [])
end
