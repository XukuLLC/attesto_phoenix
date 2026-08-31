# 3.0 schema-prefix cutover

Version 2.x used `:table_prefix` as a literal prefix on each table name. For
example, a value of `oauth_` produced `public.oauth_attesto_refresh_tokens`.
Version 3.0 uses the public `:schema_prefix` option instead: the table remains
`attesto_refresh_tokens` and Ecto selects PostgreSQL schema `oauth` with
`prefix: "oauth"`.

These are different database layouts. The 3.0 runtime deliberately rejects the
host `:table_prefix` key, the separate package-level
`config :attesto_phoenix, :table_prefix` setting, and `--table-prefix`; it never
guesses whether a value was a literal table prefix or a schema name.

## Critical deployment warning

Do not run 2.x and 3.0 nodes together for any deployment. 2.x does not read or
write the durable refresh-family revocation tombstones used by 3.0, so mixed
writers can diverge even when both versions use the public schema. For a
non-empty prefix, 2.x additionally reads `public.<literal-prefix><table>` while
3.0 reads `<schema>.<table>`, splitting authorization codes, refresh families,
PAR references, replay records, and revocations across two physical layouts.
Drain all 2.x nodes and complete the cutover before starting any 3.0 node. The
same rule applies to workers, scheduled jobs, and migration commands that use
the old generator.

Version 3.0 also enforces a lossless portable-JSON boundary for persisted
authorization-code, device-code, CIBA, and refresh claim maps. Any pre-3.0 row
whose claim map uses atom keys, floats, unsupported VM terms, invalid strings,
out-of-range integers, or nesting deeper than the portable limit is rejected
when read; it is never coerced into a broader grant. Audit or retire such rows
before cutover if they must remain redeemable.

The procedure below is for an existing non-empty 2.x prefix. Back up the
database, rehearse it on a copy, and keep the application stopped while the
cutover runs.

## 1. Inventory the old layout

The generated 2.x migration owns these tables:

```text
attesto_authorization_codes
attesto_refresh_tokens
attesto_device_codes
attesto_ciba_requests
attesto_logout_sessions
dpop_nonces
dpop_replays
attesto_pushed_authorization_requests
attesto_client_id_metadata
attesto_consent_grants
```

The `attesto_refresh_family_revocations` tombstone table is new in 3.0; it is
not part of the 2.x inventory and is created and backfilled in step 2.

Confirm which prefixed tables exist, their owners, and their row counts. This
query is intentionally an inventory query; it does not rename or delete data:

```sql
SELECT n.nspname AS schema_name, c.relname AS table_name,
       c.relowner::regrole AS table_owner,
       c.reltuples::bigint AS estimated_rows
FROM pg_class AS c
JOIN pg_namespace AS n ON n.oid = c.relnamespace
WHERE c.relkind = 'r'
  AND n.nspname = 'public'
  AND left(c.relname, length('oauth_')) = 'oauth_'
ORDER BY c.relname;
```

Record exact counts for every expected old table. For a precise count, run
`SELECT count(*) FROM public.<old_table>;` for each table. Also inspect indexes
and constraints before moving anything:

```sql
SELECT schemaname, tablename, indexname, indexdef
FROM pg_indexes
WHERE schemaname = 'public' AND left(tablename, length('oauth_')) = 'oauth_'
ORDER BY tablename, indexname;

SELECT n.nspname AS schema_name, c.relname AS table_name,
       con.conname, pg_get_constraintdef(con.oid) AS definition
FROM pg_constraint AS con
JOIN pg_class AS c ON c.oid = con.conrelid
JOIN pg_namespace AS n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND left(c.relname, length('oauth_')) = 'oauth_'
ORDER BY c.relname, con.conname;
```

Stop if a table is missing, an unexpected table owns the same data, counts are
not recorded, or the old prefix is not the value used by every 2.x node.

## 2. Cut over the tables

Create the target schema, then verify its owner and that it has no canonical
table-name collisions before moving anything. The following checks use the
reviewed literal `oauth` example; substitute only a validated identifier that
exactly matches `:schema_prefix`:

```sql
CREATE SCHEMA IF NOT EXISTS "oauth";

SELECT n.nspname, n.nspowner::regrole AS owner,
       has_schema_privilege(current_user, n.oid, 'USAGE') AS has_usage,
       has_schema_privilege(current_user, n.oid, 'CREATE') AS has_create
FROM pg_namespace AS n
WHERE n.nspname = 'oauth';

SELECT c.relname AS colliding_relation, c.relkind
FROM pg_class AS c
JOIN pg_namespace AS n ON n.oid = c.relnamespace
WHERE n.nspname = 'oauth'
  AND c.relname IN (
    'attesto_authorization_codes', 'attesto_refresh_tokens',
    'attesto_device_codes', 'attesto_ciba_requests',
    'attesto_logout_sessions', 'dpop_nonces', 'dpop_replays',
    'attesto_pushed_authorization_requests', 'attesto_client_id_metadata',
    'attesto_consent_grants', 'attesto_refresh_family_revocations',
    'oauth_attesto_authorization_codes', 'oauth_attesto_refresh_tokens',
    'oauth_attesto_device_codes', 'oauth_attesto_ciba_requests',
    'oauth_attesto_logout_sessions', 'oauth_dpop_nonces',
    'oauth_dpop_replays', 'oauth_attesto_pushed_authorization_requests',
    'oauth_attesto_client_id_metadata', 'oauth_attesto_consent_grants'
  );

WITH expected(name) AS (VALUES
  ('attesto_authorization_codes_code_hash_index'),
  ('attesto_authorization_codes_expires_at_index'),
  ('attesto_authorization_codes_family_id_index'),
  ('attesto_authorization_codes_access_token_jti_index'),
  ('attesto_refresh_tokens_pkey'),
  ('attesto_refresh_tokens_token_hash_index'),
  ('attesto_refresh_tokens_family_id_generation_index'),
  ('attesto_refresh_tokens_family_id_index'),
  ('attesto_refresh_tokens_expires_at_index'),
  ('attesto_device_codes_pkey'),
  ('attesto_device_codes_device_code_hash_index'),
  ('attesto_device_codes_user_code_index'),
  ('attesto_device_codes_expires_at_index'),
  ('attesto_ciba_requests_pkey'),
  ('attesto_ciba_requests_auth_req_id_hash_index'),
  ('attesto_ciba_requests_expires_at_index'),
  ('attesto_logout_sessions_pkey'),
  ('attesto_logout_sessions_sid_client_id_index'),
  ('attesto_logout_sessions_subject_index'),
  ('attesto_logout_sessions_expires_at_index'),
  ('dpop_nonces_pkey'),
  ('dpop_nonces_nonce_index'),
  ('dpop_nonces_unused_index'),
  ('dpop_replays_pkey'),
  ('dpop_replays_expires_at_index'),
  ('attesto_pushed_authorization_requests_pkey'),
  ('attesto_pushed_authorization_requests_expires_at_index'),
  ('attesto_client_id_metadata_pkey'),
  ('attesto_client_id_metadata_expires_at_index'),
  ('attesto_consent_grants_pkey'),
  ('attesto_consent_grants_expires_at_index')
), collision_candidates(name) AS (
  SELECT name FROM expected
  UNION ALL
  SELECT 'oauth_' || name
  FROM expected
  -- This index is new in 3.0, so no old literal-prefixed form can exist.
  WHERE name <> 'attesto_refresh_tokens_family_id_generation_index'
)
SELECT 'relation' AS object_kind, e.name, c.relkind::text AS definition
FROM collision_candidates AS e
JOIN pg_class AS c ON c.relname = e.name
JOIN pg_namespace AS n ON n.oid = c.relnamespace
WHERE n.nspname = 'oauth'
UNION ALL
SELECT 'constraint' AS object_kind, e.name, pg_get_constraintdef(con.oid)
FROM collision_candidates AS e
JOIN pg_constraint AS con ON con.conname = e.name
JOIN pg_class AS t ON t.oid = con.conrelid
JOIN pg_namespace AS n ON n.oid = t.relnamespace
WHERE n.nspname = 'oauth'
ORDER BY object_kind, name;
```

The owner check must show an owner that can move/rename the source tables, and
the table and object-collision queries must return zero rows (unrelated tables
may remain). These preflights cover canonical table, index, and constraint
names, preventing a rename collision after the move. Stop if any check fails.
Then move and rename each of the ten old tables. PostgreSQL moves a table's
indexes and constraints with it. Use a reviewed migration with literal,
validated identifiers; the example below shows the required order and includes
the complete old-table inventory:

```elixir
def up do
  execute("CREATE SCHEMA IF NOT EXISTS \"oauth\"")

  # The ten old literal-prefix tables, in dependency-safe order:
  execute("ALTER TABLE public.oauth_attesto_authorization_codes SET SCHEMA \"oauth\"")
  execute("ALTER TABLE \"oauth\".oauth_attesto_authorization_codes RENAME TO attesto_authorization_codes")
  execute("ALTER TABLE public.oauth_attesto_refresh_tokens SET SCHEMA \"oauth\"")
  execute("ALTER TABLE \"oauth\".oauth_attesto_refresh_tokens RENAME TO attesto_refresh_tokens")
  execute("ALTER TABLE public.oauth_attesto_device_codes SET SCHEMA \"oauth\"")
  execute("ALTER TABLE \"oauth\".oauth_attesto_device_codes RENAME TO attesto_device_codes")
  execute("ALTER TABLE public.oauth_attesto_ciba_requests SET SCHEMA \"oauth\"")
  execute("ALTER TABLE \"oauth\".oauth_attesto_ciba_requests RENAME TO attesto_ciba_requests")
  execute("ALTER TABLE public.oauth_attesto_logout_sessions SET SCHEMA \"oauth\"")
  execute("ALTER TABLE \"oauth\".oauth_attesto_logout_sessions RENAME TO attesto_logout_sessions")
  execute("ALTER TABLE public.oauth_dpop_nonces SET SCHEMA \"oauth\"")
  execute("ALTER TABLE \"oauth\".oauth_dpop_nonces RENAME TO dpop_nonces")
  execute("ALTER TABLE public.oauth_dpop_replays SET SCHEMA \"oauth\"")
  execute("ALTER TABLE \"oauth\".oauth_dpop_replays RENAME TO dpop_replays")
  execute("ALTER TABLE public.oauth_attesto_pushed_authorization_requests SET SCHEMA \"oauth\"")
  execute("ALTER TABLE \"oauth\".oauth_attesto_pushed_authorization_requests RENAME TO attesto_pushed_authorization_requests")
  execute("ALTER TABLE public.oauth_attesto_client_id_metadata SET SCHEMA \"oauth\"")
  execute("ALTER TABLE \"oauth\".oauth_attesto_client_id_metadata RENAME TO attesto_client_id_metadata")
  execute("ALTER TABLE public.oauth_attesto_consent_grants SET SCHEMA \"oauth\"")
  execute("ALTER TABLE \"oauth\".oauth_attesto_consent_grants RENAME TO attesto_consent_grants")

  # The 3.0 tombstone table is new; create and backfill it after all ten old
  # tables have moved and before starting any 3.0 writer.
  create table(:attesto_refresh_family_revocations, primary_key: false, prefix: "oauth") do
    add :family_id, :string, primary_key: true, null: false
    add :revoked_at, :utc_datetime, null: false
  end

  execute("""
  INSERT INTO "oauth".attesto_refresh_family_revocations (family_id, revoked_at)
  SELECT DISTINCT family_id, CURRENT_TIMESTAMP
  FROM "oauth".attesto_refresh_tokens
  WHERE family_revoked = true
  ON CONFLICT (family_id) DO NOTHING
  """)

  create unique_index(
    :attesto_refresh_tokens,
    [:family_id, :generation],
    name: :attesto_refresh_tokens_family_id_generation_index,
    prefix: "oauth"
  )
end
```

The callback above creates the new tombstone and backfills one row per distinct
revoked family before starting any 3.0 writer. The tombstone row count must equal
the count of distinct revoked families in
the moved refresh table. For a public-schema deployment, use `prefix: nil` and
the corresponding `public.`-qualified SQL. Do not run the complete generated
create-table migration against these tables.

The ten old tables must have moved before the new tombstone table is backfilled;
the tombstone table did not exist in 2.x and therefore cannot have an old row
count to preserve.

## 3. Align indexes and constraints

The 3.0 schemas use canonical table names and Ecto's canonical default index
names. After the table renames, compare the inventory with the names expected
by the schemas. In particular, the refresh store requires these unique indexes:

```text
attesto_authorization_codes_code_hash_index
attesto_refresh_tokens_token_hash_index
attesto_refresh_tokens_family_id_generation_index
dpop_nonces_nonce_index
```

The remaining lookup indexes must continue to cover the same keys and expiry
columns: device-code hash and user code, CIBA auth request hash, logout
`(sid, client_id)` and subject/expiry, DPoP replay expiry, PAR expiry, client
metadata expiry, consent expiry, and refresh/authorization expiry and family
lookups. Rename an old index after the table rename when only its name differs,
or create the canonical index concurrently in a separate migration when its
definition is missing. Never drop a unique index until its replacement has
been validated.

For the complete generated 2.x layout with old literal prefix `oauth_`, the
following reviewed renames align every generated primary-key constraint and
index after the ten tables have moved to schema `oauth`. Use the inventory to
confirm each old name exists. These commands are exact for the reviewed
`oauth_` example; for any other old prefix, use the exact names returned by the
inventory rather than mechanically substituting a long value (PostgreSQL can
truncate identifiers). Substitute only a validated target schema and stop on
an unexpected or missing name. `ALTER TABLE ... RENAME CONSTRAINT` also renames
its backing primary-key index. The unique and ordinary indexes use `ALTER INDEX`:

```sql
-- Primary-key constraints (the authorization-code table has no primary key).
ALTER TABLE "oauth".attesto_refresh_tokens
  RENAME CONSTRAINT oauth_attesto_refresh_tokens_pkey TO attesto_refresh_tokens_pkey;
ALTER TABLE "oauth".attesto_device_codes
  RENAME CONSTRAINT oauth_attesto_device_codes_pkey TO attesto_device_codes_pkey;
ALTER TABLE "oauth".attesto_ciba_requests
  RENAME CONSTRAINT oauth_attesto_ciba_requests_pkey TO attesto_ciba_requests_pkey;
ALTER TABLE "oauth".attesto_logout_sessions
  RENAME CONSTRAINT oauth_attesto_logout_sessions_pkey TO attesto_logout_sessions_pkey;
ALTER TABLE "oauth".dpop_nonces
  RENAME CONSTRAINT oauth_dpop_nonces_pkey TO dpop_nonces_pkey;
ALTER TABLE "oauth".dpop_replays
  RENAME CONSTRAINT oauth_dpop_replays_pkey TO dpop_replays_pkey;
ALTER TABLE "oauth".attesto_pushed_authorization_requests
  RENAME CONSTRAINT oauth_attesto_pushed_authorization_requests_pkey
  TO attesto_pushed_authorization_requests_pkey;
ALTER TABLE "oauth".attesto_client_id_metadata
  RENAME CONSTRAINT oauth_attesto_client_id_metadata_pkey TO attesto_client_id_metadata_pkey;
ALTER TABLE "oauth".attesto_consent_grants
  RENAME CONSTRAINT oauth_attesto_consent_grants_pkey TO attesto_consent_grants_pkey;

-- Unique and lookup indexes. Their definitions must match the pre-move inventory.
ALTER INDEX "oauth".oauth_attesto_authorization_codes_code_hash_index
  RENAME TO attesto_authorization_codes_code_hash_index;
ALTER INDEX "oauth".oauth_attesto_authorization_codes_expires_at_index
  RENAME TO attesto_authorization_codes_expires_at_index;
ALTER INDEX "oauth".oauth_attesto_authorization_codes_family_id_index
  RENAME TO attesto_authorization_codes_family_id_index;
ALTER INDEX "oauth".oauth_attesto_authorization_codes_access_token_jti_index
  RENAME TO attesto_authorization_codes_access_token_jti_index;
ALTER INDEX "oauth".oauth_attesto_refresh_tokens_token_hash_index
  RENAME TO attesto_refresh_tokens_token_hash_index;
ALTER INDEX "oauth".oauth_attesto_refresh_tokens_family_id_index
  RENAME TO attesto_refresh_tokens_family_id_index;
ALTER INDEX "oauth".oauth_attesto_refresh_tokens_expires_at_index
  RENAME TO attesto_refresh_tokens_expires_at_index;
ALTER INDEX "oauth".oauth_attesto_device_codes_device_code_hash_index
  RENAME TO attesto_device_codes_device_code_hash_index;
ALTER INDEX "oauth".oauth_attesto_device_codes_user_code_index
  RENAME TO attesto_device_codes_user_code_index;
ALTER INDEX "oauth".oauth_attesto_device_codes_expires_at_index
  RENAME TO attesto_device_codes_expires_at_index;
ALTER INDEX "oauth".oauth_attesto_ciba_requests_auth_req_id_hash_index
  RENAME TO attesto_ciba_requests_auth_req_id_hash_index;
ALTER INDEX "oauth".oauth_attesto_ciba_requests_expires_at_index
  RENAME TO attesto_ciba_requests_expires_at_index;
ALTER INDEX "oauth".oauth_attesto_logout_sessions_sid_client_id_index
  RENAME TO attesto_logout_sessions_sid_client_id_index;
ALTER INDEX "oauth".oauth_attesto_logout_sessions_subject_index
  RENAME TO attesto_logout_sessions_subject_index;
ALTER INDEX "oauth".oauth_attesto_logout_sessions_expires_at_index
  RENAME TO attesto_logout_sessions_expires_at_index;
ALTER INDEX "oauth".oauth_dpop_nonces_nonce_index
  RENAME TO dpop_nonces_nonce_index;
ALTER INDEX "oauth".oauth_dpop_nonces_unused_index
  RENAME TO dpop_nonces_unused_index;
ALTER INDEX "oauth".oauth_dpop_replays_expires_at_index
  RENAME TO dpop_replays_expires_at_index;
ALTER INDEX "oauth".oauth_attesto_pushed_authorization_requests_expires_at_index
  RENAME TO attesto_pushed_authorization_requests_expires_at_index;
ALTER INDEX "oauth".oauth_attesto_client_id_metadata_expires_at_index
  RENAME TO attesto_client_id_metadata_expires_at_index;
ALTER INDEX "oauth".oauth_attesto_consent_grants_expires_at_index
  RENAME TO attesto_consent_grants_expires_at_index;
```

After these renames, rerun the `pg_indexes` and `pg_constraint` inventory and
verify both canonical names and definitions. Do not rename an index whose
definition differs from the expected schema; create and validate a replacement
instead.

The complete `up/0` callback above includes the exact refresh-generation index
operation. If it fails because duplicate `(family_id, generation)` rows exist,
stop and reconcile/revoke the affected families; do not delete a row merely to
make the index build succeed. If index creation is split into a separate
forward migration, copy that operation from the complete `up/0` callback above
into that callback.

Verify the final definitions and canonical names with `pg_indexes` and
`pg_constraint` before changing application configuration. Remember that
Ecto's `prefix:` affects indexes as well as tables; an index in `public` does
not satisfy a table in `oauth`.

## 4. Switch configuration and deploy

Change the host config to the new public key and generate only future
migrations with the new flag:

```elixir
config :my_app, AttestoPhoenix.Config,
  schema_prefix: "oauth"
```

```bash
mix attesto_phoenix.gen.migration --repo MyApp.Repo --schema-prefix oauth
```

Do not leave `table_prefix: "oauth_"` in any config file. Do not pass
`--table-prefix`; both forms fail closed with an upgrade message. Start the
3.0 application only after the schema, table names, and index/constraint
definitions are in place. For a fresh installation, use `--schema-prefix` (or
the installer's `--schema-prefix`) before running the generated migration.

## 5. Verify row counts and runtime routing

Compare the precise counts recorded in step 1 with the renamed tables:

```sql
SELECT count(*) FROM oauth.attesto_authorization_codes;
SELECT count(*) FROM oauth.attesto_refresh_tokens;
SELECT count(*) FROM oauth.attesto_device_codes;
SELECT count(*) FROM oauth.attesto_ciba_requests;
SELECT count(*) FROM oauth.attesto_logout_sessions;
SELECT count(*) FROM oauth.dpop_nonces;
SELECT count(*) FROM oauth.dpop_replays;
SELECT count(*) FROM oauth.attesto_pushed_authorization_requests;
SELECT count(*) FROM oauth.attesto_client_id_metadata;
SELECT count(*) FROM oauth.attesto_consent_grants;
SELECT count(*) FROM oauth.attesto_refresh_family_revocations;
```

The first ten counts must match exactly unless the application was intentionally
quiesced with a separately documented data change. The tombstone count must
equal `count(DISTINCT family_id)` over rows where `family_revoked = true` in
`oauth.attesto_refresh_tokens`; verify that comparison explicitly:

```sql
SELECT
  (SELECT count(*) FROM oauth.attesto_refresh_family_revocations) AS tombstones,
  (SELECT count(DISTINCT family_id)
   FROM oauth.attesto_refresh_tokens
   WHERE family_revoked = true) AS distinct_revoked_families;
```

Confirm no old prefixed tables remain in
`public`, and confirm each target table resolves in the target schema:

```sql
SELECT to_regclass('oauth.attesto_authorization_codes'),
       to_regclass('oauth.attesto_refresh_tokens'),
       to_regclass('oauth.attesto_refresh_family_revocations');
```

Finally, perform a controlled authorization-code redemption, refresh rotation,
PAR consume, DPoP replay check, and revocation-family lookup while monitoring
the repo. A successful request in the wrong schema is not evidence of a safe
cutover: verify the SQL logs or database activity show the configured
`oauth` prefix for every Ecto operation. Keep the 2.x backup until these checks
and an agreed rollback window have completed.
