# 3.0 schema-prefix cutover

This is a stopped-cutover procedure for an existing `attesto_phoenix` 2.x
database. Read it before changing configuration or starting a 3.0 node.

## What the 2.x setting did (and did not) mean

The 2.x `:table_prefix` setting is not a reliable description of one runtime
database layout. In v2.14.2:

* the migration generator could prepend the value literally to table names in
  `public` (for example, `oauth_` produced
  `public.oauth_attesto_refresh_tokens`);
* most runtime stores ignored `:table_prefix` and queried the canonical table
  names in `public` (for example, `public.attesto_refresh_tokens`); and
* only `EctoCIBAStore` and `Sweeper` passed the value to Ecto as a schema
  prefix, looking for canonical table names in a PostgreSQL schema with that
  name.

Consequently, a non-empty 2.x value does not identify the source of every
table. A deployment may contain canonical public tables, literal-prefixed
tables created by a migration, schema/canonical tables used by the CIBA store
or sweeper, or more than one of these. Do not infer the live layout from the
old setting, and do not assume that the generated migration's table names
were the tables used by the runtime.

Version 3.0 removes `:table_prefix` and `--table-prefix`. It keeps the
canonical table names and uses `:schema_prefix` as an Ecto PostgreSQL schema
prefix. For example, `schema_prefix: "oauth"` means
`oauth.attesto_refresh_tokens`, not a table named
`oauth_attesto_refresh_tokens`.

## Stop first

Before inspecting or changing the database:

1. Stop every 2.x application node, worker, sweeper, scheduler, and other
   process that can write or delete Attesto rows. Do not start a 3.0 writer
   until this cutover is complete. Mixed 2.x/3.0 writers are strictly
   unsupported for four concrete reasons:
     * 3.0 records a durable tombstone and removes the family's refresh rows. A
       later 2.x insert checks only `family_revoked` rows, sees none, and can
       add a live token to the revoked family.
     * 2.x records revocation only on refresh rows. Once 3.0 cleanup removes
       every expired row in that family, it also removes the only revocation
       record because 2.x never wrote a tombstone.
     * 3.0 writes `v: 2` successor envelopes, which bind the child hash. A 2.x
       node can treat an honest retry of that rotation as reuse and revoke the
       family because it understands only `v: 1` envelopes.
     * Once the new `(family_id, generation)` unique index exists, a colliding
       2.x insert can raise an unhandled `Ecto.ConstraintError`; 3.0 reports the
       conflict through the store contract.
2. Take a database backup and rehearse the procedure against a restorable copy.
   Keep the pre-cutover backup until the post-cutover checks and a controlled
   production flow have succeeded.
3. Record the exact 2.x package version, all config sources, the old generator
   command, every configured `:table_prefix` value, and the repository/schema
   used by each deployment. A value in one config file may not have been the
   value used by every 2.x node.

If you cannot stop all writers, stop here. This guide does not support a live
or mixed-version migration.

3.0 also reads persisted authorization-code, device-code, CIBA, and refresh
claim maps through a lossless portable-JSON boundary. Rows containing unsupported
terms, invalid strings, unsafe integers, or other non-portable values fail
closed when read. Audit rows that must remain redeemable during the rehearsal;
changing the table location does not repair an incompatible claim map.

## 1. Inventory every candidate relation

The bundled migration has these canonical table names. The refresh-family
tombstone table is new in 3.0 and therefore has no 2.x source row set.

| Logical table | Canonical name |
| --- | --- |
| authorization codes | `attesto_authorization_codes` |
| refresh tokens | `attesto_refresh_tokens` |
| device codes | `attesto_device_codes` |
| CIBA requests | `attesto_ciba_requests` |
| logout sessions | `attesto_logout_sessions` |
| DPoP nonces | `dpop_nonces` |
| DPoP replays | `dpop_replays` |
| pushed authorization requests | `attesto_pushed_authorization_requests` |
| client metadata cache | `attesto_client_id_metadata` |
| consent grants | `attesto_consent_grants` |
| 3.0 refresh-family tombstones | `attesto_refresh_family_revocations` |

For each row in the table above, inventory all three candidates independently:

1. `public.<canonical_name>` — the canonical public relation used by most 2.x
   stores;
2. `public.<old_literal_prefix><canonical_name>` — the literal-prefixed
   relation a 2.x generated migration may have created; and
3. `<candidate_schema>.<canonical_name>` — the canonical relation in a schema
   that a CIBA store or sweeper may have selected, or that a host may have
   chosen manually.

Use the exact old literal prefix and candidate schema values found in the
deployment records. The following query only resolves names; it does not
create, rename, move, or delete anything. Replace `oauth_` and `oauth` with
reviewed identifiers before running it:

```sql
WITH expected(name) AS (VALUES
  ('attesto_authorization_codes'),
  ('attesto_refresh_tokens'),
  ('attesto_device_codes'),
  ('attesto_ciba_requests'),
  ('attesto_logout_sessions'),
  ('dpop_nonces'),
  ('dpop_replays'),
  ('attesto_pushed_authorization_requests'),
  ('attesto_client_id_metadata'),
  ('attesto_consent_grants'),
  ('attesto_refresh_family_revocations')
)
SELECT name AS canonical_name,
       to_regclass(format('public.%I', name)) AS public_canonical,
       to_regclass(format('public.%I', 'oauth_' || name)) AS public_literal_prefixed,
       to_regclass(format('%I.%I', 'oauth', name)) AS schema_canonical
FROM expected
ORDER BY name;
```

Also list relation owners, exact row counts, primary keys, indexes, and
foreign-key or check constraints for every relation that resolves. For exact
counts, run a reviewed query for each relation, for example:

```sql
SELECT count(*) FROM public.attesto_refresh_tokens;
SELECT count(*) FROM public.oauth_attesto_refresh_tokens;
SELECT count(*) FROM oauth.attesto_refresh_tokens;
```

Do not use `reltuples` as the cutover count. Save the exact results, including
zeroes, in the rehearsal and production records. Compare refresh `family_id`
and token hashes, authorization-code hashes, PAR request URIs, replay keys,
and other stable identifiers across candidates; equal row counts alone do not
prove that two relations contain the same data.

Inspect the 2.x source and observed behavior as well as the database:

* review the exact v2.14.2 configuration loaded by every node;
* review migration source and deployment history to determine whether literal
  table names were ever created;
* inspect repository query logs, database audit logs, or a temporary replay of
  the backed-up 2.x release to see which qualified relations each store read
  and wrote; and
* compare the candidate contents with a trusted backup from a time when the
  deployment was known to be serving traffic.

Use these observations to fill in a source-of-truth record for every logical
table. The source must be a specific qualified relation, not merely the old
`:table_prefix` value.

### Stop on split data

Stop the cutover and reconcile the data manually if any logical table has
non-empty rows in more than one candidate, including a public canonical
relation plus a public literal-prefixed relation, or a public relation plus a
schema/canonical relation. Also stop if query history, counts, stable-key
comparisons, and backups do not identify one live source.

Do not union candidate tables, choose the larger count, or delete one to make
the layout look consistent. Split authorization codes, refresh families,
consent grants, PAR references, replay records, CIBA requests, or revocations
can change security decisions. Preserve both relations and obtain a reviewed
data-reconciliation plan before continuing.

An empty stale candidate may remain for later audit, but record it and do not
use it as a source. The 3.0 cutover moves only a verified source relation.

Candidate relations may be absent during inventory, but absence is not valid
after cutover: every table in the selected ten-table 2.x source set must exist
exactly once in the target schema under its canonical name. A missing source or
target is a stop condition. Only an audited, empty stale candidate may remain
outside the target layout.

## 2. Select one 3.0 target layout

Choose one PostgreSQL schema for all Ecto-backed Attesto tables:

* leave `schema_prefix: nil` to use the Ecto/repo connection default/search_path
  (often `public`), or
* use one application-owned schema, such as `oauth`, with
  `schema_prefix: "oauth"`.

The target is exact: after the move, all ten bundled 2.x tables must be the
canonical names in this one schema. A canonical relation is not optional merely
because an alternate literal-prefixed relation exists; select and move the
verified source, then stop on any missing or colliding canonical target.

Create a non-public schema only after checking ownership and privileges. Before
moving any source, verify that every target canonical relation is absent or is
the already-verified source, and that target index and constraint names will
not collide. A relation in the target schema with unrelated rows is a stop
condition.

Do not run `mix attesto_phoenix.gen.migration` in fresh-install mode, or run its
generated create-table migration, against this existing database. Fresh mode
can attempt to create tables that already exist. The later
`--upgrade 3.0` mode generates only the two required refresh-family invariants;
neither mode is an inventory or data-move tool.

## 3. Move only verified sources

Use a reviewed forward migration or SQL session with validated identifiers.
Run one operation per verified source and check the result before continuing.
The examples below use target schema `oauth`; substitute only a reviewed
identifier.

For a verified canonical public source, move it into the target schema:

```sql
ALTER TABLE public.attesto_refresh_tokens SET SCHEMA oauth;
```

For a verified literal-prefixed public source, move and rename it:

```sql
ALTER TABLE public.oauth_attesto_refresh_tokens SET SCHEMA oauth;
ALTER TABLE oauth.oauth_attesto_refresh_tokens RENAME TO attesto_refresh_tokens;
```

Apply the same pattern to each of the ten 2.x logical tables, using the source
record to select the operation. A verified source that is already
`oauth.<canonical_name>` needs no move. If the chosen target is `public`, leave
the verified canonical public source in place and rename a verified literal
source only after checking that its canonical name is free.

Moving a table carries its indexes and constraints, but their names may still
contain the old literal prefix. Inventory them after each move and rename only
when the definition is the expected one and the canonical target name is free.
Do not drop a unique index or constraint merely to make a name fit. Keep a
record of old and new qualified names.

If a source relation is missing, a target collides, an ownership/privilege check
fails, or an operation affects a relation that was not in the source record,
stop and restore from the backup or roll back the reviewed migration.

## 4. Add the 3.0 and 3.1 invariants

### Add the refresh-family invariants

After the verified refresh-token source is in its target schema, use
attesto_phoenix 3.2 or later to generate the supported 3.0 upgrade migration:

First remove every legacy `:table_prefix` setting from the Mix environment the
task loads, after completing the inventory and while all writers remain
stopped. The generator rejects that retired setting even when an explicit
`--schema-prefix` is supplied. This prepares the migration command only; do not
start the 3.x application until the remaining verification and configuration
steps are complete.

```bash
# Use the configured schema_prefix; without one, the migration defers to the
# Ecto migrator/repo default (normally public). Keep that aligned with the
# runtime connection search path:
mix attesto_phoenix.gen.migration --upgrade 3.0 --repo MyApp.Repo

# Force public when the repo has a different migration default:
mix attesto_phoenix.gen.migration --upgrade 3.0 --repo MyApp.Repo --schema-prefix public

# When using a dedicated PostgreSQL schema:
mix attesto_phoenix.gen.migration --upgrade 3.0 --repo MyApp.Repo --schema-prefix oauth
```

The generated file is named
`<timestamp>_upgrade_attesto_phoenix_to_3_0.exs`. In one migration transaction
it:

1. applies a five-second transaction-local lock timeout, validates or creates
   the canonical unique index on
   `attesto_refresh_tokens(family_id, generation)`, and rejects a partial,
   expression, included-column, invalid, differently ordered, or otherwise
   noncanonical collision;
2. validates or creates the durable `attesto_refresh_family_revocations`
   table and its `family_id` primary key, refusing a partial or incompatible
   pre-existing object; and
3. backfills every distinct `family_revoked = true` family with an idempotent
   conflict-safe insert after the required DDL is visible.

The transaction rolls back all of those changes together if duplicate
generations, malformed catalog objects, or another validation failure is
found.

Apply the migration with `mix ecto.migrate`.

Contention and retry: If creation encounters lock contention on
`attesto_refresh_tokens` (PostgreSQL error 55P03:
`lock_not_available`), keep all token writers stopped, identify and wait for
or terminate the lock holder, and retry `mix ecto.migrate`.

Rollback also requires all 3.x writers to remain stopped. The migration locks
both refresh tables and refuses to drop a tombstone unless every corresponding
legacy `attesto_refresh_tokens` row exists and has `family_revoked = true`. A
family with a missing row or with mixed `family_revoked = true` and false rows
is rejected: 2.x cannot represent the durable revocation safely in either case.
Before starting 2.x code, wait out the longest active refresh retry deadline (or
accept that an honest retry may be treated as reuse), because 2.x cannot recover
3.x successor envelopes.

If migration execution reports duplicate `(family_id, generation)` rows, stop. Determine
the authoritative lineage, reconcile and revoke affected families, preserve
the audit trail, and retry only after review. Never delete a row just to make
the index build succeed. Never start a 3.0 writer before the migration and
tombstone backfill are complete.

### Promote the authorization-code index to a primary key

After moving the verified authorization-code source to its canonical target
name and applying the 3.0 migration, generate the 3.1 upgrade migration. It
accepts only the exact historical generated unique index or the exact
already-promoted primary key; malformed, renamed, partial, expression,
included-column, non-default-collation, or otherwise ambiguous layouts fail
closed for manual review.

```bash
mix attesto_phoenix.gen.migration --upgrade 3.1 --repo MyApp.Repo

# Dedicated PostgreSQL schema:
mix attesto_phoenix.gen.migration --upgrade 3.1 --repo MyApp.Repo --schema-prefix oauth
```

A source whose historical index retained a noncanonical name after a table
move needs a separately reviewed migration; the generator will not guess that
the renamed object has canonical semantics.

Complete this promotion before adding the table to a publication that
publishes `UPDATE` or `DELETE`; under the historical default identity, those
writes otherwise fail at the publisher. Logical replication does not copy DDL,
so apply the migration to the subscriber first, then to the publisher. The
generated migration preserves an explicit replica-identity selection when it
promotes or rolls back the canonical index.

## 5. Verify before changing application configuration

With writers still stopped:

1. Compare exact post-move counts with the recorded verified-source counts for
   all ten 2.x tables. Any unexplained difference is a stop condition.
2. Verify that the tombstone count equals
   `count(DISTINCT family_id)` in the target refresh-token table where
   `family_revoked = true`.
3. Verify the canonical table, primary-key/constraint, lookup-index, and named
   generation-index definitions in the target schema. Confirm indexes are in
   the same schema as their tables.
4. Confirm no unreviewed non-empty candidate relation remains. Keep empty stale
   relations until they have been audited; do not let them influence 3.0.
5. Do not start the old 2.14.2 deployment after moving relations. Its stores
   can miss the moved canonical tables or write stale literal-prefixed
   candidates. The 2.14.2 replay/observation belongs in the inventory phase
   against an untouched database clone. Post-move verification must use only
   3.0 and must confirm that every store resolves to the one target schema and
   canonical table name.

Only after these checks pass, confirm every old `:table_prefix` setting remains
removed and configure the 3.0 `:schema_prefix` key:

```elixir
config :my_app, AttestoPhoenix.Config,
  schema_prefix: "oauth" # nil uses the Ecto/repo connection default/search_path (often public)
```

For future fresh databases, generate tables with the schema option:

```bash
mix attesto_phoenix.gen.migration --repo MyApp.Repo --schema-prefix oauth
```

The installer accepts the same `--schema-prefix` option. Do not pass
`--table-prefix`, and do not use a fresh create-table migration as a substitute
for this cutover.

Start 3.0 only after the configuration, target tables, unique generation index,
and durable tombstones are in place. Then run a controlled authorization-code
redemption, refresh rotation and retry, PAR consume, DPoP replay check, CIBA
request (if enabled), and revocation check while monitoring qualified database
relations. Keep the backup until these flows and the first scheduled sweep have
completed successfully.
