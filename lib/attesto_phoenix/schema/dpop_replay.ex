defmodule AttestoPhoenix.Schema.DPoPReplay do
  @moduledoc """
  Ecto schema for one recorded DPoP proof `jti` (JWT ID).

  RFC 9449 §11.1 requires the resource server to refuse a DPoP proof whose
  `jti` it has already processed. A captured-and-replayed proof would
  otherwise be reusable for the full `iat` acceptance window. An in-memory,
  per-node replay cache satisfies that requirement only when every request
  for a given access token lands on the same node; behind a load balancer on
  a clustered BEAM a captured proof is replayable once per node, which is a
  silently-broken security boundary.

  This schema backs the multi-node alternative: a shared, durable store of
  seen `jti` values that every node consults. The Ecto replay-check store
  inserts one row per proof with `INSERT ... ON CONFLICT DO NOTHING` so the
  check and the record are a single atomic round trip, and reads the
  affected-row count to decide accept (`:ok`) versus replay
  (`{:error, :replay}`). Because the record is durable and shared, the §11.1
  guarantee holds across the cluster.

  ## Columns

    * `jti` (`:string`, unique) - the proof's `jti` claim (RFC 9449 §4.2,
      RFC 7519 §4.1.7). The unique constraint is the atomic record-and-check
      primitive: a conflicting insert means the `jti` was already seen.
    * `expires_at` (`:utc_datetime_usec`) - the instant after which this row
      no longer needs to be retained. The store sets it to the proof's
      freshness horizon (insert time plus the acceptance window passed as
      `ttl_seconds`) so a proof whose `iat` window has closed is rejected by
      freshness OR by replay, never just by an eviction race. A periodic
      prune deletes rows whose `expires_at` is in the past; the store stays
      correct without pruning, since a re-presented `jti` still conflicts on
      the unique constraint until its row is deleted.
    * `inserted_at` (`:utc_datetime_usec`) - when the `jti` was first
      recorded. Diagnostic only; replay decisions never read it.

  The acceptance window is verifier policy, not schema policy: the store
  receives it as the `ttl_seconds` argument of the `:replay_check` callback
  shape (`(jti, ttl_seconds) -> :ok | {:error, :replay}`) and derives
  `expires_at` from it. This schema hardcodes no window and no retention.

  The matching table is produced by the migration generator; the
  `dpop_replays` source keeps the schema and the generated migration in
  agreement.
  """

  use Ecto.Schema

  import Ecto.Changeset

  # RFC 9449 §4.2 / RFC 7519 §4.1.7: the `jti` is an opaque string token, not
  # an integer surrogate key, and is itself unique. It is therefore the
  # primary key; there is no separate id column to leak or index.
  @primary_key {:jti, :string, autogenerate: false}

  @typedoc """
  A recorded DPoP `jti` row.
  """
  @type t :: %__MODULE__{
          jti: String.t() | nil,
          expires_at: DateTime.t() | nil,
          inserted_at: DateTime.t() | nil
        }

  schema "dpop_replays" do
    field :expires_at, :utc_datetime_usec

    # Only the insert instant is meaningful here; a `jti` is never updated, so
    # there is no `updated_at`.
    timestamps(updated_at: false, type: :utc_datetime_usec)
  end

  @required_fields [:jti, :expires_at]

  @doc """
  Build the changeset for recording a single seen `jti`.

  Both `jti` and `expires_at` are required; a row with a missing freshness
  horizon could never be pruned and a row with no `jti` could never be
  matched, so the changeset rejects either rather than persisting an unusable
  record (fail closed, no silent accept).

  The unique constraint on `jti` is declared so that a conflicting insert
  surfaces as a changeset error rather than a raised `Ecto.ConstraintError`,
  letting the replay-check store map the conflict to `{:error, :replay}`. The
  atomic record-and-check path uses `INSERT ... ON CONFLICT DO NOTHING`
  directly; this changeset is the validated entry point for callers that
  prefer the changeset API.
  """
  @spec changeset(t(), map()) :: Ecto.Changeset.t()
  def changeset(replay, attrs) do
    replay
    |> cast(attrs, @required_fields)
    |> validate_required(@required_fields)
    |> unique_constraint(:jti, name: :dpop_replays_pkey)
  end
end
