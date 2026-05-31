defmodule AttestoPhoenix.Store.EctoReplayCheck do
  @moduledoc """
  Ecto-backed, shared-store `jti` replay check for DPoP proofs
  (RFC 9449 §11.1).

  RFC 9449 §11.1 requires the resource server to refuse a DPoP proof whose
  `jti` it has already processed. A captured-and-replayed proof would
  otherwise be reusable for the full `iat` acceptance window (typically 60
  seconds).

  `check_and_record/2` implements the `(jti, ttl_seconds) -> :ok |
  {:error, :replay}` callback shape that `Attesto.DPoP.verify_proof/2`
  invokes via its `:replay_check` option. Records live in one relational
  table (`AttestoPhoenix.Schema.DPoPReplay`), so the check is correct
  *across every node* of a multi-node deployment: a `jti` recorded on any
  node is rejected on every other. The verifier passes its own
  `:max_age_seconds` as `ttl_seconds`, so each record's retention is sized
  to the proof's freshness window.

  ## Why a shared store

  `Attesto.DPoP.ReplayCache` is a per-node ETS singleton. RFC 9449 §11.1
  replay rejection only holds across a deployment if every request for a
  given access token reaches the same node - otherwise a captured proof is
  replayable once per node behind a load balancer. A multi-node deployment
  MUST therefore use a shared store such as this one. A single-node host
  may instead wire `Attesto.DPoP.ReplayCache` directly and skip the
  database round-trip.

  ## Atomic record-and-check

  `check_and_record/2` inserts the `jti` with its `expires_at`:

    * `:ok` - the row was inserted; this `jti` had not been seen.
    * `{:error, :replay}` - the insert hit the unique constraint on `jti`
      (the table's primary key); this `jti` was already recorded and the
      proof is a replay.

  The decision is made by the database's unique constraint, not by a
  read-then-write in the application, so two concurrent requests carrying
  the same `jti` (on one node or several) cannot both observe `:ok`:
  exactly one insert wins and every other observes the conflict. This is
  the relational equivalent of `INSERT ... ON CONFLICT DO NOTHING` and is
  the property that makes the check safe across nodes.

  An already-`expires_at`-elapsed row for the same `jti` is treated as a
  collision and rejected rather than overwritten. That is not a
  correctness gap: a proof whose `iat` window has closed is rejected by
  DPoP freshness before replay is even consulted, so the only effect is to
  fail closed on an unreachable corner. The periodic sweep reclaims
  expired rows so the table does not grow without bound.

  ## Periodic sweep

  Rows whose `expires_at` is in the past are no longer security-relevant
  (a repeat of the same `jti` is rejected by DPoP freshness before replay
  is consulted), so they are deleted in bulk by
  `AttestoPhoenix.Store.Sweeper`, the package's GenServer sweeper, on a
  fixed interval. The check is correct without the sweeper running; the
  sweeper only reclaims space.

  ## Configuration

  All policy is read from configuration; nothing is hardcoded. The backing
  `Ecto.Repo` is the one configured for the library
  (`config :attesto_phoenix, repo: MyApp.Repo`), the same value
  `AttestoPhoenix.Config` carries under `:repo`. It is read at call time
  and a missing repo fails closed: a replay check with no backing store
  could make no decision safely.

  ## Wiring

  Use it as the verifier's `:replay_check`:

      Attesto.DPoP.verify_proof(proof,
        http_method: "GET",
        http_uri: uri,
        replay_check: &AttestoPhoenix.Store.EctoReplayCheck.check_and_record/2
      )
  """

  import Ecto.Query, only: [from: 2]

  alias AttestoPhoenix.Schema.DPoPReplay

  @app :attesto_phoenix

  @default_ttl_seconds 60

  @doc """
  Record `jti` and report whether it has already been seen within its TTL
  window.

  Returns `:ok` when the `jti` was not present and has now been recorded,
  or `{:error, :replay}` when an entry already exists. The two-argument
  form takes the `jti` and the number of seconds to retain it, which is
  the shape `Attesto.DPoP.verify_proof/2` passes its `:replay_check`
  callback (the verifier derives the TTL from its own acceptance window).
  Pass `&check_and_record/2` directly. The TTL argument defaults to
  #{@default_ttl_seconds} seconds when called as `check_and_record/1`.

  The `Ecto.Repo` is read from configuration; replay policy is never
  hardcoded here.
  """
  @spec check_and_record(String.t(), pos_integer()) :: :ok | {:error, :replay}
  def check_and_record(jti, ttl_seconds \\ @default_ttl_seconds)
      when is_binary(jti) and is_integer(ttl_seconds) and ttl_seconds > 0 do
    expires_at = DateTime.add(DateTime.utc_now(), ttl_seconds, :second)

    changeset =
      DPoPReplay.changeset(%DPoPReplay{}, %{jti: jti, expires_at: expires_at})

    case repo().insert(changeset) do
      {:ok, _record} ->
        :ok

      {:error, %Ecto.Changeset{errors: errors}} ->
        # A unique-constraint violation on `jti` is the replay signal. Any
        # other changeset error is a caller bug or a schema mismatch and
        # must surface loudly, never be masked as "not a replay" (which
        # would silently accept a proof that should have been recorded).
        if Keyword.has_key?(errors, :jti) do
          {:error, :replay}
        else
          raise ArgumentError,
                "#{inspect(__MODULE__)}: unexpected insert error: #{inspect(errors)}"
        end
    end
  end

  @doc """
  Delete every recorded `jti` whose `expires_at` has elapsed and return the
  count.

  `AttestoPhoenix.Store.Sweeper` drives the periodic sweep across all
  Ecto-backed tables; this function exposes the replay-table sweep on its
  own for hosts that prefer to drive it from their own scheduler. Deletion
  uses a strict `<` comparison against a single captured "now", so a row
  whose `expires_at` equals "now" is retained, never deleted: the sweep
  widens no acceptance window.
  """
  @spec sweep() :: non_neg_integer()
  def sweep do
    now = DateTime.utc_now()

    {deleted, _} =
      repo().delete_all(from(r in DPoPReplay, where: r.expires_at < ^now))

    deleted
  end

  defp repo do
    case Application.get_env(@app, :repo) do
      nil ->
        # Fail closed: a replay check with no backing repository cannot
        # enforce RFC 9449 §11.1, so refuse rather than silently accept.
        raise ArgumentError,
              "#{inspect(__MODULE__)} requires an Ecto.Repo. " <>
                "Set `config #{inspect(@app)}, repo: MyApp.Repo`"

      repo ->
        repo
    end
  end
end
