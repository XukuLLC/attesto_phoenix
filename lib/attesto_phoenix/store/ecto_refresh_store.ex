defmodule AttestoPhoenix.Store.EctoRefreshStore do
  @moduledoc """
  Ecto implementation of the `Attesto.RefreshStore` behaviour.

  The protocol core (`Attesto.RefreshToken`) owns all rotation logic and reuse
  detection; this module is purely the storage seam. It persists refresh-token
  records over `AttestoPhoenix.Schema.RefreshToken` and provides the atomic
  single-use claim on which reuse detection depends (RFC 6749 §10.4, OAuth 2.0
  Security BCP §4.13).

  ## Why the claim must be atomic

  Rotation requires detecting when an already-rotated (consumed) token is
  presented again: that is the captured-token signal, and the whole family
  must then be revoked. Reliable detection needs a compare-and-set that, in
  one indivisible step, checks the token is unconsumed and marks it consumed.
  Here that is a single conditional `UPDATE ... RETURNING`:

      UPDATE attesto_refresh_tokens
         SET consumed = true, consumed_at = now()
       WHERE token_hash = $1 AND consumed = false
      RETURNING ...

  Zero rows updated *with a row still present* means the token was already
  consumed: reuse. A non-atomic read-then-write would let two concurrent
  rotations both observe "unconsumed" and both succeed, defeating detection.
  This holds across all nodes sharing the database, which the single-node ETS
  store cannot offer. `consume/1` returns `{:ok, entry}` to the single winner,
  `{:reuse, entry}` on a replay, and `:error` for an unknown token.

  ## Sticky revocation

  `revoke_family/1` marks every row in the family revoked (it does not delete
  them) so the revocation persists. A subsequent `insert/1` checks the family
  before writing and refuses with `{:error, :family_revoked}`, so a successor
  whose claim won before the revocation landed cannot be added to a revoked
  family. Revocation therefore rejects later inserts, not only the rows present
  when it ran. The check and the insert run in one transaction so no concurrent
  revocation can interleave between them.

  The repo is resolved from the application environment (`:repo` under the
  `:attesto_phoenix` app) so the host owns the connection; nothing here
  hardcodes an OTP app's repo, and a missing repo fails closed.
  """

  @behaviour Attesto.RefreshStore

  import Ecto.Query

  alias AttestoPhoenix.Schema.RefreshToken
  alias Plug.Crypto.MessageEncryptor

  @app :attesto_phoenix
  @successor_aad "attesto_phoenix:refresh_successor:v1"

  # Namespace (first key of Postgres' two-argument advisory-lock form) for the
  # per-family rotation/revocation serialization locks, so they cannot collide
  # with advisory locks any other subsystem takes. Arbitrary but stable.
  @advisory_lock_namespace 0x4154_5246

  @doc """
  Persists a new (unconsumed) refresh-token record.

  Returns `{:error, :family_revoked}` when the record's `:family_id` has
  already been revoked, and the row is NOT written. The revocation check and
  the insert run in one transaction holding a per-family advisory lock (shared
  with `revoke_family/1`), so a concurrent revocation cannot interleave and
  leave a live successor in a revoked family (sticky revocation, RFC 6749
  §10.4). A plain `FOR UPDATE` on the existing rows would not suffice: under
  `READ COMMITTED` a revoking `UPDATE` that began before this insert committed
  would not see the just-inserted successor (a phantom), leaving it live. The
  advisory lock serializes the two operations outright, so a revocation that
  loses the race still runs its `UPDATE` on a fresh snapshot that includes the
  new row. The opaque store record is flattened onto the schema columns by
  `AttestoPhoenix.Schema.RefreshToken.from_store_record/2`.
  """
  @impl Attesto.RefreshStore
  @spec insert(Attesto.RefreshStore.entry()) :: :ok | {:error, :family_revoked}
  def insert(%{token_hash: token_hash, family_id: family_id} = record)
      when is_binary(token_hash) and is_binary(family_id) do
    result =
      repo().transaction(fn ->
        lock_family!(family_id)

        if family_revoked?(family_id) do
          # Sticky revocation: refuse a successor whose claim won before the
          # revocation landed (RFC 6749 §10.4 family revocation).
          repo().rollback(:family_revoked)
        else
          %RefreshToken{}
          |> RefreshToken.insert_changeset(RefreshToken.from_store_record(record))
          |> repo().insert!()

          :ok
        end
      end)

    case result do
      {:ok, :ok} -> :ok
      {:error, :family_revoked} -> {:error, :family_revoked}
    end
  end

  @doc """
  Non-consuming read of the record for `token_hash`, or `:error` if absent or
  family-revoked.

  Returns the record in the `Attesto.RefreshStore` contract shape (opaque
  `:data` context, `:expires_at` as absolute unix seconds). Used by
  `Attesto.RefreshToken` to validate a rotation (expiry, client and DPoP
  binding) and to detect an already-consumed replay before the atomic claim,
  so a recoverable validation failure does not burn the token.
  """
  @impl Attesto.RefreshStore
  @spec get(Attesto.RefreshStore.token_hash()) :: {:ok, Attesto.RefreshStore.entry()} | :error
  def get(token_hash) when is_binary(token_hash) do
    case repo().get_by(RefreshToken, token_hash: token_hash, family_revoked: false) do
      %RefreshToken{} = row -> {:ok, RefreshToken.to_store_record(row)}
      nil -> :error
    end
  end

  @doc """
  Atomically marks the token consumed if it was not already.

  Returns `{:ok, entry}` to the single caller that wins the claim (the record
  is reported as it stood, unconsumed, since the successor is minted from it),
  `{:reuse, entry}` when the token was already consumed (the caller MUST then
  `revoke_family/1`; the entry carries the `:family_id`), or `:error` for an
  unknown token. The conditional `UPDATE ... WHERE consumed = false RETURNING`
  is one indivisible statement, so concurrent rotations cannot both win.
  """
  @impl Attesto.RefreshStore
  @spec consume(Attesto.RefreshStore.token_hash(), keyword()) ::
          {:ok, Attesto.RefreshStore.entry()} | {:reuse, Attesto.RefreshStore.entry()} | :error
  def consume(token_hash, opts \\ []) when is_binary(token_hash) and is_list(opts) do
    consumed_at = opts |> Keyword.get(:now, System.system_time(:second)) |> to_datetime()

    # The atomic claim: only a row that is still unconsumed flips to consumed,
    # and the affected-row count disambiguates the winner from every concurrent
    # loser. RETURNING hands back the claimed row.
    query =
      from r in RefreshToken,
        where: r.token_hash == ^token_hash and r.consumed == false and r.family_revoked == false,
        select: r

    case repo().update_all(query, set: [consumed: true, consumed_at: consumed_at]) do
      {1, [row]} ->
        # Won the claim. Report the record as it stood (unconsumed): the next
        # token in the family is minted from it.
        {:ok, RefreshToken.to_store_record(%{row | consumed: false, consumed_at: nil})}

      {0, _} ->
        classify_consume_miss(token_hash)
    end
  end

  @doc """
  Records the successor minted by a consumed parent token.

  The core uses this for refresh-rotation idempotency: an immediate retry of a
  just-rotated token by the same client can receive the same successor rather
  than revoking the family. Only consumed parents accept a successor marker.
  The marker is encrypted before it is written to the database; if no
  `:refresh_successor_secret` is configured, the store fails closed by returning
  `:error`.
  """
  @impl Attesto.RefreshStore
  @spec remember_successor(Attesto.RefreshStore.token_hash(), map(), keyword()) :: :ok | :error
  def remember_successor(token_hash, successor, opts \\ [])
      when is_binary(token_hash) and is_map(successor) and is_list(opts) do
    with {:ok, protected} <- protect_successor(successor) do
      query =
        from r in RefreshToken,
          where: r.token_hash == ^token_hash and r.consumed == true and r.family_revoked == false

      case repo().update_all(query, set: [successor: protected]) do
        {1, _} -> :ok
        {0, _} -> :error
      end
    end
  end

  @doc """
  Revokes a token family: marks every token in `family_id` revoked.

  The rows are kept (their `:family_revoked` flag is set) rather than deleted,
  so the revocation is sticky: a successor `insert/1` serialized after this call
  is refused (see `insert/1`). The revocation runs in a transaction holding the
  same per-family advisory lock as `insert/1`, so a concurrent successor insert
  cannot slip a live row past it: a revocation that wins the lock is seen by the
  later insert (refused); one that loses runs its `UPDATE` after the insert has
  committed, on a fresh snapshot that includes the new row. Idempotent:
  re-revoking is a no-op re-set, and revoking an unknown family updates nothing
  and returns `:ok`.
  """
  @impl Attesto.RefreshStore
  @spec revoke_family(Attesto.RefreshStore.family_id()) :: :ok
  def revoke_family(family_id) when is_binary(family_id) do
    repo().transaction(fn ->
      lock_family!(family_id)
      query = from r in RefreshToken, where: r.family_id == ^family_id
      repo().update_all(query, set: [family_revoked: true])
    end)

    :ok
  end

  # RFC 6749 §10.4 sticky revocation depends on `insert/1` and `revoke_family/1`
  # never interleaving for one family. A Postgres advisory transaction lock keyed
  # on the family id serializes them (held until the surrounding transaction
  # ends). `hashtext/1` maps the family id to the int4 key the two-argument
  # advisory-lock form takes; the constant first key namespaces these locks to
  # this store so they cannot collide with another subsystem's advisory locks.
  defp lock_family!(family_id) do
    repo().query!("SELECT pg_advisory_xact_lock($1::int4, hashtext($2))", [@advisory_lock_namespace, family_id])
  end

  # No row was claimable: either the token is unknown, or it was already
  # consumed. A non-consuming read distinguishes them, so an unknown token
  # never trips reuse detection (there is no family to revoke). No silent
  # reject: each outcome maps to a distinct, explicit return value.
  defp classify_consume_miss(token_hash) do
    case repo().get_by(RefreshToken, token_hash: token_hash) do
      %RefreshToken{family_revoked: true} -> :error
      %RefreshToken{consumed: true} = row -> {:reuse, RefreshToken.to_store_record(row)}
      %RefreshToken{} -> :error
      nil -> :error
    end
  end

  defp family_revoked?(family_id) do
    query =
      from r in RefreshToken,
        where: r.family_id == ^family_id and r.family_revoked == true

    repo().exists?(query)
  end

  defp to_datetime(%DateTime{} = dt), do: dt
  defp to_datetime(seconds) when is_integer(seconds), do: DateTime.from_unix!(seconds, :second)

  defp protect_successor(successor) do
    with {:ok, enc_key, sign_key} <- successor_keys() do
      ciphertext =
        successor
        |> :erlang.term_to_binary()
        |> MessageEncryptor.encrypt(@successor_aad, enc_key, sign_key)

      {:ok, %{"v" => 1, "ciphertext" => ciphertext}}
    end
  end

  defp successor_keys do
    case Application.get_env(@app, :refresh_successor_secret) do
      secret when is_binary(secret) and byte_size(secret) >= 32 ->
        {:ok, :crypto.hash(:sha256, "refresh-successor:enc:" <> secret),
         :crypto.hash(:sha256, "refresh-successor:sign:" <> secret)}

      _ ->
        :error
    end
  end

  defp repo do
    case Application.get_env(@app, :repo) do
      nil ->
        # Fail closed: a refresh store with no backing repository cannot make
        # any rotation decision safely, so refuse rather than silently degrade.
        raise ArgumentError,
              "#{inspect(__MODULE__)} requires an Ecto.Repo configured as " <>
                "config #{inspect(@app)}, repo: MyApp.Repo"

      repo ->
        repo
    end
  end
end
