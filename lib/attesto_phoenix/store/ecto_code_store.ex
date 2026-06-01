defmodule AttestoPhoenix.Store.EctoCodeStore do
  @moduledoc """
  Ecto implementation of the `Attesto.CodeStore` behaviour.

  Authorization codes are single-use (RFC 6749 §4.1.2) and, with PKCE
  mandatory (RFC 7636), the code is the only browser-deliverable secret in
  the authorization-code flow. The single-use guarantee therefore cannot be
  advisory: it must be enforced by the store so that two concurrent
  redemptions of one code cannot both succeed.

  `take/1` issues an `UPDATE ... WHERE consumed_at IS NULL RETURNING ...`, so
  the fetch and the consumption mark are one statement. Exactly one of any
  number of racing redemptions sees the row as fresh; later callers either get
  `:error` for an unsuccessful first presentation or `{:error, :consumed, meta}`
  for a code that was already successfully redeemed. This holds across all
  nodes sharing the database. The code is consumed even when the caller later
  rejects the redemption (mismatched redirect URI, failed PKCE verifier): a code
  presented once is spent, which denies an attacker repeated validation
  attempts against a captured code.

  The plaintext code is never persisted; the primary key is the
  `Attesto.Secret.hash/1` digest of the code. The column layout and the
  record bridge live in `AttestoPhoenix.Schema.Authorization`; this module
  only owns the two atomic database operations.

  The repository module is supplied by the host application (`:repo` under
  the `:attesto_phoenix` app) and is read at call time. A store with no
  backing repository can make no guarantees, so a missing `:repo` fails
  closed rather than silently no-opping.
  """

  @behaviour Attesto.CodeStore

  import Ecto.Query, only: [from: 2]

  alias AttestoPhoenix.Schema.Authorization

  @app :attesto_phoenix

  @doc """
  Persists an authorization-code record keyed by its `:code_hash`.

  The record is the plain map the protocol layer hands over: a `:code_hash`,
  the opaque grant `:data`, and an integer `:expires_at` in unix seconds.
  `AttestoPhoenix.Schema.Authorization.from_record/1` spreads it across the
  row's columns and validates it fail-closed (missing required field or a
  non-`S256` PKCE method is rejected, not defaulted).

  The hash is the primary key, so a duplicate insert is a caller bug:
  `Attesto.AuthorizationCode` derives the hash from freshly generated random
  bytes, so a collision means the random source repeated or the same entry
  was put twice. `insert!/1` raises on the unique-constraint violation rather
  than silently overwriting an existing, possibly already-issued, code. Fail
  closed; no upsert.
  """
  @impl Attesto.CodeStore
  @spec put(Attesto.CodeStore.entry()) :: :ok
  def put(%{code_hash: code_hash, data: data, expires_at: expires_at} = record)
      when is_binary(code_hash) and is_map(data) and is_integer(expires_at) do
    record
    |> Authorization.from_record()
    |> repo().insert!()

    :ok
  end

  @doc """
  Atomically fetches and deletes the record for `code_hash`.

  Returns `{:ok, entry}` when the row existed (and is now gone), or `:error`
  when it was absent. The fetch and the delete are one indivisible statement
  (`DELETE ... RETURNING`), so the single-use contract of `Attesto.CodeStore`
  holds against concurrent redemptions.

  The loaded row is folded back into the `:code_hash` / `:data` /
  `:expires_at` (unix seconds) map via
  `AttestoPhoenix.Schema.Authorization.to_record/1`. Expiry is not checked
  here: `Attesto.AuthorizationCode` re-checks `:expires_at` after `take/1`,
  and consuming the row regardless of freshness preserves single use, since
  an expired-but-present code is still spent on first presentation.
  """
  @impl Attesto.CodeStore
  @spec take(Attesto.CodeStore.code_hash()) :: {:ok, Attesto.CodeStore.entry()} | :error
  def take(code_hash) when is_binary(code_hash) do
    consumed_at = DateTime.utc_now() |> DateTime.truncate(:second)

    query =
      from a in Authorization,
        where: a.code_hash == ^code_hash and is_nil(a.consumed_at),
        select: a

    case repo().update_all(query, set: [consumed_at: consumed_at]) do
      {1, [row]} -> {:ok, Authorization.to_record(row)}
      {0, _} -> consumed_or_missing(code_hash)
    end
  end

  @doc """
  Marks a successfully redeemed code as reuse-trackable.

  `Attesto.AuthorizationCode.redeem/4` calls this after every validation step
  has passed. A later `take/1` for the same hash can then surface
  `{:error, :consumed, meta}` instead of treating the replay as an unknown code.
  """
  @impl Attesto.CodeStore
  @spec mark_consumed(Attesto.CodeStore.code_hash(), Attesto.CodeStore.consumed_meta()) :: :ok
  def mark_consumed(code_hash, _meta) when is_binary(code_hash) do
    query = from a in Authorization, where: a.code_hash == ^code_hash
    repo().update_all(query, set: [consumed_success: true])
    :ok
  end

  @doc false
  @spec record_access_token(String.t(), String.t(), integer()) :: :ok
  def record_access_token(family_id, jti, expires_at)
      when is_binary(family_id) and is_binary(jti) and is_integer(expires_at) do
    query = from a in Authorization, where: a.family_id == ^family_id

    repo().update_all(query,
      set: [
        access_token_jti: jti,
        access_token_expires_at: DateTime.from_unix!(expires_at)
      ]
    )

    :ok
  end

  @doc false
  @spec revoke_family_access_tokens(String.t()) :: :ok
  def revoke_family_access_tokens(family_id) when is_binary(family_id) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    query =
      from a in Authorization,
        where: a.family_id == ^family_id and not is_nil(a.access_token_jti)

    repo().update_all(query, set: [access_token_revoked_at: now])
    :ok
  end

  @doc false
  @spec access_token_revoked?(String.t()) :: boolean()
  def access_token_revoked?(jti) when is_binary(jti) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    query =
      from a in Authorization,
        where:
          a.access_token_jti == ^jti and not is_nil(a.access_token_revoked_at) and
            a.access_token_expires_at > ^now

    repo().exists?(query)
  end

  defp consumed_or_missing(code_hash) do
    case repo().get_by(Authorization, code_hash: code_hash) do
      %Authorization{consumed_success: true} = row ->
        {:error, :consumed, Authorization.consumed_meta(row)}

      _ ->
        :error
    end
  end

  defp repo do
    case Application.get_env(@app, :repo) do
      nil ->
        # Fail closed: a code store with no backing repository cannot enforce
        # single use, so refuse rather than silently no-op.
        raise ArgumentError,
              "AttestoPhoenix: no :repo configured. Set `config #{inspect(@app)}, repo: MyApp.Repo`"

      repo ->
        repo
    end
  end
end
