defmodule AttestoPhoenix.Store.EctoNonceStore do
  @moduledoc """
  Postgres-backed `Attesto.DPoP.NonceStore` for clustered deployments
  (RFC 9449 §8).

  A server may require a server-issued `nonce` in every DPoP proof, binding
  each proof to a short-lived, server-chosen value. This defeats proof
  pre-generation and narrows the replay window beyond what the `jti` cache
  (RFC 9449 §11.1) alone provides. An in-memory store cannot share a nonce
  across nodes: a nonce issued on one node would be unknown to another. This
  implementation persists each nonce so any node honours a nonce issued by any
  other.

  ## Behaviour callbacks

    * `issue/1` mints, persists, and returns an opaque nonce for the
      `DPoP-Nonce` response header (RFC 9449 §8.1). The TTL is recorded on the
      row as a concrete `expires_at` so a later check needs no TTL argument.
    * `valid?/1` reports whether a nonce was issued by this store, has not
      expired, and has not yet been consumed. It is read-only, so it is the
      shape `Attesto.DPoP.verify_proof/2` expects for `:nonce_check` when the
      caller does not need single-use consumption.

  ## Single-use consume

  A read-only check cannot make a nonce single-use under concurrency: two
  requests could both observe the same live nonce. `accept/2` is the atomic
  consume primitive that delivers the single-use guarantee (RFC 9449 §8). It
  marks the nonce used and returns `:ok` to exactly one caller, or
  `{:error, :used | :expired | :unknown}` to every other, via one conditional
  statement:

      UPDATE dpop_nonces
         SET used_at = $now
       WHERE nonce = $nonce AND used_at IS NULL AND issued_at >= $cutoff

  Postgres serialises concurrent updates to the same row, so exactly one
  caller observes an affected-row count of `1` (the winner) and the rest
  observe `0`. No read-modify-write race exists.

  ## TTL

  `issue/1` records issuance and the derived expiry; `accept/2` also takes the
  TTL so the caller's policy, not this store, fixes the freshness window. A
  nonce whose `issued_at` is older than `now - ttl` is rejected with
  `{:error, :expired}` (RFC 9449 §8).

  The repository and schema prefix are read as one pair from the supplied
  `AttestoPhoenix.Config`. Behaviour-only calls use the shared
  `AttestoPhoenix.Config.ecto_repo!/0` and
  `AttestoPhoenix.Config.table_prefix/0` accessors, so request-local
  routing and the configured host application follow the same rules as every
  other Ecto store. The removed 2.x `:config` key is never consulted.
  """

  @behaviour Attesto.DPoP.NonceStore

  import Ecto.Query

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Schema.DPoPNonce
  alias AttestoPhoenix.Store.Sweeper

  # RFC 9449 §8 requires an unpredictable nonce. 256 bits from a CSPRNG,
  # URL-safe base64 with no padding so the value is header-safe.
  @nonce_bytes 32
  @default_ttl_seconds 300

  @doc """
  Mints and persists a fresh nonce valid for `ttl_seconds`, returning the
  opaque value to put in a `DPoP-Nonce` header. Behaviour entrypoint; resolves
  the repo from the application-wide configured `AttestoPhoenix.Config`.
  """
  @spec issue() :: String.t()
  def issue, do: issue(@default_ttl_seconds)

  @doc """
  Mints and persists a fresh nonce valid for `ttl_seconds`, returning the
  opaque value to put in a `DPoP-Nonce` header. Behaviour entrypoint; resolves
  the repo from the application-wide configured `AttestoPhoenix.Config`.
  """
  @impl true
  @spec issue(pos_integer()) :: String.t()
  def issue(ttl_seconds), do: issue_with(Config.ecto_repo!(), Config.table_prefix(), ttl_seconds)

  @doc "Like `issue/1`, using an explicit `AttestoPhoenix.Config`."
  @spec issue(Config.t(), pos_integer()) :: String.t()
  def issue(%Config{} = config, ttl_seconds) when is_integer(ttl_seconds) and ttl_seconds > 0 do
    issue_with(config.repo, Config.table_prefix(config), ttl_seconds)
  end

  defp issue_with(repo, prefix, ttl_seconds) do
    Sweeper.check_running_for_store(repo, prefix)
    nonce = :crypto.strong_rand_bytes(@nonce_bytes) |> Base.url_encode64(padding: false)
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    expires_at = DateTime.add(now, ttl_seconds, :second)

    DPoPNonce.issue_changeset(
      %DPoPNonce{},
      %{nonce: nonce, issued_at: now, expires_at: expires_at},
      prefix: prefix
    )
    |> repo.insert!(prefix: prefix, log: false, telemetry_event: nil)

    nonce
  end

  @doc """
  Returns true iff `nonce` was issued by this store, has not expired, and has
  not been consumed. Behaviour entrypoint; resolves the repo from the
  application-wide configured `AttestoPhoenix.Config`.
  """
  @impl true
  @spec valid?(String.t()) :: boolean()
  def valid?(nonce) when is_binary(nonce), do: valid_with(Config.ecto_repo!(), Config.table_prefix(), nonce)
  def valid?(_), do: false

  @doc "Like `valid?/1`, using an explicit `AttestoPhoenix.Config`."
  @spec valid?(Config.t(), String.t()) :: boolean()
  def valid?(%Config{} = config, nonce) when is_binary(nonce) do
    valid_with(config.repo, Config.table_prefix(config), nonce)
  end

  def valid?(%Config{}, _), do: false

  defp valid_with(repo, prefix, nonce) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    query =
      from(n in DPoPNonce,
        where: n.nonce == ^nonce and is_nil(n.used_at) and n.expires_at > ^now,
        select: true
      )

    repo.one(query, prefix: prefix, log: false, telemetry_event: nil) == true
  end

  @doc """
  Atomically consumes `nonce` under a freshness window of `ttl` seconds.

  Returns `:ok` to the single caller that wins the consume, and a precise
  reason to every other so the server can answer with the correct DPoP error
  (RFC 9449 §8) rather than silently rejecting (fail-closed):

    * `{:error, :used}` - the nonce was already consumed.
    * `{:error, :expired}` - the nonce is past the freshness window.
    * `{:error, :unknown}` - the nonce was never issued by this store.

  Behaviour-style entrypoint; resolves the repo from the application-wide
  configured `AttestoPhoenix.Config`.
  """
  @spec accept(String.t(), pos_integer()) :: :ok | {:error, :used | :expired | :unknown}
  def accept(nonce, ttl), do: accept_with(Config.ecto_repo!(), Config.table_prefix(), nonce, ttl)

  @doc "Like `accept/2`, using an explicit `AttestoPhoenix.Config`."
  @spec accept(Config.t(), String.t(), pos_integer()) ::
          :ok | {:error, :used | :expired | :unknown}
  def accept(%Config{} = config, nonce, ttl) when is_binary(nonce) and is_integer(ttl) and ttl > 0 do
    accept_with(config.repo, Config.table_prefix(config), nonce, ttl)
  end

  defp accept_with(repo, prefix, nonce, ttl) do
    Sweeper.check_running_for_store(repo, prefix)
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    cutoff = DateTime.add(now, -ttl, :second)

    # Atomic compare-and-swap: only a row that is still unused AND not yet
    # expired flips to used. The affected-row count disambiguates the winner
    # from every concurrent loser (RFC 9449 §8 single-use requirement).
    {count, _} =
      from(n in DPoPNonce,
        where:
          n.nonce == ^nonce and is_nil(n.used_at) and n.issued_at >= ^cutoff and
            n.expires_at > ^now,
        update: [set: [used_at: ^now]]
      )
      |> repo.update_all([], prefix: prefix, log: false, telemetry_event: nil)

    case count do
      1 -> :ok
      0 -> disambiguate(repo, nonce, cutoff, prefix, now)
    end
  end

  # The conditional update matched nothing. Read the row back to report the
  # precise reason rather than silently rejecting (fail-closed).
  defp disambiguate(repo, nonce, cutoff, prefix, now) do
    query =
      from(n in DPoPNonce,
        where: n.nonce == ^nonce,
        select: {n.used_at, n.issued_at, n.expires_at}
      )

    case repo.one(query, prefix: prefix, log: false, telemetry_event: nil) do
      nil ->
        {:error, :unknown}

      {used_at, _issued_at, _expires_at} when not is_nil(used_at) ->
        {:error, :used}

      {_used_at, issued_at, expires_at} ->
        # used_at is nil but the conditional update still missed. Persisted
        # expiry and the caller's freshness window are both authoritative.
        if DateTime.compare(expires_at, now) != :gt or DateTime.before?(issued_at, cutoff) do
          {:error, :expired}
        else
          {:error, :unknown}
        end
    end
  end
end
