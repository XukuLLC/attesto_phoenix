defmodule AttestoPhoenix.ClientIdMetadata.Cache.ETS do
  @moduledoc """
  Single-node ETS `AttestoPhoenix.ClientIdMetadata.Cache` - CIMD
  (`draft-ietf-oauth-client-id-metadata-document-01`, IETF OAuth WG).

  Caches a validated Client ID Metadata Document in per-node memory keyed by its
  `client_id` URL. A per-node cache is correct for CIMD - a miss simply
  re-fetches and re-validates - so this is the single-node opt-out from the
  default `AttestoPhoenix.ClientIdMetadata.Cache.Ecto`, which a clustered
  deployment prefers for cross-node coherence and to bound outbound fetch
  fan-out. Select it by configuring `:cache` under `AttestoPhoenix.Config`'s
  `:client_id_metadata` key.

  Only a validated document is ever stored (the caller stores after
  `Attesto.ClientIdMetadata.validate_document/2` succeeds), and freshness is
  re-checked on read against the stored `expires_at`, so an expired entry is a
  `:miss` and is evicted in passing - never served stale.
  """

  @behaviour AttestoPhoenix.ClientIdMetadata.Cache

  alias AttestoPhoenix.ClientIdMetadata.Cache

  @table :attesto_phoenix_client_id_metadata

  defmodule Owner do
    @moduledoc false

    use GenServer

    def ensure_table(table) do
      GenServer.call(__MODULE__, {:ensure_table, table})
    end

    @impl true
    def init(state), do: {:ok, state}

    @impl true
    def handle_call({:ensure_table, table}, _from, state) do
      case :ets.whereis(table) do
        :undefined ->
          :ets.new(table, [:set, :public, :named_table, read_concurrency: true])

        _tid ->
          table
      end

      {:reply, table, state}
    end
  end

  @doc """
  Resolves a live cached document for a CIMD `client_id` URL.

  Returns `{:ok, metadata}` for a present, unexpired entry, or `:miss` when it
  is absent or expired. An expired entry is deleted in passing (it can never be
  honored again), so freshness is enforced on read, not by sweeping.
  """
  @impl Cache
  @spec get(String.t()) :: {:ok, map()} | :miss
  def get(url) when is_binary(url) do
    ensure_table()
    now = System.system_time(:second)

    case :ets.lookup(@table, url) do
      [{^url, metadata, expires_at}] when expires_at > now ->
        {:ok, metadata}

      [{^url, _metadata, _expires_at}] ->
        :ets.delete(@table, url)
        :miss

      [] ->
        :miss
    end
  end

  @doc """
  Caches validated `metadata` for a CIMD `client_id` URL until `expires_at`.

  A re-fetched document supersedes a stale one, so this overwrites any existing
  entry for the same `url` (`:ets.insert/2` replaces a set row), keyed by URL.
  """
  @impl Cache
  @spec put(String.t(), map(), DateTime.t()) :: :ok
  def put(url, metadata, %DateTime{} = expires_at) when is_binary(url) and is_map(metadata) do
    ensure_table()
    true = :ets.insert(@table, {url, metadata, DateTime.to_unix(expires_at)})
    :ok
  end

  @doc """
  Evicts the cached document for `url`, if any.

  A cached CIMD document is otherwise honored until its TTL expires. That is
  the wrong behavior when the document has been rotated or is believed
  compromised, since the stale copy keeps authorizing the client — this is the
  operator's lever for that, and the reason the cache is not write-only.
  """
  @spec delete(String.t()) :: :ok
  def delete(url) when is_binary(url) do
    ensure_table()
    :ets.delete(@table, url)
    :ok
  end

  @doc """
  Evicts every cached document.

  Beyond bulk operational eviction, this is what gives a test suite a clean
  cache between cases: the table now outlives the process that created it (by
  design — see `ensure_owner/1`), so it no longer resets by accident when a
  caller terminates.
  """
  @spec delete_all() :: :ok
  def delete_all do
    ensure_table()
    :ets.delete_all_objects(@table)
    :ok
  end

  defp ensure_table do
    ensure_owner()
    Owner.ensure_table(@table)
  end

  # `GenServer.start/3`, NOT `start_link/3`. The owner holds the ETS table, and
  # whichever process happens to touch this store first is an ordinary request
  # process. Linking the owner to it means that when that request terminates
  # ABNORMALLY - any unhandled exception, a timeout, a shutdown - the exit
  # signal propagates and kills the owner, destroying the table with it. This
  # store then silently starts over empty for the whole node.
  #
  # Starting unlinked gives the owner no parent to be killed by. It is a
  # singleton table holder with no supervision tree available (this library
  # installs no application callback module), so a deliberate orphan is the
  # correct shape: nothing should be able to take it down but itself.
  #
  # The `:already_started` pid is checked for liveness because a registered name
  # can briefly outlive its process. Treating that window as success is what
  # produces `GenServer.call` crashing with "no process" a moment later.
  defp ensure_owner(attempts \\ 5) do
    case GenServer.start(Owner, %{}, name: Owner) do
      {:ok, _pid} ->
        :ok

      {:error, {:already_started, pid}} ->
        cond do
          Process.alive?(pid) -> :ok
          attempts > 1 -> retry_owner(attempts)
          true -> raise "#{inspect(Owner)} is registered but not alive"
        end
    end
  end

  defp retry_owner(attempts) do
    Process.sleep(10)
    ensure_owner(attempts - 1)
  end
end
