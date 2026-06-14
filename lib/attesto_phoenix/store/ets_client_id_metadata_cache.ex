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

  defp ensure_table do
    ensure_owner()
    Owner.ensure_table(@table)
  end

  defp ensure_owner do
    case GenServer.start_link(Owner, %{}, name: Owner) do
      {:ok, _pid} -> :ok
      {:error, {:already_started, _pid}} -> :ok
    end
  end
end
