defmodule AttestoPhoenix.ClientIdMetadata.Cache.ETS do
  @moduledoc """
  Single-node ETS `AttestoPhoenix.ClientIdMetadata.Cache` - CIMD
  (`draft-ietf-oauth-client-id-metadata-document-02`, IETF OAuth WG).

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
  alias AttestoPhoenix.Store.ETSOwner

  @table :attesto_phoenix_client_id_metadata

  @table_options [:set, :public, :named_table, read_concurrency: true]

  @doc """
  Resolves a live cached document for a CIMD `client_id` URL.

  Returns `{:ok, metadata}` for a present, unexpired entry, or `:miss` when it
  is absent or expired. An expired entry is deleted in passing (it can never be
  honored again), so freshness is enforced on read, not by sweeping.
  """
  @impl Cache
  @spec get(String.t()) :: {:ok, map()} | :miss
  def get(url) when is_binary(url) do
    case get_entry(url) do
      {:ok, metadata, _expiry} -> {:ok, Cache.metadata_only(metadata)}
      :miss -> :miss
    end
  end

  @impl Cache
  def get_entry(url) when is_binary(url) do
    ensure_table()
    now = System.system_time(:second)

    case :ets.lookup(@table, url) do
      [{^url, metadata, expires_at}] when expires_at > now ->
        {:ok, metadata, DateTime.from_unix!(expires_at)}

      [{^url, metadata, expires_at}] ->
        :ets.select_delete(@table, [{{url, :"$1", expires_at}, [{:"=:=", :"$1", {:const, metadata}}], [true]}])
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

  @impl Cache
  def put_jwks(url, expected_metadata, %DateTime{} = expires_at, keys) do
    ensure_table()
    expiry = DateTime.to_unix(expires_at)
    replacement = {url, Cache.with_resolved_jwks(expected_metadata, keys), expiry}

    guards = [
      {:"=:=", :"$1", {:const, expected_metadata}},
      {:"=:=", :"$2", expiry},
      {:>, :"$2", System.system_time(:second)}
    ]

    case :ets.select_replace(@table, [{{url, :"$1", :"$2"}, guards, [{:const, replacement}]}]) do
      1 -> :ok
      0 -> :stale
    end
  end

  @doc """
  Evicts the cached document for `url`, if any.

  A cached CIMD document is otherwise honored until its TTL expires. That is
  the wrong behavior when the document has been rotated or is believed
  compromised, since the stale copy keeps authorizing the client — this is the
  operator's lever for that, and the reason the cache is not write-only.
  """
  @impl Cache
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
  design — see `AttestoPhoenix.Store.ETSOwner`), so it no longer resets by accident when a
  caller terminates.
  """
  @impl Cache
  @spec delete_all() :: :ok
  def delete_all do
    ensure_table()
    :ets.delete_all_objects(@table)
    :ok
  end

  defp ensure_table do
    ETSOwner.ensure(@table, @table_options)
  end
end
