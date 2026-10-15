defmodule AttestoPhoenix.Store.PAR.ETS do
  @moduledoc """
  Single-node ETS Pushed Authorization Request store.

  This is a development/default store. Clustered deployments should provide a
  `AttestoPhoenix.PARStore` backed by shared storage.

  The table is bounded by `:par_max_entries` and `:par_max_record_bytes` from
  `AttestoPhoenix.Config`. Admission is serialized in the table owner: expired
  rows are pruned first, a live random-reference collision is rejected, and a
  new live row is never evicted to make room.
  """

  @behaviour AttestoPhoenix.PARStore

  alias AttestoPhoenix.Store.ETSOwner
  alias AttestoPhoenix.Store.PAR.Capacity

  @table :attesto_phoenix_par_requests

  @table_options [:set, :public, :named_table, read_concurrency: true]

  @impl true
  def put(request_uri, params, ttl_seconds)
      when is_binary(request_uri) and is_map(params) and is_integer(ttl_seconds) and ttl_seconds > 0 do
    now = System.system_time(:second)
    expires_at = now + ttl_seconds

    if Capacity.fits?(request_uri, params, expires_at) do
      ETSOwner.insert_bounded_expiring(
        @table,
        @table_options,
        request_uri,
        params,
        expires_at,
        now,
        Capacity.max_entries()
      )
    else
      {:error, :record_too_large}
    end
  end

  @impl true
  def fetch(request_uri) when is_binary(request_uri) do
    ensure_table()
    now = System.system_time(:second)

    case :ets.lookup(@table, request_uri) do
      [{^request_uri, params, expires_at}] when expires_at > now ->
        {:ok, params}

      [{^request_uri, _params, _expires_at}] ->
        :ets.delete(@table, request_uri)
        :error

      [] ->
        :error
    end
  end

  @impl true
  def take(request_uri) when is_binary(request_uri) do
    ensure_table()
    now = System.system_time(:second)

    case :ets.take(@table, request_uri) do
      [{^request_uri, params, expires_at}] when expires_at > now -> {:ok, params}
      _ -> :error
    end
  end

  defp ensure_table do
    ETSOwner.ensure(@table, @table_options)
  end
end
