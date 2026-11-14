defmodule AttestoPhoenix.Store.PAR.ETS do
  @moduledoc """
  Single-node ETS Pushed Authorization Request store.

  This is a development/default store. Clustered deployments should provide a
  `AttestoPhoenix.PARStore` backed by shared storage.

  The tables are bounded by `:par_max_entries` (PAR requests),
  `:interaction_max_entries` (parked interactions), and `:par_max_record_bytes`
  from `AttestoPhoenix.Config`. Admission is serialized in the table owner:
  expired rows are pruned first, a live random-reference collision is
  rejected, and a new live row is never evicted to make room.
  """

  @behaviour AttestoPhoenix.PARStore

  alias AttestoPhoenix.Interaction
  alias AttestoPhoenix.Store.ETSOwner
  alias AttestoPhoenix.Store.PAR.Capacity

  @table :attesto_phoenix_par_requests
  @interaction_table :attesto_phoenix_interactions

  @table_options [:set, :public, :named_table, read_concurrency: true]

  @impl true
  def put(request_uri, params, ttl_seconds)
      when is_binary(request_uri) and is_map(params) and is_integer(ttl_seconds) and ttl_seconds > 0 do
    now = System.system_time(:second)
    expires_at = now + ttl_seconds

    if Capacity.fits?(request_uri, params, expires_at) do
      {table, max_entries} = target_table(request_uri)

      ETSOwner.insert_bounded_expiring(
        table,
        @table_options,
        request_uri,
        params,
        expires_at,
        now,
        max_entries
      )
    else
      {:error, :record_too_large}
    end
  end

  @impl true
  def fetch(request_uri) when is_binary(request_uri) do
    table = ensure_table(request_uri)
    now = System.system_time(:second)

    case :ets.lookup(table, request_uri) do
      [{^request_uri, params, expires_at}] when expires_at > now ->
        {:ok, params}

      [{^request_uri, _params, _expires_at}] ->
        :ets.delete(table, request_uri)
        :error

      [] ->
        :error
    end
  end

  @impl true
  def take(request_uri) when is_binary(request_uri) do
    table = ensure_table(request_uri)
    now = System.system_time(:second)

    case :ets.take(table, request_uri) do
      [{^request_uri, params, expires_at}] when expires_at > now -> {:ok, params}
      _ -> :error
    end
  end

  @impl true
  def replace(request_uri, params) when is_binary(request_uri) and is_map(params) do
    table = ensure_table(request_uri)
    now = System.system_time(:second)

    match_spec = [
      {{request_uri, :_, :"$1"}, [{:>, :"$1", now}], [{{request_uri, {:const, params}, :"$1"}}]}
    ]

    case :ets.select_replace(table, match_spec) do
      1 -> :ok
      0 -> :error
    end
  end

  defp ensure_table(request_uri) do
    {table, _max_entries} = target_table(request_uri)
    ETSOwner.ensure(table, @table_options)
    table
  end

  defp target_table(request_uri) do
    if Interaction.reserved_key?(request_uri) do
      {@interaction_table, Capacity.interaction_max_entries()}
    else
      {@table, Capacity.max_entries()}
    end
  end
end
