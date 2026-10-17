defmodule AttestoPhoenix.Store.PendingDecision do
  @moduledoc false

  import Ecto.Query, only: [from: 2]

  alias Attesto.Claims
  alias AttestoPhoenix.Store.Ecto, as: StoreEcto

  @type decision_error :: {:error, :not_found | :already_decided | :expired}

  @spec decide(module(), atom(), String.t(), integer(), keyword()) ::
          {:ok, map()} | decision_error()
  def decide(schema, key_field, key, now, set)
      when is_atom(schema) and is_atom(key_field) and is_binary(key) and is_integer(now) and is_list(set) do
    {repo, prefix} = StoreEcto.mutation_context()
    now_dt = now |> DateTime.from_unix!() |> DateTime.truncate(:second)

    query =
      from row in schema,
        where:
          field(row, ^key_field) == ^key and row.status == :pending and
            row.expires_at > ^now_dt,
        select: row

    case repo.update_all(query, [set: set], query_options(prefix)) do
      {1, [row]} -> {:ok, schema.to_entry(Map.merge(row, Map.new(set)))}
      {0, _} -> decision_miss(repo, schema, key_field, key, now_dt, prefix)
    end
  end

  @spec consume(module(), atom(), String.t(), integer()) :: {:ok, map()} | :error
  def consume(schema, key_field, key, now)
      when is_atom(schema) and is_atom(key_field) and is_binary(key) and is_integer(now) do
    {repo, prefix} = StoreEcto.mutation_context()
    now_dt = now |> DateTime.from_unix!() |> DateTime.truncate(:second)

    query =
      from row in schema,
        where:
          field(row, ^key_field) == ^key and row.status == :approved and
            row.expires_at > ^now_dt,
        select: row

    case repo.update_all(query, [set: [status: :consumed]], query_options(prefix)) do
      {1, [row]} -> {:ok, schema.to_entry(%{row | status: :consumed})}
      {0, _} -> :error
    end
  end

  @spec slow_down_or_missing(module(), atom(), String.t(), module(), String.t() | nil) ::
          {:error, :slow_down} | :error
  def slow_down_or_missing(schema, key_field, key, repo, prefix)
      when is_atom(schema) and is_atom(key_field) and is_binary(key) and is_atom(repo) do
    query = from row in schema, where: field(row, ^key_field) == ^key

    if repo.exists?(query, query_options(prefix)), do: {:error, :slow_down}, else: :error
  end

  @spec validate_granted_claims!(term(), String.t()) :: :ok
  def validate_granted_claims!(granted_claims, message) when is_binary(message) do
    if Claims.portable_json_object?(granted_claims), do: :ok, else: raise(ArgumentError, message)
  end

  defp decision_miss(repo, schema, key_field, key, now_dt, prefix) do
    query =
      from row in schema,
        where: field(row, ^key_field) == ^key,
        select: {row.status, row.expires_at}

    case repo.one(query, query_options(prefix)) do
      nil -> {:error, :not_found}
      {:pending, expires_at} when not is_nil(expires_at) -> classify_pending(expires_at, now_dt)
      _decided -> {:error, :already_decided}
    end
  end

  defp classify_pending(expires_at, now_dt) do
    if DateTime.after?(expires_at, now_dt), do: {:error, :already_decided}, else: {:error, :expired}
  end

  defp query_options(prefix), do: [prefix: prefix, log: false, telemetry_event: nil]
end
