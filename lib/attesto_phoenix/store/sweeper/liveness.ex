defmodule AttestoPhoenix.Store.Sweeper.Liveness do
  @moduledoc false

  alias AttestoPhoenix.Store.Sweeper.Registration

  @spec child_spec(keyword()) :: Supervisor.child_spec()
  def child_spec(opts \\ []) do
    Registry.child_spec(
      Keyword.merge(
        [keys: :duplicate, name: __MODULE__, id: __MODULE__],
        opts
      )
    )
  end

  @spec register_sweeper(term()) :: :ok | :error
  def register_sweeper(target) do
    case Registry.register(__MODULE__, {:target, target}, :sweeper) do
      {:ok, _pid} -> :ok
      _error -> :error
    end
  rescue
    ArgumentError -> :error
  end

  @spec sweeper_pid(term()) :: {:ok, pid()} | :error
  def sweeper_pid(target) do
    entries =
      try do
        Registry.lookup(__MODULE__, {:target, target})
      rescue
        ArgumentError -> []
      end

    Enum.find_value(entries, :error, fn
      {pid, :sweeper} ->
        if local_alive?(pid), do: {:ok, pid}, else: false

      _other ->
        false
    end)
  end

  @spec sweeper_alive?(term()) :: boolean()
  def sweeper_alive?(target) do
    match?({:ok, _pid}, sweeper_pid(target))
  end

  @spec cleanup_worker_alive?(term()) :: boolean()
  def cleanup_worker_alive?(target) do
    Enum.any?(Registration.live_registrations(), fn {_pid, targets} ->
      MapSet.member?(targets, target)
    end)
  end

  @spec running_target?(term()) :: boolean()
  def running_target?(target) do
    sweeper_alive?(target) or cleanup_worker_alive?(target)
  end

  @spec registered_worker?(term()) :: boolean()
  def registered_worker?(pid) when is_pid(pid) do
    if local_alive?(pid) do
      registry_worker?(pid) or Map.has_key?(Registration.live_registrations(), pid)
    else
      false
    end
  end

  def registered_worker?(_other), do: false

  @spec registered_worker_for_target?(term(), term()) :: boolean()
  def registered_worker_for_target?(pid, target) when is_pid(pid) do
    if local_alive?(pid) do
      registry_worker_for_target?(pid, target) or cleanup_worker_for_target?(pid, target)
    else
      false
    end
  end

  def registered_worker_for_target?(_pid, _target), do: false

  @spec available?() :: boolean()
  def available? do
    case Process.whereis(__MODULE__) do
      pid when is_pid(pid) -> true
      _ -> false
    end
  end

  defp registry_worker?(pid) do
    case Registry.keys(__MODULE__, pid) do
      [] -> false
      [_ | _] -> true
    end
  rescue
    ArgumentError -> false
  end

  defp registry_worker_for_target?(pid, target) do
    {:target, target} in Registry.keys(__MODULE__, pid)
  rescue
    ArgumentError -> false
  end

  defp cleanup_worker_for_target?(pid, target) do
    case Map.fetch(Registration.live_registrations(), pid) do
      {:ok, targets} -> MapSet.member?(targets, target)
      :error -> false
    end
  end

  defp local_alive?(pid) when is_pid(pid), do: node(pid) == node() and Process.alive?(pid)
  defp local_alive?(_other), do: false
end
