defmodule AttestoPhoenix.Store.Sweeper.Registration do
  @moduledoc false

  use GenServer

  alias AttestoPhoenix.Store.Sweeper.Lifecycle
  alias AttestoPhoenix.Store.Sweeper.Signal

  @retry_ms 50
  @persistent_registrations_key {__MODULE__, :registrations}

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def register(target, worker) do
    case Process.whereis(__MODULE__) do
      pid when is_pid(pid) -> GenServer.call(pid, {:register, target, worker})
      nil -> {:error, :not_started}
    end
  catch
    :exit, {:timeout, _details} -> {:error, :timeout}
    :exit, {:noproc, _details} -> {:error, :not_started}
    :exit, _reason -> {:error, :registration_failed}
  end

  @doc false
  def live_registrations do
    persistent_registrations()
    |> retain_live_registrations()
  end

  @impl true
  def init(_opts) do
    registrations =
      persistent_registrations()
      |> merge_lifecycle_registrations()
      |> retain_live_registrations()

    persist_registrations(registrations)

    state = %{
      registrations: registrations,
      worker_monitors: monitor_workers(registrations),
      lifecycle_pid: nil,
      lifecycle_ref: nil,
      lifecycle_retry_ref: nil
    }

    {:ok, monitor_lifecycle_or_retry(state)}
  end

  @impl true
  def handle_call({:register, target, worker}, _from, state) do
    if local_alive?(worker) do
      {state, result} = register_with_lifecycle(state, target, worker)

      state =
        case result do
          :ok -> remember_registration(state, target, worker)
          _error -> state
        end

      {:reply, result, state}
    else
      {:reply, {:error, :worker_not_alive}, state}
    end
  end

  @impl true
  def handle_info(
        {:DOWN, ref, :process, lifecycle_pid, _reason},
        %{lifecycle_ref: ref, lifecycle_pid: lifecycle_pid} = state
      ) do
    state = clear_lifecycle_monitor(state)

    send(self(), :register_lifecycle)
    {:noreply, state}
  end

  def handle_info({:DOWN, ref, :process, worker, _reason}, state) do
    case Map.pop(state.worker_monitors, ref) do
      {^worker, worker_monitors} ->
        registrations = Map.delete(state.registrations, worker)
        persist_registrations(registrations)

        {:noreply,
         %{
           state
           | worker_monitors: worker_monitors,
             registrations: registrations
         }}

      {nil, _worker_monitors} ->
        {:noreply, state}
    end
  end

  def handle_info(:register_lifecycle, %{lifecycle_pid: lifecycle_pid} = state) when is_pid(lifecycle_pid) do
    {:noreply, state}
  end

  def handle_info(:register_lifecycle, state) do
    state = %{state | lifecycle_retry_ref: nil}
    {:noreply, monitor_lifecycle_or_retry(state)}
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp remember_registration(state, target, worker) do
    {worker_monitors, registrations} =
      case Map.fetch(state.registrations, worker) do
        {:ok, targets} ->
          {state.worker_monitors, Map.put(state.registrations, worker, MapSet.put(targets, target))}

        :error ->
          ref = Process.monitor(worker)

          {
            Map.put(state.worker_monitors, ref, worker),
            Map.put(state.registrations, worker, MapSet.new([target]))
          }
      end

    persist_registrations(registrations)
    %{state | worker_monitors: worker_monitors, registrations: registrations}
  end

  defp persistent_registrations do
    case :persistent_term.get(@persistent_registrations_key, %{}) do
      registrations when is_map(registrations) -> registrations
      _invalid -> %{}
    end
  end

  defp merge_lifecycle_registrations(registrations) do
    Lifecycle.cleanup_registrations()
    |> Enum.reduce(registrations, fn {target, worker}, acc ->
      Map.update(acc, worker, MapSet.new([target]), &MapSet.put(&1, target))
    end)
  end

  defp retain_live_registrations(registrations) do
    Enum.reduce(registrations, %{}, fn
      {worker, %MapSet{} = targets}, acc when is_pid(worker) ->
        if local_alive?(worker) do
          Map.put(acc, worker, targets)
        else
          acc
        end

      _invalid, acc ->
        acc
    end)
  end

  defp persist_registrations(registrations) do
    :persistent_term.put(@persistent_registrations_key, registrations)
    :ok
  end

  defp register_with_lifecycle(state, target, worker) do
    case Lifecycle.register_cleanup_worker_with_owner(target, worker) do
      {:ok, lifecycle_pid} ->
        state =
          if state.lifecycle_pid == lifecycle_pid and is_reference(state.lifecycle_ref) do
            state
          else
            monitor_lifecycle(state, lifecycle_pid)
          end

        Signal.monitor_recovered()
        {state, :ok}

      {:error, :not_started} ->
        state =
          state
          |> clear_lifecycle_monitor()
          |> schedule_lifecycle_retry()

        {state, {:error, :lifecycle_not_started}}

      {:error, reason} ->
        {state, {:error, reason}}
    end
  end

  defp monitor_lifecycle_or_retry(state) do
    case Process.whereis(Lifecycle) do
      lifecycle_pid when is_pid(lifecycle_pid) ->
        state = monitor_lifecycle(state, lifecycle_pid)

        if restore_registrations(state.registrations) do
          Signal.monitor_recovered()
          state
        else
          state
          |> clear_lifecycle_monitor()
          |> schedule_lifecycle_retry()
        end

      nil ->
        schedule_lifecycle_retry(state)
    end
  end

  defp restore_registrations(registrations) do
    Enum.reduce(registrations, true, fn {worker, targets}, all_ok? ->
      restore_worker_registrations(worker, targets, all_ok?)
    end)
  end

  defp restore_worker_registrations(worker, targets, all_ok?) do
    if local_alive?(worker) do
      Enum.reduce(targets, all_ok?, fn target, inner_ok? ->
        registration_ok?(Lifecycle.register_cleanup_worker_with_owner(target, worker)) and inner_ok?
      end)
    else
      all_ok?
    end
  end

  defp registration_ok?({:ok, _lifecycle_pid}), do: true
  defp registration_ok?(_result), do: false

  defp monitor_workers(registrations) do
    Map.new(registrations, fn {worker, _targets} -> {Process.monitor(worker), worker} end)
  end

  defp monitor_lifecycle(state, lifecycle_pid) do
    state = clear_lifecycle_monitor(state)

    %{
      state
      | lifecycle_pid: lifecycle_pid,
        lifecycle_ref: Process.monitor(lifecycle_pid),
        lifecycle_retry_ref: nil
    }
  end

  defp clear_lifecycle_monitor(%{lifecycle_ref: ref} = state) when is_reference(ref) do
    Process.demonitor(ref, [:flush])
    %{state | lifecycle_pid: nil, lifecycle_ref: nil}
  end

  defp clear_lifecycle_monitor(state), do: %{state | lifecycle_pid: nil, lifecycle_ref: nil}

  defp schedule_lifecycle_retry(%{lifecycle_retry_ref: ref} = state) when is_reference(ref), do: state

  defp schedule_lifecycle_retry(state) do
    %{state | lifecycle_retry_ref: Process.send_after(self(), :register_lifecycle, @retry_ms)}
  end

  defp local_alive?(pid) when is_pid(pid), do: node(pid) == node() and Process.alive?(pid)
  defp local_alive?(_other), do: false
end
