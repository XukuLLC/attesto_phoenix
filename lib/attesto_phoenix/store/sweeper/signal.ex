defmodule AttestoPhoenix.Store.Sweeper.Signal do
  @moduledoc false

  use GenServer

  alias AttestoPhoenix.Store.Sweeper.Lifecycle
  alias AttestoPhoenix.Store.Sweeper.SignalTaskSupervisor

  require Logger

  @task_supervisor SignalTaskSupervisor
  @admission_table :attesto_phoenix_sweeper_signal_admission
  @monitor_outage_key :monitor_outage
  @max_pending 1_026
  @max_monitor_outage_targets 1_024
  @max_monitor_recovery_passes 3
  @retry_ms 50
  @max_delivery_attempts 3
  @worker_timeout_ms 5_000
  @admission_watchdog_ms 1_000

  def task_supervisor, do: @task_supervisor

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def unsupervised(target), do: cast({:enqueue, {:unsupervised, target}})

  def unsupervised_many(targets) when is_list(targets) do
    cast({:enqueue_many, Enum.map(targets, &{:unsupervised, &1})})
  end

  def capacity, do: cast({:enqueue, :capacity})

  def monitor_unavailable(target) do
    token = make_ref()

    try do
      case :ets.whereis(@admission_table) do
        :undefined ->
          :ok

        table ->
          case retain_monitor_target(table, target, token) do
            {:retained, outage_token} ->
              # Notify Signal only for the first observation of each retained
              # target. The event key remains the outage token, so this never
              # creates a second diagnostic or lets repeated store mutations
              # grow the Signal mailbox without bound.
              cast_to_table_owner(table, {:monitor_unavailable, target, outage_token})

            {:known, _outage_token} ->
              :ok

            :full ->
              :ok
          end
      end
    rescue
      ArgumentError -> :ok
    end

    :ok
  end

  def monitor_recovered do
    try do
      case :ets.whereis(@admission_table) do
        :undefined ->
          :ok

        table ->
          case :ets.lookup(table, @monitor_outage_key) do
            [{@monitor_outage_key, token, _targets}] ->
              # Keep the marker until Signal has rechecked and re-admitted the
              # retained target. Taking it here loses the only target when
              # Lifecycle recovers before the unavailable event is delivered.
              cast_to_table_owner(table, {:monitor_recovered, token})

            [] ->
              :ok
          end
      end
    rescue
      ArgumentError -> :ok
    end

    :ok
  end

  @impl true
  def init(_opts) do
    _table = :ets.new(@admission_table, [:set, :public, :named_table])
    schedule_admission_watchdog()
    send(self(), :announce_ready)

    {:ok,
     %{
       queue: :queue.new(),
       pending_keys: MapSet.new(),
       delivery_failures: %{},
       active: nil,
       retry_ref: nil,
       monitor_outage: false
     }}
  end

  @impl true
  def handle_cast({:enqueue, event}, state) do
    {:noreply, state |> enqueue(event) |> maybe_dispatch()}
  end

  def handle_cast({:enqueue_many, events}, state) do
    state = Enum.reduce(events, state, &enqueue(&2, &1))
    {:noreply, maybe_dispatch(state)}
  end

  def handle_cast({:monitor_unavailable, target, token}, state) do
    cond do
      current_monitor_outage() != token ->
        {:noreply, state}

      Process.whereis(Lifecycle) ->
        {:noreply, state |> recover_monitor_outage(target, token) |> maybe_dispatch()}

      true ->
        state = retain_monitor_state(state, token, target)
        {:noreply, state |> maybe_enqueue_monitor_event(target, token) |> maybe_dispatch()}
    end
  end

  def handle_cast({:monitor_recovered, token}, state) do
    if current_monitor_outage() == token do
      state = retain_monitor_state(state, token, nil)
      {:noreply, state |> recover_monitor_outage(nil, token) |> maybe_dispatch()}
    else
      {:noreply, clear_monitor_state(state, token)}
    end
  end

  @impl true
  def handle_info({ref, result}, %{active: %{ref: ref, key: key, event: event, timer: timer}} = state) do
    _ = cancel_timer(timer)
    Process.demonitor(ref, [:flush])

    state = %{
      state
      | active: nil,
        pending_keys: MapSet.delete(state.pending_keys, key),
        delivery_failures: Map.delete(state.delivery_failures, key)
    }

    state = complete_delivery(state, event, result)
    {:noreply, state |> maybe_enqueue_monitor_outage() |> maybe_dispatch()}
  end

  def handle_info(
        {:DOWN, ref, :process, _pid, _reason},
        %{active: %{ref: ref, key: key, event: event, timer: timer}} = state
      ) do
    _ = cancel_timer(timer)

    if is_nil(timer) do
      state = %{
        state
        | active: nil,
          pending_keys: MapSet.delete(state.pending_keys, key),
          delivery_failures: Map.delete(state.delivery_failures, key)
      }

      state = complete_delivery(state, event, :timed_out)
      {:noreply, state |> maybe_enqueue_monitor_outage() |> maybe_dispatch()}
    else
      {:noreply, retry_or_drop_delivery(%{state | active: nil}, event)}
    end
  end

  def handle_info({:signal_timeout, ref}, %{active: %{ref: ref, pid: pid} = active} = state) do
    Process.exit(pid, :kill)
    {:noreply, %{state | active: %{active | timer: nil}}}
  end

  def handle_info(:dispatch, state) do
    {:noreply, state |> Map.put(:retry_ref, nil) |> maybe_dispatch()}
  end

  def handle_info(:admission_watchdog, state) do
    schedule_admission_watchdog()
    {:noreply, state |> reconcile_monitor_outage() |> maybe_dispatch()}
  end

  def handle_info(:announce_ready, state) do
    case Process.whereis(Lifecycle) do
      pid when is_pid(pid) ->
        GenServer.cast(pid, :signal_ready)

      nil ->
        Process.send_after(self(), :announce_ready, @retry_ms)
    end

    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp cast(message) do
    case Process.whereis(__MODULE__) do
      pid when is_pid(pid) -> GenServer.cast(pid, message)
      nil -> :ok
    end
  end

  defp cast_to_table_owner(table, message) do
    case :ets.info(table, :owner) do
      pid when is_pid(pid) -> GenServer.cast(pid, message)
      _other -> :ok
    end
  rescue
    ArgumentError -> :ok
  end

  defp enqueue(state, event) do
    key = event_key(event)

    cond do
      MapSet.member?(state.pending_keys, key) ->
        state

      MapSet.size(state.pending_keys) >= @max_pending ->
        state

      true ->
        %{
          state
          | queue: :queue.in(event, state.queue),
            pending_keys: MapSet.put(state.pending_keys, key)
        }
    end
  end

  defp maybe_dispatch(%{active: active} = state) when not is_nil(active), do: state
  defp maybe_dispatch(%{retry_ref: retry_ref} = state) when is_reference(retry_ref), do: state

  defp maybe_dispatch(state) do
    case :queue.out(state.queue) do
      {:empty, _queue} ->
        state

      {{:value, event}, queue} ->
        case start_signal_worker(event) do
          {:ok, %Task{pid: pid, ref: ref}} ->
            timer = Process.send_after(self(), {:signal_timeout, ref}, @worker_timeout_ms)

            %{
              state
              | queue: queue,
                active: %{pid: pid, ref: ref, timer: timer, key: event_key(event), event: event}
            }

          {:error, _reason} ->
            state
            |> Map.put(:queue, queue)
            |> retry_or_drop_delivery(event)
        end
    end
  end

  defp retry_or_drop_delivery(state, event) do
    key = event_key(event)
    failures = Map.get(state.delivery_failures, key, 0) + 1

    if failures < @max_delivery_attempts do
      state
      |> Map.put(:queue, :queue.in_r(event, state.queue))
      |> Map.put(:delivery_failures, Map.put(state.delivery_failures, key, failures))
      |> schedule_dispatch()
    else
      state = %{
        state
        | pending_keys: MapSet.delete(state.pending_keys, key),
          delivery_failures: Map.delete(state.delivery_failures, key)
      }

      state
      |> complete_delivery(event, :timed_out)
      |> maybe_enqueue_monitor_outage()
      |> maybe_dispatch()
    end
  end

  defp start_signal_worker(event) do
    {:ok, Task.Supervisor.async_nolink(@task_supervisor, fn -> emit(event) end)}
  catch
    :exit, reason -> {:error, reason}
  end

  defp schedule_dispatch(state) do
    %{state | retry_ref: Process.send_after(self(), :dispatch, @retry_ms)}
  end

  defp cancel_timer(timer) when is_reference(timer), do: Process.cancel_timer(timer)
  defp cancel_timer(_timer), do: false

  defp event_key({:unsupervised, target}), do: {:unsupervised, target}
  defp event_key({:monitor_unavailable, _target, token}), do: {:monitor_unavailable, token}
  defp event_key(:capacity), do: :capacity

  defp emit({:unsupervised, {repo, prefix} = target}) do
    # A worker may register while this event waits behind another signal. Check
    # again immediately before the external effects so recovery cancels stale
    # queued diagnostics.
    if Lifecycle.running_target?(target) do
      :suppressed
    else
      :telemetry.execute(
        [:attesto_phoenix, :store, :sweeper_unsupervised],
        %{count: 1},
        %{repo: repo, schema_prefix: prefix}
      )

      Logger.warning(
        "AttestoPhoenix: AttestoPhoenix.Store.Sweeper is not running for #{inspect(repo)} " <>
          "(schema_prefix: #{inspect(prefix)}). " <>
          "Expired TTL rows will not be pruned. When positive refresh retry grace is enabled, " <>
          "refresh-token successor ciphertext will not be redacted either. " <>
          "Supervise AttestoPhoenix.Store.Sweeper with a positive :sweep_interval_ms in your " <>
          "application supervision tree (or register an equivalent cleanup worker)."
      )

      :emitted
    end
  end

  defp emit({:monitor_unavailable, {repo, prefix}, token}) do
    cond do
      current_monitor_outage() != token ->
        :stale

      Process.whereis(Lifecycle) ->
        :recovered

      true ->
        :telemetry.execute(
          [:attesto_phoenix, :store, :sweeper_monitor_unavailable],
          %{count: 1},
          %{repo: repo, schema_prefix: prefix}
        )

        Logger.error(
          "AttestoPhoenix: sweeper lifecycle monitor is unavailable; " <>
            "cleanup supervision could not be verified for #{inspect(repo)} " <>
            "(schema_prefix: #{inspect(prefix)})."
        )

        :emitted
    end
  end

  defp emit(:capacity) do
    :telemetry.execute(
      [:attesto_phoenix, :store, :sweeper_signal_capacity],
      %{count: 1},
      %{}
    )

    Logger.error(
      "AttestoPhoenix: missing-sweeper signal capacity is exhausted; " <>
        "additional unmonitored cleanup targets may be suppressed temporarily."
    )

    :emitted
  end

  defp current_monitor_outage do
    case current_monitor_outage_record() do
      {token, _target} -> token
      nil -> nil
    end
  end

  defp current_monitor_outage_record do
    case :ets.lookup(@admission_table, @monitor_outage_key) do
      [{@monitor_outage_key, token, targets}] ->
        case normalize_monitor_targets(targets) do
          [target | _rest] -> {token, target}
          [] -> nil
        end

      [] ->
        nil
    end
  rescue
    ArgumentError -> nil
  end

  defp current_monitor_outage_targets do
    case :ets.lookup(@admission_table, @monitor_outage_key) do
      [{@monitor_outage_key, token, targets}] ->
        {token, normalize_monitor_targets(targets)}

      [] ->
        nil
    end
  rescue
    ArgumentError -> nil
  end

  defp retain_monitor_target(table, target, token, attempts_left \\ 3)

  defp retain_monitor_target(_table, _target, _token, attempts_left) when attempts_left <= 0, do: :full

  defp retain_monitor_target(table, target, token, attempts_left) do
    case :ets.lookup(table, @monitor_outage_key) do
      [] ->
        if :ets.insert_new(table, {@monitor_outage_key, token, [target]}) do
          {:retained, token}
        else
          retain_monitor_target(table, target, token, attempts_left - 1)
        end

      [{@monitor_outage_key, current_token, stored_targets} = current] ->
        targets = normalize_monitor_targets(stored_targets)

        cond do
          target in targets ->
            {:known, current_token}

          length(targets) >= @max_monitor_outage_targets ->
            :full

          true ->
            retain_new_monitor_target(table, target, token, attempts_left, current, current_token, targets)
        end
    end
  rescue
    ArgumentError ->
      retain_monitor_target(table, target, token, attempts_left - 1)
  end

  defp retain_new_monitor_target(table, target, token, attempts_left, current, current_token, targets) do
    replacement = {@monitor_outage_key, current_token, [target | targets]}

    if :ets.select_replace(table, [{current, [], [{:const, replacement}]}]) == 1 do
      {:retained, current_token}
    else
      retain_monitor_target(table, target, token, attempts_left - 1)
    end
  end

  defp normalize_monitor_targets(targets) when is_list(targets) do
    targets
    |> Enum.uniq()
    |> Enum.take(@max_monitor_outage_targets)
  end

  defp normalize_monitor_targets(target), do: [target]

  defp retain_monitor_state(state, token, target) do
    case state.monitor_outage do
      {status, ^token, retained_target} when status in [:pending, :delivered] ->
        %{state | monitor_outage: {status, token, retained_target || target}}

      _other ->
        %{state | monitor_outage: {:pending, token, target}}
    end
  end

  defp clear_monitor_outage(token, targets) do
    case :ets.lookup(@admission_table, @monitor_outage_key) do
      [{@monitor_outage_key, ^token, stored_targets} = current] ->
        if normalize_monitor_targets(stored_targets) == targets do
          :ets.select_delete(@admission_table, [{current, [], [true]}]) == 1
        else
          false
        end

      [] ->
        false
    end
  rescue
    ArgumentError -> false
  end

  defp clear_monitor_state(%{monitor_outage: {status, token, _target}} = state, token)
       when status in [:pending, :delivered] do
    state
    |> Map.put(:monitor_outage, false)
    |> drop_queued_monitor_event()
  end

  defp clear_monitor_state(state, _token), do: state

  defp complete_delivery(
         %{monitor_outage: {:pending, token, target}} = state,
         {:monitor_unavailable, _event_target, token},
         :emitted
       ) do
    %{state | monitor_outage: {:delivered, token, target}}
  end

  defp complete_delivery(state, {:monitor_unavailable, target, token}, :recovered) do
    # Recovery disappeared between the worker's check and this result? The
    # marker remains and the watchdog will retry the nonblocking re-admission.
    recover_monitor_outage(state, target, token)
  end

  defp complete_delivery(state, {:monitor_unavailable, _target, token}, :stale) do
    clear_monitor_state(state, token)
  end

  # A timed-out delivery is deliberately dropped: external telemetry or Logger
  # handlers must never keep this single-worker queue stuck forever.
  defp complete_delivery(
         %{monitor_outage: {:pending, token, target}} = state,
         {:monitor_unavailable, _event_target, token},
         :timed_out
       ) do
    %{state | monitor_outage: {:delivered, token, target}}
  end

  defp complete_delivery(state, _event, _result), do: state

  defp maybe_enqueue_monitor_outage(%{monitor_outage: {:pending, token, target}} = state) do
    enqueue(state, {:monitor_unavailable, target, token})
  end

  defp maybe_enqueue_monitor_outage(state), do: state

  defp reconcile_monitor_outage(state) do
    case current_monitor_outage_record() do
      nil ->
        case state.monitor_outage do
          false -> state
          {_status, token, _target} -> clear_monitor_state(state, token)
        end

      {token, target} ->
        cond do
          Process.whereis(Lifecycle) ->
            recover_monitor_outage(state, target, token)

          match?({status, ^token, _target} when status in [:pending, :delivered], state.monitor_outage) ->
            state

          true ->
            state
            |> Map.put(:monitor_outage, {:pending, token, target})
            |> maybe_enqueue_monitor_event(target, token)
        end
    end
  end

  # Lifecycle owns the admission table, but check_target/1 only performs ETS
  # work and never waits on its GenServer mailbox. Keep this recovery bounded
  # to the bounded set of retained targets and leave the marker in place
  # whenever Lifecycle disappears during the check; the watchdog then gives
  # the recovery another chance. A worker that registered in the meantime wins
  # and releases its retained target without producing a diagnostic.
  defp recover_monitor_outage(state, _target, token),
    do: recover_monitor_outage_pass(state, token, @max_monitor_recovery_passes)

  defp recover_monitor_outage_pass(state, token, attempts_left) do
    case current_monitor_outage_targets() do
      nil ->
        clear_monitor_state(state, token)

      {^token, targets} ->
        target = List.first(targets)
        state = retain_monitor_state(state, token, target)

        cond do
          not is_pid(Process.whereis(Lifecycle)) ->
            state |> maybe_enqueue_monitor_event(target, token) |> maybe_dispatch()

          Enum.all?(targets, &recover_monitor_target/1) and
              clear_monitor_outage(token, targets) ->
            clear_monitor_state(state, token)

          attempts_left > 0 ->
            recover_monitor_outage_pass(state, token, attempts_left - 1)

          true ->
            state |> maybe_enqueue_monitor_event(target, token) |> maybe_dispatch()
        end

      {_other_token, _targets} ->
        clear_monitor_state(state, token)
    end
  end

  defp recover_monitor_target(target) do
    Lifecycle.running_target?(target) or Lifecycle.check_target(target) == :ok
  end

  defp maybe_enqueue_monitor_event(
         %{monitor_outage: {:delivered, _delivered_token, _delivered_target}} = state,
         _event_target,
         _event_token
       ), do: state

  defp maybe_enqueue_monitor_event(state, target, token), do: enqueue(state, {:monitor_unavailable, target, token})

  defp drop_queued_monitor_event(state) do
    queue =
      state.queue
      |> :queue.to_list()
      |> Enum.reject(&match?({:monitor_unavailable, _target, _token}, &1))
      |> :queue.from_list()

    active_monitor_key =
      case state.active do
        %{key: {:monitor_unavailable, _token} = key} -> key
        _other -> nil
      end

    pending_keys =
      Enum.reduce(state.pending_keys, MapSet.new(), fn
        key, pending_keys when key == active_monitor_key -> MapSet.put(pending_keys, key)
        {:monitor_unavailable, _token}, pending_keys -> pending_keys
        key, pending_keys -> MapSet.put(pending_keys, key)
      end)

    delivery_failures =
      Enum.reduce(state.delivery_failures, %{}, fn
        {key, failures}, delivery_failures when key == active_monitor_key ->
          Map.put(delivery_failures, key, failures)

        {{:monitor_unavailable, _token}, _failures}, delivery_failures ->
          delivery_failures

        {key, failures}, delivery_failures ->
          Map.put(delivery_failures, key, failures)
      end)

    %{
      state
      | queue: queue,
        pending_keys: pending_keys,
        delivery_failures: delivery_failures
    }
  end

  defp schedule_admission_watchdog do
    Process.send_after(self(), :admission_watchdog, @admission_watchdog_ms)
  end
end
