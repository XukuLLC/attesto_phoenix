defmodule AttestoPhoenix.Store.Sweeper.Lifecycle do
  @moduledoc false

  use GenServer

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Store.Sweeper.Liveness
  alias AttestoPhoenix.Store.Sweeper.Signal

  @workers_table :attesto_phoenix_sweeper_workers
  @pids_table :attesto_phoenix_sweeper_pids
  @episodes_table :attesto_phoenix_sweeper_episodes
  @wake_key :drain_pending
  @capacity_key :capacity_pending
  @max_missing_episodes 1_024
  @episode_ttl_ms 3_600_000
  @restart_quiet_ms 250
  @doorbell_watchdog_ms 1_000
  @episode_prune_ms 60_000
  @target_offer_attempts @max_missing_episodes

  @type target :: {module(), String.t() | nil}

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @spec register_sweeper(target(), pid()) ::
          {:ok, pid()}
          | {:error, :not_started | :worker_not_alive | :invalid_target | :timeout | :registration_failed}
  def register_sweeper(target, pid) when is_pid(pid) do
    call_if_started({:register, pid, target, :sweeper})
  end

  def register_sweeper(_target, _pid), do: {:error, :invalid_target}

  @spec register_cleanup_worker_with_owner(target(), pid()) ::
          {:ok, pid()}
          | {:error, :not_started | :worker_not_alive | :invalid_target | :timeout | :registration_failed}
  def register_cleanup_worker_with_owner(target, pid) when is_pid(pid) do
    call_if_started({:register, pid, target, :cleanup_worker})
  end

  def register_cleanup_worker_with_owner(_target, _pid), do: {:error, :invalid_target}

  @spec cleanup_registrations() :: [{target(), pid()}]
  def cleanup_registrations do
    case :ets.whereis(@workers_table) do
      :undefined ->
        []

      _table ->
        try do
          for {target, workers} <- :ets.tab2list(@workers_table),
              {pid, :cleanup_worker} <- workers,
              local_alive?(pid) do
            {target, pid}
          end
        rescue
          ArgumentError -> []
        end
    end
  end

  @spec get_sweeper(target()) :: {:ok, pid()} | :error
  def get_sweeper(target) when is_tuple(target) do
    if Liveness.available?() do
      Liveness.sweeper_pid(target)
    else
      fallback_sweeper(target)
    end
  end

  def get_sweeper(_other), do: :error

  defp fallback_sweeper(target) do
    target
    |> target_workers()
    |> Enum.find_value(:error, fn
      {pid, :sweeper} -> if local_alive?(pid), do: {:ok, pid}, else: false
      {_pid, :cleanup_worker} -> false
    end)
  end

  @spec running_target?(term()) :: boolean()
  def running_target?({repo, prefix} = target)
      when is_atom(repo) and not is_nil(repo) and (is_binary(prefix) or is_nil(prefix)) do
    if Liveness.available?() do
      Liveness.running_target?(target)
    else
      Enum.any?(target_workers(target), fn {pid, _kind} -> local_alive?(pid) end)
    end
  end

  def running_target?(_other), do: false

  @spec registered_worker?(term()) :: boolean()
  def registered_worker?(pid) when is_pid(pid) do
    if Liveness.available?() do
      Liveness.registered_worker?(pid)
    else
      case lookup_pid(pid) do
        [{^pid, _ref, targets}] -> map_size(targets) > 0 and local_alive?(pid)
        [] -> false
      end
    end
  end

  def registered_worker?(_other), do: false

  @spec registered_worker_for_target?(term(), term()) :: boolean()
  def registered_worker_for_target?(pid, target) when is_pid(pid) and is_tuple(target) do
    if Liveness.available?() do
      Liveness.registered_worker_for_target?(pid, target)
    else
      case lookup_pid(pid) do
        [{^pid, _ref, targets}] -> Map.has_key?(targets, target) and local_alive?(pid)
        [] -> false
      end
    end
  end

  def registered_worker_for_target?(_pid, _target), do: false

  # Admission is ETS-only. It neither calls a process nor executes a
  # telemetry handler or logger on the token-store caller's path. One coalesced
  # doorbell bounds the coordinator mailbox independently of request volume.
  @spec check_target(target()) :: :ok | :unavailable
  def check_target({repo, prefix} = target)
      when is_atom(repo) and not is_nil(repo) and (is_binary(prefix) or is_nil(prefix)) do
    offer_current_target(target, 3)
  rescue
    ArgumentError -> :unavailable
  catch
    :exit, _reason -> :unavailable
  end

  def check_target(_other), do: :unavailable

  @doc false
  @spec tracked_target_count() :: non_neg_integer()
  def tracked_target_count do
    case admission_context() do
      {table, _owner} ->
        :ets.select_count(table, [
          {{{:target, :"$1"}, {:"$2", :"$3"}}, [], [true]}
        ])

      _ ->
        0
    end
  rescue
    ArgumentError -> 0
  end

  @impl true
  def init(opts) do
    init_tables()

    quiet_ms = Keyword.get(opts, :restart_quiet_ms, @restart_quiet_ms)
    watchdog_ms = Keyword.get(opts, :doorbell_watchdog_ms, @doorbell_watchdog_ms)
    prune_ms = Keyword.get(opts, :episode_prune_ms, @episode_prune_ms)

    validate_positive_interval!(watchdog_ms, :doorbell_watchdog_ms)
    validate_positive_interval!(prune_ms, :episode_prune_ms)

    if quiet_ms > 0 do
      Process.send_after(self(), :warming_timeout, quiet_ms)
    end

    schedule_doorbell_watchdog(watchdog_ms)
    schedule_episode_prune(prune_ms)

    {:ok,
     %{
       monitors: %{},
       capacity_reported: false,
       warming: quiet_ms > 0,
       doorbell_watchdog_ms: watchdog_ms,
       episode_prune_ms: prune_ms
     }}
  end

  @impl true
  def handle_call({:register, pid, target, kind}, _from, state) do
    case validate_target(target) do
      {:ok, target} ->
        if local_alive?(pid) do
          {ref, targets, state} = registration_for(pid, state)
          targets = Map.put(targets, target, kind)
          :ets.insert(@pids_table, {pid, ref, targets})
          :ets.insert(@workers_table, {target, Map.put(target_workers(target), pid, kind)})

          {:reply, {:ok, self()}, clear_target_state(state, target)}
        else
          {:reply, {:error, :worker_not_alive}, state}
        end

      {:error, _reason} ->
        {:reply, {:error, :invalid_target}, state}
    end
  end

  @impl true
  def handle_cast(:signal_ready, state) do
    rearm_after_signal_restart()

    state =
      if tracked_target_count() >= @max_missing_episodes do
        :ets.insert(@episodes_table, {@capacity_key, true})
        %{state | capacity_reported: false}
      else
        state
      end

    if admission_work_pending?(), do: ring_current_doorbell()
    {:noreply, state}
  end

  @impl true
  def handle_info(:drain, state) do
    :ets.delete(@episodes_table, @wake_key)

    now = System.monotonic_time(:millisecond)
    {targets, state} = drain_observations(state, now)
    Signal.unsupervised_many(targets)

    {capacity?, state} = take_capacity_notice(state)
    if capacity?, do: Signal.capacity()

    {:noreply, refresh_capacity_state(state)}
  end

  def handle_info(:warming_timeout, state) do
    now = System.monotonic_time(:millisecond)
    targets = drain_warming_targets(now)
    Signal.unsupervised_many(targets)

    # Observations queued behind the timer are handled as active checks.
    ring_current_doorbell()
    {:noreply, refresh_capacity_state(%{state | warming: false})}
  end

  def handle_info(:doorbell_watchdog, state) do
    # A caller can be terminated between admitting work, claiming the
    # coalesced doorbell, and sending :drain. Rechecking both the marker and
    # admitted work from the table owner recovers every such interruption.
    if admission_work_pending?(), do: send(self(), :drain)
    schedule_doorbell_watchdog(state.doorbell_watchdog_ms)
    {:noreply, state}
  end

  def handle_info(:prune_episodes, state) do
    prune_expired_episodes(System.monotonic_time(:millisecond))
    schedule_episode_prune(state.episode_prune_ms)
    {:noreply, refresh_capacity_state(state)}
  end

  def handle_info({:DOWN, ref, :process, pid, _reason}, state) do
    case Map.pop(state.monitors, ref) do
      {^pid, monitors} ->
        targets = registered_targets(pid)
        :ets.delete(@pids_table, pid)

        Enum.each(targets, fn {target, _kind} -> remove_target_worker(target, pid) end)

        {:noreply, %{state | monitors: monitors}}

      {nil, _monitors} ->
        {:noreply, state}
    end
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp init_tables do
    if :ets.whereis(@workers_table) == :undefined do
      :ets.new(@workers_table, [:set, :protected, :named_table, read_concurrency: true])
    end

    if :ets.whereis(@pids_table) == :undefined do
      :ets.new(@pids_table, [:set, :protected, :named_table, read_concurrency: true])
    end

    if :ets.whereis(@episodes_table) == :undefined do
      :ets.new(@episodes_table, [
        :set,
        :public,
        :named_table,
        read_concurrency: true,
        write_concurrency: true
      ])
    end

    :ok
  end

  defp validate_target({repo, prefix} = target)
       when is_atom(repo) and not is_nil(repo) and (is_binary(prefix) or is_nil(prefix)) do
    case prefix do
      nil ->
        {:ok, target}

      prefix when is_binary(prefix) ->
        try do
          Config.validate_schema_prefix!(prefix)
          {:ok, target}
        rescue
          ArgumentError -> {:error, :invalid_prefix}
        end
    end
  end

  defp validate_target(_other), do: {:error, :invalid_target}

  defp offer_current_target(_target, 0), do: :unavailable

  defp offer_current_target(target, attempts_left) do
    case admission_context() do
      {table, owner} ->
        case offer_target(table, owner, target, @target_offer_attempts) do
          :retry -> offer_current_target(target, attempts_left - 1)
          result -> result
        end

      nil ->
        :unavailable
    end
  rescue
    ArgumentError -> offer_current_target(target, attempts_left - 1)
  catch
    :error, :badarg -> offer_current_target(target, attempts_left - 1)
  end

  defp offer_target(_table, _owner, _target, 0), do: :retry

  defp offer_target(table, owner, target, attempts_left) do
    now = System.monotonic_time(:millisecond)
    target_key = {:target, target}

    case :ets.lookup(table, target_key) do
      [] ->
        claim_target_slot(table, owner, target, target_key, 0, now, attempts_left)

      [{^target_key, {_slot, {:armed, expires_at} = status}}] when now >= expires_at ->
        rearm_target(table, owner, target, target_key, status, now, attempts_left)

      [{^target_key, {_slot, {:observed, _observed_at}}}] ->
        ring_doorbell(table, owner)

      [{^target_key, {_slot, _status}}] ->
        :ok
    end
  end

  defp claim_target_slot(table, owner, _target, _target_key, @max_missing_episodes, _now, _attempts_left) do
    _inserted = :ets.insert_new(table, {@capacity_key, true})
    ring_doorbell(table, owner)
  end

  defp claim_target_slot(table, owner, target, target_key, slot_offset, now, attempts_left) do
    slot = target_slot(target, slot_offset)

    case :ets.lookup(table, slot) do
      [] ->
        observation = {target_key, {slot, {:observed, now}}}
        permit = {slot, target}

        if :ets.insert_new(table, [observation, permit]) do
          ring_doorbell(table, owner)
        else
          offer_target(table, owner, target, attempts_left - 1)
        end

      [{^slot, _other_target}] ->
        claim_target_slot(
          table,
          owner,
          target,
          target_key,
          slot_offset + 1,
          now,
          attempts_left
        )
    end
  end

  defp rearm_target(table, owner, target, target_key, status, now, attempts_left) do
    replacement = {:observed, now}

    case :ets.lookup(table, target_key) do
      [{^target_key, {slot, ^status}} = current] ->
        if replace_exact(table, current, {target_key, {slot, replacement}}) do
          ring_doorbell(table, owner)
        else
          offer_target(table, owner, target, attempts_left - 1)
        end

      _other ->
        offer_target(table, owner, target, attempts_left - 1)
    end
  end

  defp replace_exact(table, current, replacement) do
    :ets.select_replace(table, [
      {current, [], [{:const, replacement}]}
    ]) == 1
  end

  # The table itself is the semaphore. ETS atomically inserts one direct target
  # index and one of these fixed permit slots, so same-target and same-slot
  # races are all-or-nothing and a terminated caller cannot orphan half a
  # reservation. The odd step visits every slot in this power-of-two table
  # before capacity is reported.
  defp target_slot(target, offset) do
    base = :erlang.phash2(target, @max_missing_episodes)
    step = 2 * :erlang.phash2({:step, target}, div(@max_missing_episodes, 2)) + 1
    {:target_slot, rem(base + offset * step, @max_missing_episodes)}
  end

  defp ring_doorbell(table, owner) when is_pid(owner) do
    inserted? = :ets.insert_new(table, {@wake_key, true})

    case :ets.info(table, :owner) do
      ^owner ->
        if inserted?, do: send(owner, :drain)
        :ok

      _other ->
        :retry
    end
  end

  defp ring_current_doorbell do
    case admission_context() do
      {table, owner} when owner == self() -> ring_doorbell(table, owner)
      _other -> :unavailable
    end
  end

  defp schedule_doorbell_watchdog(interval_ms) do
    Process.send_after(self(), :doorbell_watchdog, interval_ms)
  end

  defp schedule_episode_prune(interval_ms) do
    Process.send_after(self(), :prune_episodes, interval_ms)
  end

  defp admission_work_pending? do
    :ets.member(@episodes_table, @wake_key) or
      :ets.member(@episodes_table, @capacity_key) or
      observed_target_pending?()
  rescue
    ArgumentError -> false
  end

  defp observed_target_pending? do
    match_spec = [
      {
        {{:target, :"$1"}, {:"$2", {:observed, :"$3"}}},
        [],
        [true]
      }
    ]

    case :ets.select(@episodes_table, match_spec, 1) do
      {[_match], _continuation} -> true
      :"$end_of_table" -> false
    end
  end

  defp validate_positive_interval!(value, _name) when is_integer(value) and value > 0, do: :ok

  defp validate_positive_interval!(_value, name) do
    raise ArgumentError, ":#{name} must be a positive integer"
  end

  defp admission_context do
    case :ets.whereis(@episodes_table) do
      :undefined ->
        nil

      table ->
        case :ets.info(table, :owner) do
          owner when is_pid(owner) -> {table, owner}
          _other -> nil
        end
    end
  rescue
    ArgumentError -> nil
  end

  defp drain_observations(state, now) do
    observations =
      for {{:target, {repo, prefix} = target} = target_key, {slot, {:observed, _observed_at}}} <-
            :ets.tab2list(@episodes_table),
          is_atom(repo) and (is_binary(prefix) or is_nil(prefix)) do
        {target_key, slot, target}
      end

    Enum.reduce(observations, {[], state}, fn {target_key, slot, target}, {signals, acc} ->
      cond do
        running_target?(target) ->
          {signals, clear_target_state(acc, target)}

        acc.warming ->
          :ets.insert(@episodes_table, {target_key, {slot, {:warming, now}}})
          {signals, acc}

        true ->
          :ets.insert(@episodes_table, {target_key, {slot, {:armed, now + @episode_ttl_ms}}})
          {[target | signals], acc}
      end
    end)
  end

  defp drain_warming_targets(now) do
    warming_targets =
      for {{:target, {repo, prefix} = target} = target_key, {slot, {:warming, _observed_at}}} <-
            :ets.tab2list(@episodes_table),
          is_atom(repo) and (is_binary(prefix) or is_nil(prefix)) do
        {target_key, slot, target}
      end

    Enum.reduce(warming_targets, [], fn {target_key, slot, target}, signals ->
      if running_target?(target) do
        _released = release_target(target)
        signals
      else
        :ets.insert(@episodes_table, {target_key, {slot, {:armed, now + @episode_ttl_ms}}})
        [target | signals]
      end
    end)
  end

  defp prune_expired_episodes(now) do
    expired =
      for {{:target, {repo, prefix} = target} = target_key, {slot, {:armed, expires_at} = status}} <-
            :ets.tab2list(@episodes_table),
          is_atom(repo) and (is_binary(prefix) or is_nil(prefix)),
          expires_at <= now do
        {target_key, slot, target, status}
      end

    Enum.each(expired, fn {target_key, slot, target, status} ->
      retire_target(target_key, slot, target, status)
    end)
  end

  defp rearm_after_signal_restart do
    now = System.monotonic_time(:millisecond)

    for {{:target, target} = target_key, {slot, {:armed, _expires_at}}} <-
          :ets.tab2list(@episodes_table) do
      if running_target?(target) do
        _released = release_target(target)
      else
        :ets.insert(@episodes_table, {target_key, {slot, {:observed, now}}})
      end
    end
  end

  defp take_capacity_notice(state) do
    requested? = :ets.take(@episodes_table, @capacity_key) != []

    if requested? and not state.capacity_reported do
      {true, %{state | capacity_reported: true}}
    else
      {false, state}
    end
  end

  defp refresh_capacity_state(state) do
    if tracked_target_count() < @max_missing_episodes do
      %{state | capacity_reported: false}
    else
      state
    end
  end

  defp call_if_started(message) do
    case Process.whereis(__MODULE__) do
      pid when is_pid(pid) ->
        try do
          GenServer.call(pid, message)
        catch
          :exit, {:timeout, _details} -> {:error, :timeout}
          :exit, {:noproc, _details} -> {:error, :not_started}
          :exit, _reason -> {:error, :registration_failed}
        end

      nil ->
        {:error, :not_started}
    end
  end

  defp registration_for(pid, state) do
    case lookup_pid(pid) do
      [{^pid, ref, targets}] ->
        {ref, targets, state}

      [] ->
        ref = Process.monitor(pid)
        {ref, %{}, %{state | monitors: Map.put(state.monitors, ref, pid)}}
    end
  end

  defp target_workers(target) do
    case lookup(@workers_table, target) do
      [{^target, workers}] -> workers
      [] -> %{}
    end
  end

  defp registered_targets(pid) do
    case lookup_pid(pid) do
      [{^pid, _ref, targets}] -> targets
      [] -> %{}
    end
  end

  defp remove_target_worker(target, pid) do
    case Map.delete(target_workers(target), pid) do
      remaining when map_size(remaining) == 0 -> :ets.delete(@workers_table, target)
      remaining -> :ets.insert(@workers_table, {target, remaining})
    end
  end

  defp lookup_pid(pid), do: lookup(@pids_table, pid)

  defp lookup(table, key) do
    :ets.lookup(table, key)
  rescue
    ArgumentError -> []
  end

  defp clear_target_state(state, target) do
    _released = release_target(target)
    refresh_capacity_state(state)
  end

  defp release_target(target), do: release_target(target, 3)

  defp release_target(_target, 0), do: false

  defp release_target(target, attempts_left) do
    target_key = {:target, target}

    case :ets.lookup(@episodes_table, target_key) do
      [] ->
        false

      [{^target_key, {slot, status}}] ->
        if retire_target(target_key, slot, target, status) do
          true
        else
          release_target(target, attempts_left - 1)
        end
    end
  rescue
    ArgumentError -> false
  end

  defp retire_target(target_key, slot, target, status) do
    current = {target_key, {slot, status}}

    if :ets.select_delete(@episodes_table, [{current, [], [true]}]) == 1 do
      :ets.delete_object(@episodes_table, {slot, target})
      true
    else
      false
    end
  end

  defp local_alive?(pid) when is_pid(pid), do: node(pid) == node() and Process.alive?(pid)
  defp local_alive?(_other), do: false
end
