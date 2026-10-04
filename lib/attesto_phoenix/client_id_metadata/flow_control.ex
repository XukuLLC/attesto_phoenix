defmodule AttestoPhoenix.ClientIdMetadata.FlowControl do
  @moduledoc """
  Per-node admission control for outbound CIMD documents and public keys.

  Concurrent misses for the same URL and trusted configuration share one
  fetch. Different URLs and hosts still share global concurrency and request
  budgets. Rejected and failed requests never become metadata cache entries;
  a short, bounded failure marker only suppresses repeated outbound work.

  Fetch callbacks run in the admitted caller, preserving request-local
  configuration and repository ownership. A crashed caller releases its slot.
  A slow caller retains its slot until it terminates, so even a custom fetcher
  that ignores the request timeout cannot exceed the concurrency budget.
  Followers have a bounded wait and cannot accumulate without limit.
  """

  use GenServer

  alias AttestoPhoenix.Config

  @defaults [
    max_concurrent_fetches: 16,
    max_concurrent_fetches_per_host: 4,
    max_fetches_per_window: 120,
    max_fetches_per_host_per_window: 30,
    fetch_rate_window_ms: 60_000,
    failure_backoff_ms: 1_000,
    max_flow_entries: 1_024,
    max_singleflight_waiters: 32,
    request_timeout_ms: 5_000
  ]

  @type result :: {:ok, term()} | {:error, term()}

  @doc false
  def start_link(opts) do
    GenServer.start_link(__MODULE__, :ok, Keyword.take(opts, [:name]))
  end

  @doc "Runs one bounded miss operation, or joins an identical in-flight operation."
  @spec run(String.t(), term(), term(), keyword(), (-> result())) :: result()
  def run(host, key, scope, opts, fetch) when is_binary(host) and is_function(fetch, 0) do
    server = Keyword.get(opts, :flow_control_server, __MODULE__)
    key = :crypto.hash(:sha256, :erlang.term_to_binary({host, key, scope, request_scope()}))
    limits = Keyword.merge(@defaults, Keyword.take(opts, Keyword.keys(@defaults)))

    case admit(server, key, host, limits) do
      {:run, token} -> execute(server, key, token, fetch)
      {:result, result} -> result
      {:error, reason} -> {:error, {:fetch, reason}}
    end
  end

  @doc false
  def stats(server \\ __MODULE__), do: GenServer.call(server, :stats)

  defp request_scope do
    # Custom fetchers may consult more than the repository/prefix. Hash the
    # whole trusted context, retaining neither configuration nor credentials
    # in coordinator state or diagnostics.
    Config.request_config()
  end

  defp admit(server, key, host, limits) do
    GenServer.call(server, {:admit, key, host, limits}, :infinity)
  catch
    :exit, _ -> {:error, :flow_control_unavailable}
  end

  defp execute(server, key, token, fetch) do
    result = fetch.()
    finish(server, key, token, result)
    result
  catch
    kind, reason ->
      finish(server, key, token, {:error, {:fetch, :fetch_failed}})
      :erlang.raise(kind, reason, __STACKTRACE__)
  end

  defp finish(server, key, token, result) do
    GenServer.call(server, {:finish, key, token, result})
  catch
    :exit, _ -> :ok
  end

  @impl true
  def init(:ok) do
    {:ok, %{flights: %{}, hosts: %{}, failures: %{}, global: nil}}
  end

  @impl true
  def handle_call({:admit, key, host, limits}, from, state) do
    now = System.monotonic_time(:millisecond)
    state = prune(state, now)

    cond do
      Map.has_key?(state.flights, key) -> join(state, key, from, limits)
      Map.has_key?(state.failures, key) -> {:reply, {:error, :failure_backoff}, state}
      true -> admit_new(state, key, host, from, limits, now)
    end
  end

  def handle_call({:finish, key, token, result}, _from, state) do
    case Map.get(state.flights, key) do
      %{token: ^token} = flight -> {:reply, :ok, complete(state, key, flight, result)}
      _ -> {:reply, :ok, state}
    end
  end

  def handle_call(:stats, _from, state) do
    state = prune(state, System.monotonic_time(:millisecond))

    stats = %{
      active: map_size(state.flights),
      hosts: map_size(state.hosts),
      failures: map_size(state.failures),
      waiters: Enum.sum(Enum.map(state.flights, fn {_key, flight} -> map_size(flight.waiters) end))
    }

    {:reply, stats, state}
  end

  @impl true
  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    case Enum.find(state.flights, fn {_key, flight} -> flight.monitor == ref end) do
      {key, flight} -> {:noreply, complete(state, key, flight, {:error, {:fetch, :fetch_failed}})}
      nil -> {:noreply, state}
    end
  end

  def handle_info({:wait_timeout, key, from}, state) do
    case Map.get(state.flights, key) do
      nil -> {:noreply, state}
      flight -> expire_waiter(state, key, flight, from)
    end
  end

  defp join(state, key, from, limits) do
    flight = Map.fetch!(state.flights, key)

    if map_size(flight.waiters) < limits[:max_singleflight_waiters] do
      timer = Process.send_after(self(), {:wait_timeout, key, from}, limits[:request_timeout_ms])
      flight = %{flight | waiters: Map.put(flight.waiters, from, timer)}
      {:noreply, put_in(state.flights[key], flight)}
    else
      {:reply, {:error, :singleflight_limit}, state}
    end
  end

  defp expire_waiter(state, key, flight, from) do
    if Map.has_key?(flight.waiters, from) do
      GenServer.reply(from, {:error, :fetch_timeout})
      {:noreply, put_in(state.flights[key].waiters, Map.delete(flight.waiters, from))}
    else
      {:noreply, state}
    end
  end

  defp admit_new(state, key, host, {pid, _tag}, limits, now) do
    window = limits[:fetch_rate_window_ms]
    global = bucket(state.global, now, window)
    host_bucket = bucket(Map.get(state.hosts, host), now, window)

    case admission_error(state, host, global, host_bucket, limits) do
      nil ->
        flight = %{
          token: make_ref(),
          monitor: Process.monitor(pid),
          host: host,
          waiters: %{},
          limits: limits
        }

        state = %{
          state
          | flights: Map.put(state.flights, key, flight),
            global: %{global | count: global.count + 1},
            hosts: Map.put(state.hosts, host, %{host_bucket | count: host_bucket.count + 1})
        }

        {:reply, {:run, flight.token}, state}

      reason ->
        {:reply, {:error, reason}, state}
    end
  end

  defp admission_error(state, host, global, host_bucket, limits) do
    active_host = Enum.count(state.flights, fn {_key, flight} -> flight.host == host end)

    cond do
      map_size(state.flights) >= limits[:max_concurrent_fetches] -> :concurrency_limit
      active_host >= limits[:max_concurrent_fetches_per_host] -> :concurrency_limit
      global.count >= limits[:max_fetches_per_window] -> :rate_limit
      host_bucket.count >= limits[:max_fetches_per_host_per_window] -> :rate_limit
      not Map.has_key?(state.hosts, host) and map_size(state.hosts) >= limits[:max_flow_entries] -> :flow_capacity
      true -> nil
    end
  end

  defp complete(state, key, flight, result) do
    Process.demonitor(flight.monitor, [:flush])

    Enum.each(flight.waiters, fn {from, timer} ->
      Process.cancel_timer(timer)
      GenServer.reply(from, {:result, result})
    end)

    state = %{state | flights: Map.delete(state.flights, key)}
    remember_failure(state, key, result, flight.limits)
  end

  defp remember_failure(state, _key, {:ok, _}, _limits), do: state

  defp remember_failure(state, key, _result, limits) do
    deadline = System.monotonic_time(:millisecond) + limits[:failure_backoff_ms]
    failures = bounded_failure_map(state.failures, limits[:max_flow_entries])
    %{state | failures: Map.put(failures, key, deadline)}
  end

  defp bounded_failure_map(failures, capacity) when map_size(failures) < capacity, do: failures

  defp bounded_failure_map(failures, _capacity) do
    {oldest, _deadline} = Enum.min_by(failures, fn {_key, deadline} -> deadline end)
    Map.delete(failures, oldest)
  end

  defp prune(state, now) do
    active_hosts = MapSet.new(state.flights, fn {_key, flight} -> flight.host end)

    %{
      state
      | failures: Map.reject(state.failures, fn {_key, deadline} -> deadline <= now end),
        hosts:
          Map.reject(state.hosts, fn {host, bucket} ->
            bucket.deadline <= now and not MapSet.member?(active_hosts, host)
          end)
    }
  end

  defp bucket(nil, now, window), do: %{count: 0, deadline: now + window}
  defp bucket(%{deadline: deadline}, now, window) when deadline <= now, do: bucket(nil, now, window)
  defp bucket(bucket, _now, _window), do: bucket
end
