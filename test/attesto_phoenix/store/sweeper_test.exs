defmodule AttestoPhoenix.Store.SweeperTest do
  use ExUnit.Case, async: false

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Store.Sweeper

  # A stub Ecto.Repo that records every delete_all/2 call so the test can assert
  # which tables were swept, the WHERE comparison used, and the forwarded
  # options, without standing up a database.
  #
  # The sweeper only knows the repo *module*, and `delete_all/2` runs inside the
  # sweeper's process, not the test's. The recorder is therefore a named Agent
  # (`RecordingRepo`) so the module callback can reach it from any process.
  defmodule RecordingRepo do
    @moduledoc false

    def start(deleted_per_table) do
      Agent.start_link(fn -> %{calls: [], deleted: deleted_per_table} end, name: __MODULE__)
    end

    def calls, do: Agent.get(__MODULE__, & &1.calls)

    def delete_all(%Ecto.Query{} = query, opts) do
      table = query_source(query)
      now = where_now(query)

      Agent.update(__MODULE__, fn state ->
        %{state | calls: state.calls ++ [%{table: table, prefix: opts[:prefix], now: now}]}
      end)

      count = Agent.get(__MODULE__, fn state -> Map.get(state.deleted, table, 0) end)
      {count, nil}
    end

    defp query_source(%Ecto.Query{from: %{source: {table, _schema}}}), do: table

    # Pull the pinned `now` value out of `where: r.expires_at < ^now` so the
    # test can assert the strict-less-than boundary is fed a single timestamp.
    defp where_now(%Ecto.Query{wheres: [%{params: params} | _]}) do
      case params do
        [{value, _type} | _] -> value
        _ -> nil
      end
    end
  end

  defmodule FakeKeystore do
    @moduledoc false
  end

  @swept_tables [
    "attesto_authorization_codes",
    "attesto_refresh_tokens",
    "attesto_device_codes",
    "attesto_ciba_requests",
    "attesto_logout_sessions",
    "dpop_nonces",
    "dpop_replays",
    "attesto_pushed_authorization_requests",
    "attesto_client_id_metadata",
    "attesto_consent_grants"
  ]

  defp valid_config(overrides) do
    base = [
      issuer: "https://issuer.example",
      audience: "https://api.example.com",
      keystore: FakeKeystore,
      repo: RecordingRepo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end
    ]

    base |> Keyword.merge(overrides) |> Config.new()
  end

  defp start_recorder(deleted_per_table) do
    {:ok, agent} = RecordingRepo.start(deleted_per_table)
    on_exit(fn -> safe_stop(agent, &Agent.stop/1) end)
    agent
  end

  defp start_sweeper(config) do
    {:ok, pid} = Sweeper.start_link(config: config, name: nil)
    on_exit(fn -> safe_stop(pid, &GenServer.stop/1) end)
    pid
  end

  defp safe_stop(pid, stop_fun) do
    if Process.alive?(pid) do
      stop_fun.(pid)
    end
  catch
    :exit, {:noproc, _} -> :ok
    :exit, {:normal, _} -> :ok
  end

  describe "start_link/1 configuration validation" do
    test "raises when :config is missing" do
      assert_raise ArgumentError, ~r/:config .* is required/, fn ->
        Sweeper.start_link([])
      end
    end

    test "raises when :config is not a %Config{}" do
      assert_raise ArgumentError, ~r/must be a %AttestoPhoenix.Config\{\}/, fn ->
        Sweeper.start_link(config: %{sweep_interval_ms: 1_000})
      end
    end

    test "raises when :sweep_interval_ms is unset" do
      config = valid_config([])

      assert_raise ArgumentError, ~r/must be a positive integer/, fn ->
        Sweeper.start_link(config: config)
      end
    end

    test "raises when :sweep_interval_ms is non-positive" do
      config = valid_config(sweep_interval_ms: 0)

      assert_raise ArgumentError, ~r/must be a positive integer/, fn ->
        Sweeper.start_link(config: config)
      end
    end
  end

  describe "init/1 and supervised lifecycle" do
    test "starts and schedules a sweep without running one synchronously" do
      start_recorder(%{})
      config = valid_config(sweep_interval_ms: 60_000)
      pid = start_sweeper(config)

      # No sweep has fired yet (interval is long); the process is alive.
      assert Process.alive?(pid)
      assert RecordingRepo.calls() == []
    end
  end

  describe "sweep behavior" do
    test "deletes from every generated store table exactly once per sweep" do
      start_recorder(%{
        "attesto_authorization_codes" => 3,
        "attesto_refresh_tokens" => 1,
        "attesto_device_codes" => 6,
        "attesto_ciba_requests" => 9,
        "attesto_logout_sessions" => 8,
        "dpop_nonces" => 0,
        "dpop_replays" => 7,
        "attesto_pushed_authorization_requests" => 2,
        "attesto_client_id_metadata" => 4,
        "attesto_consent_grants" => 5
      })

      config = valid_config(sweep_interval_ms: 60_000)
      pid = start_sweeper(config)

      result = Sweeper.sweep_now(pid)

      assert result == %{
               "attesto_authorization_codes" => 3,
               "attesto_refresh_tokens" => 1,
               "attesto_device_codes" => 6,
               "attesto_ciba_requests" => 9,
               "attesto_logout_sessions" => 8,
               "dpop_nonces" => 0,
               "dpop_replays" => 7,
               "attesto_pushed_authorization_requests" => 2,
               "attesto_client_id_metadata" => 4,
               "attesto_consent_grants" => 5
             }

      swept = RecordingRepo.calls() |> Enum.map(& &1.table) |> Enum.sort()
      assert swept == Enum.sort(@swept_tables)
    end

    test "forwards :table_prefix to every delete" do
      start_recorder(%{})
      config = valid_config(sweep_interval_ms: 60_000, table_prefix: "auth")
      pid = start_sweeper(config)

      Sweeper.sweep_now(pid)

      prefixes = RecordingRepo.calls() |> Enum.map(& &1.prefix) |> Enum.uniq()
      assert prefixes == ["auth"]
    end

    test "defaults :table_prefix to nil when unset" do
      start_recorder(%{})
      config = valid_config(sweep_interval_ms: 60_000)
      pid = start_sweeper(config)

      Sweeper.sweep_now(pid)

      prefixes = RecordingRepo.calls() |> Enum.map(& &1.prefix) |> Enum.uniq()
      assert prefixes == [nil]
    end

    test "passes a single now timestamp to the strict-less-than comparison" do
      start_recorder(%{})
      config = valid_config(sweep_interval_ms: 60_000)
      pid = start_sweeper(config)

      before = DateTime.utc_now()
      Sweeper.sweep_now(pid)
      later = DateTime.utc_now()

      nows = RecordingRepo.calls() |> Enum.map(& &1.now)

      assert length(nows) == length(@swept_tables)

      Enum.each(nows, fn now ->
        assert %DateTime{} = now
        assert DateTime.compare(now, before) in [:gt, :eq]
        assert DateTime.compare(now, later) in [:lt, :eq]
      end)
    end

    test "handle_info(:sweep, state) runs a sweep and reschedules" do
      start_recorder(%{"dpop_replays" => 2})
      config = valid_config(sweep_interval_ms: 60_000)
      pid = start_sweeper(config)

      # Drive the timer message directly rather than waiting out the interval.
      send(pid, :sweep)
      # A round-trip call ensures the :sweep info message has been processed.
      _ = Sweeper.sweep_now(pid)

      tables = RecordingRepo.calls() |> Enum.map(& &1.table)
      # One full set from the :sweep message, one from the explicit sweep_now.
      assert Enum.count(tables, &(&1 == "dpop_replays")) == 2

      assert Process.alive?(pid)
    end
  end
end
