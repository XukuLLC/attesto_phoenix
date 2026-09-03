defmodule AttestoPhoenix.Store.SweeperTest do
  use ExUnit.Case, async: false

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.DiagnosticsSupervisor
  alias AttestoPhoenix.Store.EctoRefreshStore
  alias AttestoPhoenix.Store.Sweeper
  alias AttestoPhoenix.Store.Sweeper.Lifecycle
  alias AttestoPhoenix.Store.Sweeper.Registration
  alias AttestoPhoenix.Store.Sweeper.Signal
  alias AttestoPhoenix.Store.Sweeper.SignalTaskSupervisor

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
      Agent.start_link(fn -> %{calls: [], updates: [], deleted: deleted_per_table} end, name: __MODULE__)
    end

    def calls, do: Agent.get(__MODULE__, & &1.calls)
    def updates, do: Agent.get(__MODULE__, & &1.updates)

    def update_all(%Ecto.Query{} = query, [], opts) do
      table = query_source(query)

      Agent.update(__MODULE__, fn state ->
        call = %{
          table: table,
          prefix: opts[:prefix],
          log: opts[:log],
          telemetry_event: opts[:telemetry_event]
        }

        %{state | updates: state.updates ++ [call]}
      end)

      {0, nil}
    end

    def delete_all(%Ecto.Query{} = query, opts) do
      table = query_source(query)
      now = where_now(query)
      expr = where_expr(query)

      Agent.update(__MODULE__, fn state ->
        call = %{
          table: table,
          prefix: opts[:prefix],
          now: now,
          expr: expr,
          log: opts[:log],
          telemetry_event: opts[:telemetry_event]
        }

        %{state | calls: state.calls ++ [call]}
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

    defp where_expr(%Ecto.Query{wheres: [%{expr: expr} | _]}), do: expr
  end

  defmodule FakeKeystore do
    @moduledoc false
  end

  defmodule BrokenRegistry do
    @moduledoc false

    def whereis_name(_name), do: raise("broken registry")
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
    :exit, _reason -> :ok
  end

  defp restart_attesto_child(child) do
    old_pid = Process.whereis(child)
    assert is_pid(old_pid)
    assert :ok = Supervisor.terminate_child(DiagnosticsSupervisor, child)
    assert {:ok, new_pid} = Supervisor.restart_child(DiagnosticsSupervisor, child)
    assert new_pid != old_pid
    {old_pid, new_pid}
  end

  defp replace_lifecycle(opts) do
    assert :ok = Supervisor.terminate_child(DiagnosticsSupervisor, Lifecycle)
    assert {:ok, pid} = Lifecycle.start_link(opts)

    on_exit(fn ->
      safe_stop(pid, &GenServer.stop/1)

      if Process.whereis(Lifecycle) == nil do
        assert {:ok, _pid} = Supervisor.restart_child(DiagnosticsSupervisor, Lifecycle)
      end
    end)

    pid
  end

  defp await_signal_idle do
    eventually(fn ->
      state = :sys.get_state(Signal)
      assert state.active == nil
      assert :queue.is_empty(state.queue)
      assert state.retry_ref == nil
      assert state.delivery_failures == %{}
    end)
  end

  defp diagnostics_child_spec do
    Supervisor.child_spec({DiagnosticsSupervisor, []}, restart: :temporary)
  end

  defp restore_diagnostics_supervisor(root) do
    case Supervisor.start_child(root, diagnostics_child_spec()) do
      {:ok, pid} ->
        pid

      {:ok, pid, _info} ->
        pid

      {:error, {:already_started, pid}} ->
        pid

      {:error, :already_present} ->
        {:ok, pid} = Supervisor.restart_child(root, DiagnosticsSupervisor)
        pid
    end
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

    test "returns :ignore for an unset interval when explicitly conditional" do
      config = valid_config([])

      assert :ignore = Sweeper.start_link(config: config, if_configured: true)
    end

    test "raises when :sweep_interval_ms is non-positive" do
      config = %{valid_config(sweep_interval_ms: 1) | sweep_interval_ms: 0}

      assert_raise ArgumentError, ~r/must be a positive integer/, fn ->
        Sweeper.start_link(config: config, if_configured: true)
      end
    end

    test "rejects a non-boolean :if_configured option" do
      config = valid_config([])

      assert_raise ArgumentError, ~r/:if_configured must be true or false/, fn ->
        Sweeper.start_link(config: config, if_configured: "true")
      end
    end
  end

  describe "init/1 and supervised lifecycle" do
    test "the application supervises lifecycle and cleanup-worker registration" do
      root_children = Supervisor.which_children(AttestoPhoenix.Supervisor)

      assert {DiagnosticsSupervisor, diagnostics_pid, :supervisor, [DiagnosticsSupervisor]} =
               List.keyfind(root_children, DiagnosticsSupervisor, 0)

      assert Process.alive?(diagnostics_pid)

      children = Supervisor.which_children(DiagnosticsSupervisor)

      assert {Lifecycle, lifecycle_pid, :worker, [Lifecycle]} =
               List.keyfind(children, Lifecycle, 0)

      assert {Registration, registration_pid, :worker, [Registration]} =
               List.keyfind(children, Registration, 0)

      assert {SignalTaskSupervisor, signal_task_pid, :supervisor, [Task.Supervisor]} =
               List.keyfind(children, SignalTaskSupervisor, 0)

      assert {Signal, signal_pid, :worker, [Signal]} =
               List.keyfind(children, Signal, 0)

      assert Process.alive?(lifecycle_pid)
      assert Process.alive?(registration_pid)
      assert Process.alive?(signal_task_pid)
      assert Process.alive?(signal_pid)
    end

    test "a diagnostics restart storm cannot terminate the package application" do
      import ExUnit.CaptureLog

      root = Process.whereis(AttestoPhoenix.Supervisor)
      assert is_pid(root)

      # Earlier tests may have consumed part of the diagnostics supervisor's
      # restart budget. Start from a fresh supervisor so only the kills below
      # decide when it stops.
      if Process.whereis(DiagnosticsSupervisor) != nil do
        assert :ok = Supervisor.terminate_child(root, DiagnosticsSupervisor)
      end

      restore_diagnostics_supervisor(root)

      eventually(fn ->
        assert is_pid(Process.whereis(Signal))
        assert is_pid(Process.whereis(Lifecycle))
        assert is_pid(Process.whereis(Registration))
      end)

      on_exit(fn ->
        if Process.whereis(DiagnosticsSupervisor) == nil do
          diagnostics_pid = restore_diagnostics_supervisor(root)
          assert Process.alive?(diagnostics_pid)
        end

        eventually(fn ->
          assert is_pid(Process.whereis(Signal))
          assert is_pid(Process.whereis(Lifecycle))
          assert is_pid(Process.whereis(Registration))
        end)
      end)

      capture_log(fn ->
        for _attempt <- 1..3 do
          signal = Process.whereis(Signal)
          assert is_pid(signal)
          Process.exit(signal, :kill)

          eventually(fn ->
            replacement = Process.whereis(Signal)
            assert is_pid(replacement)
            assert replacement != signal
          end)
        end

        Process.exit(Process.whereis(Signal), :kill)

        eventually(fn ->
          assert Process.whereis(DiagnosticsSupervisor) == nil
        end)
      end)

      assert Process.alive?(root)

      assert Enum.any?(Application.started_applications(), fn {app, _description, _version} ->
               app == :attesto_phoenix
             end)
    end

    test "starts and schedules a sweep without running one synchronously" do
      start_recorder(%{})
      config = valid_config(sweep_interval_ms: 60_000)
      pid = start_sweeper(config)

      # No sweep has fired yet (interval is long); the process is alive.
      assert Process.alive?(pid)
      assert RecordingRepo.calls() == []
    end

    test "starts housekeeping while lifecycle monitoring is temporarily unavailable and registers after recovery" do
      start_recorder(%{})
      prefix = "monitor_recovery_#{System.unique_integer([:positive])}"
      config = valid_config(schema_prefix: prefix, sweep_interval_ms: 10)

      assert :ok = Supervisor.terminate_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)

      on_exit(fn ->
        if Process.whereis(Lifecycle) == nil do
          Supervisor.restart_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)
        end
      end)

      pid = start_sweeper(config)
      assert Process.alive?(pid)
      assert %{lifecycle_pid: nil, lifecycle_ref: nil} = :sys.get_state(pid)

      eventually(fn ->
        assert Process.whereis(Lifecycle) == nil
        assert length(RecordingRepo.calls()) >= 10
      end)

      assert {:ok, lifecycle_pid} = Supervisor.restart_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)

      eventually(fn ->
        assert %{lifecycle_pid: ^lifecycle_pid, lifecycle_ref: lifecycle_ref} = :sys.get_state(pid)
        assert is_reference(lifecycle_ref)
        assert Sweeper.running?(config)
      end)
    end

    test "monitoring processes and sweepers ignore stale GenServer replies" do
      start_recorder(%{})

      config =
        valid_config(
          schema_prefix: "stale_reply_#{System.unique_integer([:positive])}",
          sweep_interval_ms: 60_000
        )

      sweeper_pid = start_sweeper(config)
      pids = [Process.whereis(Lifecycle), Process.whereis(Registration), Process.whereis(Signal), sweeper_pid]

      Enum.each(pids, fn pid ->
        send(pid, {make_ref(), {:ok, self()}})
        assert is_map(:sys.get_state(pid))
        assert Process.alive?(pid)
      end)
    end
  end

  describe "sweep behavior" do
    test "sweep_now/0 targets the default registered sweeper" do
      start_recorder(%{})
      config = valid_config(sweep_interval_ms: 60_000)

      Config.with_request_config(config, fn ->
        {:ok, pid} = Sweeper.start_link(config: config)
        on_exit(fn -> safe_stop(pid, &GenServer.stop/1) end)

        assert is_map(Sweeper.sweep_now())
        assert Process.alive?(pid)
      end)
    end

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

      assert RecordingRepo.updates() == [
               %{
                 table: "attesto_refresh_tokens",
                 prefix: nil,
                 log: false,
                 telemetry_event: nil
               },
               %{
                 table: "attesto_refresh_tokens",
                 prefix: nil,
                 log: false,
                 telemetry_event: nil
               }
             ]
    end

    test "suppresses SQL logging and repo telemetry for every housekeeping query" do
      start_recorder(%{})
      config = valid_config(sweep_interval_ms: 60_000)
      pid = start_sweeper(config)

      Sweeper.sweep_now(pid)

      assert Enum.all?(RecordingRepo.calls(), fn call ->
               call.log == false and call.telemetry_event == nil
             end)

      assert Enum.all?(RecordingRepo.updates(), fn call ->
               call.log == false and call.telemetry_event == nil
             end)
    end

    test "forwards :schema_prefix to every delete" do
      start_recorder(%{})
      config = valid_config(sweep_interval_ms: 60_000, schema_prefix: "auth")
      pid = start_sweeper(config)

      Sweeper.sweep_now(pid)

      prefixes = RecordingRepo.calls() |> Enum.map(& &1.prefix) |> Enum.uniq()
      assert prefixes == ["auth"]
      assert Enum.all?(RecordingRepo.updates(), &(&1.prefix == "auth"))
    end

    test "defaults :schema_prefix to nil when unset" do
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

    test "authorization-code query preserves live linked access tokens" do
      start_recorder(%{})
      config = valid_config(sweep_interval_ms: 60_000)
      pid = start_sweeper(config)

      Sweeper.sweep_now(pid)

      authorization_call =
        RecordingRepo.calls()
        |> Enum.find(&(&1.table == "attesto_authorization_codes"))

      assert %DateTime{} = authorization_call.now

      assert {:and, _,
              [
                {:<, _, [expires_at, {:^, _, [0]}]},
                token_liveness
              ]} = authorization_call.expr

      assert field_name(expires_at) == :expires_at

      assert token_liveness
             |> flatten_or()
             |> Enum.any?(fn
               {:is_nil, _, [field]} -> field_name(field) == :access_token_jti
               _ -> false
             end)

      assert token_liveness
             |> flatten_or()
             |> Enum.any?(fn
               {:==, _, [field, %Ecto.Query.Tagged{value: ""}]} ->
                 field_name(field) == :access_token_jti

               _ ->
                 false
             end)

      assert token_liveness
             |> flatten_or()
             |> Enum.any?(fn
               {:is_nil, _, [field]} -> field_name(field) == :access_token_expires_at
               _ -> false
             end)

      assert token_liveness
             |> flatten_or()
             |> Enum.any?(fn
               {:<=, _, [field, {:^, _, [1]}]} ->
                 field_name(field) == :access_token_expires_at

               _ ->
                 false
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

  describe "child identity" do
    test "is stable for one repo and schema and differs for another schema" do
      first = valid_config(schema_prefix: "oauth_a", sweep_interval_ms: 60_000)
      same = valid_config(schema_prefix: "oauth_a", sweep_interval_ms: 60_000)
      other = valid_config(schema_prefix: "oauth_b", sweep_interval_ms: 60_000)

      assert Sweeper.child_spec(config: first).id == Sweeper.child_spec(config: same).id
      refute Sweeper.child_spec(config: first).id == Sweeper.child_spec(config: other).id
    end
  end

  describe "running?/0 and running?/1" do
    test "returns false when sweeper is not running" do
      cfg = valid_config(sweep_interval_ms: 60_000)
      refute Sweeper.running?(cfg)
      refute Sweeper.running?(nil)
      refute Sweeper.running?(:nonexistent_sweeper)
      refute Sweeper.running?({RecordingRepo, "nonexistent_prefix"})
    end

    test "returns false when sweep_interval_ms is unset or non-positive" do
      cfg_nil = valid_config([])
      refute Sweeper.running?(cfg_nil)

      cfg_zero = %{valid_config(sweep_interval_ms: 60_000) | sweep_interval_ms: 0}
      refute Sweeper.running?(cfg_zero)
    end

    test "returns true when sweeper is running with positive interval" do
      start_recorder(%{})
      cfg = valid_config(sweep_interval_ms: 60_000)
      {:ok, pid} = Sweeper.start_link(config: cfg)
      on_exit(fn -> safe_stop(pid, &GenServer.stop/1) end)

      assert Sweeper.running?(cfg)
      assert Sweeper.running?(pid)
      assert Sweeper.running?(config: cfg)
      assert Sweeper.running?({RecordingRepo, Config.table_prefix(cfg)})
    end

    test "handles default, custom, and unnamed (name: nil) registrations" do
      start_recorder(%{})
      cfg_default = valid_config(schema_prefix: "t_def", sweep_interval_ms: 60_000)
      {:ok, pid_def} = Sweeper.start_link(config: cfg_default)
      on_exit(fn -> safe_stop(pid_def, &GenServer.stop/1) end)
      assert Sweeper.running?(cfg_default)

      cfg_custom = valid_config(schema_prefix: "t_cust", sweep_interval_ms: 60_000)
      {:ok, pid_cust} = Sweeper.start_link(config: cfg_custom, name: :custom_sweeper_cust)
      on_exit(fn -> safe_stop(pid_cust, &GenServer.stop/1) end)
      assert Sweeper.running?(:custom_sweeper_cust)
      assert Sweeper.running?(cfg_custom)

      cfg_unnamed = valid_config(schema_prefix: "t_unnamed", sweep_interval_ms: 60_000)
      {:ok, pid_unnamed} = Sweeper.start_link(config: cfg_unnamed, name: nil)
      on_exit(fn -> safe_stop(pid_unnamed, &GenServer.stop/1) end)
      assert Sweeper.running?(cfg_unnamed)
      assert Sweeper.running?(pid_unnamed)
    end

    test "resolves global, via, and node-qualified local registrations" do
      start_recorder(%{})

      remote_config = valid_config(schema_prefix: "remote_name", sweep_interval_ms: 60_000)
      remote_name = :attesto_phoenix_remote_name_test
      {:ok, remote_pid} = Sweeper.start_link(config: remote_config, name: remote_name)
      on_exit(fn -> safe_stop(remote_pid, &GenServer.stop/1) end)

      assert Sweeper.running?({remote_name, node()})
      assert :ok = Sweeper.verify_running!({remote_name, node()})
      refute Sweeper.running?({remote_name, :not_this_node@invalid})

      global_config = valid_config(schema_prefix: "global_name", sweep_interval_ms: 60_000)
      global_name = {:global, {__MODULE__, make_ref()}}
      {:ok, global_pid} = Sweeper.start_link(config: global_config, name: global_name)
      on_exit(fn -> safe_stop(global_pid, &GenServer.stop/1) end)

      assert Sweeper.running?(global_name)
      assert :ok = Sweeper.verify_running!(global_name)

      registry_name = AttestoPhoenix.Store.SweeperTest.Registry
      {:ok, registry_pid} = Registry.start_link(keys: :unique, name: registry_name)
      on_exit(fn -> safe_stop(registry_pid, &GenServer.stop/1) end)

      via_config = valid_config(schema_prefix: "via_name", sweep_interval_ms: 60_000)
      via_name = {:via, Registry, {registry_name, make_ref()}}
      {:ok, via_pid} = Sweeper.start_link(config: via_config, name: via_name)
      on_exit(fn -> safe_stop(via_pid, &GenServer.stop/1) end)

      assert Sweeper.running?(via_name)
      assert :ok = Sweeper.verify_running!(via_name)
    end

    test "returns false when a custom via registry fails" do
      refute Sweeper.running?({:via, BrokenRegistry, :worker})
    end

    test "rejects arbitrary live processes not registered as sweepers" do
      arbitrary_pid = spawn(fn -> Process.sleep(10_000) end)
      on_exit(fn -> if Process.alive?(arbitrary_pid), do: Process.exit(arbitrary_pid, :kill) end)

      refute Sweeper.running?(arbitrary_pid)
    end

    test "rejects remote worker pids without crashing the registration manager" do
      node_name = Atom.to_string(:attesto_remote_test@invalid)

      remote_pid =
        :erlang.binary_to_term(
          <<131, 103, 119, byte_size(node_name), node_name::binary, 0::32, 0::32, 0>>,
          [:safe]
        )

      refute Sweeper.running?(remote_pid)

      assert_raise ArgumentError, ~r/local pid/, fn ->
        Sweeper.register_cleanup_worker({RecordingRepo, nil}, remote_pid)
      end

      assert Process.alive?(Process.whereis(Registration))
    end

    test "rejects sweeper running for a different target" do
      start_recorder(%{})
      cfg1 = valid_config(schema_prefix: "tenant_1", sweep_interval_ms: 60_000)
      cfg2 = valid_config(schema_prefix: "tenant_2", sweep_interval_ms: 60_000)

      {:ok, pid1} = Sweeper.start_link(config: cfg1)
      on_exit(fn -> safe_stop(pid1, &GenServer.stop/1) end)

      assert Sweeper.running?(cfg1)
      refute Sweeper.running?(cfg2)
      refute Sweeper.running?(config: cfg2, pid: pid1)
    end

    test "running?/0 inspects current request config" do
      start_recorder(%{})
      cfg = valid_config(sweep_interval_ms: 60_000)
      {:ok, pid} = Sweeper.start_link(config: cfg)
      on_exit(fn -> safe_stop(pid, &GenServer.stop/1) end)

      Config.with_request_config(cfg, fn ->
        assert Sweeper.running?()
      end)

      other_cfg = valid_config(schema_prefix: "unsupervised", sweep_interval_ms: 60_000)

      Config.with_request_config(other_cfg, fn ->
        refute Sweeper.running?()
      end)
    end

    test "does not dynamically generate atoms on request paths" do
      # Load every module on this path before measuring the VM-global atom
      # table; otherwise test order can count unrelated lazy module loading.
      refute Sweeper.running?({RecordingRepo, "atom_count_warmup"})
      _warmup = "atom_count_warmup_#{System.unique_integer([:positive])}"
      before_count = :erlang.system_info(:atom_count)

      for i <- 1..100 do
        prefix = "dynamic_schema_prefix_#{i}_#{System.unique_integer([:positive])}"
        refute Sweeper.running?({RecordingRepo, prefix})
      end

      after_count = :erlang.system_info(:atom_count)
      # Assert atom table did not grow by 100 atoms
      assert after_count - before_count < 10
    end
  end

  describe "verify_running!/0 and verify_running!/1" do
    test "returns :ok when sweeper is running" do
      start_recorder(%{})
      cfg = valid_config(sweep_interval_ms: 60_000)
      {:ok, pid} = Sweeper.start_link(config: cfg)
      on_exit(fn -> safe_stop(pid, &GenServer.stop/1) end)

      assert :ok = Sweeper.verify_running!(cfg)

      Config.with_request_config(cfg, fn ->
        assert :ok = Sweeper.verify_running!()
      end)
    end

    test "raises actionable RuntimeError when sweeper is not running" do
      cfg = valid_config(schema_prefix: "auth_tombstones", sweep_interval_ms: 60_000)

      error =
        assert_raise RuntimeError, ~r/AttestoPhoenix\.Store\.Sweeper is not running/, fn ->
          Sweeper.verify_running!(cfg)
        end

      assert error.message =~ "schema_prefix: \"auth_tombstones\""
      assert error.message =~ "RecordingRepo"
      assert error.message =~ "redact expired refresh-successor ciphertext and prune expired TTL rows"
      refute error.message =~ "tombstones will not be swept"
    end

    test "reports an unregistered worker without claiming its target lacks a sweeper" do
      start_recorder(%{})
      cfg = valid_config(sweep_interval_ms: 60_000)
      {:ok, sweeper_pid} = Sweeper.start_link(config: cfg)
      on_exit(fn -> safe_stop(sweeper_pid, &GenServer.stop/1) end)

      unrelated_pid = spawn(fn -> Process.sleep(:infinity) end)
      on_exit(fn -> if Process.alive?(unrelated_pid), do: Process.exit(unrelated_pid, :kill) end)

      error =
        assert_raise RuntimeError, ~r/supplied sweeper or cleanup worker/, fn ->
          Sweeper.verify_running!(unrelated_pid)
        end

      refute error.message =~ "Sweeper is not running for"
      assert Sweeper.running?(cfg)
    end
  end

  describe "register_cleanup_worker/2" do
    test "allows host cleanup worker to register and satisfy running?" do
      worker_pid = spawn(fn -> Process.sleep(10_000) end)
      on_exit(fn -> if Process.alive?(worker_pid), do: Process.exit(worker_pid, :kill) end)

      target = {RecordingRepo, "host_worker_prefix"}
      refute Sweeper.running?(target)

      assert :ok = Sweeper.register_cleanup_worker(target, worker_pid)
      assert Sweeper.running?(target)
      assert Sweeper.running?(worker_pid)

      Process.exit(worker_pid, :kill)
      Process.sleep(20)

      refute Sweeper.running?(target)
      refute Sweeper.running?(worker_pid)
    end

    test "tracks every target registered by the same worker" do
      worker_pid = spawn(fn -> Process.sleep(:infinity) end)
      on_exit(fn -> if Process.alive?(worker_pid), do: Process.exit(worker_pid, :kill) end)

      first = {RecordingRepo, "worker_target_one"}
      second = {RecordingRepo, "worker_target_two"}

      assert :ok = Sweeper.register_cleanup_worker(first, worker_pid)
      assert :ok = Sweeper.register_cleanup_worker(second, worker_pid)
      assert Sweeper.running?(first)
      assert Sweeper.running?(second)

      Process.exit(worker_pid, :kill)

      eventually(fn ->
        refute Sweeper.running?(first)
        refute Sweeper.running?(second)
      end)
    end

    test "an equivalent worker does not impersonate the packaged sweeper for sweep_now/0" do
      config = valid_config(schema_prefix: "equivalent_only", sweep_interval_ms: 60_000)
      worker_pid = spawn(fn -> Process.sleep(:infinity) end)
      on_exit(fn -> if Process.alive?(worker_pid), do: Process.exit(worker_pid, :kill) end)

      assert :ok = Sweeper.register_cleanup_worker(config, worker_pid)
      assert Sweeper.running?(config)

      Config.with_request_config(config, fn ->
        assert_raise RuntimeError, ~r/Sweeper is not running/, fn ->
          Sweeper.sweep_now()
        end
      end)
    end
  end

  describe "store check and runtime signal" do
    import ExUnit.CaptureLog

    test "emits loud warning and telemetry with safe scalars and conventional count" do
      prefix = "signal_test_#{System.unique_integer([:positive])}"
      ref = make_ref()
      owner = self()
      handler_id = {__MODULE__, :unsupervised_test, ref}

      :telemetry.attach(
        handler_id,
        [:attesto_phoenix, :store, :sweeper_unsupervised],
        &__MODULE__.handle_telemetry/4,
        owner
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      log =
        capture_log(fn ->
          Sweeper.check_running_for_store(RecordingRepo, prefix)

          assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], measurements, metadata},
                         1000

          send(self(), {:captured_signal, measurements, metadata})
          await_signal_idle()
        end)

      assert log =~ "AttestoPhoenix: AttestoPhoenix.Store.Sweeper is not running"
      assert log =~ prefix
      assert log =~ "Expired TTL rows will not be pruned"
      refute log =~ "tombstones will not be swept"

      assert_receive {:captured_signal, measurements, metadata}

      # Conventional count measurement
      assert measurements == %{count: 1}

      # Safe scalar metadata only
      assert metadata == %{repo: RecordingRepo, schema_prefix: prefix}
      refute Map.has_key?(metadata, :config)
      refute Map.has_key?(metadata, :refresh_successor_secret)
      refute Map.has_key?(metadata, :client_secret)

      # De-duplicated: second call does not re-log or re-emit telemetry
      second_log =
        capture_log(fn ->
          Sweeper.check_running_for_store(RecordingRepo, prefix)
        end)

      refute second_log =~ "schema_prefix: #{inspect(prefix)}"
      refute_receive {:telemetry_event, _, _, %{schema_prefix: ^prefix}}
    end

    test "concurrent store checks atomically deduplicate to exactly one event across 200 tasks" do
      prefix = "concurrent_signal_#{System.unique_integer([:positive])}"
      ref = make_ref()
      owner = self()
      handler_id = {__MODULE__, :concurrent_signal_test, ref}

      :telemetry.attach(
        handler_id,
        [:attesto_phoenix, :store, :sweeper_unsupervised],
        &__MODULE__.handle_telemetry/4,
        owner
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      capture_log(fn ->
        1..200
        |> Enum.map(fn _ ->
          Task.async(fn ->
            Sweeper.check_running_for_store(RecordingRepo, prefix)
          end)
        end)
        |> Task.await_many(5000)

        assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], %{count: 1},
                        %{schema_prefix: ^prefix}},
                       1000

        await_signal_idle()
      end)

      refute_receive {:telemetry_event, _, _, %{schema_prefix: ^prefix}}
    end

    test "concurrent checks schedule exactly one reminder after an episode expires" do
      prefix = "expired_episode_#{System.unique_integer([:positive])}"
      target = {RecordingRepo, prefix}
      handler_id = {__MODULE__, :expired_episode, make_ref()}

      :telemetry.attach(
        handler_id,
        [:attesto_phoenix, :store, :sweeper_unsupervised],
        &__MODULE__.handle_telemetry/4,
        self()
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      capture_log(fn ->
        assert :ok = Sweeper.check_running_for_store(RecordingRepo, prefix)

        assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], _,
                        %{schema_prefix: ^prefix}},
                       1000

        await_signal_idle()

        replace_episode_status(target, {:armed, System.monotonic_time(:millisecond) - 1})

        1..200
        |> Enum.map(fn _ ->
          Task.async(fn -> Sweeper.check_running_for_store(RecordingRepo, prefix) end)
        end)
        |> Task.await_many(5000)

        assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], _,
                        %{schema_prefix: ^prefix}},
                       1000

        await_signal_idle()
        refute_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], _, _}
      end)
    end

    test "expired episode state releases capacity without another store mutation" do
      replace_lifecycle(restart_quiet_ms: 0, episode_prune_ms: 25)
      prefix = "expired_prune_#{System.unique_integer([:positive])}"
      target = {RecordingRepo, prefix}

      capture_log(fn ->
        assert :ok = Sweeper.check_running_for_store(RecordingRepo, prefix)
        await_signal_idle()
      end)

      assert Lifecycle.tracked_target_count() == 1

      replace_episode_status(target, {:armed, System.monotonic_time(:millisecond) - 1})

      eventually(fn ->
        assert Lifecycle.tracked_target_count() == 0
        refute episode_tracked?(target)
      end)
    end

    test "releasing a colliding target preserves one episode for the displaced target" do
      replace_lifecycle(restart_quiet_ms: 0)
      {first_target, displaced_target} = colliding_targets()
      {RecordingRepo, first_prefix} = first_target
      {RecordingRepo, displaced_prefix} = displaced_target
      handler_id = {__MODULE__, :collision_release, make_ref()}

      :telemetry.attach(
        handler_id,
        [:attesto_phoenix, :store, :sweeper_unsupervised],
        &__MODULE__.handle_telemetry/4,
        self()
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      capture_log(fn ->
        assert :ok = Sweeper.check_running_for_store(RecordingRepo, first_prefix)

        assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], _,
                        %{schema_prefix: ^first_prefix}},
                       1000

        assert :ok = Sweeper.check_running_for_store(RecordingRepo, displaced_prefix)

        assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], _,
                        %{schema_prefix: ^displaced_prefix}},
                       1000

        await_signal_idle()
        assert episode_record_count(displaced_target) == 1

        worker = spawn(fn -> Process.sleep(:infinity) end)
        on_exit(fn -> if Process.alive?(worker), do: Process.exit(worker, :kill) end)
        assert :ok = Sweeper.register_cleanup_worker(first_target, worker)

        eventually(fn ->
          refute episode_tracked?(first_target)
          assert episode_record_count(displaced_target) == 1
        end)

        assert :ok = Sweeper.check_running_for_store(RecordingRepo, displaced_prefix)
        await_signal_idle()

        assert episode_record_count(displaced_target) == 1
        assert Lifecycle.tracked_target_count() == 1

        refute_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], _,
                        %{schema_prefix: ^displaced_prefix}},
                       100
      end)
    end

    test "recovery and relapse: rearms missing-sweeper episode after worker exits" do
      prefix = "recovery_relapse_#{System.unique_integer([:positive])}"
      target = {RecordingRepo, prefix}
      ref = make_ref()
      owner = self()
      handler_id = {__MODULE__, :recovery_relapse_test, ref}

      :telemetry.attach(
        handler_id,
        [:attesto_phoenix, :store, :sweeper_unsupervised],
        &__MODULE__.handle_telemetry/4,
        owner
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      # Episode 1: missing sweeper emits warning and telemetry
      capture_log(fn ->
        Sweeper.check_running_for_store(RecordingRepo, prefix)

        assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], %{count: 1},
                        %{schema_prefix: ^prefix}},
                       1000

        await_signal_idle()
      end)

      # Suppressed while missing
      capture_log(fn ->
        Sweeper.check_running_for_store(RecordingRepo, prefix)
      end)

      refute_receive {:telemetry_event, _, _, %{schema_prefix: ^prefix}}

      # Recovery: worker appears
      worker_pid = spawn(fn -> Process.sleep(10_000) end)
      Sweeper.register_cleanup_worker(target, worker_pid)
      assert Sweeper.running?(target)

      # Worker exits: relapse occurs
      Process.exit(worker_pid, :kill)
      Process.sleep(20)
      refute Sweeper.running?(target)

      # Relapse: missing sweeper emits warning and telemetry again!
      log =
        capture_log(fn ->
          Sweeper.check_running_for_store(RecordingRepo, prefix)

          assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], %{count: 1},
                          %{schema_prefix: ^prefix}},
                         1000

          await_signal_idle()
        end)

      assert log =~ "AttestoPhoenix: AttestoPhoenix.Store.Sweeper is not running"
    end

    test "does not emit warning or telemetry when sweeper is running" do
      start_recorder(%{})
      prefix = "running_test_#{System.unique_integer([:positive])}"

      cfg =
        valid_config(
          refresh_store: EctoRefreshStore,
          schema_prefix: prefix,
          sweep_interval_ms: 60_000
        )

      {:ok, pid} = Sweeper.start_link(config: cfg)
      on_exit(fn -> safe_stop(pid, &GenServer.stop/1) end)

      log =
        capture_log(fn ->
          Sweeper.check_running_for_store(RecordingRepo, prefix)
        end)

      refute log =~ "schema_prefix: #{inspect(prefix)}"
    end
  end

  describe "lifecycle recovery across process restarts" do
    test "recovers registrations when Lifecycle process restarts" do
      start_recorder(%{})
      prefix_sweeper = "recover_sw_#{System.unique_integer([:positive])}"
      cfg = valid_config(schema_prefix: prefix_sweeper, sweep_interval_ms: 60_000)
      {:ok, sweeper_pid} = Sweeper.start_link(config: cfg)
      on_exit(fn -> safe_stop(sweeper_pid, &GenServer.stop/1) end)

      prefix_worker = "recover_wk_#{System.unique_integer([:positive])}"
      target_worker = {RecordingRepo, prefix_worker}
      worker_pid = spawn(fn -> Process.sleep(:infinity) end)
      on_exit(fn -> if Process.alive?(worker_pid), do: Process.exit(worker_pid, :kill) end)

      assert :ok = Sweeper.register_cleanup_worker(target_worker, worker_pid)

      assert Sweeper.running?(cfg)
      assert Sweeper.running?(target_worker)

      {_old_lifecycle_pid, _new_lifecycle_pid} = restart_attesto_child(Lifecycle)

      eventually(fn ->
        assert Sweeper.running?(cfg)
        assert Sweeper.running?(target_worker)
      end)

      # Cleanup worker exit is still tracked after restart
      Process.exit(worker_pid, :kill)

      eventually(fn ->
        refute Sweeper.running?(target_worker)
      end)
    end

    test "recovers registrations when Registration manager process restarts" do
      prefix_worker = "recover_reg_#{System.unique_integer([:positive])}"
      target_worker = {RecordingRepo, prefix_worker}
      worker_pid = spawn(fn -> Process.sleep(:infinity) end)
      on_exit(fn -> if Process.alive?(worker_pid), do: Process.exit(worker_pid, :kill) end)

      assert :ok = Sweeper.register_cleanup_worker(target_worker, worker_pid)
      assert Sweeper.running?(target_worker)

      {_old_reg_pid, _new_reg_pid} = restart_attesto_child(Registration)

      assert Sweeper.running?(target_worker)

      Process.exit(worker_pid, :kill)

      eventually(fn ->
        refute Sweeper.running?(target_worker)
      end)
    end

    test "custom-worker registrations survive a full diagnostics subtree restart" do
      target = {RecordingRepo, "joint_restart_#{System.unique_integer([:positive])}"}
      worker = spawn(fn -> Process.sleep(:infinity) end)
      on_exit(fn -> if Process.alive?(worker), do: Process.exit(worker, :kill) end)

      root = Process.whereis(AttestoPhoenix.Supervisor)

      on_exit(fn ->
        if Process.whereis(DiagnosticsSupervisor) == nil do
          restore_diagnostics_supervisor(root)
        end
      end)

      assert :ok = Sweeper.register_cleanup_worker(target, worker)
      assert Sweeper.running?(target)

      diagnostics = Process.whereis(DiagnosticsSupervisor)
      assert is_pid(diagnostics)
      assert :ok = Supervisor.terminate_child(AttestoPhoenix.Supervisor, DiagnosticsSupervisor)
      replacement = restore_diagnostics_supervisor(root)
      assert replacement != diagnostics

      eventually(fn ->
        assert Sweeper.running?(target)
      end)
    end

    test "does not acknowledge a cleanup worker while Lifecycle is unavailable" do
      target = {RecordingRepo, "unacknowledged_#{System.unique_integer([:positive])}"}
      worker = spawn(fn -> Process.sleep(:infinity) end)
      on_exit(fn -> if Process.alive?(worker), do: Process.exit(worker, :kill) end)

      assert :ok = Supervisor.terminate_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)

      on_exit(fn ->
        if Process.whereis(Lifecycle) == nil do
          Supervisor.restart_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)
        end
      end)

      eventually(fn -> assert :sys.get_state(Registration).lifecycle_pid == nil end)

      assert_raise RuntimeError, ~r/Sweeper\.Lifecycle is not running.*register.*again/s, fn ->
        Sweeper.register_cleanup_worker(target, worker)
      end

      {_old_registration, _new_registration} = restart_attesto_child(Registration)
      assert {:ok, lifecycle} = Supervisor.restart_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)

      eventually(fn ->
        assert :sys.get_state(Registration).lifecycle_pid == lifecycle
      end)

      refute Sweeper.running?(target)
      assert :ok = Sweeper.register_cleanup_worker(target, worker)
      assert Sweeper.running?(target)
    end
  end

  describe "liveness independent of diagnostics supervisor" do
    test "sweeper liveness survives Lifecycle restart" do
      start_recorder(%{})
      target = {RecordingRepo, "lifecycle_restart_#{System.unique_integer([:positive])}"}
      config = valid_config(schema_prefix: elem(target, 1), sweep_interval_ms: 60_000)
      pid = start_sweeper(config)

      assert Sweeper.running?(target)

      on_exit(fn ->
        if Process.whereis(Lifecycle) == nil do
          Supervisor.restart_child(DiagnosticsSupervisor, Lifecycle)
        end
      end)

      assert :ok = Supervisor.terminate_child(DiagnosticsSupervisor, Lifecycle)
      assert Process.whereis(Lifecycle) == nil

      assert Sweeper.running?(target)
      assert :ok = Sweeper.verify_running!(target)
      assert is_map(Sweeper.sweep_now(pid))

      assert {:ok, _new_lifecycle} = Supervisor.restart_child(DiagnosticsSupervisor, Lifecycle)
      eventually(fn -> assert is_pid(Process.whereis(Lifecycle)) end)

      assert Sweeper.running?(target)
      assert :ok = Sweeper.verify_running!(target)
      assert is_map(Sweeper.sweep_now(pid))
    end

    test "sweeper liveness never reports false during Lifecycle crash and restart" do
      start_recorder(%{})
      target = {RecordingRepo, "lifecycle_crash_#{System.unique_integer([:positive])}"}
      config = valid_config(schema_prefix: elem(target, 1), sweep_interval_ms: 60_000)
      pid = start_sweeper(config)

      assert Sweeper.running?(target)

      lifecycle_pid = Process.whereis(Lifecycle)
      assert is_pid(lifecycle_pid)

      Process.exit(lifecycle_pid, :kill)

      Enum.each(1..100, fn _ ->
        assert Sweeper.running?(target)
        Process.sleep(1)
      end)

      eventually(fn ->
        new_lifecycle = Process.whereis(Lifecycle)
        assert is_pid(new_lifecycle)
        assert new_lifecycle != lifecycle_pid
      end)

      assert Sweeper.running?(target)
      assert Process.alive?(pid)
    end

    test "sweeper liveness answers stay correct across permanent diagnostics supervisor stop" do
      start_recorder(%{})
      target = {RecordingRepo, "perm_stop_#{System.unique_integer([:positive])}"}
      unregistered_target = {RecordingRepo, "unregistered_#{System.unique_integer([:positive])}"}
      cleanup_target = {RecordingRepo, "cleanup_perm_#{System.unique_integer([:positive])}"}

      worker =
        spawn(fn ->
          receive do
            :stop -> :ok
          end
        end)

      on_exit(fn -> if Process.alive?(worker), do: Process.exit(worker, :kill) end)

      assert :ok = Sweeper.register_cleanup_worker(cleanup_target, worker)
      assert Sweeper.running?(cleanup_target)

      config = valid_config(schema_prefix: elem(target, 1), sweep_interval_ms: 60_000)
      root = AttestoPhoenix.Supervisor

      on_exit(fn ->
        if Process.whereis(DiagnosticsSupervisor) == nil do
          case Supervisor.restart_child(root, AttestoPhoenix.DiagnosticsSupervisor) do
            {:ok, _pid} -> :ok
            {:error, {:already_started, _pid}} -> :ok
            {:error, :running} -> :ok
            _ -> restore_diagnostics_supervisor(root)
          end
        end

        eventually(fn ->
          assert is_pid(Process.whereis(Lifecycle))
          assert is_pid(Process.whereis(Signal))
          assert is_pid(Process.whereis(Registration))
        end)
      end)

      Config.with_request_config(config, fn ->
        {:ok, pid} = Sweeper.start_link(config: config)
        on_exit(fn -> safe_stop(pid, &GenServer.stop/1) end)

        assert :ok = Supervisor.terminate_child(root, DiagnosticsSupervisor)
        assert Process.whereis(DiagnosticsSupervisor) == nil

        # For the running sweeper
        assert Sweeper.running?(target)
        assert :ok = Sweeper.verify_running!(target)
        assert is_map(Sweeper.sweep_now())

        # For a target with no worker
        refute Sweeper.running?(unregistered_target)

        assert_raise RuntimeError, ~r/AttestoPhoenix\.Store\.Sweeper is not running for .*RecordingRepo/, fn ->
          Sweeper.verify_running!(unregistered_target)
        end

        # Cleanup worker registered before stop is still running
        assert Sweeper.running?(cleanup_target)

        # Becomes false after that worker process exits
        send(worker, :stop)
        eventually(fn -> refute Process.alive?(worker) end)
        refute Sweeper.running?(cleanup_target)
      end)
    end

    test "backs off lifecycle registration retries and resets on recovery" do
      start_recorder(%{})
      target = {RecordingRepo, "backoff_#{System.unique_integer([:positive])}"}
      config = valid_config(schema_prefix: elem(target, 1), sweep_interval_ms: 60_000)
      root = AttestoPhoenix.Supervisor

      on_exit(fn ->
        if Process.whereis(DiagnosticsSupervisor) == nil do
          case Supervisor.restart_child(root, AttestoPhoenix.DiagnosticsSupervisor) do
            {:ok, _pid} -> :ok
            {:error, {:already_started, _pid}} -> :ok
            {:error, :running} -> :ok
            _ -> restore_diagnostics_supervisor(root)
          end
        end

        eventually(fn ->
          assert is_pid(Process.whereis(Lifecycle))
          assert is_pid(Process.whereis(Signal))
          assert is_pid(Process.whereis(Registration))
        end)
      end)

      {:ok, sweeper} = Sweeper.start_link(config: config, name: nil)
      on_exit(fn -> safe_stop(sweeper, &GenServer.stop/1) end)

      assert :ok = Supervisor.terminate_child(root, DiagnosticsSupervisor)
      assert Process.whereis(DiagnosticsSupervisor) == nil

      # Read :sys.get_state(sweeper).lifecycle_retry_ms repeatedly for up to two seconds:
      # assert it grows above 50 and never exceeds 5_000
      eventually(
        fn ->
          delay = :sys.get_state(sweeper).lifecycle_retry_ms
          assert delay > 50
          assert delay <= 5_000
        end,
        200
      )

      # Restore diagnostics supervisor
      case Supervisor.restart_child(root, AttestoPhoenix.DiagnosticsSupervisor) do
        {:ok, _pid} -> :ok
        {:error, {:already_started, _pid}} -> :ok
        {:error, :running} -> :ok
        _ -> restore_diagnostics_supervisor(root)
      end

      eventually(fn ->
        assert is_pid(Process.whereis(Lifecycle))
      end)

      # After diagnostics are restored and registration succeeds, assert it is back to 50
      eventually(fn ->
        assert :sys.get_state(sweeper).lifecycle_retry_ms == 50
        assert is_pid(:sys.get_state(sweeper).lifecycle_pid)
      end)
    end
  end

  describe "equivalent cleanup workers" do
    import ExUnit.CaptureLog

    test "supports multiple equivalent workers on the same target and tracks cumulative liveness" do
      prefix = "equiv_#{System.unique_integer([:positive])}"
      target = {RecordingRepo, prefix}
      handler_id = {__MODULE__, :equivalent_worker_signal, make_ref()}

      :telemetry.attach(
        handler_id,
        [:attesto_phoenix, :store, :sweeper_unsupervised],
        &__MODULE__.handle_telemetry/4,
        self()
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      worker_1 = spawn(fn -> Process.sleep(:infinity) end)
      worker_2 = spawn(fn -> Process.sleep(:infinity) end)

      on_exit(fn ->
        if Process.alive?(worker_1), do: Process.exit(worker_1, :kill)
        if Process.alive?(worker_2), do: Process.exit(worker_2, :kill)
      end)

      assert :ok = Sweeper.register_cleanup_worker(target, worker_1)
      assert :ok = Sweeper.register_cleanup_worker(target, worker_2)

      assert Sweeper.running?(target)
      assert Sweeper.running?(worker_1)
      assert Sweeper.running?(worker_2)

      # Killing one equivalent worker keeps target running
      Process.exit(worker_1, :kill)
      Process.sleep(20)

      assert Sweeper.running?(target)
      refute Sweeper.running?(worker_1)
      assert Sweeper.running?(worker_2)

      log_while_equiv_alive =
        capture_log(fn ->
          Sweeper.check_running_for_store(RecordingRepo, prefix)
        end)

      assert log_while_equiv_alive == ""

      # Killing the remaining equivalent worker makes target not running and rearms signal
      Process.exit(worker_2, :kill)
      Process.sleep(20)

      refute Sweeper.running?(target)
      refute Sweeper.running?(worker_2)

      log_relapse =
        capture_log(fn ->
          Sweeper.check_running_for_store(RecordingRepo, prefix)

          assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], _,
                          %{schema_prefix: ^prefix}},
                         1000

          await_signal_idle()
        end)

      assert log_relapse =~ "AttestoPhoenix: AttestoPhoenix.Store.Sweeper is not running"
    end
  end

  describe "fail-open behavior and invalid targets" do
    test "check_running_for_store is fail-open for invalid targets" do
      assert :ok = Sweeper.check_running_for_store(nil, nil)
      assert :ok = Sweeper.check_running_for_store("not_an_atom", "prefix")
      assert :ok = Sweeper.check_running_for_store(RecordingRepo, "INVALID PREFIX WITH UPPERCASE!")
      assert :ok = Sweeper.check_running_for_store(RecordingRepo, 12_345)
      assert :ok = Sweeper.check_running_for_store(nil, "prefix")
      assert :ok = Sweeper.check_running_for_store(RecordingRepo, "")
    end

    test "running?/1 safely returns false for invalid targets" do
      malformed_config = %{valid_config(sweep_interval_ms: 60_000) | repo: nil}
      malformed_prefix_config = %{valid_config(sweep_interval_ms: 60_000) | schema_prefix: :invalid}

      refute Sweeper.running?({nil, nil})
      refute Sweeper.running?({"invalid_repo", nil})
      refute Sweeper.running?({RecordingRepo, "INVALID PREFIX!"})
      refute Sweeper.running?(repo: "not_an_atom")
      refute Sweeper.running?(repo: RecordingRepo, schema_prefix: "INVALID PREFIX!")
      refute Sweeper.running?(config: :not_a_config, name: :not_a_worker)
      refute Sweeper.running?(config: %{repo: RecordingRepo}, pid: self())
      refute Sweeper.running?("not_a_target")
      refute Sweeper.running?(12_345)
      refute Sweeper.running?(malformed_config)
      refute Sweeper.running?(malformed_prefix_config)
      refute Sweeper.running?(repo: RecordingRepo, schema_prefx: "typo")
      refute Sweeper.running?(repo: RecordingRepo, name: :ambiguous)
      refute Sweeper.running?(config: valid_config([]), pid: self(), name: :ambiguous)
      refute Sweeper.running?(repo: RecordingRepo, repo: RecordingRepo)
      refute Sweeper.running?([{:repo, RecordingRepo}, :not_a_pair])
    end

    test "verify_running!/1 reports controlled errors for malformed public targets" do
      malformed_config = %{valid_config(sweep_interval_ms: 60_000) | repo: nil}

      for target <- [
            {RecordingRepo, :invalid},
            malformed_config,
            [foo: 1],
            [repo: RecordingRepo, schema_prefx: "typo"],
            [repo: RecordingRepo, name: :ambiguous],
            [repo: RecordingRepo, repo: RecordingRepo]
          ] do
        assert_raise RuntimeError, ~r/target is invalid/, fn ->
          Sweeper.verify_running!(target)
        end
      end
    end

    test "register_cleanup_worker/2 raises ArgumentError for invalid targets" do
      worker = spawn(fn -> Process.sleep(10_000) end)
      on_exit(fn -> if Process.alive?(worker), do: Process.exit(worker, :kill) end)

      assert_raise ArgumentError, ~r/sweeper target must be \{repo_module, schema_prefix\}/, fn ->
        Sweeper.register_cleanup_worker({nil, nil}, worker)
      end

      assert_raise ArgumentError, ~r/sweeper target must be \{repo_module, schema_prefix\}/, fn ->
        Sweeper.register_cleanup_worker({RecordingRepo, "INVALID PREFIX!"}, worker)
      end

      assert_raise ArgumentError, ~r/sweeper target must be \{repo_module, schema_prefix\}/, fn ->
        Sweeper.register_cleanup_worker(Process.get(make_ref(), "invalid"), worker)
      end

      assert_raise ArgumentError, ~r/cleanup worker must be a pid/, fn ->
        Sweeper.register_cleanup_worker({RecordingRepo, nil}, :not_a_pid)
      end

      for target <- [
            :implicit_default,
            self(),
            [],
            [foo: 1],
            [repo: RecordingRepo, schema_prefx: "typo"],
            [repo: RecordingRepo, config: valid_config([])],
            [repo: RecordingRepo, repo: RecordingRepo]
          ] do
        assert_raise ArgumentError, ~r/sweeper target must be/, fn ->
          Sweeper.register_cleanup_worker(target, worker)
        end
      end

      refute Sweeper.running?(worker)
    end
  end

  describe "bounded asynchronous signaling" do
    import ExUnit.CaptureLog

    test "the lifecycle owner recovers a claimed doorbell when its caller disappears" do
      replace_lifecycle(restart_quiet_ms: 0, doorbell_watchdog_ms: 25)
      await_signal_idle()

      prefix = "poisoned_doorbell_#{System.unique_integer([:positive])}"
      target = {RecordingRepo, prefix}
      table = :ets.whereis(:attesto_phoenix_sweeper_episodes)

      handler_id = {__MODULE__, :poisoned_doorbell, make_ref()}

      :telemetry.attach(
        handler_id,
        [:attesto_phoenix, :store, :sweeper_unsupervised],
        &__MODULE__.handle_telemetry/4,
        self()
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      capture_log(fn ->
        assert insert_observed_episode(table, target)
        assert :ets.insert_new(table, {:drain_pending, true})

        assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], %{count: 1},
                        %{repo: RecordingRepo, schema_prefix: ^prefix}},
                       1000

        await_signal_idle()
      end)
    end

    test "the lifecycle watchdog recovers admitted work when its caller dies before claiming the doorbell" do
      replace_lifecycle(restart_quiet_ms: 0, doorbell_watchdog_ms: 25)
      await_signal_idle()

      prefix = "orphaned_observation_#{System.unique_integer([:positive])}"
      target = {RecordingRepo, prefix}
      table = :ets.whereis(:attesto_phoenix_sweeper_episodes)
      handler_id = {__MODULE__, :orphaned_observation, make_ref()}

      :telemetry.attach(
        handler_id,
        [:attesto_phoenix, :store, :sweeper_unsupervised],
        &__MODULE__.handle_telemetry/4,
        self()
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      capture_log(fn ->
        assert insert_observed_episode(table, target)
        refute :ets.member(table, :drain_pending)

        assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], %{count: 1},
                        %{repo: RecordingRepo, schema_prefix: ^prefix}},
                       1000

        await_signal_idle()
      end)
    end

    test "the lifecycle watchdog recovers a capacity notice without a doorbell" do
      replace_lifecycle(restart_quiet_ms: 0, doorbell_watchdog_ms: 25)
      await_signal_idle()

      table = :ets.whereis(:attesto_phoenix_sweeper_episodes)
      handler_id = {__MODULE__, :orphaned_capacity_notice, make_ref()}

      :telemetry.attach(
        handler_id,
        [:attesto_phoenix, :store, :sweeper_signal_capacity],
        &__MODULE__.handle_telemetry/4,
        self()
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      capture_log(fn ->
        assert :ets.insert_new(table, {:capacity_pending, true})
        refute :ets.member(table, :drain_pending)

        assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_signal_capacity], %{count: 1}, %{}},
                       1000

        await_signal_idle()
      end)
    end

    test "store checks return while Lifecycle and Registration are suspended" do
      lifecycle = replace_lifecycle(restart_quiet_ms: 60_000)
      registration = Process.whereis(Registration)
      assert is_pid(lifecycle)
      assert is_pid(registration)

      eventually(fn ->
        assert :sys.get_state(registration).lifecycle_pid == lifecycle
      end)

      :sys.suspend(lifecycle)
      :sys.suspend(registration)

      on_exit(fn ->
        if Process.alive?(registration), do: :sys.resume(registration)
        if Process.alive?(lifecycle), do: :sys.resume(lifecycle)
      end)

      owner = self()
      prefix = "suspended_#{System.unique_integer([:positive])}"

      spawn(fn ->
        send(owner, {:store_check_result, Sweeper.check_running_for_store(RecordingRepo, prefix)})
      end)

      assert_receive {:store_check_result, :ok}, 100
      assert Lifecycle.tracked_target_count() >= 1

      :sys.resume(registration)
      :sys.resume(lifecycle)
    end

    test "a Signal restart rearms retained episodes that may not have been delivered" do
      replace_lifecycle(restart_quiet_ms: 0)
      prefix = "signal_restart_#{System.unique_integer([:positive])}"
      handler_id = {__MODULE__, :signal_restart, make_ref()}

      :telemetry.attach(
        handler_id,
        [:attesto_phoenix, :store, :sweeper_unsupervised],
        &__MODULE__.handle_telemetry/4,
        self()
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      capture_log(fn ->
        assert :ok = Sweeper.check_running_for_store(RecordingRepo, prefix)

        assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], _,
                        %{schema_prefix: ^prefix}},
                       1000

        await_signal_idle()
        {_old_signal, _new_signal} = restart_attesto_child(Signal)

        assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], _,
                        %{schema_prefix: ^prefix}},
                       1000

        await_signal_idle()
      end)
    end

    test "a blocked telemetry handler cannot block callers or Lifecycle" do
      replace_lifecycle(restart_quiet_ms: 0)
      handler_id = {__MODULE__, :blocking_signal, make_ref()}
      release_ref = make_ref()

      :telemetry.attach(
        handler_id,
        [:attesto_phoenix, :store, :sweeper_unsupervised],
        &__MODULE__.handle_blocking_telemetry/4,
        {self(), release_ref}
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      capture_log(fn ->
        first_prefix = "blocked_signal_#{System.unique_integer([:positive])}"
        assert :ok = Sweeper.check_running_for_store(RecordingRepo, first_prefix)
        assert_receive {:telemetry_handler_blocked, emitter_pid, ^release_ref}, 1000

        owner = self()

        spawn(fn ->
          result = Sweeper.check_running_for_store(RecordingRepo, first_prefix)
          send(owner, {:blocked_handler_store_result, result})
        end)

        assert_receive {:blocked_handler_store_result, :ok}, 100

        worker = spawn(fn -> Process.sleep(:infinity) end)
        target = {RecordingRepo, "coordinator_responsive_#{System.unique_integer([:positive])}"}
        assert :ok = Sweeper.register_cleanup_worker(target, worker)
        assert Sweeper.running?(target)
        Process.exit(worker, :kill)

        send(emitter_pid, {:release_telemetry, release_ref})
        await_signal_idle()
      end)
    end

    test "an active signal is retried when its task supervisor terminates" do
      replace_lifecycle(restart_quiet_ms: 0)
      handler_id = {__MODULE__, :task_supervisor_restart, make_ref()}
      release_ref = make_ref()

      :telemetry.attach(
        handler_id,
        [:attesto_phoenix, :store, :sweeper_unsupervised],
        &__MODULE__.handle_blocking_telemetry/4,
        {self(), release_ref}
      )

      on_exit(fn ->
        :telemetry.detach(handler_id)

        if Process.whereis(SignalTaskSupervisor) == nil do
          Supervisor.restart_child(AttestoPhoenix.DiagnosticsSupervisor, SignalTaskSupervisor)
        end
      end)

      prefix = "task_supervisor_restart_#{System.unique_integer([:positive])}"

      capture_log(fn ->
        assert :ok = Sweeper.check_running_for_store(RecordingRepo, prefix)
        assert_receive {:telemetry_handler_blocked, first_emitter, ^release_ref}, 1000

        assert :ok =
                 Supervisor.terminate_child(
                   AttestoPhoenix.DiagnosticsSupervisor,
                   SignalTaskSupervisor
                 )

        assert {:ok, _task_supervisor} =
                 Supervisor.restart_child(
                   AttestoPhoenix.DiagnosticsSupervisor,
                   SignalTaskSupervisor
                 )

        assert_receive {:telemetry_handler_blocked, second_emitter, ^release_ref}, 1000
        assert second_emitter != first_emitter
        send(second_emitter, {:release_telemetry, release_ref})
        await_signal_idle()
      end)
    end

    test "a crashing signal delivery is abandoned after three attempts" do
      replace_lifecycle(restart_quiet_ms: 0)
      handler_id = {__MODULE__, :crashing_signal, make_ref()}
      release_ref = make_ref()

      :telemetry.attach(
        handler_id,
        [:attesto_phoenix, :store, :sweeper_unsupervised],
        &__MODULE__.handle_blocking_telemetry/4,
        {self(), release_ref}
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      prefix = "crashing_signal_#{System.unique_integer([:positive])}"

      capture_log(fn ->
        assert :ok = Sweeper.check_running_for_store(RecordingRepo, prefix)

        for _attempt <- 1..3 do
          assert_receive {:telemetry_handler_blocked, emitter, ^release_ref}, 1000
          Process.exit(emitter, :kill)
        end

        await_signal_idle()
        refute_receive {:telemetry_handler_blocked, _emitter, ^release_ref}, 150

        state = :sys.get_state(Signal)
        assert state.delivery_failures == %{}
        refute MapSet.member?(state.pending_keys, {:unsupervised, {RecordingRepo, prefix}})
      end)
    end

    test "task-start failures are bounded and a later episode can still be delivered" do
      replace_lifecycle(restart_quiet_ms: 0)
      handler_id = {__MODULE__, :bounded_task_start, make_ref()}

      :telemetry.attach(
        handler_id,
        [:attesto_phoenix, :store, :sweeper_unsupervised],
        &__MODULE__.handle_telemetry/4,
        self()
      )

      on_exit(fn ->
        :telemetry.detach(handler_id)

        if Process.whereis(SignalTaskSupervisor) == nil do
          Supervisor.restart_child(DiagnosticsSupervisor, SignalTaskSupervisor)
        end
      end)

      assert :ok = Supervisor.terminate_child(DiagnosticsSupervisor, SignalTaskSupervisor)
      unavailable_prefix = "task_start_unavailable_#{System.unique_integer([:positive])}"
      unavailable_key = {:unsupervised, {RecordingRepo, unavailable_prefix}}

      assert :ok = Sweeper.check_running_for_store(RecordingRepo, unavailable_prefix)

      eventually(fn ->
        state = :sys.get_state(Signal)
        assert Map.get(state.delivery_failures, unavailable_key, 0) > 0
      end)

      eventually(fn ->
        state = :sys.get_state(Signal)
        assert state.active == nil
        assert :queue.is_empty(state.queue)
        assert state.retry_ref == nil
        refute MapSet.member?(state.pending_keys, unavailable_key)
        assert state.delivery_failures == %{}
      end)

      refute_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], _, _}

      state = :sys.get_state(Signal)
      assert state.delivery_failures == %{}
      assert MapSet.size(state.pending_keys) == 0

      assert {:ok, _task_supervisor} =
               Supervisor.restart_child(DiagnosticsSupervisor, SignalTaskSupervisor)

      recovered_prefix = "task_start_recovered_#{System.unique_integer([:positive])}"
      assert :ok = Sweeper.check_running_for_store(RecordingRepo, recovered_prefix)

      assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], _,
                      %{schema_prefix: ^recovered_prefix}},
                     1000

      await_signal_idle()
    end

    test "registration cancels a warning queued before signal delivery" do
      await_signal_idle()
      assert :ok = Supervisor.terminate_child(AttestoPhoenix.DiagnosticsSupervisor, SignalTaskSupervisor)

      on_exit(fn ->
        if Process.whereis(SignalTaskSupervisor) == nil do
          assert {:ok, _pid} =
                   Supervisor.restart_child(AttestoPhoenix.DiagnosticsSupervisor, SignalTaskSupervisor)
        end
      end)

      prefix = "queued_recovery_#{System.unique_integer([:positive])}"
      target = {RecordingRepo, prefix}
      handler_id = {__MODULE__, :queued_recovery, make_ref()}

      :telemetry.attach(
        handler_id,
        [:attesto_phoenix, :store, :sweeper_unsupervised],
        &__MODULE__.handle_telemetry/4,
        self()
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      log =
        capture_log(fn ->
          assert :ok = Sweeper.check_running_for_store(RecordingRepo, prefix)

          eventually(fn ->
            state = :sys.get_state(Signal)
            assert MapSet.member?(state.pending_keys, {:unsupervised, target})
          end)

          worker = spawn(fn -> Process.sleep(:infinity) end)
          on_exit(fn -> if Process.alive?(worker), do: Process.exit(worker, :kill) end)
          assert :ok = Sweeper.register_cleanup_worker(target, worker)

          assert {:ok, _pid} =
                   Supervisor.restart_child(AttestoPhoenix.DiagnosticsSupervisor, SignalTaskSupervisor)

          await_signal_idle()
        end)

      refute log =~ "schema_prefix: #{inspect(prefix)}"
      refute_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], _, _}
    end
  end

  describe "capacity bounds under high cardinality" do
    import ExUnit.CaptureLog

    test "probe collisions do not masquerade as exhausted capacity" do
      lifecycle = replace_lifecycle(restart_quiet_ms: 60_000)
      :sys.suspend(lifecycle)
      on_exit(fn -> if Process.alive?(lifecycle), do: :sys.resume(lifecycle) end)

      table = :ets.whereis(:attesto_phoenix_sweeper_episodes)
      target = {RecordingRepo, "probe_collision_#{System.unique_integer([:positive])}"}
      now = System.monotonic_time(:millisecond)

      for offset <- 0..7 do
        slot = target_slot_for_test(target, offset)
        blocker = {RecordingRepo, "probe_blocker_#{offset}_#{System.unique_integer([:positive])}"}

        assert :ets.insert_new(table, [
                 {{:target, blocker}, {slot, {:armed, now + 60_000}}},
                 {slot, blocker}
               ])
      end

      assert Lifecycle.tracked_target_count() == 8
      assert :ok = Sweeper.check_running_for_store(elem(target, 0), elem(target, 1))
      assert episode_tracked?(target)
      assert Lifecycle.tracked_target_count() == 9
    end

    test "bounds memory under high-cardinality targets and emits capacity signal once" do
      lifecycle = replace_lifecycle(restart_quiet_ms: 60_000)

      eventually(fn ->
        assert :sys.get_state(Registration).lifecycle_pid == lifecycle
      end)

      :sys.suspend(lifecycle)
      on_exit(fn -> if Process.alive?(lifecycle), do: :sys.resume(lifecycle) end)

      ref = make_ref()
      owner = self()
      handler_id = {__MODULE__, :capacity_test, ref}

      :telemetry.attach(
        handler_id,
        [:attesto_phoenix, :store, :sweeper_signal_capacity],
        &__MODULE__.handle_telemetry/4,
        owner
      )

      on_exit(fn ->
        :telemetry.detach(handler_id)
      end)

      log =
        capture_log(fn ->
          prefixes =
            for i <- 1..1100 do
              "cap_#{i}_#{System.unique_integer([:positive])}"
            end

          for prefix <- prefixes do
            Sweeper.check_running_for_store(RecordingRepo, prefix)
          end

          assert Lifecycle.tracked_target_count() == 1_024
          assert {:message_queue_len, queue_len} = Process.info(lifecycle, :message_queue_len)
          assert queue_len <= 1

          :sys.resume(lifecycle)

          assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_signal_capacity], %{count: 1}, %{}},
                         1000

          await_signal_idle()

          worker = spawn(fn -> Process.sleep(:infinity) end)
          on_exit(fn -> if Process.alive?(worker), do: Process.exit(worker, :kill) end)
          assert :ok = Sweeper.register_cleanup_worker({RecordingRepo, hd(prefixes)}, worker)
          assert Lifecycle.tracked_target_count() == 1_023

          replacement = "cap_replacement_#{System.unique_integer([:positive])}"
          overflow = "cap_overflow_#{System.unique_integer([:positive])}"
          assert :ok = Sweeper.check_running_for_store(RecordingRepo, replacement)
          assert :ok = Sweeper.check_running_for_store(RecordingRepo, overflow)

          assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_signal_capacity], %{count: 1}, %{}},
                         1000

          await_signal_idle()
        end)

      assert log =~ "missing-sweeper signal capacity is exhausted"

      refute_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_signal_capacity], _, _}
    end
  end

  describe "non-blocking cold-start signaling" do
    import ExUnit.CaptureLog

    test "cold-start check does not sleep or block callers, and suppresses warning if worker registers before quiet window ends" do
      replace_lifecycle(restart_quiet_ms: 200)

      prefix = "cs_suppressed_#{System.unique_integer([:positive])}"
      target = {RecordingRepo, prefix}

      ref = make_ref()
      owner = self()
      handler_id = {__MODULE__, :cold_start_suppressed_test, ref}

      :telemetry.attach(
        handler_id,
        [:attesto_phoenix, :store, :sweeper_unsupervised],
        &__MODULE__.handle_telemetry/4,
        owner
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      # 1. Caller calls check_running_for_store during quiet window.
      # Must return promptly without sleeping for the 200ms quiet window.
      start_time = System.monotonic_time(:millisecond)
      assert :ok = Sweeper.check_running_for_store(RecordingRepo, prefix)
      elapsed_ms = System.monotonic_time(:millisecond) - start_time
      assert elapsed_ms < 100

      # 2. Worker registers before the 200ms quiet window ends
      worker = spawn(fn -> Process.sleep(:infinity) end)
      on_exit(fn -> if Process.alive?(worker), do: Process.exit(worker, :kill) end)
      assert :ok = Sweeper.register_cleanup_worker(target, worker)

      # 3. Wait out the remaining quiet window
      Process.sleep(250)

      # 4. No telemetry or warning was emitted
      refute_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], _, _}
    end

    test "cold-start check does not sleep or block callers, and eventually emits signal if no worker registers" do
      replace_lifecycle(restart_quiet_ms: 200)

      prefix = "cs_emitted_#{System.unique_integer([:positive])}"

      ref = make_ref()
      owner = self()
      handler_id = {__MODULE__, :cold_start_emitted_test, ref}

      :telemetry.attach(
        handler_id,
        [:attesto_phoenix, :store, :sweeper_unsupervised],
        &__MODULE__.handle_telemetry/4,
        owner
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      capture_log(fn ->
        # 1. Caller calls check_running_for_store during quiet window.
        # Must return promptly without sleeping for the 200ms quiet window.
        start_time = System.monotonic_time(:millisecond)
        assert :ok = Sweeper.check_running_for_store(RecordingRepo, prefix)
        elapsed_ms = System.monotonic_time(:millisecond) - start_time
        assert elapsed_ms < 100

        # 2. Immediately after the call, signal has NOT been emitted yet
        refute_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], _, _}

        # 3. Once the quiet window passes, signal is eventually emitted!
        assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], %{count: 1},
                        %{schema_prefix: ^prefix}},
                       1000

        await_signal_idle()
      end)
    end

    test "a check queued across the warming deadline emits exactly once" do
      lifecycle = replace_lifecycle(restart_quiet_ms: 200)
      prefix = "warming_boundary_#{System.unique_integer([:positive])}"
      handler_id = {__MODULE__, :warming_boundary, make_ref()}

      :telemetry.attach(
        handler_id,
        [:attesto_phoenix, :store, :sweeper_unsupervised],
        &__MODULE__.handle_telemetry/4,
        self()
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      capture_log(fn ->
        assert :ok = Sweeper.check_running_for_store(RecordingRepo, prefix)
        assert :sys.get_state(lifecycle).warming

        :sys.suspend(lifecycle)
        on_exit(fn -> if Process.alive?(lifecycle), do: :sys.resume(lifecycle) end)

        for _ <- 1..200 do
          assert :ok = Sweeper.check_running_for_store(RecordingRepo, prefix)
        end

        Process.sleep(225)
        :sys.resume(lifecycle)

        assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], %{count: 1},
                        %{schema_prefix: ^prefix}},
                       1000

        await_signal_idle()
        refute_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], _, _}
      end)
    end
  end

  describe "lifecycle monitor unavailability" do
    import ExUnit.CaptureLog

    test "re-admits the retained target when Lifecycle recovers before delivery" do
      await_signal_idle()

      handler_id = {__MODULE__, :recovered_before_monitor_delivery, make_ref()}

      :telemetry.attach(
        handler_id,
        [:attesto_phoenix, :store, :sweeper_unsupervised],
        &__MODULE__.handle_telemetry/4,
        self()
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      assert :ok = :sys.suspend(Signal)
      on_exit(fn -> if is_pid(Process.whereis(Signal)), do: :sys.resume(Signal) end)

      assert :ok = Supervisor.terminate_child(DiagnosticsSupervisor, Lifecycle)
      eventually(fn -> assert :sys.get_state(Registration).lifecycle_pid == nil end)

      prefix = "recovered_before_monitor_delivery_#{System.unique_integer([:positive])}"
      target = {RecordingRepo, prefix}
      assert :ok = Sweeper.check_running_for_store(RecordingRepo, prefix)

      assert [{:monitor_outage, _token, [^target]}] =
               :ets.lookup(:attesto_phoenix_sweeper_signal_admission, :monitor_outage)

      assert {:ok, lifecycle} = Supervisor.restart_child(DiagnosticsSupervisor, Lifecycle)
      eventually(fn -> assert :sys.get_state(Registration).lifecycle_pid == lifecycle end)

      :sys.resume(Signal)

      assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], %{count: 1},
                      %{repo: RecordingRepo, schema_prefix: ^prefix}},
                     1000

      await_signal_idle()
      refute :ets.member(:attesto_phoenix_sweeper_signal_admission, :monitor_outage)
    end

    test "retains and re-admits every distinct target observed during one outage" do
      await_signal_idle()

      monitor_handler_id = {__MODULE__, :multi_target_monitor_outage, make_ref()}
      unsupervised_handler_id = {__MODULE__, :multi_target_unsupervised, make_ref()}

      :telemetry.attach(
        monitor_handler_id,
        [:attesto_phoenix, :store, :sweeper_monitor_unavailable],
        &__MODULE__.handle_telemetry/4,
        self()
      )

      :telemetry.attach(
        unsupervised_handler_id,
        [:attesto_phoenix, :store, :sweeper_unsupervised],
        &__MODULE__.handle_telemetry/4,
        self()
      )

      on_exit(fn ->
        :telemetry.detach(monitor_handler_id)
        :telemetry.detach(unsupervised_handler_id)

        if Process.whereis(Lifecycle) == nil do
          Supervisor.restart_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)
        end

        if is_pid(Process.whereis(Signal)) do
          :sys.resume(Signal)
        end
      end)

      assert :ok = :sys.suspend(Signal)
      assert :ok = Supervisor.terminate_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)
      eventually(fn -> assert :sys.get_state(Registration).lifecycle_pid == nil end)

      first = {RecordingRepo, "multi_target_first_#{System.unique_integer([:positive])}"}
      second = {RecordingRepo, "multi_target_second_#{System.unique_integer([:positive])}"}

      assert :ok = Sweeper.check_running_for_store(elem(first, 0), elem(first, 1))
      assert :ok = Sweeper.check_running_for_store(elem(second, 0), elem(second, 1))
      assert :ok = Sweeper.check_running_for_store(elem(first, 0), elem(first, 1))

      assert [{:monitor_outage, token, targets}] =
               :ets.lookup(:attesto_phoenix_sweeper_signal_admission, :monitor_outage)

      assert is_reference(token)
      assert Enum.sort(targets) == Enum.sort([first, second])

      assert {:ok, lifecycle} = Supervisor.restart_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)
      eventually(fn -> assert :sys.get_state(Registration).lifecycle_pid == lifecycle end)

      :sys.resume(Signal)

      assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], %{count: 1},
                      %{repo: RecordingRepo, schema_prefix: first_prefix}},
                     1000

      assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], %{count: 1},
                      %{repo: RecordingRepo, schema_prefix: second_prefix}},
                     1000

      assert Enum.sort([first_prefix, second_prefix]) ==
               Enum.sort([elem(first, 1), elem(second, 1)])

      refute_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_monitor_unavailable], _, _}, 100
      await_signal_idle()
      refute :ets.member(:attesto_phoenix_sweeper_signal_admission, :monitor_outage)
    end

    test "suppresses the retained target when a cleanup worker registers during recovery" do
      await_signal_idle()

      handler_id = {__MODULE__, :recovered_with_worker, make_ref()}

      :telemetry.attach(
        handler_id,
        [:attesto_phoenix, :store, :sweeper_unsupervised],
        &__MODULE__.handle_telemetry/4,
        self()
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      assert :ok = :sys.suspend(Signal)
      on_exit(fn -> if is_pid(Process.whereis(Signal)), do: :sys.resume(Signal) end)

      assert :ok = Supervisor.terminate_child(DiagnosticsSupervisor, Lifecycle)
      eventually(fn -> assert :sys.get_state(Registration).lifecycle_pid == nil end)

      prefix = "recovered_with_worker_#{System.unique_integer([:positive])}"
      target = {RecordingRepo, prefix}
      assert :ok = Sweeper.check_running_for_store(RecordingRepo, prefix)

      assert {:ok, lifecycle} = Supervisor.restart_child(DiagnosticsSupervisor, Lifecycle)
      eventually(fn -> assert :sys.get_state(Registration).lifecycle_pid == lifecycle end)

      worker = spawn(fn -> Process.sleep(:infinity) end)
      on_exit(fn -> if Process.alive?(worker), do: Process.exit(worker, :kill) end)
      assert :ok = Sweeper.register_cleanup_worker(target, worker)

      :sys.resume(Signal)
      await_signal_idle()

      refute_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], _, _}, 100
      refute :ets.member(:attesto_phoenix_sweeper_signal_admission, :monitor_outage)
    end

    test "the signal owner recovers an outage marker when its caller disappears" do
      await_signal_idle()

      handler_id = {__MODULE__, :orphaned_outage_marker, make_ref()}

      :telemetry.attach(
        handler_id,
        [:attesto_phoenix, :store, :sweeper_monitor_unavailable],
        &__MODULE__.handle_telemetry/4,
        self()
      )

      unsupervised_handler_id = {__MODULE__, :orphaned_outage_unsupervised, make_ref()}

      :telemetry.attach(
        unsupervised_handler_id,
        [:attesto_phoenix, :store, :sweeper_unsupervised],
        &__MODULE__.handle_telemetry/4,
        self()
      )

      on_exit(fn ->
        :telemetry.detach(handler_id)
        :telemetry.detach(unsupervised_handler_id)

        if Process.whereis(Lifecycle) == nil do
          Supervisor.restart_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)
        end
      end)

      assert :ok = Supervisor.terminate_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)
      eventually(fn -> assert :sys.get_state(Registration).lifecycle_pid == nil end)

      prefix = "orphaned_outage_#{System.unique_integer([:positive])}"
      target = {RecordingRepo, prefix}
      token = make_ref()

      assert :ets.insert_new(
               :attesto_phoenix_sweeper_signal_admission,
               {:monitor_outage, token, target}
             )

      log =
        capture_log(fn ->
          assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_monitor_unavailable], %{count: 1},
                          %{repo: RecordingRepo, schema_prefix: ^prefix}},
                         1500

          await_signal_idle()
        end)

      assert log =~ prefix
      assert length(Regex.scan(~r/lifecycle monitor is unavailable/, log)) == 1

      assert {:ok, recovered_pid} = Supervisor.restart_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)

      assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], %{count: 1},
                      %{repo: RecordingRepo, schema_prefix: ^prefix}},
                     1000

      eventually(fn ->
        assert :sys.get_state(Registration).lifecycle_pid == recovered_pid
        refute :sys.get_state(Signal).monitor_outage
      end)

      await_signal_idle()
    end

    test "a recovered queued outage cannot hide a later outage" do
      await_signal_idle()

      handler_id = {__MODULE__, :queued_monitor_outage, make_ref()}

      :telemetry.attach(
        handler_id,
        [:attesto_phoenix, :store, :sweeper_monitor_unavailable],
        &__MODULE__.handle_telemetry/4,
        self()
      )

      on_exit(fn ->
        :telemetry.detach(handler_id)

        if Process.whereis(SignalTaskSupervisor) == nil do
          Supervisor.restart_child(AttestoPhoenix.DiagnosticsSupervisor, SignalTaskSupervisor)
        end

        if Process.whereis(Lifecycle) == nil do
          Supervisor.restart_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)
        end
      end)

      first_prefix = "queued_outage_first_#{System.unique_integer([:positive])}"
      second_prefix = "queued_outage_second_#{System.unique_integer([:positive])}"

      log =
        capture_log(fn ->
          assert :ok = Supervisor.terminate_child(AttestoPhoenix.DiagnosticsSupervisor, SignalTaskSupervisor)
          assert :ok = Supervisor.terminate_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)

          eventually(fn -> assert :sys.get_state(Registration).lifecycle_pid == nil end)

          assert :ok = Sweeper.check_running_for_store(RecordingRepo, first_prefix)

          eventually(fn ->
            assert match?({:pending, _token, {RecordingRepo, ^first_prefix}}, :sys.get_state(Signal).monitor_outage)
          end)

          assert {:ok, recovered_pid} = Supervisor.restart_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)

          eventually(fn ->
            assert :sys.get_state(Registration).lifecycle_pid == recovered_pid
            refute :sys.get_state(Signal).monitor_outage
          end)

          assert :ok = Supervisor.terminate_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)
          eventually(fn -> assert :sys.get_state(Registration).lifecycle_pid == nil end)

          assert :ok = Sweeper.check_running_for_store(RecordingRepo, second_prefix)

          eventually(fn ->
            assert match?({:pending, _token, {RecordingRepo, ^second_prefix}}, :sys.get_state(Signal).monitor_outage)
          end)

          assert {:ok, _pid} = Supervisor.restart_child(AttestoPhoenix.DiagnosticsSupervisor, SignalTaskSupervisor)

          assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_monitor_unavailable], %{count: 1},
                          %{repo: RecordingRepo, schema_prefix: ^second_prefix}},
                         1000

          await_signal_idle()
          refute_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_monitor_unavailable], _, _}
        end)

      refute log =~ first_prefix
      assert log =~ second_prefix
      assert length(Regex.scan(~r/lifecycle monitor is unavailable/, log)) == 1

      assert {:ok, final_lifecycle_pid} = Supervisor.restart_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)

      eventually(fn ->
        assert :sys.get_state(Registration).lifecycle_pid == final_lifecycle_pid
        refute :sys.get_state(Signal).monitor_outage
      end)

      # The recovered monitor re-admits both retained targets and would signal
      # them once its warming window ends. Acknowledge a worker for each so this
      # test leaves no diagnostic in flight for a later test to observe.
      for prefix <- [first_prefix, second_prefix] do
        worker = spawn(fn -> Process.sleep(:infinity) end)
        on_exit(fn -> if Process.alive?(worker), do: Process.exit(worker, :kill) end)
        assert :ok = Sweeper.register_cleanup_worker({RecordingRepo, prefix}, worker)
      end

      eventually(fn -> refute :sys.get_state(Lifecycle).warming end)
      await_signal_idle()
    end

    test "a transient recovery during delivery cannot hide a later outage" do
      await_signal_idle()

      handler_id = {__MODULE__, :transient_monitor_recovery, make_ref()}

      :telemetry.attach(
        handler_id,
        [:attesto_phoenix, :store, :sweeper_monitor_unavailable],
        &__MODULE__.handle_telemetry/4,
        self()
      )

      unsupervised_handler_id = {__MODULE__, :transient_recovery_unsupervised, make_ref()}

      :telemetry.attach(
        unsupervised_handler_id,
        [:attesto_phoenix, :store, :sweeper_unsupervised],
        &__MODULE__.handle_telemetry/4,
        self()
      )

      registration = Process.whereis(Registration)

      on_exit(fn ->
        :telemetry.detach(handler_id)
        :telemetry.detach(unsupervised_handler_id)

        if Process.alive?(registration), do: :sys.resume(registration)

        if Process.whereis(SignalTaskSupervisor) == nil do
          Supervisor.restart_child(AttestoPhoenix.DiagnosticsSupervisor, SignalTaskSupervisor)
        end

        lifecycle =
          case Process.whereis(Lifecycle) do
            nil ->
              {:ok, pid} = Supervisor.restart_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)
              pid

            pid ->
              pid
          end

        eventually(fn ->
          assert :sys.get_state(Registration).lifecycle_pid == lifecycle
          refute :sys.get_state(Signal).monitor_outage
          refute :ets.member(:attesto_phoenix_sweeper_signal_admission, :monitor_outage)
        end)
      end)

      first_prefix = "transient_recovery_first_#{System.unique_integer([:positive])}"
      second_prefix = "transient_recovery_second_#{System.unique_integer([:positive])}"

      capture_log(fn ->
        assert :ok = Supervisor.terminate_child(AttestoPhoenix.DiagnosticsSupervisor, SignalTaskSupervisor)
        assert :ok = Supervisor.terminate_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)

        eventually(fn -> assert :sys.get_state(registration).lifecycle_pid == nil end)
        :sys.suspend(registration)

        assert :ok = Sweeper.check_running_for_store(RecordingRepo, first_prefix)

        eventually(fn ->
          assert match?(
                   {:pending, _token, {RecordingRepo, ^first_prefix}},
                   :sys.get_state(Signal).monitor_outage
                 )
        end)

        assert {:ok, _lifecycle} =
                 Supervisor.restart_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)

        assert {:ok, _task_supervisor} =
                 Supervisor.restart_child(AttestoPhoenix.DiagnosticsSupervisor, SignalTaskSupervisor)

        await_signal_idle()

        # Recovery must re-admit the retained target. The missing-sweeper
        # warning is delivered even though the monitor event is suppressed.
        assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], %{count: 1},
                        %{repo: RecordingRepo, schema_prefix: ^first_prefix}},
                       1000

        eventually(fn ->
          refute :sys.get_state(Signal).monitor_outage
          refute :ets.member(:attesto_phoenix_sweeper_signal_admission, :monitor_outage)
        end)

        refute_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_monitor_unavailable], _, _}

        assert :ok = Supervisor.terminate_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)
        assert :ok = Sweeper.check_running_for_store(RecordingRepo, second_prefix)

        assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_monitor_unavailable], %{count: 1},
                        %{repo: RecordingRepo, schema_prefix: ^second_prefix}},
                       1000

        # Recover this outage inside the test so the retained target is
        # re-admitted and its missing-sweeper warning is observed here rather
        # than leaking into the next test's log capture.
        assert {:ok, _lifecycle} = Supervisor.restart_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)
        assert :ok = Signal.monitor_recovered()

        assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], %{count: 1},
                        %{repo: RecordingRepo, schema_prefix: ^second_prefix}},
                       1000

        await_signal_idle()
      end)
    end

    test "emits at most one event per outage and rearms after recovery" do
      ref = make_ref()
      owner = self()
      handler_id = {__MODULE__, :monitor_unavailable_test, ref}
      unsupervised_handler_id = {__MODULE__, :monitor_recovery_unsupervised_test, ref}

      :telemetry.attach(
        handler_id,
        [:attesto_phoenix, :store, :sweeper_monitor_unavailable],
        &__MODULE__.handle_telemetry/4,
        owner
      )

      :telemetry.attach(
        unsupervised_handler_id,
        [:attesto_phoenix, :store, :sweeper_unsupervised],
        &__MODULE__.handle_telemetry/4,
        owner
      )

      on_exit(fn ->
        :telemetry.detach(handler_id)
        :telemetry.detach(unsupervised_handler_id)

        if Process.whereis(Lifecycle) == nil do
          Supervisor.restart_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)
        end
      end)

      assert :ok = Supervisor.terminate_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)

      eventually(fn ->
        assert :sys.get_state(Registration).lifecycle_pid == nil
      end)

      await_signal_idle()
      assert :ok = :sys.suspend(Signal)
      on_exit(fn -> if is_pid(Process.whereis(Signal)), do: :sys.resume(Signal) end)

      first_log =
        capture_log(fn ->
          for _i <- 1..100 do
            Sweeper.check_running_for_store(RecordingRepo, "unavailable_repeated")
          end

          assert {:message_queue_len, queue_len} =
                   Signal
                   |> Process.whereis()
                   |> Process.info(:message_queue_len)

          assert queue_len <= 1
          :sys.resume(Signal)

          assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_monitor_unavailable], %{count: 1}, _},
                         1000

          await_signal_idle()
        end)

      assert length(Regex.scan(~r/lifecycle monitor is unavailable/, first_log)) == 1
      refute_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_monitor_unavailable], _, _}

      assert {:ok, recovered_pid} = Supervisor.restart_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)

      eventually(fn ->
        assert :sys.get_state(Registration).lifecycle_pid == recovered_pid
        refute :sys.get_state(Signal).monitor_outage
      end)

      assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], %{count: 1},
                      %{repo: RecordingRepo, schema_prefix: "unavailable_repeated"}},
                     1000

      await_signal_idle()

      assert :ok = Supervisor.terminate_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)

      eventually(fn ->
        assert :sys.get_state(Registration).lifecycle_pid == nil
      end)

      second_log =
        capture_log(fn ->
          for _i <- 1..100 do
            Sweeper.check_running_for_store(RecordingRepo, "unavailable_again_repeated")
          end

          assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_monitor_unavailable], %{count: 1}, _},
                         1000

          await_signal_idle()
        end)

      assert length(Regex.scan(~r/lifecycle monitor is unavailable/, second_log)) == 1
      refute_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_monitor_unavailable], _, _}

      assert {:ok, final_lifecycle_pid} =
               Supervisor.restart_child(AttestoPhoenix.DiagnosticsSupervisor, Lifecycle)

      eventually(fn ->
        assert :sys.get_state(Registration).lifecycle_pid == final_lifecycle_pid
        refute :sys.get_state(Signal).monitor_outage
      end)

      assert_receive {:telemetry_event, [:attesto_phoenix, :store, :sweeper_unsupervised], %{count: 1},
                      %{repo: RecordingRepo, schema_prefix: "unavailable_again_repeated"}},
                     1000

      await_signal_idle()
    end
  end

  def handle_telemetry(event, measurements, metadata, owner) do
    send(owner, {:telemetry_event, event, measurements, metadata})
  end

  def handle_blocking_telemetry(_event, _measurements, _metadata, {owner, release_ref}) do
    send(owner, {:telemetry_handler_blocked, self(), release_ref})

    receive do
      {:release_telemetry, ^release_ref} -> :ok
    end
  end

  defp replace_episode_status(target, status) do
    table = :ets.whereis(:attesto_phoenix_sweeper_episodes)
    target_key = {:target, target}

    case :ets.lookup(table, target_key) do
      [{^target_key, {slot, _old_status}}] ->
        true = :ets.insert(table, {target_key, {slot, status}})
        :ok

      [] ->
        flunk("expected a retained sweeper episode for #{inspect(target)}")
    end
  end

  defp episode_tracked?(target) do
    :ets.member(:attesto_phoenix_sweeper_episodes, {:target, target})
  end

  defp episode_record_count(target) do
    case :ets.lookup(:attesto_phoenix_sweeper_episodes, {:target, target}) do
      [] -> 0
      [_record] -> 1
    end
  end

  defp colliding_targets do
    Enum.reduce_while(1..5_000, %{}, fn index, seen ->
      target = {RecordingRepo, "collision_#{index}"}
      base_slot = :erlang.phash2(target, 1_024)

      case Map.fetch(seen, base_slot) do
        {:ok, first_target} -> {:halt, {first_target, target}}
        :error -> {:cont, Map.put(seen, base_slot, target)}
      end
    end)
  end

  defp target_slot_for_test(target, offset) do
    base = :erlang.phash2(target, 1_024)
    step = 2 * :erlang.phash2({:step, target}, 512) + 1
    {:target_slot, rem(base + offset * step, 1_024)}
  end

  defp insert_observed_episode(table, target) do
    now = System.monotonic_time(:millisecond)
    target_key = {:target, target}

    Enum.find_value(0..1_023, false, fn index ->
      slot = {:target_slot, index}

      if :ets.insert_new(table, [
           {target_key, {slot, {:observed, now}}},
           {slot, target}
         ]) do
        true
      end
    end)
  end

  defp eventually(assertion, attempts \\ 50)

  defp eventually(assertion, 0), do: assertion.()

  defp eventually(assertion, attempts) do
    assertion.()
  rescue
    ExUnit.AssertionError ->
      Process.sleep(10)
      eventually(assertion, attempts - 1)
  end

  defp field_name({{:., _, [{:&, _, [_binding]}, field]}, _, []}), do: field
  defp field_name(_), do: nil

  defp flatten_or({:or, _, [left, right]}), do: flatten_or(left) ++ flatten_or(right)
  defp flatten_or(expression), do: [expression]
end
