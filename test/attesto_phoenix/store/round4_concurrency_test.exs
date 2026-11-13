defmodule AttestoPhoenix.Store.Round4ConcurrencyTest do
  use ExUnit.Case, async: false

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Revocation
  alias AttestoPhoenix.Schema.Authorization
  alias AttestoPhoenix.Schema.RefreshToken
  alias AttestoPhoenix.Store.EctoCodeStore
  alias AttestoPhoenix.Store.EctoRefreshStore
  alias AttestoPhoenix.Store.Sweeper

  @moduletag :ecto
  @moduletag timeout: 30_000

  # A separate ordinary pool: sharing an SQL Sandbox owner serializes every
  # operation on one connection and cannot exercise a PostgreSQL deadlock.
  defmodule Repo do
    use Ecto.Repo, otp_app: :attesto_phoenix, adapter: Ecto.Adapters.Postgres
  end

  defmodule GateRepo do
    alias AttestoPhoenix.Store.Round4ConcurrencyTest.Repo

    for {name, arity} <- [
          transaction: 1,
          transaction: 2,
          checkout: 1,
          query!: 3,
          all: 2,
          one: 2,
          exists?: 2,
          insert: 2,
          insert!: 2,
          update: 2,
          rollback: 1,
          update_all: 3,
          delete_all: 2
        ] do
      args = Macro.generate_arguments(arity, __MODULE__)

      def unquote(name)(unquote_splicing(args)) do
        args = unquote(args)
        hook = Application.get_env(__MODULE__, :hook, fn _, _, _, result -> result end)
        hook.(:before, unquote(name), args, nil)
        result = apply(Repo, unquote(name), args)
        hook.(:after, unquote(name), args, result)
      end
    end
  end

  defmodule Keystore do
    def signing_pem, do: "unused"
    def verification_pems, do: []
  end

  setup do
    opts =
      AttestoPhoenix.TestRepo.config()
      |> Keyword.put(:pool, DBConnection.ConnectionPool)
      |> Keyword.put(:pool_size, 5)
      |> Keyword.put(:name, Repo)

    start_supervised!({Repo, opts})
    prefix = "round4_#{System.system_time(:microsecond)}"
    Repo.query!("CREATE SCHEMA #{prefix}")
    tables = Repo.query!("SELECT tablename FROM pg_tables WHERE schemaname = 'public'").rows

    for [table] <- tables, table != "schema_migrations" do
      Repo.query!(~s|CREATE TABLE "#{prefix}"."#{table}" (LIKE public."#{table}" INCLUDING ALL)|)
    end

    config =
      Config.new(
        issuer: "https://issuer.example",
        audience: "https://api.example",
        keystore: Keystore,
        repo: GateRepo,
        schema_prefix: prefix,
        code_store: EctoCodeStore,
        refresh_store: EctoRefreshStore,
        sweep_interval_ms: 600_000,
        load_client: fn _ -> {:error, :not_found} end,
        verify_client_secret: fn _, _ -> false end,
        load_principal: fn _ -> {:error, :not_found} end
      )

    Sweeper.register_cleanup_worker({GateRepo, prefix}, self())
    on_exit(fn -> Application.delete_env(GateRepo, :hook) end)
    # The pool is supervised until test completion; explicit cleanup runs
    # before it stops, even when an assertion fails.
    {:ok, config: config, prefix: prefix}
  end

  defp with_cleanup(%{prefix: prefix}, work) do
    work.()
  after
    Application.delete_env(GateRepo, :hook)
    Repo.query!("DROP SCHEMA #{prefix} CASCADE")
  end

  defp hook(fun), do: Application.put_env(GateRepo, :hook, fun)

  defp task(config, role, work) do
    Task.async(fn ->
      try do
        Process.put(:round4_role, role)

        Config.with_request_config(config, fn ->
          Repo.checkout(fn ->
            work.()
          end)
        end)
      rescue
        e in Postgrex.Error -> {:postgres, e.postgres.code, e.postgres.pg_code}
      end
    end)
  end

  defp pause(owner, event) do
    %{rows: [[backend]]} = Repo.query!("SELECT pg_backend_pid()")
    send(owner, {event, self(), backend})

    receive do
      :continue -> :ok
    after
      10_000 -> raise "gate timed out: #{event}"
    end
  end

  defp wait_for_lock(backend, attempts \\ 500)
  defp wait_for_lock(_backend, 0), do: flunk("backend never waited for a PostgreSQL lock")

  defp wait_for_lock(backend, attempts) do
    case Repo.query!("SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1", [backend]).rows do
      [["Lock"]] ->
        :ok

      _ ->
        Process.sleep(10)
        wait_for_lock(backend, attempts - 1)
    end
  end

  defp refresh(prefix, family, successor) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    Repo.insert!(
      %RefreshToken{
        token_hash: "hash-#{family}",
        family_id: family,
        subject: "subject",
        client_id: "client",
        consumed: true,
        consumed_at: DateTime.add(now, -120),
        expires_at: DateTime.add(now, 600),
        successor: successor
      },
      prefix: prefix
    )
  end

  defp modern do
    %{"v" => 2, "ciphertext" => "expired", "retry_until" => 1, "child_hash" => "child"}
  end

  defp source(%Ecto.Query{from: %{source: {table, _}}}), do: table
  defp source(_), do: nil

  test "cluster sweep releases refresh locks before waiting for authorization codes", ctx do
    with_cleanup(ctx, fn ->
      refresh(ctx.prefix, "family", modern())
      now = DateTime.utc_now() |> DateTime.truncate(:second)

      Repo.insert!(
        %Authorization{
          code_hash: "code",
          client_id: "client",
          subject: "subject",
          redirect_uri: "https://rp.example/cb",
          inserted_at: now,
          expires_at: DateTime.add(now, -60)
        },
        prefix: ctx.prefix
      )

      owner = self()

      hook(fn phase, operation, args, result ->
        role = Process.get(:round4_role, :sweeper)

        if operation == :delete_all and source(hd(args)) == "attesto_authorization_codes" do
          case {role, phase} do
            {:sweeper, :before} -> pause(owner, :sweep_at_codes)
            {:revoker, :after} -> pause(owner, :revoker_has_codes)
            _ -> :ok
          end
        end

        result
      end)

      sweeper = start_supervised!({Sweeper, config: ctx.config, name: nil, cluster_lock: {:advisory, 721_001}})
      sweep = Task.async(fn -> Sweeper.sweep_now(sweeper) end)
      assert_receive {:sweep_at_codes, sweep_pid, sweep_backend}, 5000

      revoke =
        task(ctx.config, :revoker, fn ->
          Repo.transaction(fn -> Revocation.revoke_subject(ctx.config, "subject") end)
        end)

      assert_receive {:revoker_has_codes, revoke_pid, revoke_backend}, 5000
      refute sweep_backend == revoke_backend
      send(sweep_pid, :continue)
      wait_for_lock(sweep_backend)
      send(revoke_pid, :continue)
      assert {:ok, {:ok, _}} = Task.await(revoke, 10_000)
      assert is_map(Task.await(sweep, 10_000))
    end)
  end

  test "overlapping family revocations sort opposite database result orders", ctx do
    with_cleanup(ctx, fn ->
      refresh(ctx.prefix, "a", nil)
      refresh(ctx.prefix, "z", nil)
      owner = self()

      hook(fn phase, operation, args, result ->
        role = Process.get(:round4_role)

        cond do
          phase == :after and operation == :all and is_list(result) and Enum.sort(result) == ["a", "z"] ->
            if role == :a, do: ["a", "z"], else: ["z", "a"]

          operation == :query! and String.contains?(hd(args), "pg_advisory_xact_lock") ->
            if phase == :before and role == :b and not Process.get(:announced, false) do
              Process.put(:announced, true)
              pause(owner, :b_attempt)
            end

            if phase == :after and not Process.get(:first_lock, false) do
              Process.put(:first_lock, true)
              pause(owner, if(role == :a, do: :a_locked, else: :b_locked))
            end

            result

          true ->
            result
        end
      end)

      a =
        task(ctx.config, :a, fn -> Repo.transaction(fn -> EctoRefreshStore.revoke_families(subject: "subject") end) end)

      assert_receive {:a_locked, a_pid, a_backend}, 5000

      b =
        task(ctx.config, :b, fn -> Repo.transaction(fn -> EctoRefreshStore.revoke_families(subject: "subject") end) end)

      assert_receive {:b_attempt, b_pid, b_backend}, 5000
      refute a_backend == b_backend
      send(b_pid, :continue)
      # Old code locks z; fixed code waits for a. Either observation is a
      # real database barrier, not a timing assumption about task scheduling.
      await_b(b_backend)
      send(a_pid, :continue)
      send(b_pid, :continue)
      assert {:ok, {:ok, 2}} = Task.await(a, 10_000)
      assert {:ok, {:ok, 2}} = Task.await(b, 10_000)
    end)
  end

  defp await_b(backend, attempts \\ 500)
  defp await_b(_backend, 0), do: flunk("second revoker did not acquire or wait for a lock")

  defp await_b(backend, attempts) do
    receive do
      {:b_locked, _pid, ^backend} -> :ok
    after
      10 ->
        case Repo.query!("SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1", [backend]).rows do
          [["Lock"]] -> :ok
          _ -> await_b(backend, attempts - 1)
        end
    end
  end

  test "sweep_once rolls back with the caller transaction", ctx do
    with_cleanup(ctx, fn ->
      refresh(ctx.prefix, "family", modern())
      now = DateTime.utc_now() |> DateTime.truncate(:second)

      Repo.insert!(
        %Authorization{
          code_hash: "code",
          client_id: "client",
          subject: "subject",
          redirect_uri: "https://rp.example/cb",
          inserted_at: now,
          expires_at: DateTime.add(now, -60)
        },
        prefix: ctx.prefix
      )

      assert {:error, :undo} =
               Repo.transaction(fn ->
                 assert Sweeper.sweep_once(ctx.config, now)["attesto_authorization_codes"] == 1
                 Repo.rollback(:undo)
               end)

      assert Repo.get_by!(Authorization, [code_hash: "code"], prefix: ctx.prefix)
      assert Repo.get_by!(RefreshToken, [family_id: "family"], prefix: ctx.prefix).successor == modern()
    end)
  end

  test "a grace retry waits for revocation and rechecks the family", ctx do
    with_cleanup(ctx, fn ->
      Config.with_request_config(ctx.config, fn ->
        assert {:ok, issued} =
                 Attesto.RefreshToken.issue(
                   EctoRefreshStore,
                   %{
                     subject: "subject",
                     client_id: "client",
                     issuer: ctx.config.issuer,
                     scope: [],
                     resource: [],
                     claims: %{}
                   },
                   issuer: ctx.config.issuer
                 )

        assert {:ok, _child} =
                 Attesto.RefreshToken.rotate(EctoRefreshStore, issued.token,
                   client_id: "client",
                   issuer: ctx.config.issuer,
                   rotation_grace_seconds: 60
                 )

        owner = self()

        hook(fn phase, operation, args, result ->
          if phase == :after and operation == :query! and Process.get(:round4_role) == :revoker and
               String.contains?(hd(args), "pg_advisory_xact_lock") do
            pause(owner, :revocation_lock)
          end

          result
        end)

        revoke = task(ctx.config, :revoker, fn -> EctoRefreshStore.revoke_family(issued.family_id) end)
        assert_receive {:revocation_lock, revoker, revoke_backend}, 5000

        retry =
          task(ctx.config, :retry, fn ->
            %{rows: [[backend]]} = Repo.query!("SELECT pg_backend_pid()")
            send(owner, {:retry_backend, backend})

            Attesto.RefreshToken.rotate(EctoRefreshStore, issued.token,
              client_id: "client",
              issuer: ctx.config.issuer,
              rotation_grace_seconds: 60
            )
          end)

        assert_receive {:retry_backend, retry_backend}, 5000
        refute retry_backend == revoke_backend
        status = wait_for_lock_or_result(retry_backend, retry.ref)
        send(revoker, :continue)
        assert :ok = Task.await(revoke, 5000)
        assert status == :waiting
        assert {:error, :invalid_grant} = Task.await(retry, 5000)
      end)
    end)
  end

  defp wait_for_lock_or_result(backend, ref, attempts \\ 500)
  defp wait_for_lock_or_result(_backend, _ref, 0), do: flunk("retry neither waited nor completed")

  defp wait_for_lock_or_result(backend, ref, attempts) do
    receive do
      {^ref, result} -> {:finished, result}
    after
      10 ->
        case Repo.query!("SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1", [backend]).rows do
          [["Lock"]] -> :waiting
          _ -> wait_for_lock_or_result(backend, ref, attempts - 1)
        end
    end
  end

  test "the session sweep lock excludes a second sweeper and is released after errors or process death", ctx do
    with_cleanup(ctx, fn ->
      owner = self()

      for failure <- [:raise, :kill] do
        key = 721_002

        hook(fn phase, operation, args, result ->
          if phase == :before and operation == :delete_all and source(hd(args)) == "attesto_authorization_codes" do
            pause(owner, :sweep_locked)
            if failure == :raise, do: raise("injected sweep failure")
          end

          result
        end)

        spec =
          Supervisor.child_spec({Sweeper, config: ctx.config, name: nil, cluster_lock: {:advisory, key}},
            id: {:crashing_sweeper, failure},
            restart: :temporary
          )

        sweeper = start_supervised!(spec)
        monitor = Process.monitor(sweeper)

        caller =
          Task.async(fn ->
            try do
              Sweeper.sweep_now(sweeper)
            catch
              :exit, _ -> :stopped
            end
          end)

        assert_receive {:sweep_locked, ^sweeper, _backend}, 5000

        other =
          start_supervised!(
            Supervisor.child_spec(
              {Sweeper, config: ctx.config, name: nil, cluster_lock: {:advisory, key}},
              id: {:other_sweeper, failure}
            )
          )

        assert Sweeper.sweep_now(other) == :skipped
        if failure == :raise, do: send(sweeper, :continue), else: Process.exit(sweeper, :kill)
        assert_receive {:DOWN, ^monitor, :process, ^sweeper, _}, 5000
        assert Task.await(caller) == :stopped
        await_unlock(key)
        stop_supervised({:other_sweeper, failure})
      end
    end)
  end

  defp await_unlock(key, attempts \\ 500)
  defp await_unlock(_key, 0), do: flunk("crashed sweep retained its session advisory lock")

  defp await_unlock(key, attempts) do
    case Repo.query!("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND classid = 0 AND objid = $1", [key]).rows do
      [[0]] ->
        :ok

      _ ->
        Process.sleep(10)
        await_unlock(key, attempts - 1)
    end
  end

  test "redaction and revocation acquire families in the same order", ctx do
    with_cleanup(ctx, fn ->
      # Opposite heap order to family order. The original single UPDATE scans
      # z then a and retains z's row lock while waiting for a.
      refresh(ctx.prefix, "z", modern())
      refresh(ctx.prefix, "a", modern())
      owner = self()

      hook(fn phase, operation, args, result ->
        if phase == :after and operation == :delete_all and Process.get(:round4_role) == :revoker and
             source(hd(args)) == "attesto_refresh_tokens" and not Process.get(:first_lock, false) do
          Process.put(:first_lock, true)
          pause(owner, :revoker_locked)
        end

        result
      end)

      revoke =
        task(ctx.config, :revoker, fn ->
          Repo.transaction(fn -> EctoRefreshStore.revoke_families(subject: "subject") end)
        end)

      assert_receive {:revoker_locked, pid, revoke_backend}, 5000

      redact =
        task(ctx.config, :redactor, fn ->
          %{rows: [[backend]]} = Repo.query!("SELECT pg_backend_pid()")
          send(owner, {:redactor, backend})
          EctoRefreshStore.redact_expired_successors(GateRepo, DateTime.utc_now(), prefix: ctx.prefix)
        end)

      assert_receive {:redactor, redact_backend}, 5000
      refute revoke_backend == redact_backend
      wait_for_lock(redact_backend)
      send(pid, :continue)
      assert {:ok, {:ok, 2}} = Task.await(revoke, 10_000)
      assert is_integer(Task.await(redact, 10_000))
    end)
  end
end
