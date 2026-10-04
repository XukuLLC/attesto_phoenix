defmodule AttestoPhoenix.ClientIdMetadata.AmplificationTest do
  use ExUnit.Case, async: false

  alias AttestoPhoenix.ClientIdMetadata
  alias AttestoPhoenix.ClientIdMetadata.Cache
  alias AttestoPhoenix.ClientIdMetadata.Cache.ETS
  alias AttestoPhoenix.ClientIdMetadata.{FlowControl, Resolver}
  alias AttestoPhoenix.Config

  defmodule Fetcher do
    @moduledoc false

    def preflight(_uri, _opts), do: :ok

    def fetch(url, _opts) do
      callback = Agent.get_and_update(__MODULE__, fn {count, callback} -> {callback, {count + 1, callback}} end)
      callback.(url)
    end
  end

  defmodule DNSFetcher do
    @moduledoc false

    def preflight(uri, opts) do
      send(Keyword.fetch!(opts, :test_pid), {:dns, uri})
      :ok
    end

    def fetch(uri, opts) do
      send(Keyword.fetch!(opts, :test_pid), {:http, uri})
      {:ok, %{body: JSON.encode!(Keyword.fetch!(opts, :test_keys)), cache_control: [max_age: 300]}}
    end
  end

  setup do
    server = start_supervised!({FlowControl, []})
    ETS.delete_all()
    on_exit(fn -> ETS.delete_all() end)
    %{server: server, opts: [flow_control_server: server]}
  end

  defp response(url) do
    body =
      JSON.encode!(%{
        "client_id" => url,
        "redirect_uris" => ["https://app.example/cb"],
        "token_endpoint_auth_method" => "none"
      })

    {:ok, %{body: body, cache_control: [max_age: 300]}}
  end

  defp start_fetcher(callback) do
    start_supervised!(%{id: Fetcher, start: {Agent, :start_link, [fn -> {0, callback} end, [name: Fetcher]]}})
  end

  defp config(opts) do
    %Config{
      issuer: "https://issuer.example",
      keystore: Fetcher,
      repo: Fetcher,
      client_id_metadata:
        Keyword.merge(
          [
            enabled: true,
            fetcher: Fetcher,
            cache: ETS,
            max_document_bytes: 5_120,
            request_timeout_ms: 5_000,
            allow_loopback: false,
            cache_ttl_bounds: {0, 300}
          ],
          opts
        )
    }
  end

  defp wait_for(server, key, value, attempts \\ 100)
  defp wait_for(_server, _key, _value, 0), do: flunk("admission state did not reach expected bound")

  defp wait_for(server, key, value, attempts) do
    if FlowControl.stats(server)[key] == value do
      :ok
    else
      Process.sleep(5)
      wait_for(server, key, value, attempts - 1)
    end
  end

  test "unique document URLs share a request budget and stop before the fetcher", %{opts: opts} do
    start_fetcher(&response/1)
    # The fetcher is deliberately in-memory; these URLs never reach a socket.
    agent = Process.whereis(Fetcher)
    if is_nil(agent), do: flunk("fetcher must be registered")
    opts = Keyword.merge(opts, max_fetches_per_window: 3, max_fetches_per_host_per_window: 3)
    host = config(opts)

    results = for index <- 1..20, do: Resolver.resolve("https://amplification.example/#{index}.json", host)
    assert Enum.count(results, &match?({:ok, _}, &1)) == 3
    assert Enum.count(results, &(&1 == {:error, {:fetch, :rate_limit}})) == 17
    assert Agent.get(Fetcher, &elem(&1, 0)) == 3
  end

  test "slow identical document misses use one caller-local fetch", %{server: server, opts: opts} do
    parent = self()

    start_fetcher(fn url ->
      send(parent, {:fetch_started, self()})
      receive do: (:release -> response(url))
    end)

    host = config(opts)
    url = "https://amplification.example/singleflight.json"
    tasks = for _ <- 1..8, do: Task.async(fn -> Resolver.resolve(url, host) end)
    assert_receive {:fetch_started, leader}
    wait_for(server, :waiters, 7)
    send(leader, :release)
    results = Enum.map(tasks, &Task.await/1)
    assert Enum.all?(results, &match?({:ok, %{"client_id" => ^url}}, &1))
    assert Agent.get(Fetcher, &elem(&1, 0)) == 1
    assert FlowControl.stats(server).active == 0
    assert {:ok, _} = Resolver.resolve(url, host)
    assert Agent.get(Fetcher, &elem(&1, 0)) == 1
  end

  test "global and host concurrency limits aggregate distinct scopes and URL keys", %{opts: opts} do
    opts = Keyword.merge(opts, max_concurrent_fetches: 2, max_concurrent_fetches_per_host: 1)
    parent = self()

    fetch = fn ->
      send(parent, {:active, self()})
      receive do: (:release -> {:ok, :done})
    end

    first = Task.async(fn -> FlowControl.run("one.example", 1, :documents, opts, fetch) end)
    assert_receive {:active, first_pid}

    assert {:error, {:fetch, :concurrency_limit}} =
             FlowControl.run("one.example", 2, :keys, opts, fn -> {:ok, :bad} end)

    second = Task.async(fn -> FlowControl.run("two.example", 3, :keys, opts, fetch) end)
    assert_receive {:active, second_pid}

    assert {:error, {:fetch, :concurrency_limit}} =
             FlowControl.run("three.example", 4, :documents, opts, fn -> {:ok, :bad} end)

    send(first_pid, :release)
    send(second_pid, :release)
    assert Task.await(first) == {:ok, :done}
    assert Task.await(second) == {:ok, :done}
  end

  test "failed fetches back off briefly without storing invalid metadata", %{server: server, opts: opts} do
    start_fetcher(fn _ -> {:error, {:status, 404}} end)
    opts = Keyword.put(opts, :failure_backoff_ms, 30)
    host = config(opts)
    url = "https://amplification.example/failure.json"
    assert {:error, {:fetch, {:status, 404}}} = Resolver.resolve(url, host)
    assert {:error, {:fetch, :failure_backoff}} = Resolver.resolve(url, host)
    assert :miss = ETS.get(url)
    assert Agent.get(Fetcher, &elem(&1, 0)) == 1
    Process.sleep(40)
    assert {:error, {:fetch, {:status, 404}}} = Resolver.resolve(url, host)
    assert Agent.get(Fetcher, &elem(&1, 0)) == 2
    assert FlowControl.stats(server).failures == 1
  end

  test "unique host and failure bookkeeping is bounded", %{server: server, opts: opts} do
    opts = Keyword.put(opts, :max_flow_entries, 3)

    for key <- 1..20 do
      assert {:error, :invalid_json} =
               FlowControl.run("one.example", key, :documents, opts, fn -> {:error, :invalid_json} end)
    end

    assert FlowControl.stats(server).failures == 3
    assert {:ok, :done} = FlowControl.run("two.example", :new, :documents, opts, fn -> {:ok, :done} end)
    assert {:ok, :done} = FlowControl.run("three.example", :new, :documents, opts, fn -> {:ok, :done} end)

    assert {:error, {:fetch, :flow_capacity}} =
             FlowControl.run("four.example", :new, :documents, opts, fn -> {:ok, :bad} end)

    assert FlowControl.stats(server).hosts == 3
  end

  test "singleflight followers are capped and time out while the leader keeps its slot", %{server: server, opts: opts} do
    opts = Keyword.merge(opts, max_singleflight_waiters: 1, request_timeout_ms: 40)
    parent = self()

    leader =
      Task.async(fn ->
        FlowControl.run("one.example", :key, :scope, opts, fn ->
          send(parent, {:leader, self()})
          receive do: (:release -> {:ok, :done})
        end)
      end)

    assert_receive {:leader, pid}

    follower =
      Task.async(fn -> FlowControl.run("one.example", :key, :scope, opts, fn -> flunk("duplicate fetch") end) end)

    wait_for(server, :waiters, 1)

    assert {:error, {:fetch, :singleflight_limit}} =
             FlowControl.run("one.example", :key, :scope, opts, fn -> flunk("duplicate fetch") end)

    assert Task.await(follower) == {:error, {:fetch, :fetch_timeout}}
    assert FlowControl.stats(server).active == 1
    send(pid, :release)
    assert Task.await(leader) == {:ok, :done}
  end

  test "leader death releases admission and fails followers without duplicating work", %{server: server, opts: opts} do
    parent = self()

    leader =
      spawn(fn ->
        FlowControl.run("one.example", :key, :scope, opts, fn ->
          send(parent, :started)
          receive do: (:release -> {:ok, :done})
        end)
      end)

    assert_receive :started

    follower =
      Task.async(fn -> FlowControl.run("one.example", :key, :scope, opts, fn -> flunk("duplicate fetch") end) end)

    wait_for(server, :waiters, 1)
    Process.exit(leader, :kill)
    assert Task.await(follower) == {:error, {:fetch, :fetch_failed}}
    wait_for(server, :active, 0)
    assert {:ok, :done} = FlowControl.run("two.example", :key, :scope, opts, fn -> {:ok, :done} end)
  end

  test "cache capacity holds under concurrent writes and expired entries are physically removed" do
    config = %Config{
      issuer: "https://issuer.example",
      keystore: Fetcher,
      repo: Fetcher,
      client_id_metadata: [cache_max_entries: 3]
    }

    expiry = DateTime.utc_now() |> DateTime.add(300, :second)
    :ok = ETS.put("https://expired.example/old", %{}, DateTime.add(expiry, -400, :second))
    # Simulate rows retained by the previous unbounded implementation.
    true =
      :ets.insert(
        :attesto_phoenix_client_id_metadata,
        [
          {"https://expired.example/old", %{}, DateTime.to_unix(expiry) - 400}
          | for(index <- 1..100, do: {"https://legacy.example/#{index}", %{}, DateTime.to_unix(expiry) + index})
        ]
      )

    1..25
    |> Task.async_stream(
      fn index ->
        Config.with_request_config(config, fn ->
          url = "https://cache.example/#{index}"
          assert :ok = ETS.put(url, %{"client_id" => url}, expiry)
          assert :ets.info(:attesto_phoenix_client_id_metadata, :size) <= 3
        end)
      end,
      max_concurrency: 10,
      timeout: 10_000
    )
    |> Enum.each(fn {:ok, _} -> :ok end)

    assert :ets.info(:attesto_phoenix_client_id_metadata, :size) == 3
    assert :ets.lookup(:attesto_phoenix_client_id_metadata, "https://expired.example/old") == []
  end

  test "oversized documents and attached keys cannot expand or replace the cache" do
    config = %Config{
      issuer: "https://issuer.example",
      keystore: Fetcher,
      repo: Fetcher,
      client_id_metadata: [cache_max_record_bytes: 200]
    }

    url = "https://cache.example/client"
    metadata = %{"client_id" => url}
    expiry = DateTime.utc_now() |> DateTime.add(300, :second) |> DateTime.truncate(:second)

    Config.with_request_config(config, fn ->
      assert :ok = ETS.put(url, metadata, expiry)
      assert {:error, :too_large} = ETS.put(url, Map.put(metadata, "data", String.duplicate("x", 300)), expiry)
      assert {:ok, ^metadata, ^expiry} = ETS.get_entry(url)
      assert {:error, :too_large} = ETS.put_jwks(url, metadata, expiry, %{"data" => String.duplicate("x", 300)})
      assert {:ok, ^metadata, ^expiry} = ETS.get_entry(url)
    end)
  end

  test "an already-expired write does not evict fresh records from a full cache" do
    host = %Config{
      issuer: "https://issuer.example",
      keystore: Fetcher,
      repo: Fetcher,
      client_id_metadata: [cache_max_entries: 3]
    }

    expiry = DateTime.add(DateTime.utc_now(), 300, :second)
    urls = for index <- 1..3, do: "https://cache.example/live-#{index}"

    Config.with_request_config(host, fn ->
      for url <- urls, do: assert(:ok = ETS.put(url, %{}, expiry))
      assert :ok = ETS.put("https://cache.example/past", %{}, DateTime.add(expiry, -400, :second))
      for url <- urls, do: assert({:ok, %{}} = ETS.get(url))
      assert :ets.info(:attesto_phoenix_client_id_metadata, :size) == 3
    end)
  end

  test "cached key DNS preflight is admitted and consumes the same host budget", %{opts: opts} do
    id = "https://dns.example/client.json"
    uri = "https://dns.example/keys.json"

    {:ok, metadata} =
      Attesto.ClientIdMetadata.validate_document(id, %{
        "client_id" => id,
        "redirect_uris" => ["https://app.example/cb"],
        "token_endpoint_auth_method" => "private_key_jwt",
        "jwks_uri" => uri
      })

    {_, public} = JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_public_map()
    keys = %{"keys" => [public]}
    :ok = ETS.put(id, metadata, DateTime.add(DateTime.utc_now(), 300, :second))

    host =
      config(
        Keyword.merge(opts, fetcher: DNSFetcher, test_pid: self(), test_keys: keys, max_fetches_per_host_per_window: 2)
      )

    assert {:ok, ^keys} = ClientIdMetadata.resolve_jwks(metadata, host)
    assert_receive {:dns, ^uri}
    assert_receive {:http, ^uri}
    assert {:ok, ^keys} = ClientIdMetadata.resolve_jwks(metadata, host)
    assert_receive {:dns, ^uri}
    refute_receive {:http, _}
    assert {:error, :missing_client_jwks} = ClientIdMetadata.resolve_jwks(metadata, host)
    refute_receive {:dns, _}
    refute_receive {:http, _}
  end

  test "singleflight keeps repositories and schema prefixes isolated", %{server: server, opts: opts} do
    parent = self()

    tasks =
      for prefix <- ["first_tenant", "second_tenant"] do
        Task.async(fn ->
          host = %Config{issuer: "https://issuer.example", keystore: Fetcher, repo: Fetcher, schema_prefix: prefix}

          Config.with_request_config(host, fn ->
            FlowControl.run("one.example", :same_url, :same_options, opts, fn ->
              send(parent, {:tenant_fetch, self(), prefix})
              receive do: (:release -> {:ok, prefix})
            end)
          end)
        end)
      end

    assert_receive {:tenant_fetch, first, first_prefix}
    assert_receive {:tenant_fetch, second, second_prefix}
    assert first_prefix != second_prefix
    assert FlowControl.stats(server).active == 2
    send(first, :release)
    send(second, :release)
    assert Enum.map(tasks, &Task.await/1) == [{:ok, "first_tenant"}, {:ok, "second_tenant"}]
  end

  test "request budgets reopen after their bounded window", %{opts: opts} do
    opts = Keyword.merge(opts, max_fetches_per_window: 1, fetch_rate_window_ms: 30)
    assert {:ok, :done} = FlowControl.run("one.example", 1, :scope, opts, fn -> {:ok, :done} end)
    assert {:error, {:fetch, :rate_limit}} = FlowControl.run("two.example", 2, :scope, opts, fn -> {:ok, :bad} end)
    Process.sleep(40)
    assert {:ok, :done} = FlowControl.run("two.example", 2, :scope, opts, fn -> {:ok, :done} end)
  end

  test "custom fetchers never share work across different trusted issuers or callbacks", %{server: server, opts: opts} do
    parent = self()

    profiles = [
      {"https://first.example", :first},
      {"https://first.example", :second},
      {"https://third.example", :third}
    ]

    tasks =
      Enum.map(profiles, fn {issuer, value} ->
        Task.async(fn -> profile_fetch(issuer, value, parent, opts) end)
      end)

    workers =
      for _ <- profiles do
        assert_receive {:profile_fetch, worker}
        worker
      end

    assert FlowControl.stats(server).active == 3
    Enum.each(workers, &send(&1, :release))
    assert Enum.map(tasks, &Task.await/1) == [{:ok, :first}, {:ok, :second}, {:ok, :third}]
  end

  test "origin-supplied internal annotations cannot seed remote verification keys", %{opts: opts} do
    id = "https://origin.example/client.json"
    uri = "https://origin.example/keys.json"
    {_, first} = JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_public_map()
    {_, second} = JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_public_map()
    injected = %{"keys" => [Map.put(first, "kid", "injected")]}
    genuine = %{"keys" => [Map.put(second, "kid", "from-endpoint")]}
    annotation = %{"uri" => uri, "keys" => injected, "expires_at" => System.system_time(:second) + 100}

    document = %{
      "client_id" => id,
      "redirect_uris" => ["https://app.example/cb"],
      "token_endpoint_auth_method" => "private_key_jwt",
      "jwks_uri" => uri,
      "__attesto_resolved_jwks" => annotation
    }

    start_fetcher(fn target ->
      value = if target == id, do: document, else: genuine
      {:ok, %{body: JSON.encode!(value), cache_control: [max_age: 300]}}
    end)

    host = config(opts)

    assert {:ok, fresh} = Resolver.resolve(id, host)
    refute Map.has_key?(fresh, "__attesto_resolved_jwks")
    assert {:ok, stored, _} = ETS.get_entry(id)
    assert is_nil(Cache.resolved_jwks(stored))
    assert {:ok, cached} = Resolver.resolve(id, host)
    assert {:ok, ^genuine} = ClientIdMetadata.resolve_jwks(cached, host)
    assert Agent.get(Fetcher, &elem(&1, 0)) == 2
    assert {:ok, stored, _} = ETS.get_entry(id)
    assert Cache.resolved_jwks(stored)["keys"] == genuine
  end

  defp profile_fetch(issuer, value, parent, opts) do
    host = %Config{issuer: issuer, keystore: Fetcher, repo: Fetcher, load_client: fn _ -> value end}

    Config.with_request_config(host, fn ->
      FlowControl.run("one.example", :same_url, :same_options, opts, fn ->
        send(parent, {:profile_fetch, self()})
        receive do: (:release -> {:ok, Config.request_config().load_client.(:client)})
      end)
    end)
  end
end
