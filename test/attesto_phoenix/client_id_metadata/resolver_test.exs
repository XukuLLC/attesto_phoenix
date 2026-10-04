defmodule AttestoPhoenix.ClientIdMetadata.ResolverTest do
  @moduledoc """
  Tests for the Client ID Metadata Document resolver
  (`AttestoPhoenix.ClientIdMetadata.Resolver`,
  `draft-ietf-oauth-client-id-metadata-document-01`).

  The resolver is the orchestrator; its collaborators are stubbed so the wiring
  is exercised in isolation: a STUB fetcher returns a canned valid/invalid body
  (no socket, no SSRF), and the per-node `AttestoPhoenix.ClientIdMetadata.Cache.ETS`
  is the cache. The assertions cover the design doc (§11) resolver cases - a
  valid document yields a client and is cached (the second resolve does not
  refetch), an invalid document is never cached, a `client_id` mismatch errors,
  and an expired cache entry triggers a refetch.

  A discovery test (`describe "discovery advertisement"`) confirms the
  `client_id_metadata_document_supported` member is advertised iff the feature
  is enabled.
  """

  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias AttestoPhoenix.ClientIdMetadata.Cache.ETS
  alias AttestoPhoenix.ClientIdMetadata.FlowControl
  alias AttestoPhoenix.ClientIdMetadata.Resolver
  alias AttestoPhoenix.Config

  # A stub fetcher driven by a per-test Agent: each test registers the canned
  # `{:ok, %{body, cache_control}}` (or `{:error, reason}`) the fetch returns and
  # a counter so a test can assert a cache hit did NOT refetch. The fetched URL
  # keys the script so unrelated URLs in the same node never collide.
  alias AttestoPhoenix.Controller.DiscoveryController

  defmodule StubFetcher do
    @moduledoc false
    @behaviour AttestoPhoenix.ClientIdMetadata.Fetcher

    def start_link do
      Agent.start_link(fn -> %{} end)
    end

    def script(agent, url, result) do
      Agent.update(agent, &Map.put(&1, url, %{result: result, calls: 0}))
      Process.put(__MODULE__, agent)
    end

    def calls(agent, url) do
      Agent.get(agent, fn state -> get_in(state, [url, :calls]) end)
    end

    @impl true
    def fetch(url, _opts) do
      agent = Process.get(__MODULE__)

      Agent.get_and_update(agent, fn state ->
        entry = Map.fetch!(state, url)
        {entry.result, put_in(state, [url, :calls], entry.calls + 1)}
      end)
    end
  end

  defmodule FaultCache do
    @moduledoc false
    @behaviour AttestoPhoenix.ClientIdMetadata.Cache

    def script(get_result, put_result \\ :ok) do
      Process.put({__MODULE__, :get}, get_result)
      Process.put({__MODULE__, :put}, put_result)
      Process.put({__MODULE__, :put_calls}, 0)
    end

    @impl true
    def get(_url), do: respond(Process.get({__MODULE__, :get}, :miss))

    @impl true
    def put(url, metadata, expires_at) do
      Process.put({__MODULE__, :put_calls}, Process.get({__MODULE__, :put_calls}, 0) + 1)
      Process.put({__MODULE__, :last_put}, {url, metadata, expires_at})
      respond(Process.get({__MODULE__, :put}, :ok))
    end

    def put_calls, do: Process.get({__MODULE__, :put_calls}, 0)
    def last_put, do: Process.get({__MODULE__, :last_put})

    defp respond({:raise, message}), do: raise(message)
    defp respond(result), do: result
  end

  setup do
    {:ok, agent} = StubFetcher.start_link()
    Process.put(StubFetcher, agent)
    Process.put(FlowControl, start_supervised!({FlowControl, []}))
    %{agent: agent}
  end

  # A unique CIMD client_id URL per test, so the node-wide ETS cache never
  # carries an entry from one test into another (the tests run async).
  defp unique_url do
    "https://app.example/clients/#{System.unique_integer([:positive])}/metadata.json"
  end

  defp valid_body(url) do
    JSON.encode!(%{
      "client_id" => url,
      "client_name" => "Example App",
      "redirect_uris" => ["https://app.example/cb"],
      "token_endpoint_auth_method" => "none",
      "grant_types" => ["authorization_code", "refresh_token"],
      "response_types" => ["code"]
    })
  end

  # The host-facing config the resolver reads its CIMD options from: the STUB
  # fetcher and the per-node ETS cache, with the feature enabled.
  defp resolver_config(overrides \\ []) do
    cimd =
      Keyword.merge(
        [
          enabled: true,
          fetcher: StubFetcher,
          cache: ETS,
          flow_control_server: Process.get(FlowControl)
        ],
        overrides
      )

    Config.new(
      issuer: "https://issuer.example",
      audience: "https://api.example.com",
      keystore: __MODULE__.StubKeystore,
      repo: __MODULE__.StubRepo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      client_id_metadata: cimd
    )
  end

  defmodule StubKeystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @pem JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_pem() |> elem(1)

    @impl true
    def signing_pem, do: @pem

    @impl true
    def verification_pems, do: [@pem]
  end

  defmodule StubRepo do
    @moduledoc false
  end

  describe "resolve/2" do
    test "returns the normalized client for a valid document", %{agent: agent} do
      url = unique_url()
      StubFetcher.script(agent, url, {:ok, %{body: valid_body(url), cache_control: []}})

      assert {:ok, client} = Resolver.resolve(url, resolver_config())
      assert client["client_id"] == url
      assert client["redirect_uris"] == ["https://app.example/cb"]
      assert client["token_endpoint_auth_method"] == "none"
    end

    test "caches a valid document so the second resolve does not refetch", %{agent: agent} do
      url = unique_url()
      StubFetcher.script(agent, url, {:ok, %{body: valid_body(url), cache_control: [max_age: 3600]}})

      assert {:ok, client} = Resolver.resolve(url, resolver_config())
      assert {:ok, ^client} = Resolver.resolve(url, resolver_config())

      assert StubFetcher.calls(agent, url) == 1
    end

    test "Cache-Control no-store skips cache writes and refetches", %{agent: agent} do
      url = unique_url()
      FaultCache.script(:miss, {:error, :cache_write_must_not_run})
      StubFetcher.script(agent, url, {:ok, %{body: valid_body(url), cache_control: [no_store: true]}})
      config = resolver_config(cache: FaultCache)

      assert {:ok, _client} = Resolver.resolve(url, config)
      assert {:ok, _client} = Resolver.resolve(url, config)

      assert FaultCache.put_calls() == 0
      assert StubFetcher.calls(agent, url) == 2
    end

    test "Cache-Control no-cache skips cache writes and refetches", %{agent: agent} do
      url = unique_url()
      FaultCache.script(:miss, {:error, :cache_write_must_not_run})
      StubFetcher.script(agent, url, {:ok, %{body: valid_body(url), cache_control: [no_cache: true]}})
      config = resolver_config(cache: FaultCache)

      assert {:ok, _client} = Resolver.resolve(url, config)
      assert {:ok, _client} = Resolver.resolve(url, config)

      assert FaultCache.put_calls() == 0
      assert StubFetcher.calls(agent, url) == 2
    end

    test "Cache-Control private skips shared-cache writes and refetches", %{agent: agent} do
      url = unique_url()
      FaultCache.script(:miss, {:error, :cache_write_must_not_run})

      StubFetcher.script(
        agent,
        url,
        {:ok, %{body: valid_body(url), cache_control: [private: true, max_age: 3600]}}
      )

      config = resolver_config(cache: FaultCache)

      assert {:ok, _client} = Resolver.resolve(url, config)
      assert {:ok, _client} = Resolver.resolve(url, config)

      assert FaultCache.put_calls() == 0
      assert StubFetcher.calls(agent, url) == 2
    end

    test "s-maxage strictly overrides max-age for the shared document cache", %{agent: agent} do
      url = unique_url()
      now = ~U[2026-10-04 12:00:00Z]
      FaultCache.script(:miss)

      StubFetcher.script(
        agent,
        url,
        {:ok, %{body: valid_body(url), cache_control: [s_maxage: 5, max_age: 300]}}
      )

      config = resolver_config(cache: FaultCache, clock: fn -> now end)

      assert {:ok, client} = Resolver.resolve(url, config)
      assert {^url, ^client, expiry} = FaultCache.last_put()
      assert DateTime.compare(expiry, ~U[2026-10-04 12:00:05Z]) == :eq
    end

    test "zero or malformed s-maxage cannot fall back to a fresh max-age", %{agent: agent} do
      now = ~U[2026-10-04 12:00:00Z]

      for s_maxage <- [0, "invalid"] do
        url = unique_url()
        FaultCache.script(:miss, {:error, :cache_write_must_not_run})

        StubFetcher.script(
          agent,
          url,
          {:ok, %{body: valid_body(url), cache_control: [s_maxage: s_maxage, max_age: 300]}}
        )

        config = resolver_config(cache: FaultCache, clock: fn -> now end)

        assert {:ok, _client} = Resolver.resolve(url, config)
        assert {:ok, _client} = Resolver.resolve(url, config)
        assert FaultCache.put_calls() == 0
        assert StubFetcher.calls(agent, url) == 2
      end
    end

    test "a cache read error is visible and falls back to a fresh document", %{agent: agent} do
      url = unique_url()
      FaultCache.script({:error, :private_backend_detail})
      StubFetcher.script(agent, url, {:ok, %{body: valid_body(url), cache_control: []}})

      log =
        capture_log(fn ->
          assert {:ok, client} = Resolver.resolve(url, resolver_config(cache: FaultCache))
          assert client["client_id"] == url
        end)

      assert StubFetcher.calls(agent, url) == 1
      assert log =~ "AttestoPhoenix CIMD cache failed; fetching fresh client metadata"
      refute log =~ "private_backend_detail"
      refute log =~ url
    end

    test "a malformed cache hit is visible and cannot become client metadata", %{agent: agent} do
      url = unique_url()
      FaultCache.script({:ok, [:private_unvalidated_value]})
      StubFetcher.script(agent, url, {:ok, %{body: valid_body(url), cache_control: []}})

      log =
        capture_log(fn ->
          assert {:ok, client} = Resolver.resolve(url, resolver_config(cache: FaultCache))
          assert client["client_id"] == url
        end)

      assert StubFetcher.calls(agent, url) == 1
      assert log =~ "AttestoPhoenix CIMD cache failed; fetching fresh client metadata"
      refute log =~ "private_unvalidated_value"
    end

    test "a cached map without validated metadata is visible and cannot become client metadata", %{agent: agent} do
      url = unique_url()
      FaultCache.script({:ok, %{"private" => "unvalidated"}})
      StubFetcher.script(agent, url, {:ok, %{body: valid_body(url), cache_control: []}})

      log =
        capture_log(fn ->
          assert {:ok, client} = Resolver.resolve(url, resolver_config(cache: FaultCache))
          assert client["client_id"] == url
        end)

      assert StubFetcher.calls(agent, url) == 1
      assert log =~ "AttestoPhoenix CIMD cache failed; fetching fresh client metadata"
      refute log =~ "private"
      refute log =~ "unvalidated"
    end

    test "a cache write error is visible without rejecting fresh validated metadata", %{agent: agent} do
      url = unique_url()
      FaultCache.script(:miss, {:error, :private_backend_detail})
      StubFetcher.script(agent, url, {:ok, %{body: valid_body(url), cache_control: []}})

      log =
        capture_log(fn ->
          assert {:ok, client} = Resolver.resolve(url, resolver_config(cache: FaultCache))
          assert client["client_id"] == url
        end)

      assert log =~ "AttestoPhoenix CIMD cache failed; fresh client metadata was not cached"
      refute log =~ "private_backend_detail"
      refute log =~ url
    end

    test "cache exceptions are visible and degrade to an uncached fresh document", %{agent: agent} do
      url = unique_url()
      FaultCache.script({:raise, "private backend exception"}, {:raise, "private write exception"})
      StubFetcher.script(agent, url, {:ok, %{body: valid_body(url), cache_control: []}})

      log =
        capture_log(fn ->
          assert {:ok, client} = Resolver.resolve(url, resolver_config(cache: FaultCache))
          assert client["client_id"] == url
        end)

      assert log =~ "AttestoPhoenix CIMD cache failed; fetching fresh client metadata"
      assert log =~ "AttestoPhoenix CIMD cache failed; fresh client metadata was not cached"
      refute log =~ "private backend exception"
      refute log =~ "private write exception"
    end

    test "never caches an invalid document (refetches every time)", %{agent: agent} do
      url = unique_url()
      # A document whose token_endpoint_auth_method is a symmetric method is
      # rejected by Attesto.ClientIdMetadata.validate_document/2.
      invalid =
        JSON.encode!(%{
          "client_id" => url,
          "redirect_uris" => ["https://app.example/cb"],
          "token_endpoint_auth_method" => "client_secret_basic"
        })

      StubFetcher.script(agent, url, {:ok, %{body: invalid, cache_control: [max_age: 3600]}})

      assert {:error, :symmetric_auth_method} = Resolver.resolve(url, resolver_config())
      assert {:error, {:fetch, :failure_backoff}} = Resolver.resolve(url, resolver_config())

      assert StubFetcher.calls(agent, url) == 1
      assert :miss = ETS.get(url)
    end

    test "errors and never caches a client_id mismatch", %{agent: agent} do
      url = unique_url()
      # The document's client_id does not equal the URL it was fetched from.
      mismatched =
        JSON.encode!(%{
          "client_id" => "https://attacker.example/metadata.json",
          "redirect_uris" => ["https://app.example/cb"],
          "token_endpoint_auth_method" => "none"
        })

      StubFetcher.script(agent, url, {:ok, %{body: mismatched, cache_control: [max_age: 3600]}})

      assert {:error, :client_id_mismatch} = Resolver.resolve(url, resolver_config())
      assert {:error, {:fetch, :failure_backoff}} = Resolver.resolve(url, resolver_config())

      assert StubFetcher.calls(agent, url) == 1
      assert :miss = ETS.get(url)
    end

    test "errors on a malformed JSON body and does not cache", %{agent: agent} do
      url = unique_url()
      StubFetcher.script(agent, url, {:ok, %{body: "{not json", cache_control: []}})

      assert {:error, :invalid_json} = Resolver.resolve(url, resolver_config())
      assert {:error, {:fetch, :failure_backoff}} = Resolver.resolve(url, resolver_config())

      assert StubFetcher.calls(agent, url) == 1
      assert :miss = ETS.get(url)
    end

    test "wraps a fetcher error and does not cache", %{agent: agent} do
      url = unique_url()
      StubFetcher.script(agent, url, {:error, {:status, 404}})

      assert {:error, {:fetch, {:status, 404}}} = Resolver.resolve(url, resolver_config())
      assert StubFetcher.calls(agent, url) == 1
    end

    test "caches using an Expires header when no max-age is present", %{agent: agent} do
      url = unique_url()
      # An Expires date far in the future keeps the entry live, so the second
      # resolve is a cache hit and does not refetch - exercising the RFC 9111
      # Expires fallback path of the TTL derivation.
      expires =
        DateTime.utc_now()
        |> DateTime.add(3600, :second)
        |> Calendar.strftime("%a, %d %b %Y %H:%M:%S GMT")

      StubFetcher.script(
        agent,
        url,
        {:ok, %{body: valid_body(url), cache_control: [expires: expires]}}
      )

      assert {:ok, _client} = Resolver.resolve(url, resolver_config())
      assert {:ok, _client} = Resolver.resolve(url, resolver_config())

      assert StubFetcher.calls(agent, url) == 1
    end

    test "refetches once a cached entry has expired", %{agent: agent} do
      url = unique_url()

      # The origin's explicit zero freshness must not be raised to the default
      # heuristic minimum, so no stale entry is written.
      config = resolver_config()
      StubFetcher.script(agent, url, {:ok, %{body: valid_body(url), cache_control: [max_age: 0]}})

      assert {:ok, _client} = Resolver.resolve(url, config)
      assert {:ok, _client} = Resolver.resolve(url, config)

      assert StubFetcher.calls(agent, url) == 2
    end

    test "subtracts Age without extending remaining freshness to the heuristic minimum", %{agent: agent} do
      url = unique_url()
      now = ~U[2026-10-04 12:00:00Z]
      FaultCache.script(:miss)
      StubFetcher.script(agent, url, {:ok, %{body: valid_body(url), cache_control: [max_age: 300, age: 295]}})
      config = resolver_config(cache: FaultCache, cache_ttl_bounds: {60, 3600}, clock: fn -> now end)

      assert {:ok, client} = Resolver.resolve(url, config)
      assert {^url, ^client, expiry} = FaultCache.last_put()
      assert DateTime.compare(expiry, ~U[2026-10-04 12:00:05Z]) == :eq
      assert FaultCache.put_calls() == 1
    end

    test "stale Age, Expires and apparent Date age never write a cache entry", %{agent: agent} do
      now = ~U[2026-10-04 12:00:00Z]

      for directives <- [
            [max_age: 300, age: 300],
            [max_age: 300, age: 301],
            [max_age: 300, age: 295, response_delay_ms: 5001, received_at: now],
            [max_age: 0],
            [max_age: 60, date: "Sun, 04 Oct 2026 11:58:00 GMT"],
            [expires: "Sun, 04 Oct 2026 11:59:59 GMT"],
            [expires: "not a date"],
            [age: 60]
          ] do
        url = unique_url()
        FaultCache.script(:miss, {:error, :cache_write_must_not_run})
        StubFetcher.script(agent, url, {:ok, %{body: valid_body(url), cache_control: directives}})
        config = resolver_config(cache: FaultCache, clock: fn -> now end)

        assert {:ok, _client} = Resolver.resolve(url, config)
        assert {:ok, _client} = Resolver.resolve(url, config)
        assert FaultCache.put_calls() == 0
        assert StubFetcher.calls(agent, url) == 2
      end
    end

    test "Expires lifetime uses Date and Age with the injected clock", %{agent: agent} do
      url = unique_url()
      now = ~U[2026-10-04 12:00:00Z]
      directives = [date: "Sun, 04 Oct 2026 11:58:00 GMT", expires: "Sun, 04 Oct 2026 12:03:00 GMT", age: 200]
      FaultCache.script(:miss)
      StubFetcher.script(agent, url, {:ok, %{body: valid_body(url), cache_control: directives}})
      config = resolver_config(cache: FaultCache, clock: fn -> now end)

      assert {:ok, client} = Resolver.resolve(url, config)
      assert {^url, ^client, expiry} = FaultCache.last_put()
      assert DateTime.compare(expiry, ~U[2026-10-04 12:01:40Z]) == :eq

      assert DateTime.compare(Resolver.key_cache_expires_at(directives, Config.client_id_metadata(config)), expiry) ==
               :eq
    end

    test "adds resident time once and preserves subsecond remaining freshness" do
      now = ~U[2026-10-04 12:00:00Z]
      opts = [cache_ttl_bounds: {60, 3600}, clock: fn -> now end]

      directives = [
        max_age: 10,
        age: 1,
        response_delay_ms: 2000,
        received_at: ~U[2026-10-04 11:59:58Z],
        date: "Sun, 04 Oct 2026 11:59:55 GMT"
      ]

      assert DateTime.diff(Resolver.key_cache_expires_at(directives, opts), now, :millisecond) == 5000

      assert DateTime.diff(
               Resolver.key_cache_expires_at([max_age: 1, response_delay_ms: 1, received_at: now], opts),
               now,
               :millisecond
             ) == 999
    end

    test "a 304 response cannot revive expired metadata", %{agent: agent} do
      url = unique_url()
      :ok = ETS.put(url, JSON.decode!(valid_body(url)), DateTime.add(DateTime.utc_now(), -1, :second))
      StubFetcher.script(agent, url, {:error, {:status, 304}})

      assert {:error, {:fetch, {:status, 304}}} = Resolver.resolve(url, resolver_config())
      assert :miss = ETS.get(url)
      assert StubFetcher.calls(agent, url) == 1
    end

    test "fails fast on a non-CIMD client_id without fetching", %{agent: agent} do
      assert {:error, {:invalid_client_id, :not_https}} =
               Resolver.resolve("http://app.example/cb", resolver_config())

      assert {:error, {:invalid_client_id, :no_path}} =
               Resolver.resolve("https://app.example", resolver_config())

      # The fetcher's agent was never scripted, so no fetch happened.
      assert Agent.get(agent, & &1) == %{}
    end

    test "refuses a blocked host before any fetch", %{agent: agent} do
      url = "https://blocked.example/clients/metadata.json"
      config = resolver_config(blocked_hosts: ["blocked.example"])

      assert {:error, {:blocked_host, "blocked.example"}} = Resolver.resolve(url, config)
      assert Agent.get(agent, & &1) == %{}
    end

    test "block policy screens case, root-dot and IDNA aliases before fetching", %{agent: agent} do
      for {host, blocked} <- [
            {"APP.Example", "app.example"},
            {"app.example.", "APP.Example"},
            {"app.example", "APP.Example."},
            {"xn--bcher-kva.example", "bücher.example"},
            {"XN--BCHER-KVA.example.", "BÜCHER.Example"}
          ] do
        url = "https://#{host}/clients/metadata.json"
        assert {:error, {:blocked_host, ^host}} = Resolver.resolve(url, resolver_config(blocked_hosts: [blocked]))
      end

      assert Agent.get(agent, & &1) == %{}
    end

    test "allow policy compares canonical names without changing the document identifier", %{agent: agent} do
      url = "https://XN--BCHER-KVA.example./clients/#{System.unique_integer([:positive])}/metadata.json"
      StubFetcher.script(agent, url, {:ok, %{body: valid_body(url), cache_control: [max_age: 3600]}})
      config = resolver_config(allowed_hosts: ["BÜCHER.example"])

      assert {:ok, %{"client_id" => ^url}} = Resolver.resolve(url, config)
      assert {:ok, %{"client_id" => ^url}} = Resolver.resolve(url, config)
      assert StubFetcher.calls(agent, url) == 1

      assert {:error, {:blocked_host, "XN--BCHER-KVA.example."}} =
               Resolver.resolve(url, resolver_config(blocked_hosts: ["xn--bcher-kva.example"]))

      assert StubFetcher.calls(agent, url) == 1
    end

    test "a raw Unicode URL fails the URI grammar before reaching DNS", %{agent: agent} do
      assert {:error, {:invalid_client_id, :not_a_url}} =
               Resolver.resolve("https://bücher.example/client.json", resolver_config())

      assert Agent.get(agent, & &1) == %{}
    end

    test "refuses a host outside the allowlist before any fetch", %{agent: agent} do
      url = "https://other.example/clients/metadata.json"
      config = resolver_config(allowed_hosts: ["app.example"])

      assert {:error, {:blocked_host, "other.example"}} = Resolver.resolve(url, config)
      assert Agent.get(agent, & &1) == %{}
    end

    test "permits an allowlisted host", %{agent: agent} do
      url = "https://app.example/clients/allowlisted/metadata.json"
      config = resolver_config(allowed_hosts: ["app.example"])
      StubFetcher.script(agent, url, {:ok, %{body: valid_body(url), cache_control: []}})

      assert {:ok, client} = Resolver.resolve(url, config)
      assert client["client_id"] == url
    end
  end

  describe "discovery advertisement" do
    import Plug.Conn
    import Plug.Test

    alias Attesto.PrincipalKind

    defp protocol_config do
      Attesto.Config.new(
        issuer: "https://issuer.example",
        audience: "https://issuer.example",
        keystore: StubKeystore,
        principal_kinds: [
          PrincipalKind.new("client", "oc_", required_claims: [{"client_id", :non_empty_string}])
        ]
      )
    end

    # Drive the real RFC 8414 discovery controller so the assertion covers the
    # wired path (Config -> discovery_opts -> Attesto.Discovery.metadata), not
    # just the core builder.
    defp discovery_metadata(host) do
      conn(:get, "/.well-known/oauth-authorization-server")
      |> put_private(:attesto_phoenix_config, host)
      |> put_private(:attesto_protocol_config, protocol_config())
      |> DiscoveryController.show(%{})
      |> Map.fetch!(:resp_body)
      |> JSON.decode!()
    end

    test "advertises client_id_metadata_document_supported when enabled" do
      host = resolver_config(enabled: true)
      assert discovery_metadata(host)["client_id_metadata_document_supported"] == true
    end

    test "omits client_id_metadata_document_supported when disabled" do
      host = resolver_config(enabled: false)
      refute Map.has_key?(discovery_metadata(host), "client_id_metadata_document_supported")
    end
  end
end
