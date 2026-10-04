defmodule AttestoPhoenix.ClientIdMetadata.FetcherTest do
  @moduledoc """
  Tests for the SSRF-guarded Client ID Metadata Document fetcher
  (`AttestoPhoenix.ClientIdMetadata.Fetcher.Req`).

  The SSRF / DNS-rebinding cases are the load-bearing safety net the design doc
  (§11) calls out: no generic conformance suite exercises them. They run against
  an injected `:resolver` so the guard's CIDR table and IP-pinning are exercised
  without real DNS, while the protocol rejections (non-200, redirect, oversize,
  non-JSON) and the happy path run against a real local Bandit HTTP origin.
  """

  use ExUnit.Case, async: true

  alias AttestoPhoenix.ClientIdMetadata.Fetcher.Req, as: Fetcher
  alias AttestoPhoenix.ClientIdMetadata.Resolver

  @url "https://app.example/cb"

  # A resolver that always returns `ips` for the inet family and nothing for
  # inet6 (or vice versa via `family`), letting a test inject exactly the
  # addresses the guard must screen.
  defp resolver(ips, family \\ :inet) do
    fn _host, queried ->
      if queried == family, do: {:ok, ips}, else: {:ok, []}
    end
  end

  describe "special_use_ip?/1 (RFC 6890 CIDR table)" do
    test "rejects every required special-use IPv4 class" do
      blocked = [
        {127, 0, 0, 1},
        {10, 0, 0, 1},
        {172, 16, 5, 5},
        {172, 31, 255, 255},
        {192, 168, 1, 1},
        {169, 254, 1, 1},
        {100, 64, 0, 1},
        {0, 0, 0, 0},
        {0, 1, 2, 3},
        {224, 0, 0, 1},
        {239, 255, 255, 255},
        {240, 0, 0, 1}
      ]

      for ip <- blocked do
        assert Fetcher.special_use_ip?(ip), "expected #{inspect(ip)} to be special-use"
      end
    end

    test "rejects special-use IPv6 (loopback, ULA, link-local, multicast)" do
      blocked = [
        {0, 0, 0, 0, 0, 0, 0, 1},
        {0xFC00, 0, 0, 0, 0, 0, 0, 1},
        {0xFD00, 0, 0, 0, 0, 0, 0, 1},
        {0xFE80, 0, 0, 0, 0, 0, 0, 1},
        {0xFF02, 0, 0, 0, 0, 0, 0, 1}
      ]

      for ip <- blocked do
        assert Fetcher.special_use_ip?(ip), "expected #{inspect(ip)} to be special-use"
      end
    end

    test "rejects Teredo (2001:0000::/32) and ORCHIDv2 (2001:20::/28), accepts neighbouring public 2001:: space" do
      # Teredo embeds a client IPv4 in its low bits (here 169.254.169.254); the
      # whole prefix is blocked regardless (RFC 4380 / RFC 6890). ORCHIDv2 is the
      # /28 at 2001:20:: (RFC 7343). Both are non-octet-aligned/edge cases.
      blocked = [
        {0x2001, 0x0000, 0x4136, 0xE378, 0x8000, 0x63BF, 0xA9FE, 0xA9FE},
        {0x2001, 0x0020, 0, 0, 0, 0, 0, 1},
        {0x2001, 0x002F, 0, 0, 0, 0, 0, 1}
      ]

      for ip <- blocked do
        assert Fetcher.special_use_ip?(ip), "expected #{inspect(ip)} to be special-use"
      end

      # Tight edges: 2001:1::/32 (one below Teredo) and 2001:30::/28 (one above
      # ORCHIDv2) are ordinary global unicast and must NOT be blocked.
      refute Fetcher.special_use_ip?({0x2001, 0x0001, 0, 0, 0, 0, 0, 1})
      refute Fetcher.special_use_ip?({0x2001, 0x0030, 0, 0, 0, 0, 0, 1})
      # A real public 2001:: host (Google PDNS 2001:4860:4860::8888) stays allowed.
      refute Fetcher.special_use_ip?({0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888})
    end

    test "rejects IPv4-mapped IPv6 of a special-use IPv4" do
      # ::ffff:127.0.0.1 and ::ffff:10.0.0.1
      assert Fetcher.special_use_ip?({0, 0, 0, 0, 0, 0xFFFF, 0x7F00, 0x0001})
      assert Fetcher.special_use_ip?({0, 0, 0, 0, 0, 0xFFFF, 0x0A00, 0x0001})
    end

    test "rejects IPv6 forms that embed an internal IPv4 (NAT64, 6to4, IPv4-compatible)" do
      # NAT64 64:ff9b::169.254.169.254 (cloud metadata via a NAT64 gateway).
      assert Fetcher.special_use_ip?({0x0064, 0xFF9B, 0, 0, 0, 0, 0xA9FE, 0xA9FE})
      # NAT64 local-use 64:ff9b:1::/48 (RFC 8215, RFC 6052 §2.2 /48 embedding) of
      # 169.254.169.254: a=169 b=254 -> w4=0xA9FE; c=169 -> w5=0x00A9; d=254 -> w6=0xFE00.
      assert Fetcher.special_use_ip?({0x0064, 0xFF9B, 0x0001, 0xA9FE, 0x00A9, 0xFE00, 0, 0})
      # NAT64 wrapping loopback / private.
      assert Fetcher.special_use_ip?({0x0064, 0xFF9B, 0, 0, 0, 0, 0x7F00, 0x0001})
      # 6to4 2002:a9fe:a9fe::/48 embeds 169.254.169.254.
      assert Fetcher.special_use_ip?({0x2002, 0xA9FE, 0xA9FE, 0, 0, 0, 0, 0})
      # IPv4-compatible ::169.254.169.254 (deprecated form).
      assert Fetcher.special_use_ip?({0, 0, 0, 0, 0, 0, 0xA9FE, 0xA9FE})
    end

    test "accepts a normal public address" do
      refute Fetcher.special_use_ip?({93, 184, 216, 34})
      refute Fetcher.special_use_ip?({0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25C8, 0x1946})
      # ::ffff:93.184.216.34 (mapped public address) must also pass.
      refute Fetcher.special_use_ip?({0, 0, 0, 0, 0, 0xFFFF, 0x5DB8, 0xD822})
      # NAT64 / 6to4 wrapping a PUBLIC IPv4 (93.184.216.34) must pass - only the
      # embedded-internal case is blocked.
      refute Fetcher.special_use_ip?({0x0064, 0xFF9B, 0, 0, 0, 0, 0x5DB8, 0xD822})
      refute Fetcher.special_use_ip?({0x2002, 0x5DB8, 0xD822, 0, 0, 0, 0, 0})
    end
  end

  describe "fetch/2 SSRF rejections via injected resolver" do
    test "IDNA DNS canonicalization keeps the special-use IP screen authoritative" do
      test_pid = self()

      resolver = fn host, family ->
        send(test_pid, {:dns_host, host, family})
        if family == :inet, do: {:ok, [{127, 0, 0, 1}]}, else: {:ok, []}
      end

      assert {:error, {:blocked_ip, {127, 0, 0, 1}}} =
               Fetcher.preflight("https://XN--BCHER-KVA.example./client.json", resolver: resolver)

      assert_received {:dns_host, ~c"xn--bcher-kva.example", :inet}
      assert_received {:dns_host, ~c"xn--bcher-kva.example", :inet6}
    end

    test "preflight repeats the same DNS screening without dereferencing the URL" do
      assert :ok = Fetcher.preflight(@url, resolver: resolver([{93, 184, 216, 34}]))

      assert {:error, {:blocked_ip, {10, 1, 2, 3}}} =
               Fetcher.preflight(@url, resolver: resolver([{93, 184, 216, 34}, {10, 1, 2, 3}]))

      assert {:error, :unresolvable} = Fetcher.preflight(@url, resolver: resolver([]))
    end

    test "rejects loopback by default" do
      assert {:error, {:blocked_ip, {127, 0, 0, 1}}} =
               Fetcher.fetch(@url, resolver: resolver([{127, 0, 0, 1}]))
    end

    test "rejects private 10/8" do
      assert {:error, {:blocked_ip, {10, 1, 2, 3}}} =
               Fetcher.fetch(@url, resolver: resolver([{10, 1, 2, 3}]))
    end

    test "rejects link-local 169.254/16" do
      assert {:error, {:blocked_ip, {169, 254, 0, 5}}} =
               Fetcher.fetch(@url, resolver: resolver([{169, 254, 0, 5}]))
    end

    test "rejects CGNAT 100.64/10" do
      assert {:error, {:blocked_ip, {100, 100, 0, 1}}} =
               Fetcher.fetch(@url, resolver: resolver([{100, 100, 0, 1}]))
    end

    test "rejects 0.0.0.0/8" do
      assert {:error, {:blocked_ip, {0, 0, 0, 0}}} =
               Fetcher.fetch(@url, resolver: resolver([{0, 0, 0, 0}]))
    end

    test "rejects IPv4-mapped IPv6 loopback returned as AAAA" do
      mapped = {0, 0, 0, 0, 0, 0xFFFF, 0x7F00, 0x0001}

      assert {:error, {:blocked_ip, ^mapped}} =
               Fetcher.fetch(@url, resolver: resolver([mapped], :inet6))
    end

    test "rejects when ANY address in a mixed answer is special-use" do
      # A public A record paired with a loopback AAAA must still be refused -
      # the guard screens the whole resolved set, not just the pinned family.
      resolver = fn _host, family ->
        case family do
          :inet -> {:ok, [{93, 184, 216, 34}]}
          :inet6 -> {:ok, [{0, 0, 0, 0, 0, 0, 0, 1}]}
        end
      end

      assert {:error, {:blocked_ip, {0, 0, 0, 0, 0, 0, 0, 1}}} =
               Fetcher.fetch(@url, resolver: resolver)
    end

    test "unresolvable host errors closed" do
      assert {:error, :unresolvable} =
               Fetcher.fetch(@url, resolver: fn _host, _family -> {:ok, []} end)
    end

    test "re-validates the URL grammar (defense in depth)" do
      assert {:error, {:invalid_url, :not_https}} =
               Fetcher.fetch("http://app.example/cb", resolver: resolver([{93, 184, 216, 34}]))
    end

    test "rejects non-boolean loopback policy instead of treating it as enabled" do
      for invalid <- ["false", 1, {:error, :unavailable}] do
        test_pid = self()

        assert_raise ArgumentError, ~r/:allow_loopback must be true or false/, fn ->
          Fetcher.fetch(@url,
            resolver: fn _host, _family ->
              send(test_pid, :resolver_called)
              {:ok, [{127, 0, 0, 1}]}
            end,
            allow_loopback: invalid
          )
        end

        refute_received :resolver_called
      end
    end

    test "allow_loopback: true permits loopback only" do
      # loopback now allowed...
      server = AttestoPhoenix.TestHTTPServer.open()

      AttestoPhoenix.TestHTTPServer.expect_once(server, "GET", "/cb", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(200, ~s({"client_id":"#{@url}"}))
      end)

      assert {:ok, %{body: body}} =
               Fetcher.fetch(@url,
                 resolver: resolver([{127, 0, 0, 1}]),
                 allow_loopback: true,
                 req_options: server_url(server)
               )

      assert body =~ "client_id"

      # ...but a non-loopback private address stays blocked even with the flag.
      assert {:error, {:blocked_ip, {10, 0, 0, 1}}} =
               Fetcher.fetch(@url, resolver: resolver([{10, 0, 0, 1}]), allow_loopback: true)
    end
  end

  describe "fetch/2 protocol rejections (real Bandit transport)" do
    setup do
      server = AttestoPhoenix.TestHTTPServer.open()
      {:ok, server: server}
    end

    test "rejects a non-200 status", %{server: server} do
      AttestoPhoenix.TestHTTPServer.expect_once(server, "GET", "/cb", fn conn ->
        Plug.Conn.resp(conn, 404, "nope")
      end)

      assert {:error, {:status, 404}} = fetch_via(server)
    end

    test "rejects 304 and sends no unsupported ETag conditional request", %{server: server} do
      AttestoPhoenix.TestHTTPServer.expect_once(server, "GET", "/cb", fn conn ->
        assert Plug.Conn.get_req_header(conn, "if-none-match") == []
        assert Plug.Conn.get_req_header(conn, "if-modified-since") == []

        conn
        |> Plug.Conn.put_resp_header("etag", ~s("v1"))
        |> Plug.Conn.put_resp_header("cache-control", "max-age=600")
        |> Plug.Conn.resp(304, "")
      end)

      assert {:error, {:status, 304}} = fetch_via(server)
    end

    test "rejects any redirect (redirects disabled, surfaced as 3xx)", %{server: server} do
      AttestoPhoenix.TestHTTPServer.expect_once(server, "GET", "/cb", fn conn ->
        conn
        |> Plug.Conn.put_resp_header("location", "https://elsewhere.example/cb")
        |> Plug.Conn.resp(302, "")
      end)

      assert {:error, {:status, 302}} = fetch_via(server)
    end

    test "rejects a non-JSON content type", %{server: server} do
      AttestoPhoenix.TestHTTPServer.expect_once(server, "GET", "/cb", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("text/html")
        |> Plug.Conn.resp(200, "<html></html>")
      end)

      assert {:error, :bad_content_type} = fetch_via(server)
    end

    test "accepts the application/<x>+json structured suffix", %{server: server} do
      AttestoPhoenix.TestHTTPServer.expect_once(server, "GET", "/cb", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/cimd+json")
        |> Plug.Conn.resp(200, ~s({"client_id":"#{@url}"}))
      end)

      assert {:ok, %{body: body}} = fetch_via(server)
      assert body =~ "client_id"
    end

    test "rejects a body over the cap", %{server: server} do
      AttestoPhoenix.TestHTTPServer.expect_once(server, "GET", "/cb", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(200, String.duplicate("x", 6_000))
      end)

      assert {:error, :too_large} = fetch_via(server, max_document_bytes: 5_120)
    end

    test "happy path: returns the document body and parsed cache-control", %{server: server} do
      AttestoPhoenix.TestHTTPServer.expect_once(server, "GET", "/cb", fn conn ->
        # the fetcher sends Accept: application/json and Host: app.example
        assert {"accept", "application/json"} in conn.req_headers
        assert {"host", "app.example"} in conn.req_headers

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.put_resp_header("cache-control", "max-age=600, no-cache")
        |> Plug.Conn.put_resp_header("age", "120")
        |> Plug.Conn.put_resp_header("date", "Sun, 04 Oct 2026 12:00:00 GMT")
        |> Plug.Conn.resp(200, ~s({"client_id":"#{@url}","redirect_uris":["#{@url}"]}))
      end)

      assert {:ok, %{body: body, cache_control: cache_control}} = fetch_via(server)
      assert Jason.decode!(body)["client_id"] == @url
      assert cache_control[:max_age] == 600
      assert cache_control[:no_cache] == true
      assert cache_control[:age] == 120
      assert cache_control[:date] == "Sun, 04 Oct 2026 12:00:00 GMT"
    end

    test "parses shared-cache s-maxage and private directives", %{server: server} do
      AttestoPhoenix.TestHTTPServer.expect_once(server, "GET", "/cb", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.put_resp_header("cache-control", ~s(max-age=600, s-maxage="120", private="Set-Cookie"))
        |> Plug.Conn.resp(200, ~s({"client_id":"#{@url}"}))
      end)

      assert {:ok, %{cache_control: directives}} = fetch_via(server)
      assert directives[:max_age] == 600
      assert directives[:s_maxage] == 120
      assert directives[:private] == true
    end

    test "treats the first malformed s-maxage as zero instead of falling back to max-age", %{server: server} do
      for header <- [
            "s-maxage=0, s-maxage=600, max-age=600",
            "s-maxage, max-age=600",
            "s-maxage=invalid, max-age=600",
            "s-maxage=-1, max-age=600",
            "s-maxage=+600, max-age=600",
            ~s(s-maxage="invalid", max-age=600)
          ] do
        AttestoPhoenix.TestHTTPServer.expect_once(server, "GET", "/cb", fn conn ->
          conn
          |> Plug.Conn.put_resp_content_type("application/json")
          |> Plug.Conn.put_resp_header("cache-control", header)
          |> Plug.Conn.resp(200, ~s({"client_id":"#{@url}"}))
        end)

        assert {:ok, %{cache_control: directives}} = fetch_via(server)
        assert directives[:s_maxage] == 0
        assert directives[:max_age] == 600
        assert_stale(directives)
      end
    end

    test "includes transport delay in remaining HTTP freshness", %{server: server} do
      AttestoPhoenix.TestHTTPServer.expect_once(server, "GET", "/cb", fn conn ->
        Process.sleep(25)

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.put_resp_header("cache-control", "max-age=600")
        |> Plug.Conn.put_resp_header("age", "0")
        |> Plug.Conn.resp(200, ~s({"client_id":"#{@url}"}))
      end)

      assert {:ok, %{cache_control: directives}} = fetch_via(server)
      assert directives[:response_delay_ms] >= 25
      assert %DateTime{} = received_at = directives[:received_at]
      expiry = Resolver.key_cache_expires_at(directives, cache_ttl_bounds: {60, 3600}, clock: fn -> received_at end)
      assert DateTime.diff(expiry, received_at, :millisecond) <= 600_000 - directives[:response_delay_ms]
    end

    test "uses the first Age field and list member rather than discarding duplicates", %{server: server} do
      for headers <- [[{"age", "300"}, {"age", "0"}], [{"age", "300, 0"}]] do
        AttestoPhoenix.TestHTTPServer.expect_once(server, "GET", "/cb", fn conn ->
          conn =
            conn
            |> Plug.Conn.put_resp_content_type("application/json")
            |> Plug.Conn.put_resp_header("cache-control", "max-age=300")

          %{conn | resp_headers: headers ++ conn.resp_headers}
          |> Plug.Conn.resp(200, ~s({"client_id":"#{@url}"}))
        end)

        assert {:ok, %{cache_control: directives}} = fetch_via(server)
        assert directives[:age] == 300
        assert_stale(directives)
      end
    end

    test "uses the first duplicate max-age and treats malformed explicit freshness as stale", %{server: server} do
      for header <- [
            "max-age=0, max-age=600",
            "max-age, max-age=600",
            "max-age=invalid, max-age=600",
            "max-age=-1",
            "max-age=+600",
            "max-age=\"invalid\"",
            "extension=\"ignored,max-age=600,ignored\", max-age=0",
            "extension=\"escaped\\\",max-age=600,ignored\", max-age=0",
            "extension=\"unterminated,max-age=600"
          ] do
        AttestoPhoenix.TestHTTPServer.expect_once(server, "GET", "/cb", fn conn ->
          conn
          |> Plug.Conn.put_resp_content_type("application/json")
          |> Plug.Conn.put_resp_header("cache-control", header)
          |> Plug.Conn.put_resp_header("expires", "Tue, 04 Oct 2028 12:00:00 GMT")
          |> Plug.Conn.resp(200, ~s({"client_id":"#{@url}"}))
        end)

        assert {:ok, %{cache_control: directives}} = fetch_via(server)
        assert directives[:max_age] == 0
        assert_stale(directives)
      end
    end

    test "accepts quoted max-age and ignores an invalid first Age value", %{server: server} do
      AttestoPhoenix.TestHTTPServer.expect_once(server, "GET", "/cb", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.put_resp_header("cache-control", "max-age = \"300\"")
        |> Plug.Conn.put_resp_header("age", "invalid, 300")
        |> Plug.Conn.resp(200, ~s({"client_id":"#{@url}"}))
      end)

      assert {:ok, %{cache_control: directives}} = fetch_via(server)
      assert directives[:max_age] == 300
      refute Keyword.has_key?(directives, :age)
    end
  end

  defp assert_stale(directives) do
    received_at = Keyword.fetch!(directives, :received_at)
    expiry = Resolver.key_cache_expires_at(directives, cache_ttl_bounds: {60, 3600}, clock: fn -> received_at end)
    assert DateTime.compare(expiry, received_at) == :eq
  end

  describe "fetch/2 DNS-rebinding: pins the first validated IP" do
    test "dials the resolver-supplied IP, not a re-resolved hostname" do
      test_pid = self()
      pinned = {93, 184, 216, 34}

      # A capture plug stands in for the transport: Req builds the request URL
      # from the fetcher's pinned IP, so `conn.host` is exactly the address the
      # socket would have dialed. A second resolver call (re-resolution) would
      # be observable here too - there is none.
      capture_plug = fn conn ->
        send(test_pid, {:dialed_host, conn.host})

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(200, ~s({"client_id":"#{@url}"}))
      end

      assert {:ok, %{body: _body}} =
               Fetcher.fetch(@url,
                 resolver: resolver([pinned]),
                 req_options: [plug: capture_plug]
               )

      assert_received {:dialed_host, "93.184.216.34"}
    end

    test "calls the resolver exactly once per family, then pins - no re-resolution" do
      test_pid = self()

      counting_resolver = fn _host, family ->
        send(test_pid, {:resolved, family})
        if family == :inet, do: {:ok, [{93, 184, 216, 34}]}, else: {:ok, []}
      end

      capture_plug = fn conn ->
        send(test_pid, {:dialed_host, conn.host})

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(200, ~s({"client_id":"#{@url}"}))
      end

      assert {:ok, _result} =
               Fetcher.fetch(@url,
                 resolver: counting_resolver,
                 req_options: [plug: capture_plug]
               )

      # The host is resolved once for A and once for AAAA up front; the dial
      # then targets the validated IP - there is no further resolution that a
      # rebind could race.
      assert_received {:resolved, :inet}
      assert_received {:resolved, :inet6}
      assert_received {:dialed_host, "93.184.216.34"}
      refute_received {:resolved, _family}
    end
  end

  # Point the fetcher's request at the local Bandit HTTP origin: the SSRF guard and IP
  # screening still run on the injected resolver, but the actual transport hits
  # Bandit over plain HTTP (the test server does not serve TLS).
  defp fetch_via(server, extra_opts \\ []) do
    opts =
      [
        resolver: resolver([{127, 0, 0, 1}]),
        allow_loopback: true,
        req_options: server_url(server)
      ] ++ extra_opts

    Fetcher.fetch(@url, opts)
  end

  defp server_url(server) do
    [url: "http://127.0.0.1:#{server.port}/cb", connect_options: [hostname: "app.example"]]
  end
end
