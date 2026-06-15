defmodule AttestoPhoenix.ClientIdMetadata.FetcherTest do
  @moduledoc """
  Tests for the SSRF-guarded Client ID Metadata Document fetcher
  (`AttestoPhoenix.ClientIdMetadata.Fetcher.Req`).

  The SSRF / DNS-rebinding cases are the load-bearing safety net the design doc
  (§11) calls out: no generic conformance suite exercises them. They run against
  an injected `:resolver` so the guard's CIDR table and IP-pinning are exercised
  without real DNS, while the protocol rejections (non-200, redirect, oversize,
  non-JSON) and the happy path run against a real `Bypass` HTTP origin.
  """

  use ExUnit.Case, async: true

  alias AttestoPhoenix.ClientIdMetadata.Fetcher.Req, as: Fetcher

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

    test "allow_loopback: true permits loopback only" do
      # loopback now allowed...
      bypass = Bypass.open()

      Bypass.expect_once(bypass, "GET", "/cb", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(200, ~s({"client_id":"#{@url}"}))
      end)

      assert {:ok, %{body: body}} =
               Fetcher.fetch(@url,
                 resolver: resolver([{127, 0, 0, 1}]),
                 allow_loopback: true,
                 req_options: bypass_url(bypass)
               )

      assert body =~ "client_id"

      # ...but a non-loopback private address stays blocked even with the flag.
      assert {:error, {:blocked_ip, {10, 0, 0, 1}}} =
               Fetcher.fetch(@url, resolver: resolver([{10, 0, 0, 1}]), allow_loopback: true)
    end
  end

  describe "fetch/2 protocol rejections (real Bypass transport)" do
    setup do
      bypass = Bypass.open()
      {:ok, bypass: bypass}
    end

    test "rejects a non-200 status", %{bypass: bypass} do
      Bypass.expect_once(bypass, "GET", "/cb", fn conn ->
        Plug.Conn.resp(conn, 404, "nope")
      end)

      assert {:error, {:status, 404}} = fetch_via(bypass)
    end

    test "rejects any redirect (redirects disabled, surfaced as 3xx)", %{bypass: bypass} do
      Bypass.expect_once(bypass, "GET", "/cb", fn conn ->
        conn
        |> Plug.Conn.put_resp_header("location", "https://elsewhere.example/cb")
        |> Plug.Conn.resp(302, "")
      end)

      assert {:error, {:status, 302}} = fetch_via(bypass)
    end

    test "rejects a non-JSON content type", %{bypass: bypass} do
      Bypass.expect_once(bypass, "GET", "/cb", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("text/html")
        |> Plug.Conn.resp(200, "<html></html>")
      end)

      assert {:error, :bad_content_type} = fetch_via(bypass)
    end

    test "accepts the application/<x>+json structured suffix", %{bypass: bypass} do
      Bypass.expect_once(bypass, "GET", "/cb", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/cimd+json")
        |> Plug.Conn.resp(200, ~s({"client_id":"#{@url}"}))
      end)

      assert {:ok, %{body: body}} = fetch_via(bypass)
      assert body =~ "client_id"
    end

    test "rejects a body over the cap", %{bypass: bypass} do
      Bypass.expect_once(bypass, "GET", "/cb", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(200, String.duplicate("x", 6_000))
      end)

      assert {:error, :too_large} = fetch_via(bypass, max_document_bytes: 5_120)
    end

    test "happy path: returns the document body and parsed cache-control", %{bypass: bypass} do
      Bypass.expect_once(bypass, "GET", "/cb", fn conn ->
        # the fetcher sends Accept: application/json and Host: app.example
        assert {"accept", "application/json"} in conn.req_headers
        assert {"host", "app.example"} in conn.req_headers

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.put_resp_header("cache-control", "max-age=600, no-cache")
        |> Plug.Conn.resp(200, ~s({"client_id":"#{@url}","redirect_uris":["#{@url}"]}))
      end)

      assert {:ok, %{body: body, cache_control: cache_control}} = fetch_via(bypass)
      assert Jason.decode!(body)["client_id"] == @url
      assert cache_control[:max_age] == 600
      assert cache_control[:no_cache] == true
    end
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

  # Point the fetcher's request at the Bypass HTTP origin: the SSRF guard and IP
  # screening still run on the injected resolver, but the actual transport hits
  # Bypass over plain HTTP (Bypass does not serve TLS).
  defp fetch_via(bypass, extra_opts \\ []) do
    opts =
      [
        resolver: resolver([{127, 0, 0, 1}]),
        allow_loopback: true,
        req_options: bypass_url(bypass)
      ] ++ extra_opts

    Fetcher.fetch(@url, opts)
  end

  defp bypass_url(bypass) do
    [url: "http://127.0.0.1:#{bypass.port}/cb", connect_options: [hostname: "app.example"]]
  end
end
