defmodule AttestoPhoenix.RequestContextTest do
  use ExUnit.Case, async: true

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.RequestContext

  # A minimal config satisfying the required keys, with the request-context
  # knobs overridable per test. The protocol-level callbacks are stubbed; this
  # module never invokes them.
  defp config(overrides \\ []) do
    base = [
      issuer: "https://issuer.example",
      audience: "https://api.example.com",
      keystore: __MODULE__.Keystore,
      repo: __MODULE__.Repo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end
    ]

    Config.new(Keyword.merge(base, overrides))
  end

  # Build a Plug.Conn without booting an endpoint. `Plug.Test.conn/3` yields a
  # conn whose `remote_ip` defaults to loopback and `scheme` to `:http`; tests
  # override those fields directly to exercise the trust gate.
  defp build_conn(method, path, opts \\ []) do
    conn = Plug.Test.conn(method, path)

    conn =
      Enum.reduce(opts[:headers] || [], conn, fn {k, v}, acc ->
        Plug.Conn.put_req_header(acc, k, v)
      end)

    conn
    |> Map.put(:remote_ip, opts[:remote_ip] || {127, 0, 0, 1})
    |> Map.put(:scheme, opts[:scheme] || :http)
    |> Map.put(:host, opts[:host] || "internal.app")
    |> Map.put(:port, opts[:port] || 80)
  end

  describe "from_trusted_proxy?/2" do
    test ":loopback matches IPv4 loopback and ::1" do
      cfg = config(trusted_proxies: [:loopback])

      assert RequestContext.from_trusted_proxy?(
               build_conn(:get, "/", remote_ip: {127, 0, 0, 1}),
               cfg
             )

      assert RequestContext.from_trusted_proxy?(
               build_conn(:get, "/", remote_ip: {127, 5, 6, 7}),
               cfg
             )

      assert RequestContext.from_trusted_proxy?(
               build_conn(:get, "/", remote_ip: {0, 0, 0, 0, 0, 0, 0, 1}),
               cfg
             )

      refute RequestContext.from_trusted_proxy?(
               build_conn(:get, "/", remote_ip: {10, 0, 0, 1}),
               cfg
             )
    end

    test ":any matches every peer" do
      cfg = config(trusted_proxies: [:any])

      assert RequestContext.from_trusted_proxy?(
               build_conn(:get, "/", remote_ip: {8, 8, 8, 8}),
               cfg
             )
    end

    test "empty allowlist trusts no one" do
      cfg = config(trusted_proxies: [])

      refute RequestContext.from_trusted_proxy?(
               build_conn(:get, "/", remote_ip: {127, 0, 0, 1}),
               cfg
             )
    end

    test "exact IP tuple match" do
      cfg = config(trusted_proxies: [{10, 1, 2, 3}])

      assert RequestContext.from_trusted_proxy?(
               build_conn(:get, "/", remote_ip: {10, 1, 2, 3}),
               cfg
             )

      refute RequestContext.from_trusted_proxy?(
               build_conn(:get, "/", remote_ip: {10, 1, 2, 4}),
               cfg
             )
    end

    test "IPv4 CIDR subnet match" do
      cfg = config(trusted_proxies: ["10.0.0.0/8"])

      assert RequestContext.from_trusted_proxy?(
               build_conn(:get, "/", remote_ip: {10, 9, 9, 9}),
               cfg
             )

      refute RequestContext.from_trusted_proxy?(
               build_conn(:get, "/", remote_ip: {11, 0, 0, 1}),
               cfg
             )
    end

    test "IPv4-mapped IPv6 peer matches an IPv4 CIDR (dual-stack listener behind a proxy)" do
      # A `::` listener surfaces the proxy's 172.18.0.5 peer as ::ffff:172.18.0.5.
      cfg = config(trusted_proxies: ["172.16.0.0/12"])

      assert RequestContext.from_trusted_proxy?(
               build_conn(:get, "/", remote_ip: {0, 0, 0, 0, 0, 0xFFFF, 0xAC12, 0x0005}),
               cfg
             )

      # ::ffff:10.0.0.1 is outside 172.16.0.0/12 once folded to IPv4.
      refute RequestContext.from_trusted_proxy?(
               build_conn(:get, "/", remote_ip: {0, 0, 0, 0, 0, 0xFFFF, 0x0A00, 0x0001}),
               cfg
             )
    end

    test "IPv6 CIDR subnet match" do
      cfg = config(trusted_proxies: ["fd00::/8"])

      assert RequestContext.from_trusted_proxy?(
               build_conn(:get, "/", remote_ip: {0xFD00, 0, 0, 0, 0, 0, 0, 1}),
               cfg
             )

      refute RequestContext.from_trusted_proxy?(
               build_conn(:get, "/", remote_ip: {0xFE00, 0, 0, 0, 0, 0, 0, 1}),
               cfg
             )
    end

    test "address family does not cross: IPv4 peer never matches IPv6 CIDR" do
      cfg = config(trusted_proxies: ["::/0"])

      refute RequestContext.from_trusted_proxy?(
               build_conn(:get, "/", remote_ip: {10, 0, 0, 1}),
               cfg
             )
    end

    test "malformed CIDR is treated as no-match, not a crash" do
      cfg = config(trusted_proxies: ["not-a-cidr", "10.0.0.0/99"])

      refute RequestContext.from_trusted_proxy?(
               build_conn(:get, "/", remote_ip: {10, 0, 0, 1}),
               cfg
             )
    end

    test "nil remote_ip is never trusted" do
      cfg = config(trusted_proxies: [:any])
      conn = %{build_conn(:get, "/") | remote_ip: nil}
      refute RequestContext.from_trusted_proxy?(conn, cfg)
    end
  end

  describe "https?/2 and check_https/2" do
    test "direct https connection is secure" do
      cfg = config()
      assert RequestContext.https?(build_conn(:get, "/", scheme: :https), cfg)
    end

    test "direct http connection is not secure" do
      cfg = config()
      refute RequestContext.https?(build_conn(:get, "/", scheme: :http), cfg)
    end

    test "trusted proxy forwarding https is honored" do
      cfg = config(trusted_proxies: [:loopback])

      conn =
        build_conn(:get, "/",
          scheme: :http,
          remote_ip: {127, 0, 0, 1},
          headers: [{"x-forwarded-proto", "https"}]
        )

      assert RequestContext.https?(conn, cfg)
    end

    test "untrusted peer forwarding https is ignored (spoof rejected)" do
      cfg = config(trusted_proxies: [:loopback])

      conn =
        build_conn(:get, "/",
          scheme: :http,
          remote_ip: {203, 0, 113, 1},
          headers: [{"x-forwarded-proto", "https"}]
        )

      refute RequestContext.https?(conn, cfg)
    end

    test "left-most forwarded-proto token wins" do
      cfg = config(trusted_proxies: [:loopback])

      conn =
        build_conn(:get, "/",
          scheme: :http,
          remote_ip: {127, 0, 0, 1},
          headers: [{"x-forwarded-proto", "https, http"}]
        )

      assert RequestContext.https?(conn, cfg)
    end

    test "check_https passes when require_https is false on plain http" do
      cfg = config(require_https: false)
      assert RequestContext.check_https(build_conn(:get, "/", scheme: :http), cfg) == :ok
    end

    test "check_https fails closed when require_https is true on plain http" do
      cfg = config(require_https: true)

      assert RequestContext.check_https(build_conn(:get, "/", scheme: :http), cfg) ==
               {:error, :insecure_transport}
    end

    test "check_https passes on https when require_https is true" do
      cfg = config(require_https: true)
      assert RequestContext.check_https(build_conn(:get, "/", scheme: :https), cfg) == :ok
    end
  end

  describe "client_ip/2" do
    test "uses remote_ip when no forwarded header" do
      cfg = config(trusted_proxies: [:loopback])

      assert RequestContext.client_ip(build_conn(:get, "/", remote_ip: {127, 0, 0, 1}), cfg) ==
               "127.0.0.1"
    end

    test "uses left-most forwarded-for from a trusted proxy" do
      cfg = config(trusted_proxies: [:loopback])

      conn =
        build_conn(:get, "/",
          remote_ip: {127, 0, 0, 1},
          headers: [{"x-forwarded-for", "198.51.100.7, 127.0.0.1"}]
        )

      assert RequestContext.client_ip(conn, cfg) == "198.51.100.7"
    end

    test "ignores forwarded-for from an untrusted peer" do
      cfg = config(trusted_proxies: [:loopback])

      conn =
        build_conn(:get, "/",
          remote_ip: {203, 0, 113, 9},
          headers: [{"x-forwarded-for", "198.51.100.7"}]
        )

      assert RequestContext.client_ip(conn, cfg) == "203.0.113.9"
    end
  end

  describe "http_method/1" do
    test "returns the verbatim request method" do
      assert RequestContext.http_method(build_conn(:post, "/oauth/token")) == "POST"
    end
  end

  describe "canonical_url/2" do
    test "builds htu from the direct connection authority" do
      cfg = config()
      conn = build_conn(:post, "/oauth/token", scheme: :https, host: "issuer.example", port: 443)
      assert RequestContext.canonical_url(conn, cfg) == "https://issuer.example/oauth/token"
    end

    test "omits the default https port" do
      cfg = config()
      conn = build_conn(:get, "/x", scheme: :https, host: "h", port: 443)
      assert RequestContext.canonical_url(conn, cfg) == "https://h/x"
    end

    test "includes a non-default port" do
      cfg = config()
      conn = build_conn(:get, "/x", scheme: :https, host: "h", port: 8443)
      assert RequestContext.canonical_url(conn, cfg) == "https://h:8443/x"
    end

    test "honors forwarded scheme/host/port from a trusted proxy" do
      cfg = config(trusted_proxies: [:loopback])

      conn =
        build_conn(:post, "/oauth/token",
          scheme: :http,
          host: "internal.app",
          port: 80,
          remote_ip: {127, 0, 0, 1},
          headers: [
            {"x-forwarded-proto", "https"},
            {"x-forwarded-host", "issuer.example"},
            {"x-forwarded-port", "443"}
          ]
        )

      assert RequestContext.canonical_url(conn, cfg) == "https://issuer.example/oauth/token"
    end

    test "ignores forwarded authority from an untrusted peer" do
      cfg = config(trusted_proxies: [:loopback])

      conn =
        build_conn(:post, "/oauth/token",
          scheme: :https,
          host: "internal.app",
          port: 443,
          remote_ip: {203, 0, 113, 1},
          headers: [{"x-forwarded-host", "evil.example"}]
        )

      assert RequestContext.canonical_url(conn, cfg) == "https://internal.app/oauth/token"
    end

    test "config.htu callback overrides reconstruction" do
      cfg = config(htu: fn _conn -> "https://override.example/path" end)

      assert RequestContext.canonical_url(build_conn(:get, "/x"), cfg) ==
               "https://override.example/path"
    end

    test "falls back to derivation when the htu callback returns nil" do
      cfg = config(htu: fn _conn -> nil end)
      conn = build_conn(:get, "/x", scheme: :https, host: "h", port: 443)
      assert RequestContext.canonical_url(conn, cfg) == "https://h/x"
    end
  end

  describe "cert_der/2" do
    test "returns nil when no peer certificate and no callback" do
      cfg = config()
      assert RequestContext.cert_der(build_conn(:get, "/"), cfg) == nil
    end

    test "config.cert_der callback extracts the DER" do
      cfg = config(cert_der: fn _conn -> "DER-BYTES" end, mtls_enabled: true)
      assert RequestContext.cert_der(build_conn(:get, "/"), cfg) == "DER-BYTES"
    end

    test "callback returning an empty binary is treated as no certificate" do
      cfg = config(cert_der: fn _conn -> "" end, mtls_enabled: true)
      assert RequestContext.cert_der(build_conn(:get, "/"), cfg) == nil
    end

    test "callback returning a non-binary is treated as no certificate" do
      cfg = config(cert_der: fn _conn -> :no_cert end, mtls_enabled: true)
      assert RequestContext.cert_der(build_conn(:get, "/"), cfg) == nil
    end
  end

  describe "embedded_user_agent?/1 (RFC 8252 §8.12)" do
    defp with_user_agent(user_agent) do
      build_conn(:get, "/oauth/authorize", headers: [{"user-agent", user_agent}])
    end

    test "detects the Android System WebView platform token" do
      assert RequestContext.embedded_user_agent?(
               with_user_agent(
                 "Mozilla/5.0 (Linux; Android 13; Pixel 7 Build/TQ3A; wv) AppleWebKit/537.36 " <>
                   "(KHTML, like Gecko) Version/4.0 Chrome/119.0.0.0 Mobile Safari/537.36"
               )
             )
    end

    test "detects an iOS WKWebView by the absent Safari product token" do
      assert RequestContext.embedded_user_agent?(
               with_user_agent(
                 "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 " <>
                   "(KHTML, like Gecko) Mobile/21A329"
               )
             )
    end

    test "detects well-known in-app browser product tokens" do
      for marker <- [
            "FBAN/FBIOS;FBAV/440.0",
            "Instagram 302.0.0.23.113",
            "Line/13.5.0",
            "MicroMessenger/8.0.42",
            "Electron/27.0.0"
          ] do
        assert RequestContext.embedded_user_agent?(with_user_agent("Mozilla/5.0 " <> marker)),
               "expected #{marker} to be detected as an embedded user agent"
      end
    end

    test "matches case-insensitively" do
      assert RequestContext.embedded_user_agent?(with_user_agent("Mozilla/5.0 fban/FBIOS"))
      assert RequestContext.embedded_user_agent?(with_user_agent("Mozilla/5.0 MICROMESSENGER/8.0"))
    end

    test "does not flag the system browsers a native app is supposed to use" do
      for user_agent <- [
            # Mobile Safari on iOS.
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 " <>
              "(KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
            # Chrome on iOS - a WebKit shell, but a browser: it keeps Safari/.
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 " <>
              "(KHTML, like Gecko) CriOS/119.0.6045.109 Mobile/15E148 Safari/604.1",
            # Firefox on iOS.
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 " <>
              "(KHTML, like Gecko) FxiOS/119.0 Mobile/15E148 Safari/605.1.15",
            # Chrome on Android, including a Custom Tab (same UA, no `wv`).
            "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) " <>
              "Chrome/119.0.0.0 Mobile Safari/537.36",
            # Desktop browsers.
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) " <>
              "Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0"
          ] do
        refute RequestContext.embedded_user_agent?(with_user_agent(user_agent)),
               "expected #{user_agent} to pass as an external user agent"
      end
    end

    test "an absent or empty User-Agent is not treated as embedded" do
      refute RequestContext.embedded_user_agent?(build_conn(:get, "/oauth/authorize"))
      refute RequestContext.embedded_user_agent?(with_user_agent(""))
    end

    # X-Requested-With is set by Android webviews AND by some Custom Tabs
    # implementations, so keying on it would refuse the arrangement RFC 8252
    # recommends. It is deliberately ignored.
    test "X-Requested-With alone is not evidence" do
      conn =
        build_conn(:get, "/oauth/authorize",
          headers: [
            {"user-agent",
             "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) " <>
               "Chrome/119.0.0.0 Mobile Safari/537.36"},
            {"x-requested-with", "com.example.app"}
          ]
        )

      refute RequestContext.embedded_user_agent?(conn)
    end
  end

  describe "check_embedded_user_agent/2 (RFC 8252 §8.12)" do
    @webview "Mozilla/5.0 (Linux; Android 13; Pixel 7 Build/TQ3A; wv) AppleWebKit/537.36 " <>
               "(KHTML, like Gecko) Version/4.0 Chrome/119.0.0.0 Mobile Safari/537.36"

    test "is off by default, so a webview request passes" do
      assert RequestContext.check_embedded_user_agent(with_user_agent(@webview), config()) == :ok
    end

    test "refuses a webview request once the host opts in" do
      cfg = config(native_apps: [reject_embedded_user_agents: true])

      assert RequestContext.check_embedded_user_agent(with_user_agent(@webview), cfg) ==
               {:error, :embedded_user_agent}
    end

    test "an external user agent passes with the check enabled" do
      cfg = config(native_apps: [reject_embedded_user_agents: true])

      user_agent =
        "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) " <>
          "Chrome/119.0.0.0 Mobile Safari/537.36"

      assert RequestContext.check_embedded_user_agent(with_user_agent(user_agent), cfg) == :ok
    end

    test "enabling the loopback redirect exception does not enable this check" do
      cfg = config(native_apps: [loopback_redirect: true])

      assert RequestContext.check_embedded_user_agent(with_user_agent(@webview), cfg) == :ok
    end
  end
end
