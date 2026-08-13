defmodule AttestoPhoenix.RequestContext do
  @moduledoc """
  Neutral request-fact helpers the OAuth 2.0 / OIDC flows derive from a `Plug.Conn`.

  Authorization-server endpoints need a handful of transport-level facts that are
  not safe to read straight off the `Plug.Conn` when the listener sits behind a
  reverse proxy:

    * the **client IP**, honoring `X-Forwarded-For` only for trusted proxies;
    * whether the request effectively arrived over **HTTPS** (RFC 8446), honoring
      a trusted `X-Forwarded-Proto: https` hop;
    * the canonical request **URL** (`htu`) and **method** (`htm`) a DPoP proof is
      bound to, per RFC 9449 §4.2 / §4.3;
    * the peer **certificate DER** presented at the TLS layer, used for the
      RFC 8705 §3 mutual-TLS `cnf` binding;
    * whether the request appears to come from an **embedded user agent**
      (an in-app webview), which RFC 8252 §8.12 recommends refusing at the
      authorization endpoint.

  Every forwarded-header-derived fact is gated on a trusted-proxy allowlist. A
  request that arrives from a peer outside that allowlist with forged
  `X-Forwarded-*` headers is a spoofing attempt: the headers are dropped and the
  fact is derived from the direct connection only. This is fail-closed by
  construction, an untrusted peer cannot assert `https`, cannot redirect the
  DPoP `htu`, and cannot forge a client IP.

  The trust boundary, the HTTPS requirement, and the optional certificate
  extractor are read from `AttestoPhoenix.Config`; this module never hardcodes
  deployment policy.

  ## Trusted-proxy allowlist

  `config.trusted_proxies` controls whether `X-Forwarded-*` headers are honored.
  It accepts a list whose elements are any of:

    * `:loopback` - matches `127.0.0.0/8` and `::1`.
    * `:any` - matches every peer. Only safe when another mechanism (firewall,
      ingress ACL) guarantees that only the proxy can reach the app port. Prefer
      explicit CIDRs.
    * an IP tuple (`{10, 0, 0, 1}` / an 8-element IPv6 tuple) - exact match.
    * a binary CIDR string (`"10.0.0.0/8"`, `"::1/128"`) - subnet match.

  The default (`[]`) trusts no proxy, so forwarded headers are never honored
  unless the host opts in.
  """

  alias AttestoPhoenix.Callback
  alias AttestoPhoenix.Config

  # RFC 9449 §4.3: `htu` is the HTTP target URI of the request to which the DPoP
  # proof is attached, without query or fragment. The scheme/host/port that make
  # up that URI are the client-observed values, which behind a TLS-terminating
  # proxy live in the forwarded headers rather than on the inter-proxy hop.
  @forwarded_proto_header "x-forwarded-proto"
  @forwarded_host_header "x-forwarded-host"
  @forwarded_port_header "x-forwarded-port"
  @forwarded_for_header "x-forwarded-for"

  # IANA default ports per scheme; omitted from the canonical authority so the
  # `htu` matches what a client built from a bare `https://host/path` URL.
  @https_default_port 443
  @http_default_port 80

  @user_agent_header "user-agent"

  # RFC 8252 §8.12: substrings that identify a request as coming from an
  # embedded user agent (an in-app webview) rather than the system browser.
  # Matched case-insensitively against the `User-Agent`. Two kinds of marker:
  # the platform webview tokens, and the product tokens well-known applications
  # add to their in-app browser.
  #
  # This list is a heuristic, not a specification. It cannot be complete (any
  # application may ship a webview with an unmodified UA) and it can be wrong
  # (a UA string is client-supplied and freely spoofable in both directions),
  # which is why the check it backs is opt-in.
  # Markers distinctive enough to match anywhere in the string.
  @embedded_user_agent_markers [
    # Android System WebView adds the `wv` platform token (Chrome 42+).
    "; wv)",
    "; wv;",
    # Desktop application shells that embed Chromium directly.
    "electron/",
    # Product tokens for widely deployed in-app browsers. Each of these renders
    # the authorization page inside the host application's process, which is
    # exactly the arrangement §8.12 warns about.
    "fban/",
    "fbav/",
    "fb_iab",
    "micromessenger",
    "twitterandroid",
    "twitter for i",
    "bytedancewebview",
    "musical_ly",
    "whatsapp/",
    "telegram",
    "linkedinapp"
  ]

  # Markers short or generic enough that a bare substring test would collide
  # with unrelated product tokens - `line/` inside `Streamline/`, `snapchat` or
  # `instagram` inside an arbitrary vendor string. Matched only at a token
  # boundary: the start of the User-Agent, or immediately after a space.
  @embedded_user_agent_tokens [
    "line/",
    "instagram",
    "snapchat",
    "reddit/",
    "pinterest"
  ]

  # `GSA/` (the Google App on iOS/Android) is deliberately NOT a marker. The
  # Google App hands external links to an in-app browser tab rather than a
  # webview it can inspect, which is the very arrangement RFC 8252 §8.1
  # recommends - so matching it would refuse the correct behavior.

  # An iOS in-app webview (WKWebView) renders with WebKit and reports a
  # `Mobile/<build>` token, but - unlike Safari and every third-party iOS
  # browser, which are WebKit shells and keep the token - omits `Safari/`.
  # Absence of `Safari/` alongside those two is the standard signal, and it is
  # the only structural (rather than product-name) rule here.
  @ios_webkit_marker "applewebkit"
  @ios_mobile_marker "mobile/"
  @ios_browser_marker "safari/"

  @loopback_v4_cidr {{127, 0, 0, 0}, 8}
  @loopback_v6 {0, 0, 0, 0, 0, 0, 0, 1}

  @max_port 65_535

  @doc """
  Returns the client IP as a string, or `nil` if it cannot be determined.

  When the request comes from a trusted proxy and carries `X-Forwarded-For`, the
  left-most entry (the original client per RFC 7239 / the de-facto
  `X-Forwarded-For` convention) is returned. Otherwise the direct connection's
  adapter-reported socket peer address is used. An untrusted peer cannot forge
  the client IP this way: its `X-Forwarded-For` is ignored entirely, and a
  middleware-rewritten `conn.remote_ip` is not authoritative.
  """
  @spec client_ip(Plug.Conn.t(), Config.t()) :: String.t() | nil
  def client_ip(%Plug.Conn{} = conn, %Config{} = config) do
    forwarded =
      if from_trusted_proxy?(conn, config) do
        first_forwarded_for(conn)
      end

    case forwarded do
      ip when is_binary(ip) -> ip
      _ -> socket_peer_ip_string(conn)
    end
  end

  @doc """
  Returns `true` when the request effectively arrived over HTTPS.

  The effective scheme is the connection scheme, upgraded to `https` when a
  trusted proxy forwards `X-Forwarded-Proto: https`. An untrusted peer's
  forwarded scheme is ignored, so a plain-HTTP hop cannot masquerade as TLS.
  """
  @spec https?(Plug.Conn.t(), Config.t()) :: boolean()
  def https?(%Plug.Conn{} = conn, %Config{} = config) do
    effective_scheme(conn, config) == "https"
  end

  @doc """
  Returns `:ok` when the request satisfies the configured transport policy, or
  `{:error, :insecure_transport}` when `config.require_https` is set and the
  request did not effectively arrive over HTTPS.

  This is the fail-closed transport check the token and protected-resource
  endpoints run before touching a credential: a bearer token or client secret
  that has already crossed a plain-HTTP hop must be treated as compromised, so
  the request is refused rather than served or redirected (a redirect would have
  the client replay the exposed credential).
  """
  @spec check_https(Plug.Conn.t(), Config.t()) :: :ok | {:error, :insecure_transport}
  def check_https(%Plug.Conn{} = conn, %Config{} = config) do
    if config.require_https and not https?(conn, config) do
      {:error, :insecure_transport}
    else
      :ok
    end
  end

  @doc """
  Returns `true` when the request's `User-Agent` looks like an embedded user
  agent - an in-app webview - rather than the system browser (RFC 8252 §8.12).

  §8.12 recommends that an authorization server not permit an embedded user
  agent for the authorization request: the application hosting the webview can
  read the page's DOM, inject scripts, and capture keystrokes, so the user's
  credentials are exposed to the very party the authorization is meant to
  constrain. The native-app remedy is an external user agent - the system
  browser, an in-app browser tab (`SFSafariViewController` /
  Android Custom Tabs) - which the host application cannot inspect.

  ## This is a heuristic

  The `User-Agent` is client-supplied and unauthenticated. A webview can send
  any string, so this check is trivially evaded by an attacker who wants to; and
  because it matches on product tokens and platform quirks it will
  misclassify some honest browsers. It is therefore a defense-in-depth hint,
  never a security boundary, and the enforcement it backs is off by default (see
  `check_embedded_user_agent/2`).

  Both error directions are real and known:

    * **False negatives.** Any Android webview whose host app calls
      `setUserAgentString/1` and drops the `wv` token is missed, as is any
      in-app browser whose product token is not on the list. The list names the
      largest ones; it cannot be complete.
    * **False positives.** An iOS web app launched from the home screen
      (standalone display mode) is indistinguishable from a WKWebView by
      `User-Agent` and is flagged. Deployments serving such an app should leave
      this off.

  Only the `User-Agent` is consulted. `X-Requested-With` is deliberately
  ignored: Android webviews set it to the host application's package name, but
  so have some Custom Tabs implementations, and Custom Tabs is precisely the
  RFC 8252 §8.1-recommended arrangement - keying on that header would refuse the
  behavior the RFC asks for.

  A request with no `User-Agent` is not treated as embedded: absence is not
  evidence, and refusing it would break non-browser callers.
  """
  @spec embedded_user_agent?(Plug.Conn.t()) :: boolean()
  def embedded_user_agent?(%Plug.Conn{} = conn) do
    case first_header(conn, @user_agent_header) do
      value when is_binary(value) and value != "" ->
        user_agent = String.downcase(value)

        Enum.any?(@embedded_user_agent_markers, &String.contains?(user_agent, &1)) or
          Enum.any?(@embedded_user_agent_tokens, &token_present?(user_agent, &1)) or
          ios_webview?(user_agent)

      _ ->
        false
    end
  end

  @doc """
  Returns `:ok` when the request satisfies the configured embedded-user-agent
  policy, or `{:error, :embedded_user_agent}` when the host has enabled
  `native_apps: [reject_embedded_user_agents: true]` and the request looks like
  it came from an in-app webview (RFC 8252 §8.12).

  Returns `:ok` unconditionally when the flag is off, which is the default. The
  caller reports the failure directly to the user agent - there is no trusted
  `redirect_uri` at this point, and redirecting the flow onward inside the
  webview would defeat the purpose of refusing it.

  This applies to the front-channel authorization request only. The PAR and
  token endpoints are back-channel calls from the client itself, where no user
  agent is involved and the `User-Agent` carries no such meaning.
  """
  @spec check_embedded_user_agent(Plug.Conn.t(), Config.t()) :: :ok | {:error, :embedded_user_agent}
  def check_embedded_user_agent(%Plug.Conn{} = conn, %Config{} = config) do
    if Config.reject_embedded_user_agents?(config) and embedded_user_agent?(conn) do
      {:error, :embedded_user_agent}
    else
      :ok
    end
  end

  # A marker at a token boundary: at the very start, or immediately after a
  # space. Keeps `line/` from matching inside `Streamline/`.
  defp token_present?(user_agent, marker) do
    String.starts_with?(user_agent, marker) or String.contains?(user_agent, " " <> marker)
  end

  # WebKit + a `Mobile/` build token but no `Safari/` product token: an iOS
  # WKWebView. Safari and every third-party iOS browser (which are all WebKit
  # shells) keep `Safari/`, so its absence distinguishes an app-hosted webview
  # from a browser.
  #
  # KNOWN FALSE POSITIVE: an iOS web app launched from the home screen
  # (standalone/PWA display mode) reports the same shape - WebKit and `Mobile/`
  # with no `Safari/` - and is flagged. The two are genuinely indistinguishable
  # by User-Agent, which is part of why this whole check is opt-in.
  defp ios_webview?(user_agent) do
    String.contains?(user_agent, @ios_webkit_marker) and
      String.contains?(user_agent, @ios_mobile_marker) and
      not String.contains?(user_agent, @ios_browser_marker)
  end

  @doc """
  Returns the HTTP method (`htm`) the DPoP proof is bound to, per RFC 9449 §4.2.

  The method is taken verbatim from the request; it is not derived from any
  forwarded header.
  """
  @spec http_method(Plug.Conn.t()) :: String.t()
  def http_method(%Plug.Conn{method: method}), do: method

  @doc """
  Returns the canonical request URL (`htu`) the DPoP proof is bound to, per
  RFC 9449 §4.3: the request URI without its query or fragment.

  When `config.htu` is set, that callback is used so a host can fully override
  URL reconstruction (e.g. for a proxy topology this module does not model).
  Otherwise the URL is built from the effective scheme/host/port, which honor
  `X-Forwarded-Proto` / `X-Forwarded-Host` / `X-Forwarded-Port` only when the
  request comes from a trusted proxy. An untrusted peer therefore cannot
  redirect the `htu` check by injecting forwarded headers: the URL falls back to
  the direct connection's authority and the proof either verifies against the
  real listener URL or fails on its signature.
  """
  @spec canonical_url(Plug.Conn.t(), Config.t()) :: String.t()
  def canonical_url(%Plug.Conn{} = conn, %Config{htu: htu} = config) when not is_nil(htu) do
    Callback.invoke(htu, [conn]) || canonical_url(conn, %{config | htu: nil})
  end

  def canonical_url(%Plug.Conn{} = conn, %Config{} = config) do
    trusted? = from_trusted_proxy?(conn, config)
    scheme = effective_scheme(conn, config)
    {direct_host, direct_port} = direct_authority(conn, scheme)
    host = (trusted? && forwarded_host(conn)) || direct_host
    port = (trusted? && forwarded_port(conn)) || direct_port

    authority =
      if default_port?(scheme, port) do
        host
      else
        "#{host}:#{port}"
      end

    "#{scheme}://#{authority}#{conn.request_path}"
  end

  @doc """
  Returns the peer certificate DER for the RFC 8705 §3 mutual-TLS `cnf` binding,
  or `nil` when no client certificate was presented.

  Direct TLS peer data wins. Configured certificate callbacks are consulted
  only for an immediate socket peer in `:trusted_proxies`. The legacy
  `:cert_der` callback remains as a gated compatibility alias for deployments
  that previously used it to read a terminator header; new deployments use
  `:forwarded_cert_der`.
  """
  @spec cert_der(Plug.Conn.t(), Config.t()) :: binary() | nil
  def cert_der(%Plug.Conn{} = conn, %Config{} = config) do
    case direct_peer_certificate(conn) || forwarded_client_certificate_der(conn, config) ||
           legacy_forwarded_certificate_der(conn, config) do
      der when is_binary(der) -> der
      nil -> nil
    end
  end

  @typedoc "Authenticated client-certificate transport facts for RFC 8705 §2."
  @type client_certificate :: %{
          der: binary(),
          source: :tls_socket | :trusted_terminator,
          proof_of_possession: true,
          chain_validated: boolean()
        }

  @doc """
  Return an authenticated client certificate for RFC 8705 §2, or `nil`.

  A certificate surfaced directly by the TLS adapter is accepted as proof that
  the peer completed CertificateVerify. A certificate forwarded by a TLS
  terminator is accepted only when the immediate peer matches
  `config.trusted_proxies`; the `:forwarded_cert_der` callback is never invoked
  for an untrusted peer. This prevents a public client from forging an
  XFCC-style header and turning it into an OAuth credential.

  PKI trust is a separate fact. `:client_certificate_chain_validated?` must
  explicitly return `true` for `tls_client_auth`; absence or any other return is
  fail-closed. `self_signed_tls_client_auth` authenticates against the client's
  registered `x5c` certificate and does not require PKI chain validation.
  """
  @spec client_certificate(Plug.Conn.t(), Config.t()) :: client_certificate() | nil
  def client_certificate(%Plug.Conn{} = conn, %Config{} = config) do
    case direct_peer_certificate(conn) do
      der when is_binary(der) -> certificate_context(conn, config, der, :tls_socket)
      nil -> forwarded_client_certificate(conn, config)
    end
  end

  @doc false
  @spec client_auth_headers(Plug.Conn.t(), Config.t()) :: map()
  def client_auth_headers(%Plug.Conn{} = conn, %Config{} = config) do
    %{
      authorization: Plug.Conn.get_req_header(conn, "authorization"),
      oauth_client_attestation: Plug.Conn.get_req_header(conn, "oauth-client-attestation"),
      oauth_client_attestation_pop: Plug.Conn.get_req_header(conn, "oauth-client-attestation-pop"),
      client_certificate: client_certificate(conn, config)
    }
  end

  defp direct_peer_certificate(conn) do
    case Plug.Conn.get_peer_data(conn) do
      %{ssl_cert: der} when is_binary(der) and byte_size(der) > 0 -> der
      _other -> nil
    end
  rescue
    _ -> nil
  end

  defp forwarded_client_certificate(conn, config) do
    case forwarded_client_certificate_der(conn, config) do
      der when is_binary(der) -> certificate_context(conn, config, der, :trusted_terminator)
      nil -> nil
    end
  end

  defp forwarded_client_certificate_der(conn, config) do
    if from_trusted_proxy?(conn, config) and not is_nil(config.forwarded_cert_der) do
      case Callback.invoke(config.forwarded_cert_der, [conn]) do
        der when is_binary(der) and byte_size(der) > 0 -> der
        _other -> nil
      end
    end
  end

  defp legacy_forwarded_certificate_der(conn, config) do
    if from_trusted_proxy?(conn, config) and not is_nil(config.cert_der) do
      case Callback.invoke(config.cert_der, [conn]) do
        der when is_binary(der) and byte_size(der) > 0 -> der
        _other -> nil
      end
    end
  end

  defp certificate_context(conn, config, der, source) do
    chain_validated =
      case config.client_certificate_chain_validated? do
        nil -> false
        callback -> Callback.invoke(callback, [conn, der]) == true
      end

    %{
      der: der,
      source: source,
      proof_of_possession: true,
      chain_validated: chain_validated
    }
  end

  @doc """
  Returns `true` when the adapter-reported socket peer address falls inside
  `config.trusted_proxies`.

  This is the single trust gate that governs whether any `X-Forwarded-*` header
  is honored. It is exposed so callers that need a custom forwarded-header read
  can apply the same boundary rather than re-implementing it and risking drift.
  """
  @spec from_trusted_proxy?(Plug.Conn.t(), Config.t()) :: boolean()
  def from_trusted_proxy?(%Plug.Conn{} = conn, %Config{trusted_proxies: proxies}) do
    # A connection with no resolved peer address is never trusted: there is no
    # IP to test against the allowlist, so it fails closed. `conn.remote_ip` is
    # intentionally not authoritative here: middleware may rewrite that plain
    # struct field from an untrusted X-Forwarded-For header.
    ip = conn |> socket_peer_ip() |> normalize_peer_ip()
    is_tuple(ip) and Enum.any?(List.wrap(proxies), &peer_matches?(ip, &1))
  end

  defp socket_peer_ip(conn) do
    %{address: address} = Plug.Conn.get_peer_data(conn)
    address
  rescue
    _ -> nil
  end

  # A dual-stack IPv6 listener (e.g. an app bound on `::` behind a reverse proxy
  # that reaches it over an IPv4 bridge network, the common Docker / Kamal
  # topology) surfaces the proxy's IPv4 peer as an IPv4-mapped IPv6 address
  # `::ffff:a.b.c.d` (`{0, 0, 0, 0, 0, 0xFFFF, g, h}`). Fold it back to its IPv4
  # 4-tuple so it matches an IPv4 CIDR allowlist (e.g. `172.16.0.0/12`); without
  # this the 8-tuple peer never matches a 4-tuple network and a legitimately
  # proxied HTTPS request is misread as plain HTTP and refused.
  defp normalize_peer_ip({0, 0, 0, 0, 0, 0xFFFF, g, h}) do
    {Bitwise.bsr(g, 8), Bitwise.band(g, 0xFF), Bitwise.bsr(h, 8), Bitwise.band(h, 0xFF)}
  end

  defp normalize_peer_ip(ip), do: ip

  # ----- effective scheme -----

  defp effective_scheme(conn, config) do
    trusted? = from_trusted_proxy?(conn, config)
    forwarded = trusted? && forwarded_scheme(conn)

    case forwarded do
      scheme when is_binary(scheme) -> scheme
      _ -> direct_scheme(conn, trusted?)
    end
  end

  # Plug.RewriteOn can mutate conn.scheme from X-Forwarded-Proto before this
  # module runs. For an untrusted socket peer that supplied that header, recover
  # the direct transport fact from adapter SSL data instead of accepting the
  # rewritten struct field. Without a forwarded header, conn.scheme remains the
  # adapter's normal direct-transport value.
  defp direct_scheme(conn, false) do
    if is_binary(first_header(conn, @forwarded_proto_header)) do
      if direct_tls?(conn), do: "https", else: "http"
    else
      Atom.to_string(conn.scheme)
    end
  end

  defp direct_scheme(conn, true), do: Atom.to_string(conn.scheme)

  defp direct_tls?(conn) do
    case Plug.Conn.get_ssl_data(conn) do
      nil -> is_binary(Map.get(Plug.Conn.get_peer_data(conn), :ssl_cert))
      _ssl_data -> true
    end
  rescue
    _ -> false
  end

  # ----- forwarded-header parsing -----

  # `X-Forwarded-For` is a comma-separated chain of proxied-through IPs; the
  # left-most entry is the original client. Only consulted for trusted peers.
  defp first_forwarded_for(conn) do
    conn
    |> first_header(@forwarded_for_header)
    |> case do
      value when is_binary(value) ->
        value
        |> String.split(",", parts: 2)
        |> List.first()
        |> String.trim()
        |> nil_if_empty()

      _ ->
        nil
    end
  end

  defp forwarded_scheme(conn) do
    conn
    |> first_forwarded_token(@forwarded_proto_header)
    |> case do
      value when is_binary(value) -> String.downcase(value)
      _ -> nil
    end
  end

  defp forwarded_host(conn), do: first_forwarded_token(conn, @forwarded_host_header)

  defp forwarded_port(conn) do
    conn
    |> first_forwarded_token(@forwarded_port_header)
    |> case do
      value when is_binary(value) ->
        case Integer.parse(value) do
          {port, ""} when port > 0 and port <= @max_port -> port
          _ -> nil
        end

      _ ->
        nil
    end
  end

  # A forwarded header may itself be a comma-separated chain when multiple
  # proxies appended values; take the left-most (closest to the client) token.
  defp first_forwarded_token(conn, header) do
    conn
    |> first_header(header)
    |> case do
      value when is_binary(value) ->
        value
        |> String.split(",", parts: 2)
        |> List.first()
        |> String.trim()
        |> nil_if_empty()

      _ ->
        nil
    end
  end

  defp first_header(conn, header) do
    case Plug.Conn.get_req_header(conn, header) do
      [value | _] -> value
      _ -> nil
    end
  end

  defp nil_if_empty(""), do: nil
  defp nil_if_empty(value), do: value

  # ----- authority helpers -----

  # The raw Host header is not modified by Plug.RewriteOn, whereas conn.host
  # and conn.port may already reflect attacker-supplied forwarded headers. A
  # valid raw authority therefore wins; the struct fields remain the fallback
  # for adapters/tests that do not retain Host in req_headers.
  defp direct_authority(conn, scheme) do
    case first_header(conn, "host") do
      host_header when is_binary(host_header) and host_header != "" ->
        case URI.parse("#{scheme}://#{host_header}") do
          %URI{host: host, port: port, userinfo: nil, path: nil, query: nil, fragment: nil}
          when is_binary(host) and is_integer(port) ->
            {host, port}

          _other ->
            {conn.host, conn.port}
        end

      _other ->
        {conn.host, conn.port}
    end
  end

  defp default_port?("https", @https_default_port), do: true
  defp default_port?("http", @http_default_port), do: true
  defp default_port?(_scheme, _port), do: false

  defp socket_peer_ip_string(%Plug.Conn{} = conn) do
    case socket_peer_ip(conn) do
      nil ->
        nil

      peer_ip ->
        case :inet.ntoa(peer_ip) do
          {:error, _} -> nil
          charlist -> List.to_string(charlist)
        end
    end
  rescue
    _ -> nil
  end

  # ----- trusted-proxy matching -----

  defp peer_matches?(_remote_ip, :any), do: true

  defp peer_matches?(remote_ip, :loopback) do
    cidr_contains?(@loopback_v4_cidr, remote_ip) or remote_ip == @loopback_v6
  end

  defp peer_matches?(remote_ip, ip) when is_tuple(ip), do: remote_ip == ip

  defp peer_matches?(remote_ip, cidr) when is_binary(cidr) do
    case parse_cidr(cidr) do
      {:ok, parsed} -> cidr_contains?(parsed, remote_ip)
      :error -> false
    end
  end

  defp peer_matches?(_remote_ip, _other), do: false

  # Parse `"<address>/<prefix>"` into `{network_tuple, prefix_len}`. An address
  # with no `/` is treated as a host route (full-length prefix). A malformed
  # entry returns `:error` and is treated as "does not match" rather than
  # raising; misconfiguration must not crash request handling, and a non-match
  # is the fail-closed outcome (the peer is not trusted).
  defp parse_cidr(cidr) do
    case String.split(cidr, "/", parts: 2) do
      [address, prefix] ->
        with {:ok, ip} <- parse_address(address),
             {prefix_len, ""} <- Integer.parse(prefix),
             true <- valid_prefix?(ip, prefix_len) do
          {:ok, {ip, prefix_len}}
        else
          _ -> :error
        end

      [address] ->
        case parse_address(address) do
          {:ok, ip} -> {:ok, {ip, full_prefix(ip)}}
          :error -> :error
        end
    end
  end

  defp parse_address(address) do
    case :inet.parse_address(String.to_charlist(address)) do
      {:ok, ip} -> {:ok, ip}
      {:error, _} -> :error
    end
  end

  defp full_prefix(ip) when tuple_size(ip) == 4, do: 32
  defp full_prefix(ip) when tuple_size(ip) == 8, do: 128

  defp valid_prefix?(ip, prefix_len) when tuple_size(ip) == 4, do: prefix_len in 0..32

  defp valid_prefix?(ip, prefix_len) when tuple_size(ip) == 8, do: prefix_len in 0..128

  # Containment by integer masking. The network and the candidate must be the
  # same address family (both IPv4 or both IPv6) to match; an IPv4 peer never
  # matches an IPv6 CIDR or vice versa.
  defp cidr_contains?({network, prefix_len}, candidate) when tuple_size(network) == tuple_size(candidate) do
    mask = bitmask(full_prefix(network), prefix_len)
    Bitwise.band(ip_to_integer(network), mask) == Bitwise.band(ip_to_integer(candidate), mask)
  end

  defp cidr_contains?(_network, _candidate), do: false

  # All host bits cleared: a `prefix_len`-bit network mask over a `total_bits`
  # address space.
  defp bitmask(total_bits, prefix_len) do
    host_bits = total_bits - prefix_len
    Bitwise.bsl(Bitwise.bsl(1, prefix_len) - 1, host_bits)
  end

  defp ip_to_integer(ip) when tuple_size(ip) == 4 do
    ip
    |> Tuple.to_list()
    |> Enum.reduce(0, fn octet, acc -> acc * 256 + octet end)
  end

  defp ip_to_integer(ip) when tuple_size(ip) == 8 do
    ip
    |> Tuple.to_list()
    |> Enum.reduce(0, fn group, acc -> acc * 65_536 + group end)
  end
end
