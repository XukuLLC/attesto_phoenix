if Code.ensure_loaded?(Req) do
  defmodule AttestoPhoenix.SSRFGuard do
    @moduledoc """
    Screen an outbound server-to-server URL against SSRF and pin the socket to a
    checked IP.

    URLs a client registers and the authorization server then fetches or POSTs to
    (Back-Channel Logout `backchannel_logout_uri`, CIBA ping
    `client_notification_endpoint`) can point at internal hosts
    (`169.254.169.254`, RFC 1918, loopback, ...). `screen/2` resolves the host,
    rejects any special-use address (RFC 6890 - reusing the CIMD fetcher's
    single-source-of-truth `special_use_ip?/1`), and returns the URL rewritten to
    dial the CHECKED IP plus the original host. Callers connect to that IP while
    keeping TLS SNI, certificate-hostname verification, and the `Host` header on
    the original name via Mint's `connect_options: [hostname: host]` - which is
    what closes the DNS-rebinding TOCTOU between the check and the connect. A
    registration-time check alone is rebind-defeatable; this is the load-bearing
    connect-time screen.

    `Req` is an optional dependency; this module exists only when it is present.

    ## Known limitation — network-specific NAT64

    The well-known NAT64 prefix `64:ff9b::/96` is screened (its embedded IPv4 is
    unwrapped and re-checked). RFC 6052 also allows a network-specific NAT64
    prefix of the operator's choosing, which is indistinguishable from ordinary
    global IPv6 without knowing that prefix. An AS that runs its own NAT64 and
    lets clients register hostnames resolving into it MUST NOT rely on this guard
    alone for that path - restrict egress at the network layer.
    """

    alias AttestoPhoenix.ClientIdMetadata.Fetcher.Req, as: CIMDFetcher

    @typedoc """
    A screened target. `url` dials the checked IP; `host` is the bare hostname
    for TLS SNI / certificate verification (`connect_options: [hostname: host]`);
    `authority` is the original `host[:port]` (IPv6 bracketed) for the `Host`
    header.
    """
    @type screened :: %{url: String.t(), host: String.t(), authority: String.t()}

    @doc """
    Screen `url`. On success returns `{:ok, %{url: <url with host replaced by the
    checked IP>, host: <bare hostname>, authority: <host[:port]>}}`; the caller
    MUST connect with `connect_options: [hostname: host]` and send
    `{"host", authority}` so TLS/SNI/cert and the Host header stay on the real
    name (with its port) while the socket targets the checked IP.

    `{:error, reason}` when the scheme is not `https`, the host does not resolve,
    or any resolved address is special-use (RFC 6890).

    Options:

      * `:resolver` - a
        `(charlist, :inet | :inet6 -> {:ok, [:inet.ip_address()]} | {:error, term})`
        resolver (defaults to `:inet.getaddrs/2`), injected by tests.
      * `:allow_loopback` - dev/test escape hatch (default `false`). When `true`,
        loopback addresses are permitted and `http` is accepted, so delivery can
        target a local test server. Every OTHER special-use range stays blocked.
        MUST stay off in production.
    """
    @spec screen(String.t(), keyword()) :: {:ok, screened()} | {:error, term()}
    def screen(url, opts \\ []) when is_binary(url) and is_list(opts) do
      allow_loopback = allow_loopback!(opts)

      with {:ok, uri} <- validate(url, allow_loopback),
           {:ok, ips} <- resolve(uri.host, opts),
           {:ok, pinned} <- pin(ips, allow_loopback) do
        {:ok,
         %{
           url: URI.to_string(%{uri | host: url_host(pinned)}),
           host: uri.host,
           authority: authority(uri)
         }}
      end
    end

    defp allow_loopback!(opts) do
      case Keyword.get(opts, :allow_loopback, false) do
        value when is_boolean(value) ->
          value

        _unexpected ->
          raise ArgumentError, ":allow_loopback must be true or false"
      end
    end

    # Put the checked IP into the request URL. `URI.to_string/1` brackets a
    # colon-containing (IPv6) host itself; the original port is preserved by
    # leaving `uri.port` untouched.
    defp url_host(ip), do: ip_to_string(ip)

    # The Host header the RP expects: original host, its port when non-default,
    # IPv6 bracketed (RFC 7230). Dropping the port misroutes an RP that routes on
    # the full authority.
    defp authority(%URI{host: host, port: port, scheme: scheme}) do
      host_part = if String.contains?(host, ":"), do: "[" <> host <> "]", else: host

      if default_port?(scheme, port), do: host_part, else: host_part <> ":" <> Integer.to_string(port)
    end

    defp default_port?("https", 443), do: true
    defp default_port?("http", 80), do: true
    defp default_port?(_scheme, _port), do: false

    defp validate(url, allow_loopback) do
      case URI.new(url) do
        {:ok, %URI{scheme: scheme, host: host} = uri}
        when is_binary(host) and host != "" and (scheme == "https" or (allow_loopback and scheme == "http")) ->
          {:ok, uri}

        {:ok, _uri} ->
          {:error, :insecure_or_hostless_url}

        {:error, _reason} ->
          {:error, :invalid_url}
      end
    end

    # Resolve both A and AAAA; every returned address is screened so a mixed
    # answer cannot smuggle an internal address in via the unused family.
    defp resolve(host, opts) do
      resolver = Keyword.get(opts, :resolver, &:inet.getaddrs/2)
      host_charlist = String.to_charlist(host)

      case lookup(resolver, host_charlist, :inet) ++ lookup(resolver, host_charlist, :inet6) do
        [] -> {:error, :unresolvable}
        ips -> {:ok, ips}
      end
    end

    defp lookup(resolver, host_charlist, family) do
      case resolver.(host_charlist, family) do
        {:ok, ips} when is_list(ips) -> ips
        _other -> []
      end
    end

    # Reject if ANY resolved address is special-use; otherwise pin to the first.
    # In production loopback is special-use and blocked; the `:allow_loopback`
    # escape hatch exempts only loopback (every other range stays blocked).
    defp pin(ips, allow_loopback) do
      case Enum.find(ips, &blocked?(&1, allow_loopback)) do
        nil -> {:ok, hd(ips)}
        blocked -> {:error, {:blocked_ip, blocked}}
      end
    end

    defp blocked?(ip, true), do: not loopback?(ip) and CIMDFetcher.special_use_ip?(ip)
    defp blocked?(ip, false), do: CIMDFetcher.special_use_ip?(ip)

    defp loopback?({127, _b, _c, _d}), do: true
    defp loopback?({0, 0, 0, 0, 0, 0, 0, 1}), do: true
    # IPv4-mapped loopback (::ffff:127.0.0.0/8): high word 0x7Fxx.
    defp loopback?({0, 0, 0, 0, 0, 0xFFFF, w7, _w8}) when div(w7, 256) == 127, do: true
    defp loopback?(_ip), do: false

    defp ip_to_string(ip), do: ip |> :inet.ntoa() |> to_string()
  end
end
