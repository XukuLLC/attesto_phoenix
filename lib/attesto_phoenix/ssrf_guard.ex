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

    alias Attesto.OutboundTarget

    @typedoc """
    A screened target. `url` dials the checked IP; `host` is the bare hostname
    for TLS SNI / certificate verification (`connect_options: [hostname: host]`);
    `authority` is the original `host[:port]` (IPv6 bracketed) for the `Host`
    header.
    """
    @type screened :: OutboundTarget.screened()

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
    defdelegate screen(url, opts \\ []), to: OutboundTarget
  end
end
