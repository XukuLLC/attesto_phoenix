if Code.ensure_loaded?(Req) do
  defmodule AttestoPhoenix.ClientIdMetadata.Fetcher.Req do
    @moduledoc """
    The default, SSRF-guarded Client ID Metadata Document fetcher - CIMD
    (`draft-ietf-oauth-client-id-metadata-document-01`, IETF OAuth WG).

    This is the only component of the CIMD feature that makes an outbound request,
    so it is where the draft's Security Considerations are enforced. Implements
    `AttestoPhoenix.ClientIdMetadata.Fetcher` over `Req` -> `Finch` -> `Mint`.

    ## SSRF algorithm (draft Security Considerations)

    `fetch/2` runs the following, erroring closed at the first failure:

      1. **Re-validate** the URL is `https` and satisfies the draft §2 grammar via
         `Attesto.ClientIdMetadata.validate_client_id/1` (defense in depth - the
         caller is never trusted). Failure -> `{:error, {:invalid_url, reason}}`.
      2. **Resolve** the host to A/AAAA records through the injectable `:resolver`
         (defaults to `:inet.getaddrs/2` for both `:inet` and `:inet6`). No
         records -> `{:error, :unresolvable}`. The resolver seam lets tests inject
         addresses without real DNS, and is the hook the DNS-rebinding defense
         below pins against.
      3. **Reject special-use IPs (RFC 6890).** Every resolved address is checked
         against `special_use_ip?/1`; if any is special-use the fetch is refused
         with `{:error, {:blocked_ip, ip}}`. Loopback is permitted only when
         `:allow_loopback` is `true` (development).
      4. **Pin to a validated IP.** The request is dialed at one checked address
         (`Mint`'s `:hostname` connect option keeps TLS SNI, certificate hostname
         verification, and the `Host` header on the original hostname while the
         socket targets the pinned IP), closing the DNS-rebinding TOCTOU between
         the check in step 3 and the connect: the name cannot be re-resolved to an
         internal address after it was validated.
      5. **GET** with `Accept: application/json`, connect and receive timeouts
         (`:request_timeout_ms`, default `5_000`), and **redirects disabled**
         (draft MUST). Any redirect is surfaced as its 3xx status.
      6. **Status** must be `200`; any other status -> `{:error, {:status, n}}`.
      7. **Content-Type** must be `application/json` or `application/<x>+json`;
         otherwise `{:error, :bad_content_type}`.
      8. **Size cap.** The body is refused once it exceeds `:max_document_bytes`
         (default `5_120`) -> `{:error, :too_large}`.

    On success returns `{:ok, %{body: body, cache_control: directives}}` where
    `directives` are the parsed `Cache-Control` / `Expires` freshness hints
    (`RFC 9111`) for the caller to clamp and store.

    ## Options

      * `:resolver` - a 2-arity DNS resolver
        `(charlist_host, :inet | :inet6 -> {:ok, [:inet.ip_address()]} | {:error, term()})`.
        Defaults to `:inet.getaddrs/2`. Injected by tests to exercise the SSRF
        guard and the DNS-rebinding pin without real DNS.
      * `:allow_loopback` - when `true`, loopback addresses (`127.0.0.0/8`, `::1`)
        are permitted (the draft's "AS runs on loopback" exception). Default
        `false`.
      * `:max_document_bytes` - body size cap. Default `5_120` (draft's
        recommended 5 KB).
      * `:request_timeout_ms` - connect and receive timeout. Default `5_000`.
      * `:req_options` - extra options merged into the underlying `Req` request
        (e.g. test transport overrides). Escape hatch; not part of the public
        contract.
    """

    @behaviour AttestoPhoenix.ClientIdMetadata.Fetcher

    import Bitwise, only: [&&&: 2, >>>: 2, <<<: 2]

    alias AttestoPhoenix.ClientIdMetadata.Fetcher

    @default_max_document_bytes 5_120
    @default_request_timeout_ms 5_000

    @typedoc "A resolved IP address, as returned by `:inet.getaddrs/2`."
    @type ip :: :inet.ip_address()

    # RFC 6890 special-use IPv4 blocks (and the operationally-equivalent CGNAT
    # RFC 6598 100.64/10). Each entry is `{network_tuple, prefix_len}`; an address
    # matches when its leading `prefix_len` bits equal the network's. Multicast
    # (224/4) and the reserved/benchmarking/documentation ranges that an SSRF
    # guard must also refuse are included so the table is the single source of
    # truth - `special_use_ip?/1` consults nothing else.
    @ipv4_special_use [
      {{0, 0, 0, 0}, 8},
      {{10, 0, 0, 0}, 8},
      {{100, 64, 0, 0}, 10},
      {{127, 0, 0, 0}, 8},
      {{169, 254, 0, 0}, 16},
      {{172, 16, 0, 0}, 12},
      {{192, 0, 0, 0}, 24},
      {{192, 0, 2, 0}, 24},
      {{192, 88, 99, 0}, 24},
      {{192, 168, 0, 0}, 16},
      {{198, 18, 0, 0}, 15},
      {{198, 51, 100, 0}, 24},
      {{203, 0, 113, 0}, 24},
      {{224, 0, 0, 0}, 4},
      {{240, 0, 0, 0}, 4}
    ]

    # RFC 6890 special-use IPv6 blocks, as `{network_tuple, prefix_len}` over the
    # eight 16-bit words. `::/8` (which covers the unspecified `::`, loopback
    # `::1`, and the IPv4-mapped `::ffff:0:0/96` space) is intentionally excluded
    # here: loopback is handled separately so `:allow_loopback` can permit it, and
    # IPv4-mapped addresses are unwrapped to their embedded IPv4 and re-checked
    # against the IPv4 table by `special_use_ip?/1`.
    @ipv6_special_use [
      {{0xFC00, 0, 0, 0, 0, 0, 0, 0}, 7},
      {{0xFE80, 0, 0, 0, 0, 0, 0, 0}, 10},
      {{0xFF00, 0, 0, 0, 0, 0, 0, 0}, 8},
      # Teredo 2001:0000::/32 (RFC 4380) and ORCHIDv2 2001:20::/28 (RFC 7343), both
      # in the RFC 6890 special-purpose registry. Teredo embeds a client IPv4 in
      # its low bits, but the fetch dials the FULL IPv6 address (Teredo is not
      # routed to the embedded IPv4), so blocking the prefix outright is the right
      # guard - it never reaches a destination the IPv4 table would screen.
      {{0x2001, 0x0000, 0, 0, 0, 0, 0, 0}, 32},
      {{0x2001, 0x0020, 0, 0, 0, 0, 0, 0}, 28},
      {{0x2001, 0xDB8, 0, 0, 0, 0, 0, 0}, 32}
    ]

    @doc """
    Fetch a validated CIMD `client_id` URL under the SSRF algorithm documented on
    this module. See `AttestoPhoenix.ClientIdMetadata.Fetcher` for the contract.
    """
    @impl Fetcher
    @spec fetch(String.t(), keyword()) ::
            {:ok, Fetcher.result()} | {:error, term()}
    def fetch(url, opts \\ []) when is_binary(url) and is_list(opts) do
      with {:ok, uri} <- revalidate(url),
           {:ok, ips} <- resolve(uri.host, opts),
           {:ok, pinned} <- screen(ips, opts) do
        request(uri, pinned, opts)
      end
    end

    # Step 1: re-validate https + draft §2 grammar; never trust the caller.
    defp revalidate(url) do
      case Attesto.ClientIdMetadata.validate_client_id(url) do
        {:ok, uri} -> {:ok, uri}
        {:error, reason} -> {:error, {:invalid_url, reason}}
      end
    end

    # Step 2: resolve A and AAAA records through the injectable resolver. Both
    # families are queried; either yielding records is enough, but every returned
    # address is screened in step 3.
    defp resolve(host, opts) do
      resolver = Keyword.get(opts, :resolver, &default_resolver/2)
      host_charlist = String.to_charlist(host)

      v4 = lookup(resolver, host_charlist, :inet)
      v6 = lookup(resolver, host_charlist, :inet6)

      case v4 ++ v6 do
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

    defp default_resolver(host_charlist, family) do
      :inet.getaddrs(host_charlist, family)
    end

    # Step 3: reject if ANY resolved address is special-use; otherwise pin to the
    # first address (the connect in step 4 targets exactly this checked IP). The
    # whole resolved set is screened so a mixed A/AAAA answer cannot smuggle an
    # internal address past the guard via the unused family.
    defp screen(ips, opts) do
      allow_loopback = Keyword.get(opts, :allow_loopback, false)

      case Enum.find(ips, &blocked?(&1, allow_loopback)) do
        nil -> {:ok, hd(ips)}
        blocked -> {:error, {:blocked_ip, blocked}}
      end
    end

    defp blocked?(ip, allow_loopback) do
      if allow_loopback and loopback?(ip) do
        false
      else
        special_use_ip?(ip)
      end
    end

    @doc """
    Returns `true` iff `ip` is a special-use address (RFC 6890) an authorization
    server MUST NOT dereference for CIMD: loopback, private, link-local, CGNAT,
    `0.0.0.0/8`, multicast, the reserved/documentation ranges, the IPv6
    equivalents (`fc00::/7`, `fe80::/10`, `ff00::/8`, `::1`, `::`), and every IPv6
    form that embeds an IPv4 - IPv4-mapped (`::ffff:0:0/96`), NAT64
    (`64:ff9b::/96`), 6to4 (`2002::/16`), and IPv4-compatible (`::/96`) - which is
    unwrapped to its embedded IPv4 and re-checked, so an internal IPv4 cannot be
    smuggled past the guard through any of them.

    This is the single source of truth for the guard's CIDR table; the
    `:allow_loopback` exception is applied by the caller (`fetch/2`), not here, so
    this predicate always reports loopback as special-use.
    """
    @spec special_use_ip?(ip()) :: boolean()
    def special_use_ip?({_a, _b, _c, _d} = ip) do
      in_any?(ip, @ipv4_special_use)
    end

    def special_use_ip?({0, 0, 0, 0, 0, 0xFFFF, w7, w8}) do
      # IPv4-mapped IPv6 (::ffff:0:0/96): unwrap to the embedded IPv4 and re-check
      # so a mapped private/loopback address cannot bypass the IPv4 table.
      special_use_ip?(embedded_v4(w7, w8))
    end

    def special_use_ip?({0x0064, 0xFF9B, 0, 0, 0, 0, w7, w8}) do
      # NAT64 well-known prefix 64:ff9b::/96 (RFC 6052): embeds an IPv4 in the low
      # 32 bits. On a network with a NAT64 gateway this reaches the embedded IPv4 -
      # e.g. 64:ff9b::a9fe:a9fe -> 169.254.169.254 cloud metadata - so unwrap the
      # embedded IPv4 and re-check it against the IPv4 table.
      special_use_ip?(embedded_v4(w7, w8))
    end

    def special_use_ip?({0x0064, 0xFF9B, 0x0001, w4, w5, w6, _w7, _w8}) do
      # NAT64 local-use prefix 64:ff9b:1::/48 (RFC 8215) with the RFC 6052 §2.2 /48
      # embedding: the IPv4 sits in bits 48-63 and 72-87 (the u-octet at 64-71 is
      # skipped). Unwrap that IPv4 and re-check, so this local NAT64 prefix cannot
      # smuggle an internal IPv4 (e.g. 169.254.169.254) past the guard either.
      special_use_ip?({w4 >>> 8, w4 &&& 0xFF, w5 &&& 0xFF, w6 >>> 8})
    end

    def special_use_ip?({0x2002, w2, w3, _w4, _w5, _w6, _w7, _w8}) do
      # 6to4 2002::/16 (RFC 3056): embeds an IPv4 in bits 16..48. Unwrap that IPv4
      # and re-check so a 6to4 address cannot smuggle an internal IPv4 past the
      # guard.
      special_use_ip?(embedded_v4(w2, w3))
    end

    def special_use_ip?({0, 0, 0, 0, 0, 0, 0, 1}), do: true

    def special_use_ip?({0, 0, 0, 0, 0, 0, 0, 0}), do: true

    def special_use_ip?({0, 0, 0, 0, 0, 0, w7, w8}) do
      # IPv4-compatible IPv6 (::/96, the deprecated ::a.b.c.d form, RFC 4291):
      # unwrap the embedded IPv4 and re-check. (::1 and :: are matched above.)
      special_use_ip?(embedded_v4(w7, w8))
    end

    def special_use_ip?({_a, _b, _c, _d, _e, _f, _g, _h} = ip) do
      in_any?(ip, @ipv6_special_use)
    end

    # Unwrap the IPv4 embedded in two 16-bit IPv6 words (high word, low word) into
    # an `:inet` IPv4 tuple, for the IPv6 forms that carry an IPv4 (mapped, NAT64,
    # 6to4, IPv4-compatible).
    defp embedded_v4(hi, lo), do: {hi >>> 8, hi &&& 0xFF, lo >>> 8, lo &&& 0xFF}

    defp loopback?({127, _b, _c, _d}), do: true
    defp loopback?({0, 0, 0, 0, 0, 0, 0, 1}), do: true
    defp loopback?({0, 0, 0, 0, 0, 0xFFFF, w7, _w8}) when w7 >>> 8 == 127, do: true
    defp loopback?(_ip), do: false

    defp in_any?(ip, table) do
      Enum.any?(table, fn {network, prefix_len} -> in_cidr?(ip, network, prefix_len) end)
    end

    # Bit-width per element: IPv4 is four 8-bit octets, IPv6 is eight 16-bit words.
    defp in_cidr?(ip, network, prefix_len) when tuple_size(ip) == 4 do
      cidr_match?(Tuple.to_list(ip), Tuple.to_list(network), prefix_len, 8)
    end

    defp in_cidr?(ip, network, prefix_len) when tuple_size(ip) == 8 do
      cidr_match?(Tuple.to_list(ip), Tuple.to_list(network), prefix_len, 16)
    end

    # Compare the leading `remaining` bits of the address against the network,
    # element by element. A fully-covered element must match exactly; the element
    # straddling the prefix boundary is masked to its high bits; elements past the
    # prefix are unconstrained.
    defp cidr_match?(_ip, _net, remaining, _width) when remaining <= 0, do: true

    defp cidr_match?([ip_el | ip_rest], [net_el | net_rest], remaining, width) do
      take = min(remaining, width)
      mask = element_mask(width, take)

      if (ip_el &&& mask) == (net_el &&& mask) do
        cidr_match?(ip_rest, net_rest, remaining - width, width)
      else
        false
      end
    end

    # A mask of the high `take` bits within a `width`-bit element.
    defp element_mask(width, take) do
      full = (1 <<< width) - 1
      full - ((1 <<< (width - take)) - 1)
    end

    # Step 4-8: dial the pinned IP while keeping SNI / cert hostname / Host header
    # on the original host, refuse redirects, require 200 + JSON, cap the body.
    defp request(uri, pinned_ip, opts) do
      timeout = Keyword.get(opts, :request_timeout_ms, @default_request_timeout_ms)
      max_bytes = Keyword.get(opts, :max_document_bytes, @default_max_document_bytes)

      req = build_req(uri, pinned_ip, timeout, max_bytes, opts)

      case Req.request(req) do
        {:ok, %Req.Response{status: 200} = resp} -> on_ok(resp, max_bytes)
        {:ok, %Req.Response{status: status}} -> {:error, {:status, status}}
        {:error, %{__exception__: true} = exception} -> {:error, {:transport, exception}}
        {:error, reason} -> {:error, {:transport, reason}}
      end
    end

    defp build_req(%URI{} = uri, pinned_ip, timeout, max_bytes, opts) do
      [
        # Connect to the pinned IP; `connect_options[:hostname]` keeps TLS SNI,
        # certificate verification, and the derived Host header on the original
        # host - so the socket cannot be rebound to an internal address, but the
        # request still presents as the real hostname.
        url: %{uri | host: ip_to_string(pinned_ip)},
        method: :get,
        headers: [{"accept", "application/json"}, {"host", uri.host}],
        redirect: false,
        retry: false,
        receive_timeout: timeout,
        connect_options: [hostname: uri.host, timeout: timeout],
        # Stream the body so the size cap can abort an oversize response instead
        # of buffering it whole; the collector halts once `max_bytes` is exceeded.
        into: size_capped_collector(max_bytes),
        decode_body: false
      ]
      |> Req.new()
      |> Req.merge(Keyword.get(opts, :req_options, []))
    end

    # An `:into` collector that accumulates chunks into `resp.body` and halts the
    # stream the moment the accumulated size exceeds `max_bytes`. On halt the body
    # already holds more than `max_bytes`, so `check_size/2` still reports
    # `:too_large` - the streaming abort just bounds the memory a hostile origin
    # can force us to buffer.
    defp size_capped_collector(max_bytes) do
      fn {:data, data}, {req, resp} ->
        body = (resp.body || "") <> data
        resp = %{resp | body: body}

        if byte_size(body) > max_bytes do
          {:halt, {req, resp}}
        else
          {:cont, {req, resp}}
        end
      end
    end

    defp on_ok(%Req.Response{} = resp, max_bytes) do
      with :ok <- check_content_type(resp),
           {:ok, body} <- check_size(resp, max_bytes) do
        {:ok, %{body: body, cache_control: parse_cache_control(resp)}}
      end
    end

    # Step 7: content type must be JSON. The draft allows `application/json` and
    # the structured-suffix `application/<x>+json`.
    defp check_content_type(%Req.Response{} = resp) do
      resp
      |> content_type()
      |> json_content_type?()
      |> case do
        true -> :ok
        false -> {:error, :bad_content_type}
      end
    end

    defp content_type(%Req.Response{} = resp) do
      case Req.Response.get_header(resp, "content-type") do
        [value | _rest] -> value
        [] -> ""
      end
    end

    defp json_content_type?(value) do
      essence =
        value
        |> String.split(";", parts: 2)
        |> hd()
        |> String.trim()
        |> String.downcase()

      essence == "application/json" or
        (String.starts_with?(essence, "application/") and String.ends_with?(essence, "+json"))
    end

    # Step 8: the authoritative body-cap gate. The streaming collector halts an
    # oversize response early (bounding buffered memory), and this byte check then
    # refuses any body - streamed-and-halted or fully buffered - that exceeds the
    # cap, regardless of what Content-Length the origin advertised.
    defp check_size(%Req.Response{body: body}, max_bytes) when is_binary(body) do
      if byte_size(body) > max_bytes do
        {:error, :too_large}
      else
        {:ok, body}
      end
    end

    defp check_size(_resp, _max_bytes), do: {:error, :too_large}

    # Parse the RFC 9111 freshness directives the caller clamps and stores. Only
    # the members the resolver needs are surfaced: `max-age` / `no-store` /
    # `no-cache` from Cache-Control, and the raw `Expires` value as a fallback.
    defp parse_cache_control(%Req.Response{} = resp) do
      directives = cache_control_directives(resp)

      []
      |> put_max_age(directives)
      |> put_flag(:no_store, Map.has_key?(directives, "no-store"))
      |> put_flag(:no_cache, Map.has_key?(directives, "no-cache"))
      |> put_expires(resp)
    end

    defp cache_control_directives(%Req.Response{} = resp) do
      resp
      |> Req.Response.get_header("cache-control")
      |> Enum.join(",")
      |> String.split(",", trim: true)
      |> Map.new(&parse_directive/1)
    end

    defp parse_directive(directive) do
      directive
      |> String.trim()
      |> String.downcase()
      |> String.split("=", parts: 2)
      |> case do
        [name, value] -> {name, value}
        [name] -> {name, true}
      end
    end

    defp put_max_age(acc, directives) do
      with {:ok, raw} <- Map.fetch(directives, "max-age"),
           {seconds, ""} <- Integer.parse(raw) do
        Keyword.put(acc, :max_age, seconds)
      else
        _other -> acc
      end
    end

    defp put_flag(acc, _key, false), do: acc
    defp put_flag(acc, key, true), do: Keyword.put(acc, key, true)

    defp put_expires(acc, %Req.Response{} = resp) do
      case Req.Response.get_header(resp, "expires") do
        [value | _rest] -> Keyword.put(acc, :expires, value)
        [] -> acc
      end
    end

    defp ip_to_string(ip) do
      ip |> :inet.ntoa() |> List.to_string()
    end
  end
end
