if Code.ensure_loaded?(Req) do
  defmodule AttestoPhoenix.ClientIdMetadata.Fetcher.Req do
    @moduledoc """
    The default, SSRF-guarded Client ID Metadata Document fetcher - CIMD
    (`draft-ietf-oauth-client-id-metadata-document-02`, IETF OAuth WG).

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

    alias AttestoPhoenix.ClientIdMetadata.Fetcher
    alias AttestoPhoenix.ClientIdMetadata.HostPolicy

    @default_max_document_bytes 5_120
    @default_request_timeout_ms 5_000
    @max_client_id_bytes 2_048

    @typedoc "A resolved IP address, as returned by `:inet.getaddrs/2`."
    @type ip :: :inet.ip_address()

    @doc """
    Fetch a validated CIMD `client_id` URL under the SSRF algorithm documented on
    this module. See `AttestoPhoenix.ClientIdMetadata.Fetcher` for the contract.
    """
    @impl Fetcher
    @spec fetch(String.t(), keyword()) ::
            {:ok, Fetcher.result()} | {:error, term()}
    def fetch(url, opts \\ []) when is_binary(url) and is_list(opts) do
      allow_loopback = allow_loopback!(opts)

      with {:ok, uri} <- revalidate(url),
           {:ok, ips} <- resolve(uri.host, opts),
           {:ok, pinned} <- screen(ips, allow_loopback) do
        request(uri, pinned, opts)
      end
    end

    @impl Fetcher
    def preflight(url, opts \\ []) when is_binary(url) and is_list(opts) do
      allow_loopback = allow_loopback!(opts)

      with {:ok, uri} <- revalidate(url),
           {:ok, ips} <- resolve(uri.host, opts),
           {:ok, _pinned} <- screen(ips, allow_loopback) do
        :ok
      end
    end

    defp allow_loopback!(opts) do
      case Keyword.get(opts, :allow_loopback, false) do
        value when is_boolean(value) -> value
        _invalid -> raise ArgumentError, ":allow_loopback must be true or false"
      end
    end

    # Step 1: re-validate https + draft §2 grammar; never trust the caller.
    defp revalidate(url) do
      if byte_size(url) > @max_client_id_bytes do
        {:error, {:invalid_url, :too_long}}
      else
        case Attesto.ClientIdMetadata.validate_client_id(url) do
          {:ok, uri} -> canonicalize_host(uri)
          {:error, reason} -> {:error, {:invalid_url, reason}}
        end
      end
    end

    defp canonicalize_host(uri) do
      case HostPolicy.canonicalize(uri.host) do
        {:ok, host} -> {:ok, %{uri | host: host}}
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
    defp screen(ips, allow_loopback) do
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

    @doc "Delegates to the always-available hostname and address policy."
    @spec special_use_ip?(ip()) :: boolean()
    defdelegate special_use_ip?(ip), to: HostPolicy

    defp loopback?({127, _b, _c, _d}), do: true
    defp loopback?({0, 0, 0, 0, 0, 0, 0, 1}), do: true
    defp loopback?({0, 0, 0, 0, 0, 0xFFFF, w7, _w8}) when div(w7, 256) == 127, do: true
    defp loopback?(_ip), do: false

    # Step 4-8: dial the pinned IP while keeping SNI / cert hostname / Host header
    # on the original host, refuse redirects, require 200 + JSON, cap the body.
    defp request(uri, pinned_ip, opts) do
      timeout = Keyword.get(opts, :request_timeout_ms, @default_request_timeout_ms)
      max_bytes = Keyword.get(opts, :max_document_bytes, @default_max_document_bytes)

      req = build_req(uri, pinned_ip, timeout, max_bytes, opts)
      started_at = System.monotonic_time(:millisecond)

      case Req.request(req) do
        {:ok, %Req.Response{status: 200} = resp} -> on_ok(resp, max_bytes, started_at)
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
        headers: [{"accept", "application/json"}, {"host", HostPolicy.authority(uri)}],
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

    defp on_ok(%Req.Response{} = resp, max_bytes, started_at) do
      received_at = DateTime.utc_now()
      response_delay_ms = max(0, System.monotonic_time(:millisecond) - started_at)

      with :ok <- check_content_type(resp),
           {:ok, body} <- check_size(resp, max_bytes) do
        cache_control =
          resp
          |> parse_cache_control()
          |> Keyword.put(:response_delay_ms, response_delay_ms)
          |> Keyword.put(:received_at, received_at)

        {:ok, %{body: body, cache_control: cache_control}}
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

    # Parse the RFC 9111 freshness directives the caller clamps and stores. This
    # is a shared cache, so `s-maxage` takes precedence over `max-age`, and a
    # `private` response is not stored. The raw `Expires` value is the fallback.
    defp parse_cache_control(%Req.Response{} = resp) do
      directives = cache_control_directives(resp)

      []
      |> put_delta_seconds(:max_age, "max-age", directives)
      |> put_delta_seconds(:s_maxage, "s-maxage", directives)
      |> put_flag(:no_store, Map.has_key?(directives, "no-store"))
      |> put_flag(:no_cache, Map.has_key?(directives, "no-cache"))
      |> put_flag(:private, Map.has_key?(directives, "private"))
      |> put_expires(resp)
      |> put_age(resp)
      |> put_date(resp)
    end

    defp cache_control_directives(%Req.Response{} = resp) do
      value = resp |> Req.Response.get_header("cache-control") |> Enum.join(",")

      case split_cache_control(value, [], [], false) do
        {:ok, directives} ->
          Enum.reduce(directives, %{}, fn directive, acc ->
            {name, value} = parse_directive(directive)
            Map.put_new(acc, name, value)
          end)

        :error ->
          %{"max-age" => 0}
      end
    end

    defp split_cache_control(<<>>, current, parts, false), do: {:ok, Enum.reverse([directive_binary(current) | parts])}

    defp split_cache_control(<<>>, _current, _parts, true), do: :error

    defp split_cache_control(<<?\\, char, rest::binary>>, current, parts, true),
      do: split_cache_control(rest, [char, ?\\ | current], parts, true)

    defp split_cache_control(<<?", rest::binary>>, current, parts, quoted?),
      do: split_cache_control(rest, [?" | current], parts, not quoted?)

    defp split_cache_control(<<?,, rest::binary>>, current, parts, false),
      do: split_cache_control(rest, [], [directive_binary(current) | parts], false)

    defp split_cache_control(<<char, rest::binary>>, current, parts, quoted?),
      do: split_cache_control(rest, [char | current], parts, quoted?)

    defp directive_binary(reversed), do: reversed |> Enum.reverse() |> :erlang.list_to_binary()

    defp parse_directive(directive) do
      directive
      |> String.trim()
      |> String.split("=", parts: 2)
      |> case do
        [name, value] -> {name |> String.trim() |> String.downcase(:ascii), String.trim(value)}
        [name] -> {String.downcase(name, :ascii), true}
      end
    end

    defp put_delta_seconds(acc, key, name, directives) do
      case Map.fetch(directives, name) do
        {:ok, raw} ->
          case max_age_seconds(raw) do
            {:ok, seconds} -> Keyword.put(acc, key, seconds)
            :error -> Keyword.put(acc, key, 0)
          end

        :error ->
          acc
      end
    end

    defp max_age_seconds(raw) when is_binary(raw) do
      value =
        case Regex.run(~r/\A"([0-9]+)"\z/, raw) do
          [_quoted, value] -> value
          _ -> raw
        end

      delta_seconds(value)
    end

    defp max_age_seconds(_raw), do: :error

    defp delta_seconds(value) do
      if Regex.match?(~r/\A[0-9]+\z/, value),
        do: {:ok, String.to_integer(value)},
        else: :error
    end

    defp put_flag(acc, _key, false), do: acc
    defp put_flag(acc, key, true), do: Keyword.put(acc, key, true)

    defp put_expires(acc, %Req.Response{} = resp) do
      case Req.Response.get_header(resp, "expires") do
        [value | _rest] -> Keyword.put(acc, :expires, value)
        [] -> acc
      end
    end

    defp put_age(acc, %Req.Response{} = resp) do
      case Req.Response.get_header(resp, "age") do
        [value | _rest] ->
          first = value |> String.split(",", parts: 2) |> hd() |> String.trim()

          case delta_seconds(first) do
            {:ok, seconds} -> Keyword.put(acc, :age, seconds)
            :error -> acc
          end

        _ ->
          acc
      end
    end

    defp put_date(acc, %Req.Response{} = resp) do
      case Req.Response.get_header(resp, "date") do
        [value | _rest] -> Keyword.put(acc, :date, value)
        _ -> acc
      end
    end

    defp ip_to_string(ip) do
      ip |> :inet.ntoa() |> List.to_string()
    end
  end
end
