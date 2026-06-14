defmodule AttestoPhoenix.ClientIdMetadata.Resolver do
  @moduledoc """
  Resolves a Client ID Metadata Document URL into a client - CIMD
  (`draft-ietf-oauth-client-id-metadata-document-01`, IETF OAuth WG).

  CIMD lets a client identify itself with no prior registration by using an
  HTTPS URL as its `client_id`; the authorization server dereferences that URL
  to a JSON client metadata document and uses it as the client. This module is
  the orchestrator that turns a presented CIMD `client_id` into the normalized
  client map attesto's resolution expects, gluing together the four collaborators
  the rest of the feature provides:

    * `Attesto.ClientIdMetadata` - the pure, network-free URL grammar
      (`validate_client_id/1`) and document validation (`validate_document/2`);
    * `AttestoPhoenix.ClientIdMetadata.Cache` - remembers a *validated* document
      so not every authorization request reaches the network;
    * `AttestoPhoenix.ClientIdMetadata.Fetcher` - the single SSRF-guarded
      outbound `GET`;
    * `AttestoPhoenix.Config` - the host's `:client_id_metadata` options
      (fetcher, cache, size/timeout caps, cache-TTL bounds, host allow/block
      lists).

  ## Algorithm (`resolve/2`)

  Each step errors closed; later steps run only when every earlier one passed:

    1. **Grammar (fail fast, no network).** `validate_client_id/1` rejects a
       non-CIMD `client_id` before any host check or socket - a request whose
       `client_id` is not a well-formed CIMD URL never reaches the resolver in
       normal operation, but the check is repeated here so a direct caller is
       never trusted. Failure -> `{:error, {:invalid_client_id, reason}}`.
    2. **Host policy.** The URL's host is screened against the configured
       `:blocked_hosts` (always refused) and, when set, `:allowed_hosts` (only
       these are permitted). A blocked or non-allowlisted host is refused
       *before* the cache or the network is consulted, so a policy change takes
       effect immediately. Failure -> `{:error, {:blocked_host, host}}`.
    3. **Cache.** `Cache.get/1` is consulted; a live (unexpired) entry is
       returned as the client without any fetch. The cache only ever holds a
       previously validated document, so a hit needs no re-validation.
    4. **Fetch.** On a miss the configured `:fetcher` performs the SSRF-guarded
       `GET`, honoring `:max_document_bytes`, `:request_timeout_ms`, and
       `:allow_loopback`. Any transport failure, non-`200`, redirect, non-JSON
       content type, or oversize body is an `{:error, _}` and is **never**
       cached (draft §6 / RFC 9111).
    5. **Decode + validate.** The body is JSON-decoded and handed to
       `validate_document/2`, which enforces the `client_id` match and the
       no-symmetric-secret rules and normalizes the document into the client
       shape. A malformed JSON body or an invalid document is an `{:error, _}`
       and is **never** cached.
    6. **Cache + return.** Only after validation succeeds is the document stored
       via `Cache.put/3`, with an `expires_at` derived from the response's
       `Cache-Control: max-age` / `Expires` freshness directives clamped to the
       configured `:cache_ttl_bounds` (RFC 9111). The normalized client map is
       returned.

  The returned client is shaped identically to a host `:load_client` result, so
  downstream resolution (scopes, redirect-URI match, JARM, DPoP) needs no
  CIMD-specific handling.
  """

  alias Attesto.ClientIdMetadata
  alias AttestoPhoenix.Config

  @typedoc """
  A reason `resolve/2` refused to produce a client. `:invalid_client_id` and
  `:blocked_host` are local policy failures (no network); `{:fetch, reason}`
  wraps a fetcher error; `:invalid_json` is an undecodable body; and a bare
  `Attesto.ClientIdMetadata.document_error/0` is a validation failure.
  """
  @type error ::
          {:invalid_client_id, ClientIdMetadata.url_error()}
          | {:blocked_host, String.t()}
          | {:fetch, term()}
          | :invalid_json
          | ClientIdMetadata.document_error()

  @doc """
  Resolve a CIMD `client_id` URL into a normalized client map.

  Runs the algorithm documented on this module against the host's
  `:client_id_metadata` configuration in `config`. Returns `{:ok, client}` for a
  freshly fetched-and-validated document (now cached) or a live cache hit, or
  `{:error, reason}` for any local-policy, fetch, decode, or validation failure -
  none of which are ever cached.
  """
  @spec resolve(String.t(), Config.t()) :: {:ok, map()} | {:error, error()}
  def resolve(client_id, %Config{} = config) when is_binary(client_id) do
    opts = Config.client_id_metadata(config)

    with {:ok, uri} <- validate_client_id(client_id),
         :ok <- check_host(uri.host, opts) do
      resolve_cached(client_id, opts)
    end
  end

  defp validate_client_id(client_id) do
    case ClientIdMetadata.validate_client_id(client_id) do
      {:ok, uri} -> {:ok, uri}
      {:error, reason} -> {:error, {:invalid_client_id, reason}}
    end
  end

  # Host allow/block policy (Config §9). `:blocked_hosts` always refuses;
  # `:allowed_hosts`, when a list, is an allowlist (only those hosts pass). A
  # `nil` allowlist means "any public host" (the fetcher's SSRF guard still
  # applies). Checked before the cache and the network so policy is authoritative.
  defp check_host(host, opts) do
    blocked = Keyword.get(opts, :blocked_hosts, [])
    allowed = Keyword.get(opts, :allowed_hosts)

    cond do
      host in blocked -> {:error, {:blocked_host, host}}
      is_list(allowed) and host not in allowed -> {:error, {:blocked_host, host}}
      true -> :ok
    end
  end

  # Cache short-circuit: a live entry is the client. The cache holds only
  # validated documents, so a hit is returned without re-validation or a fetch.
  defp resolve_cached(client_id, opts) do
    cache = Keyword.fetch!(opts, :cache)

    case cache.get(client_id) do
      {:ok, metadata} -> {:ok, metadata}
      :miss -> fetch_and_validate(client_id, opts)
    end
  end

  # Miss path: SSRF-guarded fetch, decode, validate, then (only on success)
  # cache. An error at any sub-step is returned as-is and never cached
  # (draft §6 / RFC 9111).
  defp fetch_and_validate(client_id, opts) do
    fetcher = Keyword.fetch!(opts, :fetcher)

    with {:ok, %{body: body, cache_control: cache_control}} <- fetch(fetcher, client_id, opts),
         {:ok, doc} <- decode(body),
         {:ok, metadata} <- ClientIdMetadata.validate_document(client_id, doc) do
      cache_put(client_id, metadata, cache_control, opts)
      {:ok, metadata}
    end
  end

  defp fetch(fetcher, client_id, opts) do
    fetch_opts = [
      max_document_bytes: Keyword.fetch!(opts, :max_document_bytes),
      request_timeout_ms: Keyword.fetch!(opts, :request_timeout_ms),
      allow_loopback: Keyword.fetch!(opts, :allow_loopback)
    ]

    case fetcher.fetch(client_id, fetch_opts) do
      {:ok, result} -> {:ok, result}
      {:error, reason} -> {:error, {:fetch, reason}}
    end
  end

  defp decode(body) do
    case JSON.decode(body) do
      {:ok, doc} when is_map(doc) -> {:ok, doc}
      _other -> {:error, :invalid_json}
    end
  end

  defp cache_put(client_id, metadata, cache_control, opts) do
    cache = Keyword.fetch!(opts, :cache)
    expires_at = expires_at(cache_control, opts)
    cache.put(client_id, metadata, expires_at)
  end

  # Derive `expires_at` from the response's RFC 9111 freshness directives and
  # clamp it to the configured `{min, max}` bounds. `Cache-Control: max-age`
  # wins; an `Expires` date is the fallback; absent both, the minimum bound is
  # used so a document is still cached (the draft permits a self-chosen TTL). A
  # `no-store` / `no-cache` directive collapses the lifetime to the minimum
  # bound rather than skipping the cache, keeping the per-node fetch fan-out
  # bounded while still honoring near-zero freshness.
  defp expires_at(cache_control, opts) do
    {min, max} = Keyword.fetch!(opts, :cache_ttl_bounds)

    ttl =
      cache_control
      |> raw_ttl()
      |> clamp(min, max)

    DateTime.add(DateTime.utc_now(), ttl, :second)
  end

  defp raw_ttl(cache_control) do
    cond do
      Keyword.get(cache_control, :no_store, false) -> 0
      Keyword.get(cache_control, :no_cache, false) -> 0
      is_integer(cache_control[:max_age]) -> cache_control[:max_age]
      true -> expires_ttl(cache_control[:expires])
    end
  end

  # An `Expires` header value is an HTTP-date; the freshness lifetime is the
  # seconds from now until that instant (negative/zero when already past). Any
  # unparseable value yields 0, deferring to the minimum bound after clamping.
  defp expires_ttl(value) when is_binary(value) do
    case parse_http_date(value) do
      {:ok, %DateTime{} = expires} -> DateTime.diff(expires, DateTime.utc_now(), :second)
      :error -> 0
    end
  end

  defp expires_ttl(_value), do: 0

  defp parse_http_date(value) do
    with {:ok, datetime, _offset} <- parse_rfc1123(value) do
      {:ok, datetime}
    end
  end

  @rfc1123 ~r/^\w{3}, (\d{2}) (\w{3}) (\d{4}) (\d{2}:\d{2}:\d{2}) GMT$/

  @months ~w(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec)

  # RFC 9110 §5.6.7 / RFC 1123: "Sun, 06 Nov 1994 08:49:37 GMT". Reformat into
  # the RFC 3339 shape `DateTime.from_iso8601/1` parses, in UTC (CIMD origins
  # serve GMT/UTC dates per HTTP-date).
  defp parse_rfc1123(value) do
    case Regex.run(@rfc1123, value) do
      [_match, day, mon, year, time] ->
        with {:ok, month} <- month_number(mon) do
          DateTime.from_iso8601("#{year}-#{month}-#{day}T#{time}Z")
        end

      _other ->
        :error
    end
  end

  defp month_number(name) do
    case Enum.find_index(@months, &(&1 == name)) do
      nil -> :error
      index -> {:ok, index |> Kernel.+(1) |> Integer.to_string() |> String.pad_leading(2, "0")}
    end
  end

  defp clamp(value, min, _max) when value < min, do: min
  defp clamp(value, _min, max) when value > max, do: max
  defp clamp(value, _min, _max), do: value
end
