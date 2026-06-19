defmodule AttestoPhoenix.AuthorizationServer.JwtBearer do
  @moduledoc """
  The resource server's half of the Identity Assertion JWT Authorization Grant
  (ID-JAG), the grant behind MCP Enterprise-Managed Authorization (EMA) -
  `draft-ietf-oauth-identity-assertion-authz-grant-04`.

  A token request arrives with
  `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and an `assertion`
  parameter carrying an ID-JAG: a short-lived JWT the enterprise IdP signed
  (after its own RFC 8693 token exchange) asserting one user for this resource
  application. `authorize/3` turns that assertion into the local subject and
  scope ceiling the token endpoint mints from. It owns the *stateful* concerns
  that `Attesto.IdentityAssertion` (conn-free, pure) deliberately leaves out:

    * **issuer trust** - the assertion's `iss` must be a configured trusted
      issuer (`jwt_bearer: [issuers: %{...}]`); an unconfigured issuer is denied
      without revealing which issuers are trusted.
    * **JWKS resolution** - static keys, a cached `jwks_uri` fetch (reusing the
      SSRF-guarded CIMD fetcher + cache), or a custom `:jwks_resolver`.
    * **`jti` replay** - via the configured `:replay_check` (the same seam DPoP
      uses), namespaced so an ID-JAG `jti` never collides with a DPoP proof's.
    * **subject resolution** - the host's `:resolve_jwt_bearer_subject` callback
      maps the validated claims to a local principal subject (or denies).

  Every failure returns `{:error, atom}`; the token core
  (`AttestoPhoenix.AuthorizationServer.Token`) maps a missing `assertion`
  parameter to RFC 6749 §5.2 `invalid_request` and every assertion/trust/replay/
  subject failure to `invalid_grant`, as the draft requires.

  This is NOT `private_key_jwt` client authentication (RFC 7523 §3) nor the
  RFC 8693 token-exchange grant (which runs at the IdP).
  """

  alias Attesto.DPoP.ReplayCache
  alias Attesto.IdentityAssertion
  alias AttestoPhoenix.{Callback, Config}

  require Logger

  @jti_namespace "idjag:"

  @typedoc """
  The resolved local subject, the assertion's scope ceiling (`nil` when the
  assertion carried no `scope` claim, so the host policy alone decides), and the
  validated claims.
  """
  @type result :: %{
          subject: String.t(),
          scope_ceiling: [String.t()] | nil,
          claims: IdentityAssertion.claims()
        }

  @type error ::
          :missing_assertion
          | :untrusted_issuer
          | :jwks_unavailable
          | :invalid_assertion
          | :replay
          | :subject_denied

  @doc """
  Validate the ID-JAG `assertion` and resolve the local subject.

  `client_id` is the already-authenticated client's identifier (the token
  endpoint resolved it from client authentication); the assertion's `client_id`
  claim MUST equal it. Returns `{:ok, %{subject, scope_ceiling, claims}}` or
  `{:error, t:error/0}`.
  """
  @spec authorize(Config.t(), String.t() | nil, map()) :: {:ok, result()} | {:error, error()}
  def authorize(%Config{} = config, client_id, params) when is_map(params) do
    opts = Config.jwt_bearer(config)

    with {:ok, assertion} <- require_assertion(params),
         {:ok, issuer} <- peek_issuer(assertion),
         {:ok, issuer_opts} <- trusted_issuer(opts, issuer),
         {:ok, jwks} <- resolve_jwks(opts, issuer, issuer_opts),
         {:ok, claims} <- verify(config, opts, assertion, issuer, issuer_opts, jwks, client_id),
         :ok <- check_replay(config, opts, claims),
         {:ok, subject} <- resolve_subject(config, claims) do
      {:ok, %{subject: subject, scope_ceiling: scope_ceiling(claims), claims: claims}}
    end
  end

  defp require_assertion(params) do
    case params["assertion"] do
      assertion when is_binary(assertion) and assertion != "" -> {:ok, assertion}
      _ -> {:error, :missing_assertion}
    end
  end

  defp peek_issuer(assertion) do
    case IdentityAssertion.peek_issuer(assertion) do
      {:ok, issuer} -> {:ok, issuer}
      :error -> {:error, :invalid_assertion}
    end
  end

  # The assertion's (still-unverified) issuer must be a configured trusted
  # issuer. Denied as `:untrusted_issuer` without revealing the trusted set.
  defp trusted_issuer(opts, issuer) do
    opts
    |> Keyword.get(:issuers, %{})
    |> Map.get(issuer)
    |> case do
      nil -> {:error, :untrusted_issuer}
      issuer_opts -> {:ok, normalize_issuer_opts(issuer_opts)}
    end
  end

  defp normalize_issuer_opts(opts) when is_list(opts), do: Map.new(opts)
  defp normalize_issuer_opts(%{} = opts), do: opts
  defp normalize_issuer_opts(_opts), do: %{}

  # JWKS resolution precedence: a custom `:jwks_resolver` (full host control),
  # then per-issuer static `:jwks`, then a cached `:jwks_uri` fetch.
  defp resolve_jwks(opts, issuer, issuer_opts) do
    cond do
      resolver = Keyword.get(opts, :jwks_resolver) ->
        case Callback.invoke(resolver, [issuer, issuer_opts]) do
          {:ok, jwks} when is_map(jwks) or is_list(jwks) -> {:ok, jwks}
          _ -> {:error, :jwks_unavailable}
        end

      jwks = Map.get(issuer_opts, :jwks) ->
        {:ok, jwks}

      uri = Map.get(issuer_opts, :jwks_uri) ->
        fetch_jwks(opts, uri)

      true ->
        {:error, :jwks_unavailable}
    end
  end

  defp fetch_jwks(opts, uri) do
    cache = Keyword.get(opts, :jwks_cache)

    case cache_get(cache, uri) do
      {:ok, jwks} -> {:ok, jwks}
      :miss -> fetch_and_cache(opts, cache, uri)
    end
  end

  defp cache_get(nil, _uri), do: :miss

  defp cache_get(cache, uri) do
    case cache.get(uri) do
      {:ok, jwks} when is_map(jwks) -> {:ok, jwks}
      _ -> :miss
    end
  end

  defp fetch_and_cache(opts, cache, uri) do
    fetcher = Keyword.fetch!(opts, :jwks_fetcher)
    # JWK sets with several keys exceed the CIMD body cap, so raise the default
    # unless the host pinned its own.
    fetch_opts = opts |> Keyword.get(:fetch_opts, []) |> Keyword.put_new(:max_document_bytes, 16_384)

    case fetcher.fetch(uri, fetch_opts) do
      {:ok, %{body: body, cache_control: cache_control}} ->
        case JSON.decode(body) do
          {:ok, %{"keys" => keys} = jwks} when is_list(keys) ->
            cache_put(cache, uri, jwks, cache_control, opts)
            {:ok, jwks}

          _ ->
            {:error, :jwks_unavailable}
        end

      {:error, reason} ->
        Logger.warning("jwt_bearer: JWKS fetch failed for #{uri}: #{inspect(reason)}")
        {:error, :jwks_unavailable}
    end
  end

  defp cache_put(nil, _uri, _jwks, _cache_control, _opts), do: :ok

  defp cache_put(cache, uri, jwks, cache_control, opts) do
    bounds = Keyword.get(opts, :jwks_cache_ttl_bounds, {300, 86_400})

    case ttl_seconds(cache_control, bounds) do
      ttl when ttl > 0 -> cache.put(uri, jwks, DateTime.add(DateTime.utc_now(), ttl, :second))
      _ -> :ok
    end
  end

  # RFC 9111 freshness: honor `no-store`/`no-cache` (do not cache), clamp a
  # present `max-age` to the configured bounds, and otherwise cache for the
  # minimum bound (JWKS endpoints often send no directive but keys rotate
  # slowly).
  defp ttl_seconds(cache_control, {min, max}) do
    cond do
      Keyword.get(cache_control, :no_store, false) -> 0
      Keyword.get(cache_control, :no_cache, false) -> 0
      is_integer(cache_control[:max_age]) -> clamp(cache_control[:max_age], min, max)
      true -> min
    end
  end

  defp clamp(value, min, _max) when value < min, do: min
  defp clamp(value, _min, max) when value > max, do: max
  defp clamp(value, _min, _max), do: value

  defp verify(config, opts, assertion, issuer, issuer_opts, jwks, client_id) do
    verify_opts =
      [
        issuer: issuer,
        audience: Map.get(issuer_opts, :audience) || config.issuer,
        client_id: client_id,
        max_lifetime_seconds: Keyword.get(opts, :assertion_max_lifetime_seconds)
      ] ++ accepted_algs_opt(issuer_opts)

    case IdentityAssertion.verify(assertion, jwks, verify_opts) do
      {:ok, claims} ->
        {:ok, claims}

      {:error, reason} ->
        Logger.debug("jwt_bearer: assertion rejected (#{inspect(reason)})")
        {:error, :invalid_assertion}
    end
  end

  defp accepted_algs_opt(issuer_opts) do
    case Map.get(issuer_opts, :allowed_algs) do
      algs when is_list(algs) and algs != [] -> [accepted_algs: algs]
      _ -> []
    end
  end

  # draft §6.1: the assertion `jti` MUST be replay-protected. Reuse the host's
  # configured `:replay_check` (the DPoP seam), namespaced so an ID-JAG jti can
  # never collide with a DPoP proof jti. Remember it for the assertion's
  # remaining lifetime - past `exp` the assertion is rejected on `exp` anyway.
  defp check_replay(config, opts, %{"jti" => jti, "exp" => exp}) when is_binary(jti) and is_integer(exp) do
    ttl = replay_ttl(exp, opts)

    case Callback.invoke(replay_check(config), [@jti_namespace <> jti, ttl]) do
      :ok -> :ok
      {:error, :replay} -> {:error, :replay}
      _other -> {:error, :replay}
    end
  end

  defp replay_ttl(exp, opts) do
    remaining = exp - System.system_time(:second)
    ceiling = Keyword.get(opts, :assertion_max_lifetime_seconds) || 300
    remaining |> min(ceiling) |> max(1)
  end

  defp replay_check(%Config{replay_check: nil}), do: &ReplayCache.check_and_record/2
  defp replay_check(%Config{replay_check: callback}), do: callback

  # The host maps the validated claims to a local principal subject. Required
  # when the feature is enabled (`Config.validate!/1` enforces this), so an
  # unset callback is a config fault rather than a per-request deny.
  defp resolve_subject(config, claims) do
    case Callback.invoke(Config.resolve_jwt_bearer_subject_fun(config), [claims], :no_callback) do
      {:ok, subject} when is_binary(subject) and subject != "" -> {:ok, subject}
      subject when is_binary(subject) and subject != "" -> {:ok, subject}
      _ -> {:error, :subject_denied}
    end
  end

  # draft §6.1: `scope` is OPTIONAL. When present it is the UPPER bound on what
  # the issued token may carry (the token core narrows further via the host
  # `:authorize_scope` policy). An absent scope claim places no ceiling.
  defp scope_ceiling(%{"scope" => scope}) when is_binary(scope) do
    String.split(scope, " ", trim: true)
  end

  defp scope_ceiling(_claims), do: nil
end
