defmodule AttestoPhoenix.AuthorizationServer.JwtBearer do
  @moduledoc """
  Verify and redeem Identity Assertion JWT Authorization Grants (ID-JAGs) at
  the resource authorization server.
  [ID-JAG draft -06, §4.4](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-4.4).

  The token endpoint accepts registered confidential clients and client ID
  metadata document clients authenticated with RFC 7523 private-key JWT.
  It requires authentication by default. Setting `jwt_bearer: [public_clients: :allow]`
  permits public clients, including clients with bearer assertions. Accepting
  an unauthenticated request with a bearer ID-JAG departs from draft -06 §4.4.
  The token request is no longer bound to a client credential. The assertion's
  `client_id` binding, issuer signature, short lifetime, and `jti` replay check
  still apply.

  A host can configure trusted issuers by exact identifier or resolve them
  from its own trust records. Remote issuer keys use the SSRF-guarded fetcher
  and cache shared with client ID metadata. Assertion headers never supply
  verification keys or key URLs.

  The token endpoint maps missing assertions to `invalid_request`, assertion
  validation failures to `invalid_grant`, and subject denials to `access_denied`
  (RFC 6749 §5.2 and ID-JAG draft -06 §4.4.3).
  """

  alias Attesto.{IdentityAssertion, JWS, Scope, StrictJSON}
  alias Attesto.URI, as: AttestoURI
  alias AttestoPhoenix.AuthorizationServer.JwtBearer.KeyRefresh
  alias AttestoPhoenix.{Callback, Config, DPoP.Adapter, ReplayClaim}
  alias AttestoPhoenix.ClientIdMetadata.{Cache, FlowControl, Resolver}

  require Logger

  @jti_namespace "idjag:"
  @metadata_cache_prefix "id-jag:metadata:"
  @refresh_limits [
    flow_control_server: KeyRefresh,
    max_fetches_per_host_per_window: 1,
    fetch_rate_window_ms: 30_000
  ]
  @cache_read_warning "AttestoPhoenix JWT-bearer JWKS cache failed; fetching fresh keys"
  @cache_write_warning "AttestoPhoenix JWT-bearer JWKS cache failed; fresh keys were not cached"
  @fetch_warning "AttestoPhoenix JWT-bearer JWKS fetch failed; keys unavailable"

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

  @typedoc "A verified assertion's fixed-size replay identity and remaining acceptance window."
  @type pending_claim :: {String.t(), pos_integer()}

  @type prepared_result :: %{
          scope_ceiling: [String.t()] | nil,
          claims: IdentityAssertion.claims(),
          issuer_context: term(),
          replay_claim: pending_claim()
        }

  @type error ::
          :missing_assertion
          | :untrusted_issuer
          | :jwks_unavailable
          | :invalid_assertion
          | :replay
          | :subject_denied

  @doc """
  Validate the ID-JAG `assertion`, claim its replay identity, and resolve the
  local subject.

  `client_id` is the already-authenticated client's identifier (the token
  endpoint resolved it from client authentication); the assertion's `client_id`
  claim MUST equal it. Returns `{:ok, %{subject, scope_ceiling, claims}}` or
  `{:error, t:error/0}`.
  """
  @spec authorize(Config.t(), String.t() | nil, map()) :: {:ok, result()} | {:error, error()}
  def authorize(%Config{} = config, client_id, params) when is_map(params) do
    Config.with_request_config(config, fn -> do_authorize(config, client_id, params) end)
  end

  defp do_authorize(%Config{} = config, client_id, params) do
    with {:ok, prepared} <- prepare(config, client_id, params),
         :ok <- reject_unverified_cnf(prepared.claims),
         {:ok, subject} <- resolve_subject(config, prepared.claims, prepared.issuer_context),
         :ok <- commit_replay_claim(config, prepared.replay_claim) do
      {:ok, %{scope_ceiling: prepared.scope_ceiling, claims: prepared.claims, subject: subject}}
    end
  end

  # `authorize/3` carries no sender-constraint proof context (`Token` uses
  # `prepare/3` and verifies `cnf.jkt` against the request's DPoP proof before
  # resolving the subject or claiming replay). A direct `authorize/3` caller
  # must never accept a proof-of-possession assertion as bearer.
  defp reject_unverified_cnf(%{"cnf" => _}), do: {:error, :invalid_assertion}
  defp reject_unverified_cnf(_claims), do: :ok

  @doc """
  Validate an ID-JAG while deferring subject resolution and its atomic replay
  claim.

  The token core uses this variant so sender binding, resource, scope, and host
  policy can finish before invoking a potentially side-effecting subject
  resolver or consuming the assertion. A caller MUST then call
  `resolve_subject/3` with `:issuer_context`, then pass `:replay_claim` to `commit_replay_claim/2` before
  minting or releasing an authorization result. Most callers should use
  `authorize/3`, which performs both steps itself.
  """
  @spec prepare(Config.t(), String.t() | nil, map()) ::
          {:ok, prepared_result()} | {:error, error()}
  def prepare(%Config{} = config, client_id, params) when is_map(params) do
    prepare(config, client_id, params, client_id)
  end

  @doc """
  Prepare an assertion using the request client supplied to the issuer resolver.
  `prepare/3` supplies the client identifier when only that identifier is available.
  """
  @spec prepare(Config.t(), String.t() | nil, map(), term()) ::
          {:ok, prepared_result()} | {:error, error()}
  def prepare(%Config{} = config, client_id, params, client) when is_map(params) do
    Config.with_request_config(config, fn -> do_prepare(config, client_id, params, client) end)
  end

  defp do_prepare(%Config{} = config, client_id, params, client) do
    opts = Config.jwt_bearer(config)

    with {:ok, assertion} <- require_assertion(params),
         {:ok, issuer, aud_tenant} <- peek_issuer(assertion),
         {:ok, issuer_opts, context} <- trusted_issuer(opts, issuer, aud_tenant, client),
         {:ok, key_source} <- key_source(opts, issuer, issuer_opts),
         {:ok, claims} <- verify(config, opts, assertion, issuer, issuer_opts, key_source, client_id),
         {:ok, replay_claim} <- prepare_replay(opts, claims) do
      {:ok,
       %{
         scope_ceiling: scope_ceiling(claims),
         claims: claims,
         issuer_context: context,
         replay_claim: replay_claim
       }}
    end
  end

  @doc """
  Resolve verified ID-JAG claims to a local principal subject.

  Required when the feature is enabled (configuration validation enforces this), so
  an unset callback is a configuration fault. The two-argument host callback
  receives the verified claims and a map containing `:issuer_context` and the
  verified `:aud_tenant`. The one-argument form receives only the claims.
  """
  @spec resolve_subject(Config.t(), IdentityAssertion.claims()) ::
          {:ok, String.t()} | {:error, :subject_denied}
  @spec resolve_subject(Config.t(), IdentityAssertion.claims(), term()) ::
          {:ok, String.t()} | {:error, :subject_denied}
  def resolve_subject(%Config{} = config, claims, context \\ nil) when is_map(claims) do
    {callback, arity} = Config.resolve_jwt_bearer_subject_callback(config)
    args = if arity == 2, do: [claims, %{issuer_context: context, aud_tenant: claims["aud_tenant"]}], else: [claims]

    case Callback.invoke(callback, args, :no_callback) do
      {:ok, subject} when is_binary(subject) and subject != "" -> {:ok, subject}
      subject when is_binary(subject) and subject != "" -> {:ok, subject}
      _ -> {:error, :subject_denied}
    end
  end

  @doc """
  Atomically claim a replay identity returned by `prepare/3` before minting.

  The configured replay callback must return exactly `:ok` or
  `{:error, :replay}`. Any other result raises as an integration or storage
  fault rather than being mislabeled as a replay.
  """
  @spec commit_replay_claim(Config.t(), pending_claim()) :: :ok | {:error, :replay}
  def commit_replay_claim(%Config{} = config, {key, ttl}) when is_binary(key) and is_integer(ttl) do
    Config.with_request_config(config, fn -> do_commit_replay_claim(config, key, ttl) end)
  end

  # Reuse DPoP's configured `:replay_check` or the bundled ETS cache to claim
  # the issuer-scoped assertion identifier before minting.
  defp do_commit_replay_claim(config, key, ttl) do
    ReplayClaim.commit(Adapter.replay_check(config), key, ttl)
  end

  defp require_assertion(params) do
    case params["assertion"] do
      assertion when is_binary(assertion) and assertion != "" -> {:ok, assertion}
      _ -> {:error, :missing_assertion}
    end
  end

  defp peek_issuer(assertion) do
    with {:ok, %{"iss" => issuer} = claims} when is_binary(issuer) and issuer != "" <-
           IdentityAssertion.peek_claims(assertion),
         {:ok, aud_tenant} <- peek_aud_tenant(claims) do
      {:ok, issuer, aud_tenant}
    else
      _ -> {:error, :invalid_assertion}
    end
  end

  defp peek_aud_tenant(%{"aud_tenant" => tenant}) when is_binary(tenant), do: {:ok, tenant}
  defp peek_aud_tenant(%{"aud_tenant" => _tenant}), do: :error
  defp peek_aud_tenant(_claims), do: {:ok, nil}

  # Establish trust before looking up keys (ID-JAG draft -06 §4.4.1). Pass
  # the unverified `iss`, unverified `aud_tenant`, and request client to
  # `:resolve_trusted_issuer` when configured. Otherwise look up the exact
  # `iss` in `:issuers`. A resolver refusal is final. Reject a trust record
  # whose explicit issuer differs from `iss`.
  defp trusted_issuer(opts, issuer, aud_tenant, client) do
    case Keyword.get(opts, :resolve_trusted_issuer) do
      nil ->
        case Map.fetch(Keyword.get(opts, :issuers, %{}), issuer) do
          {:ok, issuer_opts} -> resolved_issuer(issuer_opts, issuer, nil)
          :error -> {:error, :untrusted_issuer}
        end

      resolver ->
        case Callback.invoke(resolver, [issuer, aud_tenant, client]) do
          {:ok, issuer_opts, context} -> resolved_issuer(issuer_opts, issuer, context)
          _ -> {:error, :untrusted_issuer}
        end
    end
  end

  defp resolved_issuer(issuer_opts, issuer, context) when is_list(issuer_opts) do
    if Keyword.keyword?(issuer_opts),
      do: resolved_issuer(Map.new(issuer_opts), issuer, context),
      else: {:error, :untrusted_issuer}
  end

  defp resolved_issuer(%{} = issuer_opts, issuer, context) do
    if Map.get(issuer_opts, :issuer, issuer) == issuer,
      do: {:ok, issuer_opts, context},
      else: {:error, :untrusted_issuer}
  end

  defp resolved_issuer(_issuer_opts, _issuer, _context), do: {:error, :untrusted_issuer}

  # After establishing issuer trust, use `:jwks_resolver` when configured.
  # Otherwise use static `:jwks`, explicit `discovery: true`, then `:jwks_uri`.
  # Without keys or a URI, discover the URI unless discovery is disabled.
  # If the chosen source fails, reject the assertion. Fetch remote keys
  # through the SSRF-guarded CIMD fetcher and cache.
  defp key_source(opts, issuer, issuer_opts) do
    case Keyword.get(opts, :jwks_resolver) do
      nil ->
        configured_key_source(opts, issuer, issuer_opts)

      resolver ->
        case Callback.invoke(resolver, [issuer, issuer_opts]) do
          {:ok, jwks} when is_map(jwks) or is_list(jwks) -> {:ok, {:static, jwks}}
          _ -> {:error, :jwks_unavailable}
        end
    end
  end

  defp configured_key_source(opts, issuer, issuer_opts) do
    cond do
      jwks = Map.get(issuer_opts, :jwks) -> {:ok, {:static, jwks}}
      Map.get(issuer_opts, :discovery) == true -> discover_jwks_uri(opts, issuer)
      uri = Map.get(issuer_opts, :jwks_uri) -> {:ok, {:remote, uri}}
      Map.get(issuer_opts, :discovery, true) == true -> discover_jwks_uri(opts, issuer)
      true -> {:error, :jwks_unavailable}
    end
  end

  # Use the shared authorization-server metadata candidate sequence: OAuth
  # path insertion, OIDC path insertion, then OIDC path appending. A document
  # advances to the next candidate only when it is absent.
  defp discover_jwks_uri(opts, issuer) do
    cache_key = @metadata_cache_prefix <> issuer

    with true <- AttestoURI.issuer_identifier?(issuer),
         {:ok, %{"jwks_uri" => uri}} <-
           cached_document(opts, cache_key, &issuer_metadata?(issuer, &1), fn -> fetch_metadata(opts, issuer) end) do
      {:ok, {:remote, uri}}
    else
      _ -> {:error, :jwks_unavailable}
    end
  end

  defp fetch_metadata(opts, issuer) do
    with {:ok, candidates} <- Attesto.Discovery.metadata_candidates(issuer) do
      fetch_metadata_candidate(opts, candidates)
    end
  end

  defp fetch_metadata_candidate(opts, [{_kind, url} | rest]) do
    case fetch_document(opts, url) do
      {:error, {:status, 404}} when rest != [] -> fetch_metadata_candidate(opts, rest)
      result -> result
    end
  end

  # RFC 8414 §3.3 and OpenID Connect Discovery §4.3 require exact issuer matching.
  defp issuer_metadata?(issuer, %{"issuer" => issuer, "jwks_uri" => uri}), do: AttestoURI.https_identifier?(uri)
  defp issuer_metadata?(_issuer, _metadata), do: false

  defp jwks?(%{"keys" => keys}) when is_list(keys), do: true
  defp jwks?(_document), do: false

  defp cached_document(opts, key, valid?, fetch) do
    cache = Keyword.get(opts, :jwks_cache)

    case cache_get(cache, key, valid?) do
      {:ok, document} -> {:ok, document}
      :miss -> fetch_and_cache(opts, key, valid?, fetch)
    end
  end

  defp cache_get(nil, _key, _valid?), do: :miss

  defp cache_get(cache, key, valid?) do
    case cache.get(key) do
      {:ok, document} -> if valid?.(document), do: {:ok, document}, else: warn_cache_read_fault()
      :miss -> :miss
      _fault -> warn_cache_read_fault()
    end
  rescue
    _exception -> warn_cache_read_fault()
  catch
    _kind, _reason -> warn_cache_read_fault()
  end

  defp fetch_document(opts, uri) do
    fetcher = Keyword.fetch!(opts, :jwks_fetcher)
    # JWK sets with several keys exceed the CIMD body cap, so raise the default
    # unless the host pinned its own.
    fetch_opts = opts |> Keyword.get(:fetch_opts, []) |> Keyword.put_new(:max_document_bytes, 16_384)

    with true <- is_atom(fetcher) and Code.ensure_loaded?(fetcher) and function_exported?(fetcher, :fetch, 2),
         {:ok, %{body: body, cache_control: cache_control}} <- fetcher.fetch(uri, fetch_opts),
         {:ok, document} <- StrictJSON.decode(body) do
      {:ok, document, cache_control}
    else
      false -> {:error, :fetcher_unavailable}
      error -> error
    end
  end

  defp fetch_and_cache(opts, key, valid?, fetch, refresh? \\ false) do
    case fetch.() do
      {:ok, document, cache_control} ->
        if valid?.(document) do
          cache_put(Keyword.get(opts, :jwks_cache), key, document, cache_control, opts, refresh?)
          {:ok, document}
        else
          {:error, :jwks_unavailable}
        end

      {:error, _reason} ->
        Logger.warning(@fetch_warning)
        {:error, :jwks_unavailable}
    end
  end

  defp cache_put(nil, _key, _document, _cache_control, _opts, _refresh?), do: :ok

  defp cache_put(cache, key, document, cache_control, opts, refresh?) do
    bounds = Keyword.get(opts, :jwks_cache_ttl_bounds, {300, 86_400})
    expires_at = Resolver.key_cache_expires_at(cache_control, cache_ttl_bounds: bounds)

    cond do
      DateTime.after?(expires_at, DateTime.utc_now()) ->
        if cache.put(key, document, expires_at) != :ok, do: warn_cache_write_fault()

      refresh? ->
        if Cache.evict(cache, key) != :ok, do: warn_cache_write_fault()

      true ->
        :ok
    end
  rescue
    _exception -> warn_cache_write_fault()
  catch
    _kind, _reason -> warn_cache_write_fault()
  end

  defp warn_cache_read_fault do
    Logger.warning(@cache_read_warning)
    :miss
  end

  defp warn_cache_write_fault do
    Logger.warning(@cache_write_warning)
    :ok
  end

  defp verify(config, opts, assertion, issuer, issuer_opts, key_source, client_id) do
    verify_opts =
      [
        issuer: issuer,
        audience: Map.get(issuer_opts, :audience) || config.issuer,
        client_id: client_id,
        max_lifetime_seconds: Keyword.get(opts, :assertion_max_lifetime_seconds)
      ] ++ accepted_algs_opt(issuer_opts)

    case verify_with_keys(key_source, opts, assertion, verify_opts) do
      {:ok, claims} ->
        {:ok, claims}

      {:error, reason} ->
        Logger.debug("jwt_bearer: assertion rejected (#{inspect(reason)})")
        {:error, :invalid_assertion}
    end
  end

  defp verify_with_keys({:static, jwks}, _opts, assertion, verify_opts) do
    IdentityAssertion.verify(assertion, jwks, verify_opts)
  end

  defp verify_with_keys({:remote, uri}, opts, assertion, verify_opts) do
    case cache_get(Keyword.get(opts, :jwks_cache), uri, &jwks?/1) do
      {:ok, jwks} ->
        verify_cached_keys(jwks, opts, uri, assertion, verify_opts)

      :miss ->
        with {:ok, jwks} <- fetch_jwks(opts, uri), do: IdentityAssertion.verify(assertion, jwks, verify_opts)
    end
  end

  defp verify_cached_keys(jwks, opts, uri, assertion, verify_opts) do
    case IdentityAssertion.verify(assertion, jwks, verify_opts) do
      {:error, :invalid_signature} = error ->
        if unknown_kid?(assertion, jwks),
          do: refresh_and_verify_keys(opts, uri, assertion, verify_opts),
          else: error

      result ->
        result
    end
  end

  defp refresh_and_verify_keys(opts, uri, assertion, verify_opts) do
    issuer = Keyword.fetch!(verify_opts, :issuer)
    refresh = fn -> fetch_jwks(opts, uri, true) end

    case FlowControl.run(issuer, :id_jag_key_refresh, {uri, opts}, @refresh_limits, refresh) do
      {:ok, jwks} -> IdentityAssertion.verify(assertion, jwks, verify_opts)
      {:error, _reason} -> {:error, :invalid_signature}
    end
  end

  defp fetch_jwks(opts, uri, refresh? \\ false) do
    fetch_and_cache(opts, uri, &jwks?/1, fn -> fetch_document(opts, uri) end, refresh?)
  end

  defp unknown_kid?(assertion, %{"keys" => keys}) do
    case JWS.peek_json(assertion, :protected, max_compact_bytes: IdentityAssertion.max_assertion_bytes()) do
      {:ok, %{"kid" => kid}} when is_binary(kid) and kid != "" ->
        not Enum.any?(keys, &match?(%{"kid" => ^kid}, &1))

      _ ->
        false
    end
  end

  defp accepted_algs_opt(issuer_opts) do
    case Map.get(issuer_opts, :allowed_algs) do
      algs when is_list(algs) and algs != [] -> [accepted_algs: algs]
      _ -> []
    end
  end

  # Accept each assertion once by tracking its `jti` (ID-JAG draft -06 §4.4.4).
  # RFC 7519 scopes `jti` uniqueness to its issuer. Hash the verified issuer
  # and bounded `jti` into an opaque, fixed-size store key: two trusted IdPs may
  # legitimately choose the same identifier without colliding, while raw IdP
  # input never reaches a database key.
  defp prepare_replay(opts, %{"iss" => issuer, "jti" => jti, "exp" => exp})
       when is_binary(issuer) and is_binary(jti) and is_integer(exp) do
    material = <<byte_size(issuer)::unsigned-big-64, issuer::binary, jti::binary>>
    digest = :crypto.hash(:sha256, material) |> Base.url_encode64(padding: false)
    {:ok, {@jti_namespace <> digest, replay_ttl(exp, opts)}}
  end

  defp prepare_replay(_opts, _claims), do: {:error, :invalid_assertion}

  defp replay_ttl(exp, opts) do
    remaining = exp - System.system_time(:second) + 1

    case Keyword.fetch(opts, :assertion_max_lifetime_seconds) do
      {:ok, nil} ->
        max(remaining, 1)

      {:ok, max_lifetime} when is_integer(max_lifetime) and max_lifetime > 0 ->
        remaining |> min(max_lifetime + 61) |> max(1)

      _ ->
        remaining |> min(361) |> max(1)
    end
  end

  # ID-JAG draft -06 §§3.1 and 4.4.1: `scope` is OPTIONAL. When present it is the UPPER bound on what
  # the issued token may carry (the token core narrows further via the host
  # `:authorize_scope` policy). An absent scope claim places no ceiling.
  defp scope_ceiling(%{"scope" => scope}) when is_binary(scope) do
    Scope.parse(scope)
  end

  defp scope_ceiling(_claims), do: nil
end
