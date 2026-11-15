defmodule AttestoPhoenix.AuthorizationServer.Authorize do
  @moduledoc """
  Conn-free OAuth 2.0 / OIDC authorization-endpoint core.

  Owns request resolution (PAR references and Request Objects), client lookup
  (registered and CIMD), request validation, effective scope & post-scope nonce
  checks (OIDC Core §3.1.2.1), authentication freshness checks (`max_age` and
  `prompt=login`), resource authorization (RFC 8707), PAR single-use claim,
  authorization-code claims/issuance, and response construction across `query`,
  `form_post`, and JARM modes.
  """

  alias Attesto.{
    AuthorizationCode,
    AuthorizationRequest,
    Claims,
    JARM,
    MapParams,
    ResourceIndicator,
    URI
  }

  alias AttestoPhoenix.AuthorizationCodePrivateContext, as: PrivateContext

  alias AttestoPhoenix.AuthorizationServer.{
    Continuation,
    RequestPolicy,
    ScopeAuthorization
  }

  alias AttestoPhoenix.{Callback, ClientIdMetadata, Config, Interaction}
  alias AttestoPhoenix.ClientIdMetadata.Client, as: CIMDClient
  alias AttestoPhoenix.OAuthError, as: PhoenixOAuthError
  alias AttestoPhoenix.Store.PAR.ETS

  require Logger

  @authorization_response_params ~w(code state iss error error_description error_uri session_state response)
  @error_invalid_target "invalid_target"
  @error_invalid_scope "invalid_scope"
  @error_login_required "login_required"
  @error_server_error "server_error"
  @prompt_none "none"

  @doc false
  @spec reserved_response_params() :: [String.t()]
  def reserved_response_params, do: @authorization_response_params

  @doc """
  Inspect query/body request parameters (excluding router path parameters) for
  interaction resumption.
  """
  @spec resume_params_status(map()) :: {:resume, String.t()} | :fresh | {:error, :resume_with_parameters}
  def resume_params_status(%{"resume" => resume_id} = request_params) do
    if map_size(request_params) == 1,
      do: {:resume, resume_id},
      else: {:error, :resume_with_parameters}
  end

  def resume_params_status(_request_params), do: :fresh

  @doc """
  Validate, resolve, and scope-authorize an authorization request.
  """
  @spec prepare_request(Config.t(), map(), map() | nil) ::
          {:ok,
           %{
             client: term(),
             request: AuthorizationRequest.t(),
             dpop_jkt: String.t() | nil,
             par_request_uri: String.t() | nil,
             credential_configuration_ids: map()
           }}
          | {:error, term()}
  def prepare_request(%Config{} = config, params, resumed_parked \\ nil) when is_map(params) do
    par_request_uri = params["request_uri"]

    with {:ok, resolved_params, par_resolved?} <- resolve_request_uri(config, params),
         {:ok, client} <- load_client(config, resolved_params),
         {:ok, request} <- validate_request(config, client, resolved_params, par_resolved?),
         :ok <- check_resumed_client(resumed_parked, request),
         {:ok, request} <- authorize_scope(config, client, request),
         require_nonce? = Callback.config_flag(config, :require_nonce),
         :ok <- AuthorizationRequest.check_nonce(request, require_nonce: require_nonce?) do
      {:ok,
       %{
         client: client,
         request: request,
         dpop_jkt: authorize_dpop_jkt(request, resolved_params, par_resolved?),
         par_request_uri:
           if(par_resolved? and is_binary(par_request_uri) and par_request_uri != "", do: par_request_uri),
         credential_configuration_ids: credential_configuration_ids(config, request)
       }}
    end
  end

  @doc """
  Verify the authentication event's `auth_time` against `max_age` (OIDC Core §3.1.2.1).
  """
  @spec check_authentication_age(AuthorizationRequest.t(), map(), map() | nil, boolean(), integer()) ::
          :ok | {:error, :auth_time_required | :invalid_auth_time | :max_age_exceeded}
  def check_authentication_age(request, subject, resumed_parked, prompt_none?, now \\ System.system_time(:second)) do
    auth_time = Map.get(subject, :auth_time)

    allowance =
      case resumed_parked do
        _any when prompt_none? -> 0
        nil -> Interaction.reauthentication_allowance_seconds()
        %{parked_at: parked_at} -> Interaction.max_age_allowance(parked_at, auth_time, now)
      end

    AuthorizationRequest.check_auth_time(request, auth_time, now, allowance: allowance)
  end

  @doc """
  Verify that `prompt=login` produced a fresh authentication event.
  """
  @spec check_prompt_login(AuthorizationRequest.t(), map(), integer(), map() | nil, integer()) ::
          {:ok, integer()} | {:error, atom()}
  def check_prompt_login(request, subject, arrived_at, resumed_parked, now \\ System.system_time(:second)) do
    {since, allowance} =
      case resumed_parked do
        %{prompt_login_since: parked_since} -> {parked_since, 0}
        nil -> {arrived_at, Interaction.reauthentication_allowance_seconds()}
      end

    case AuthorizationRequest.check_prompt_login(request, Map.get(subject, :auth_time), since,
           now: now,
           allowance: allowance
         ) do
      :ok -> {:ok, since - allowance}
      {:error, _reason} = error -> error
    end
  end

  @doc """
  Authorize requested RFC 8707 resource indicators for the client.
  """
  @spec authorize_request_resource(Config.t(), term(), AuthorizationRequest.t()) :: :ok | {:error, :invalid_target}
  def authorize_request_resource(config, client, request) do
    case ResourceIndicator.authorize(request.resource, Config.allowed_resources(config, client)) do
      {:ok, _resources} -> :ok
      {:error, :invalid_target} -> {:error, :invalid_target}
    end
  end

  @doc """
  Atomically claim a resolved PAR `request_uri` prior to issuing a code.
  """
  @spec claim_par_request_uri(Config.t(), String.t() | nil) :: :ok | :error
  def claim_par_request_uri(config, uri) when is_binary(uri) and uri != "" do
    claim_reference(
      par_store(config),
      uri,
      Callback.config_flag(config, :require_pushed_authorization_requests)
    )
  end

  def claim_par_request_uri(_config, _uri), do: :ok

  @doc """
  Assemble code claims including optional host `:authorization_code_private_context`.
  """
  @spec build_code_claims(Config.t(), AuthorizationRequest.t(), map(), map(), term(), String.t()) ::
          {:ok, map()} | {:error, term()}
  def build_code_claims(config, request, subject, credential_context, subject_id, family_id) do
    claims = base_code_claims(config, request, subject, credential_context)

    if PrivateContext.reserved?(claims) do
      {:error, :reserved_private_context_claim}
    else
      case Config.authorization_code_private_context_fun(config) do
        nil ->
          {:ok, claims}

        callback ->
          context = %{
            client_id: request.client_id,
            subject: subject_id,
            family_id: family_id,
            authentication: subject,
            scope: request.scope,
            resource: request.resource
          }

          PrivateContext.put(claims, Callback.invoke(callback, [context]))
      end
    end
  end

  @doc """
  Issue an authorization code, invoking `:authorization_code_issuance` continuation if configured.
  """
  @spec issue_code(Config.t(), map()) :: {:ok, String.t()} | {:error, term()}
  def issue_code(config, attrs) do
    issue = fn ->
      AuthorizationCode.issue(Callback.config_callback(config, :code_store), attrs, ttl: config.authorization_code_ttl)
    end

    case Config.authorization_code_issuance_fun(config) do
      nil ->
        issue.()

      callback ->
        context = %{
          client_id: attrs.client_id,
          subject: attrs.subject,
          family_id: attrs.family_id,
          private_context: Map.get(attrs.claims, PrivateContext.claims_key())
        }

        Continuation.run(issuance_profile(), &Callback.invoke(callback, &1), context, issue)
    end
  end

  @doc """
  Map a host issuance refusal error to the RFC 6749 §4.1.2.1 redirect error code.
  """
  @spec issuance_refusal_code(PhoenixOAuthError.t(), AuthorizationRequest.t()) :: String.t()
  def issuance_refusal_code(%PhoenixOAuthError{error: error}, request) do
    cond do
      error in [:access_denied, :server_error, :temporarily_unavailable] ->
        Atom.to_string(error)

      error == :login_required and @prompt_none in request.prompt ->
        @error_login_required

      true ->
        Logger.error(
          "authorization code issuance callback refused with #{inspect(error)}, which does not " <>
            "apply to this request; answered server_error"
        )

        @error_server_error
    end
  end

  @doc """
  Compute normalized response delivery parameters across `query`, `form_post`, and JARM modes.
  """
  @spec build_response(Config.t(), String.t(), String.t() | nil, String.t() | nil, map()) ::
          {:redirect, String.t()}
          | {:form_post, String.t(), [{String.t(), String.t()}]}
          | {:bad_form_post_uri, String.t()}
  def build_response(config, redirect_uri, response_mode, client_id, params) do
    case effective_response_mode(response_mode) do
      "query" ->
        {:redirect,
         URI.put_query_params(
           redirect_uri,
           Map.to_list(params) ++ iss_param(config),
           replace: @authorization_response_params
         )}

      "form_post" ->
        build_form_post(redirect_uri, "form_post", Map.to_list(params) ++ iss_param(config))

      jwt_mode ->
        {:ok, response} = JARM.response_jwt(Config.to_attesto_config(config), client_id, params)
        build_jarm_response(redirect_uri, jwt_mode, response)
    end
  end

  # ── Internals ────────────────────────────────────────────────────────────

  defp resolve_request_uri(config, %{"request_uri" => request_uri} = params)
       when is_binary(request_uri) and request_uri != "" do
    if Interaction.reserved_key?(request_uri) do
      {:error, {:direct, :invalid_request_uri}}
    else
      case fetch_par_request(par_store(config), request_uri) do
        {:ok, stored} when is_map(stored) -> resolve_stored_request(params, stored)
        _ -> resolve_missing_request_uri(request_uri, params)
      end
    end
  end

  defp resolve_request_uri(_config, params), do: {:ok, params, false}

  defp resolve_missing_request_uri(request_uri, params) do
    if par_request_uri?(request_uri) do
      {:error, {:direct, :invalid_request_uri}}
    else
      {:ok, params, false}
    end
  end

  defp par_request_uri?(request_uri), do: String.starts_with?(request_uri, "urn:ietf:params:oauth:request_uri:")

  defp resolve_stored_request(params, stored) do
    presented = params["client_id"]

    if is_binary(presented) and presented != "" and presented != stored["client_id"] do
      {:error, {:direct, :request_uri_client_mismatch}}
    else
      {:ok, stored, true}
    end
  end

  defp fetch_par_request(store, request_uri) do
    cond do
      function_exported?(store, :fetch, 1) -> store.fetch(request_uri)
      function_exported?(store, :take, 1) -> store.take(request_uri)
      true -> :error
    end
  end

  defp par_store(config), do: Map.get(config, :par_store) || ETS

  defp load_client(config, params) do
    case params["client_id"] do
      client_id when is_binary(client_id) and client_id != "" ->
        if ClientIdMetadata.cimd_client_id?(client_id, config) do
          load_cimd_client(config, client_id)
        else
          load_registered_client(config, client_id)
        end

      _ ->
        {:error, {:direct, :invalid_client_id}}
    end
  end

  defp load_registered_client(config, client_id) do
    case Config.client_store_load(config, client_id) do
      {:ok, client} -> {:ok, client}
      {:error, reason} when reason in [:not_found, :revoked] -> {:error, {:direct, :invalid_client_id}}
    end
  end

  defp load_cimd_client(config, client_id) do
    case ClientIdMetadata.resolve(client_id, config) do
      {:ok, metadata} ->
        if ClientIdMetadata.supported_by_server?(metadata, config),
          do: {:ok, %CIMDClient{metadata: metadata}},
          else: {:error, {:direct, :invalid_client_id}}

      {:error, reason} ->
        if ClientIdMetadata.transient_error?(reason),
          do: {:error, {:direct, :client_metadata_unavailable}},
          else: {:error, {:direct, :invalid_client_id}}
    end
  end

  defp validate_request(config, client, params, par_resolved?) do
    opts = [{:require_nonce, false} | RequestPolicy.request_object_opts(config, client)]

    with {:ok, request} <- RequestPolicy.validate(config, client, params, opts),
         :ok <- require_par_if_configured(config, request, par_resolved?),
         :ok <- check_storable_nonce(request) do
      {:ok, request}
    end
  end

  defp check_storable_nonce(%AuthorizationRequest{nonce: nonce} = request) when is_binary(nonce) do
    if Claims.storable_text?(nonce) do
      :ok
    else
      {:error,
       {:redirect,
        %{
          error: "invalid_request",
          error_description: "nonce is invalid",
          redirect_uri: request.redirect_uri,
          state: request.state,
          response_mode: request.response_mode,
          client_id: request.client_id
        }}}
    end
  end

  defp check_storable_nonce(_request), do: :ok

  defp require_par_if_configured(config, request, false) do
    if Callback.config_flag(config, :require_pushed_authorization_requests) do
      {:error,
       {:redirect,
        %{
          redirect_uri: request.redirect_uri,
          error: "invalid_request",
          state: request.state
        }}}
    else
      :ok
    end
  end

  defp require_par_if_configured(_config, _request, true), do: :ok

  defp check_resumed_client(nil, _request), do: :ok
  defp check_resumed_client(%{client_id: client_id}, %{client_id: client_id}), do: :ok
  defp check_resumed_client(_mismatch, _request), do: {:error, {:direct, :invalid_resume}}

  defp authorize_scope(config, client, request) do
    case ScopeAuthorization.authorize(config, client, request.scope, request.resource) do
      {:ok, granted} ->
        if ScopeAuthorization.within_request?(granted, request.scope),
          do: {:ok, %{request | scope: granted, openid?: "openid" in granted}},
          else: {:error, {:scope_refused, request, @error_invalid_scope}}

      {:error, :invalid_scope} ->
        {:error, {:scope_refused, request, @error_invalid_scope}}

      {:error, :invalid_target} ->
        {:error, {:scope_refused, request, @error_invalid_target}}
    end
  end

  defp authorize_dpop_jkt(request, params, true), do: dpop_jkt_from_params(params) || request.dpop_jkt
  defp authorize_dpop_jkt(request, _params, false), do: request.dpop_jkt

  defp dpop_jkt_from_params(%{"dpop_jkt" => jkt}) when is_binary(jkt) and jkt != "", do: jkt
  defp dpop_jkt_from_params(_params), do: nil

  defp credential_configuration_ids(config, %AuthorizationRequest{} = request) do
    supported = Config.credential_configurations_supported(config) || %{}

    from_authorization_details =
      request.authorization_details
      |> Enum.filter(&openid_credential_entry?/1)
      |> Enum.flat_map(&entry_credential_configuration_ids/1)
      |> Enum.filter(&Map.has_key?(supported, &1))

    %{
      ids: Enum.uniq(from_authorization_details ++ credential_configuration_ids_from_scope(supported, request.scope)),
      authorization_details_ids: Enum.uniq(from_authorization_details)
    }
  end

  defp credential_configuration_ids_from_scope(supported, requested) when is_list(requested) do
    for {id, configuration} <- supported,
        scope = configuration_scope(configuration),
        scope in requested,
        do: id
  end

  defp configuration_scope(configuration) when is_map(configuration),
    do: Map.get(configuration, :scope) || Map.get(configuration, "scope")

  defp configuration_scope(_configuration), do: nil
  defp openid_credential_entry?(%{"type" => "openid_credential"}), do: true
  defp openid_credential_entry?(_entry), do: false

  defp entry_credential_configuration_ids(%{"credential_configuration_id" => id}) when is_binary(id) and id != "",
    do: [id]

  defp entry_credential_configuration_ids(_entry), do: []

  defp claim_reference(store, uri, required?) do
    if function_exported?(store, :take, 1) do
      case store.take(uri) do
        {:ok, _params} -> :ok
        :error -> :error
        _invalid -> raise RuntimeError, "#{inspect(store)}.take/1 violated its PAR-store return contract"
      end
    else
      if required?, do: :error, else: :ok
    end
  end

  defp base_code_claims(config, request, subject, credential_context) do
    auth_time = Map.get(subject, :auth_time)

    %{}
    |> MapParams.put_optional("nonce", request.nonce)
    |> MapParams.put_optional("claims", supported_claims_request(config, request))
    |> MapParams.put_optional("auth_time", auth_time)
    |> MapParams.put_optional("acr", Map.get(subject, :acr))
    |> MapParams.put_optional("amr", Map.get(subject, :amr))
    |> MapParams.put_optional("sid", Map.get(subject, :sid))
    |> MapParams.put_optional("credential_configuration_ids", Map.get(credential_context, :ids))
    |> MapParams.put_optional(
      "attesto_phoenix.credential_authorization_details_ids",
      Map.get(credential_context, :authorization_details_ids)
    )
  end

  defp supported_claims_request(%Config{claims_parameter_supported: true}, request), do: request.claims
  defp supported_claims_request(_config, _request), do: nil

  defp issuance_profile do
    %{
      callback: "authorization code issuance callback",
      continuation: "authorization code issuance continuation",
      work: "authorization code issuance",
      not_done: "no code was issued",
      no_success: "no code was returned",
      no_response: "issuance did not succeed and no code was returned",
      after_success:
        "unless the host's transaction rolled back, a code was stored that the client never " <>
          "receives; it expires unredeemed",
      state_key: {__MODULE__, :authorization_code_issuance_continuation},
      succeeded?: &match?({:ok, code} when is_binary(code), &1),
      well_formed?: fn
        {:ok, code} when is_binary(code) -> true
        {:error, _reason} -> true
        _other -> false
      end,
      refusal: {:error, :issuance_callback_contract_violation}
    }
  end

  defp effective_response_mode(nil), do: "query"
  defp effective_response_mode("jwt"), do: "query.jwt"
  defp effective_response_mode(mode), do: mode

  defp build_jarm_response(redirect_uri, "query.jwt", response) do
    {:redirect, URI.put_query_params(redirect_uri, [{"response", response}], replace: @authorization_response_params)}
  end

  defp build_jarm_response(redirect_uri, "fragment.jwt", response) do
    clean_uri = URI.put_query_params(redirect_uri, [], replace: @authorization_response_params)
    {:redirect, clean_uri <> "#" <> Elixir.URI.encode_query([{"response", response}])}
  end

  defp build_jarm_response(redirect_uri, "form_post.jwt", response) do
    build_form_post(redirect_uri, "form_post.jwt", [{"response", response}])
  end

  defp build_form_post(redirect_uri, mode, fields) do
    if web_form_action?(redirect_uri) do
      clean_uri = URI.put_query_params(redirect_uri, [], replace: @authorization_response_params)
      {:form_post, clean_uri, fields}
    else
      {:bad_form_post_uri, mode}
    end
  end

  defp web_form_action?(redirect_uri) do
    case Elixir.URI.new(redirect_uri) do
      {:ok, %Elixir.URI{scheme: scheme, host: host, userinfo: nil}} when scheme in ["https", "http"] ->
        is_binary(host) and host != ""

      _ ->
        false
    end
  rescue
    _ -> false
  end

  defp iss_param(config) do
    if Callback.config_flag(config, :authorization_response_iss),
      do: [{"iss", config.issuer}],
      else: []
  end
end
