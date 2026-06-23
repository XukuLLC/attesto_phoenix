defmodule AttestoPhoenix.AuthorizationServer.DeviceAuthorization do
  @moduledoc """
  Device authorization request processing (RFC 8628 §3.1 / §3.2), as conn-free
  core.

  Turns an authenticated client and a parsed device-authorization request into
  the RFC 8628 §3.2 response body (`device_code`, `user_code`,
  `verification_uri`, `verification_uri_complete`, `expires_in`, `interval`),
  binding the requested `scope`, the RFC 8707 `resource` indicator(s), and — when
  presented — the RFC 9449 DPoP holder-of-key onto the issued device code. The
  thin `AttestoPhoenix.Controller.DeviceAuthorizationController` parses the
  request off the `Plug.Conn`, authenticates the client (RFC 6749 §2.3), lifts
  the conn facts into a `%Request{}` of plain data, and calls `request/2`.

  ## DPoP for public clients (security)

  A device code travels on a pollable channel with no PKCE backstop and no
  redirect to bind, so a public (`:none`) client's resulting token would be a
  freely-replayable bearer token. Mirroring the public-client refresh-token rule
  (RFC 9449 §8), a public client MUST present a DPoP proof at this endpoint; the
  proof's key is pre-bound to the device code and the token endpoint requires the
  matching proof at redemption. Confidential clients may opt out.
  """

  alias Attesto.{DeviceCode, ResourceIndicator, Scope}
  alias Attesto.DPoP
  alias Attesto.DPoP.ReplayCache
  alias AttestoPhoenix.{Callback, Config, OAuthError}

  @error_invalid_scope :invalid_scope
  @error_invalid_target :invalid_target
  @error_invalid_dpop_proof :invalid_dpop_proof
  @error_invalid_client :invalid_client
  @error_server_error :server_error

  defmodule Request do
    @moduledoc "Plain-data device-authorization request the controller builds from the conn."
    @enforce_keys [:client]
    defstruct [:client, :client_auth_method, :client_ip, params: %{}, dpop_input: %{}]

    @type t :: %__MODULE__{
            client: term(),
            client_auth_method: atom() | nil,
            client_ip: String.t() | nil,
            params: map(),
            dpop_input: map()
          }
  end

  @typedoc "The RFC 8628 §3.2 device-authorization response body (atom keys)."
  @type response :: %{required(atom()) => term()}

  @doc """
  Process a device-authorization request, returning the §3.2 response body or an
  `AttestoPhoenix.OAuthError`.
  """
  @spec request(Config.t(), Request.t()) :: {:ok, response()} | {:error, OAuthError.t()}
  def request(%Config{} = config, %Request{} = request) do
    %{client: client, params: params} = request

    with {:ok, store} <- require_store(config),
         {:ok, scope} <- parse_scope(params),
         {:ok, resource} <- resolve_resource(config, client, params),
         {:ok, dpop_jkt} <- resolve_dpop(config, request),
         :ok <- require_dpop_for_public(request, dpop_jkt),
         {:ok, issued} <- issue(store, config, client, scope, resource, dpop_jkt) do
      {:ok, response_body(config, issued)}
    end
  end

  defp require_store(%Config{} = config) do
    case Config.device_code_store(config) do
      store when is_atom(store) and not is_nil(store) -> {:ok, store}
      _ -> {:error, error(@error_server_error, "device authorization is not configured")}
    end
  end

  # RFC 8628 §3.1: scope is OPTIONAL and space-delimited; it is bound to the
  # device code here and authorized (host scope policy) at the token endpoint
  # after the user approves, mirroring the authorization-code flow.
  defp parse_scope(params) do
    case Map.get(params, "scope") do
      nil ->
        {:ok, []}

      value when is_binary(value) ->
        tokens = String.split(value, " ", trim: true)

        if Enum.all?(tokens, &Scope.valid_token?/1),
          do: {:ok, tokens},
          else: {:error, error(@error_invalid_scope, "scope contains an invalid token")}

      _ ->
        {:error, error(@error_invalid_scope, "scope must be a string")}
    end
  end

  # RFC 8707 §2: validate (§2.1) + authorize (§2.2) the requested resource
  # indicator(s) and bind them to the device code, exactly as the authorize
  # endpoint binds them to an authorization code.
  defp resolve_resource(config, client, params) do
    with {:ok, resources} <- validate_resource(params) do
      case ResourceIndicator.authorize(resources, Config.allowed_resources(config, client)) do
        {:ok, resources} -> {:ok, resources}
        {:error, :invalid_target} -> {:error, error(@error_invalid_target, "the requested resource is not served")}
      end
    end
  end

  defp validate_resource(params) do
    case ResourceIndicator.validate(Map.get(params, "resource")) do
      {:ok, resources} ->
        {:ok, resources}

      {:error, :invalid_target} ->
        {:error, error(@error_invalid_target, "resource is not a valid absolute-URI indicator")}
    end
  end

  # RFC 9449: pre-bind a presented DPoP proof's key to the device code (the
  # token endpoint requires the matching proof at redemption). No proof → no
  # binding (subject to the public-client rule below). More than one proof is
  # an ambiguous request (RFC 9449 §4.1).
  defp resolve_dpop(config, %Request{dpop_input: dpop_input}) do
    case Map.get(dpop_input, :dpop_proofs, []) do
      [] ->
        {:ok, nil}

      [proof] ->
        opts = [
          http_method: Map.get(dpop_input, :http_method, "POST"),
          http_uri: Map.get(dpop_input, :http_uri),
          replay_check: replay_check(config)
        ]

        case DPoP.verify_proof(proof, opts) do
          {:ok, %{jkt: jkt}} -> {:ok, jkt}
          {:error, reason} -> {:error, error(@error_invalid_dpop_proof, "invalid DPoP proof: #{inspect(reason)}")}
        end

      _multiple ->
        {:error, error(@error_invalid_dpop_proof, "multiple DPoP proofs")}
    end
  end

  # Security: a public (`:none`) client must sender-constrain its device-issued
  # token (no PKCE/redirect backstop), so it MUST pre-bind a DPoP key here.
  defp require_dpop_for_public(%Request{client_auth_method: :none}, nil),
    do: {:error, error(@error_invalid_client, "a public client must present a DPoP proof for the device grant")}

  defp require_dpop_for_public(_request, _dpop_jkt), do: :ok

  defp issue(store, config, client, scope, resource, dpop_jkt) do
    opts = Config.device_authorization(config)

    attrs =
      %{client_id: client_id(config, client), scope: scope, resource: resource}
      |> put_optional(:dpop_jkt, dpop_jkt)

    DeviceCode.issue(store, attrs,
      ttl: Keyword.get(opts, :code_ttl_seconds),
      user_code_length: Keyword.get(opts, :user_code_length)
    )
  end

  defp response_body(config, %{device_code: device_code, user_code: user_code}) do
    opts = Config.device_authorization(config)
    verification_uri = Config.device_verification_uri(config)

    %{
      device_code: device_code,
      user_code: user_code,
      verification_uri: verification_uri,
      # RFC 8628 §3.3.1: the URI with the user_code embedded for QR/deep-link UX.
      verification_uri_complete: verification_uri <> "?user_code=" <> user_code,
      expires_in: Keyword.get(opts, :code_ttl_seconds),
      interval: Keyword.get(opts, :poll_interval_seconds)
    }
  end

  defp client_id(config, client), do: Callback.invoke(Config.client_id_fun(config), [client], nil)

  defp replay_check(%Config{replay_check: nil}), do: &ReplayCache.check_and_record/2
  defp replay_check(%Config{replay_check: callback}), do: Callback.to_fun2(callback)

  defp put_optional(map, _key, nil), do: map
  defp put_optional(map, key, value), do: Map.put(map, key, value)

  defp error(code, description), do: OAuthError.new(code, description, status: 400)
end
