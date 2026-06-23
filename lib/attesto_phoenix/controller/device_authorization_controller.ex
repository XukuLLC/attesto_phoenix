defmodule AttestoPhoenix.Controller.DeviceAuthorizationController do
  @moduledoc """
  OAuth 2.0 Device Authorization Endpoint (RFC 8628 §3.1).

  Handles `POST /oauth/device_authorization`. This module owns the HTTP framing
  only: it resolves the host `%AttestoPhoenix.Config{}`, applies no-store cache
  headers, authenticates the client (RFC 6749 §2.3 — public clients are admitted,
  since a browserless device with no secret is the point of the grant), lifts the
  request and the DPoP facts into a plain
  `AttestoPhoenix.AuthorizationServer.DeviceAuthorization.Request`, calls the
  conn-free core, and renders the RFC 8628 §3.2 JSON response (or an RFC 6749 §5.2
  error). Every grant/binding decision lives in the core.

  The endpoint is served only when the host enables the grant
  (`device_authorization: [enabled: true]`); otherwise it responds
  `invalid_request` (the route should not be mounted at all when disabled).
  """

  use Phoenix.Controller, formats: [:json]

  import Plug.Conn

  alias AttestoPhoenix.AuthorizationServer.DeviceAuthorization
  alias AttestoPhoenix.AuthorizationServer.DeviceAuthorization.Request
  alias AttestoPhoenix.ClientAuthentication
  alias AttestoPhoenix.ClientAuthentication.Policy
  alias AttestoPhoenix.{Config, OAuthError, RequestContext}

  @dpop_request_header "dpop"
  @http_method_post "POST"
  @client_assertion_max_lifetime 300

  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, params) do
    config = resolve_config()
    conn = put_no_store(conn)

    with :ok <- require_enabled(config),
         :ok <- check_https(conn, config),
         :ok <- reject_query_credentials(conn),
         {:ok, result} <- authenticate_client(config, conn, params),
         {:ok, response} <- DeviceAuthorization.request(config, build_request(config, conn, result, params)) do
      json(conn, response)
    else
      {:error, %OAuthError{} = err} -> render_error(conn, err)
    end
  end

  # RFC 6749 §2.3.1: credentials and request params belong in the form body.
  # Query-string credentials leak through access logs, caches, and browser
  # history, so reject them before client authentication (as the token endpoint
  # does), since Phoenix merges query and body params for the action.
  @query_credential_params ~w(client_id client_secret scope)
  defp reject_query_credentials(conn) do
    conn = fetch_query_params(conn)

    case Enum.find(@query_credential_params, &Map.has_key?(conn.query_params, &1)) do
      nil ->
        :ok

      key ->
        {:error,
         OAuthError.new(:invalid_request, "#{key} must be sent in the request body, not the query string", status: 400)}
    end
  end

  defp require_enabled(config) do
    if Config.device_authorization_enabled?(config),
      do: :ok,
      else: {:error, OAuthError.new(:invalid_request, "device authorization grant is not enabled", status: 400)}
  end

  defp check_https(conn, config) do
    case RequestContext.check_https(conn, config) do
      :ok -> :ok
      {:error, :insecure_transport} -> {:error, OAuthError.new(:invalid_request, "TLS required", status: 400)}
    end
  end

  # RFC 6749 §2.3: client authentication delegated to the shared conn-free core.
  # `allow_public: true` — the device grant exists for browserless clients that
  # may have no secret; the core then REQUIRES such a public client to present a
  # DPoP proof (sender constraint in lieu of a secret).
  defp authenticate_client(config, conn, params) do
    policy = %Policy{
      allow_public: true,
      assertion_audiences: [config.issuer],
      assertion_max_lifetime: @client_assertion_max_lifetime,
      assertion_signing_algs: config.client_auth_signing_algs
    }

    case ClientAuthentication.authenticate_with_context(get_req_header(conn, "authorization"), params, config, policy) do
      {:ok, %ClientAuthentication.Result{} = result} -> {:ok, result}
      {:error, %OAuthError{} = err, _context} -> {:error, err}
    end
  end

  defp build_request(config, conn, %ClientAuthentication.Result{} = result, params) do
    %Request{
      client: result.client,
      client_auth_method: result.method,
      request_client_id: result.client_id,
      client_ip: RequestContext.client_ip(conn, config),
      params: params,
      dpop_input: %{
        dpop_proofs: get_req_header(conn, @dpop_request_header),
        http_method: @http_method_post,
        http_uri: RequestContext.canonical_url(conn, config)
      }
    }
  end

  defp resolve_config do
    otp_app = Application.get_env(:attesto_phoenix, :otp_app)
    Config.from_otp_app(otp_app, Config)
  end

  defp render_error(conn, %OAuthError{} = err) do
    conn
    |> merge_resp_headers(err.headers)
    |> put_status(err.status)
    |> json(error_body(err))
  end

  defp error_body(%OAuthError{error: code, error_description: nil}), do: %{error: code}
  defp error_body(%OAuthError{error: code, error_description: desc}), do: %{error: code, error_description: desc}

  defp put_no_store(conn) do
    conn
    |> put_resp_header("cache-control", "no-store")
    |> put_resp_header("pragma", "no-cache")
  end
end
