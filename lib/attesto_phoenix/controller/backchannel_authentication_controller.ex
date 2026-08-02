defmodule AttestoPhoenix.Controller.BackchannelAuthenticationController do
  @moduledoc """
  OpenID Connect CIBA backchannel authentication endpoint (CIBA Core 1.0 §7.1).

  Handles `POST /oauth/bc-authorize`. This module owns the HTTP framing only: it
  resolves the host `%AttestoPhoenix.Config{}`, applies no-store cache headers,
  authenticates the client, lifts the request into a plain
  `AttestoPhoenix.AuthorizationServer.BackchannelAuthentication.Request`, calls
  the conn-free core, and renders the CIBA §7.3 acknowledgement JSON (or a
  §13 / RFC 6749 §5.2 error). Every grant/binding decision lives in the core.

  Unlike the device-authorization endpoint, CIBA is **confidential-clients-only**
  (FAPI-CIBA §5.2.2): the client authenticates with `private_key_jwt` or mTLS
  (`allow_public: false`), so a public/`:none` client is rejected.

  The endpoint is served only when the host enables the grant
  (`ciba: [enabled: true]`) AND mounts it (`ciba: true` on `attesto_routes/1`);
  otherwise it responds `invalid_request` (the route should not be mounted at
  all when disabled).
  """

  use Phoenix.Controller, formats: [:json]

  import Plug.Conn

  alias AttestoPhoenix.AuthorizationServer.BackchannelAuthentication
  alias AttestoPhoenix.AuthorizationServer.BackchannelAuthentication.Request
  alias AttestoPhoenix.ClientAuthentication
  alias AttestoPhoenix.{Config, OAuthError, RequestContext}

  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, params) do
    config = Config.resolve!()
    conn = OAuthError.no_store(conn, config)

    with :ok <- require_enabled(config),
         :ok <- check_https(conn, config),
         :ok <- reject_query_credentials(conn),
         {:ok, result} <- authenticate_client(config, conn, params),
         {:ok, response} <- BackchannelAuthentication.request(config, build_request(config, conn, result, params)) do
      json(conn, response)
    else
      {:error, %OAuthError{} = err} -> render_error(conn, config, err)
    end
  end

  # RFC 6749 §2.3.1: credentials and request params belong in the form body.
  # Query-string credentials leak through access logs, caches, and browser
  # history, so reject them before client authentication (as the token/device
  # endpoints do), since Phoenix merges query and body params for the action.
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
    if Config.ciba_enabled?(config),
      do: :ok,
      else: {:error, OAuthError.new(:invalid_request, "CIBA is not enabled", status: 400)}
  end

  defp check_https(conn, config) do
    case RequestContext.check_https(conn, config) do
      :ok -> :ok
      {:error, :insecure_transport} -> {:error, OAuthError.new(:invalid_request, "TLS required", status: 400)}
    end
  end

  # FAPI-CIBA §5.2.2: the backchannel authentication endpoint accepts confidential
  # clients only (`private_key_jwt` / mTLS), so `allow_public: false`. The client
  # assertion `aud` may be the issuer identifier, the token endpoint URL, or this
  # backchannel endpoint's own URL (RFC 7523 §3: any value that identifies the
  # AS — the conformance suite exercises all three), all derived from trusted
  # `Config` (never the request `Host`).
  defp authenticate_client(config, conn, params) do
    policy = ClientAuthentication.Policy.for_endpoint(config, :backchannel_authentication)

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
      params: params
    }
  end

  defp render_error(conn, config, %OAuthError{} = err) do
    OAuthError.render(conn, err, auth_scheme: :none, config: config)
  end
end
