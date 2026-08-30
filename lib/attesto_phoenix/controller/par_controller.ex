defmodule AttestoPhoenix.Controller.PARController do
  @moduledoc """
  Pushed Authorization Request endpoint (RFC 9126).

  The endpoint authenticates the client, stores the submitted authorization
  request parameters behind a `request_uri`, and returns that reference to be
  used at `/oauth/authorize`. The authorization endpoint still performs the
  normal client/redirect/scope/PKCE validation when the reference is resolved.

  This controller is a thin adapter: it parses the request off the `Plug.Conn`,
  authenticates the client via `AttestoPhoenix.ClientAuthentication`
  (RFC 6749 §2.3), lifts the DPoP facts into a `%PAR.Request{}` of plain data,
  and calls `AttestoPhoenix.AuthorizationServer.PAR.store/2`. Every storage,
  credential-stripping, and DPoP-binding decision lives in that conn-free core.
  """

  use Phoenix.Controller, formats: [:json]

  import Plug.Conn

  alias AttestoPhoenix.AuthorizationServer.PAR
  alias AttestoPhoenix.{ClientAuthentication, Config, OAuthError, RequestContext}

  @dpop_request_header "dpop"

  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, params) do
    config = Config.resolve!(conn)
    conn = OAuthError.no_store(conn, config)

    with :ok <- RequestContext.check_https(conn, config),
         {:ok, auth} <- authenticate_client(config, conn, params),
         {:ok, stored} <- PAR.store(config, par_request(config, conn, auth, params)) do
      conn
      |> put_status(:created)
      |> json(stored)
    else
      {:error, :insecure_transport} ->
        render_error(conn, config, OAuthError.new(:invalid_request, "TLS required", status: 400))

      {:error, %OAuthError{} = err} ->
        render_error(conn, config, err)
    end
  end

  # RFC 6749 §2.3: client authentication is delegated to the conn-free core
  # `AttestoPhoenix.ClientAuthentication`, shared with the token endpoint. The
  # PAR endpoint's policy: a request reference established without proof of
  # possession of the client secret would let anyone who knows a confidential
  # client's `client_id` push requests in its name, so the secretless
  # public-client path is refused here (`allow_public: false`); the client
  # assertion MUST be audienced to the issuer identifier (FAPI 2.0 Security
  # Profile §5.3.2.1 / RFC 9126), derived from trusted `Config` (never the
  # request `Host`) - the concrete endpoint URL is NOT accepted as `aud`, so a
  # confused-deputy assertion minted for a different endpoint is rejected. The
  # shared endpoint policy limits the assertion to 300 seconds (RFC 7523 §3).
  defp authenticate_client(config, conn, params) do
    policy = ClientAuthentication.Policy.for_endpoint(config, :par)

    case ClientAuthentication.authenticate(
           AttestoPhoenix.RequestContext.client_auth_headers(conn, config),
           params,
           config,
           policy
         ) do
      # The whole Result is carried onward, not just the client: the identifier
      # the caller AUTHENTICATED as is what binds the stored request to its
      # pusher, and the opaque client term alone cannot supply it.
      {:ok, %ClientAuthentication.Result{} = result} -> {:ok, result}
      {:error, %OAuthError{}} = err -> err
    end
  end

  # Lift the conn facts the PAR core needs into a `%PAR.Request{}` of plain
  # data: the authenticated client, the request body, and the conn-free DPoP
  # facts (RFC 9449 §4.1 / §4.2 / §4.3 - the `DPoP` request-header values and
  # the canonical request URL/method the proof is bound to). The core reads
  # only this data; it never touches the conn.
  defp par_request(config, conn, %ClientAuthentication.Result{} = auth, params) do
    %PAR.Request{
      client: auth.client,
      client_id: auth.client_id,
      params: params,
      dpop_input: %{
        proofs: get_req_header(conn, @dpop_request_header),
        http_uri: RequestContext.canonical_url(conn, config),
        http_method: RequestContext.http_method(conn)
      }
    }
  end

  defp render_error(conn, config, %OAuthError{} = err) do
    # PAR's existing renderer returns 400 for every failure, including any
    # future core error that carries a different default status.
    OAuthError.render(conn, %{err | status: 400}, auth_scheme: :none, config: config)
  end
end
