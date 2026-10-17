defmodule AttestoPhoenix.Controller.PARController do
  @moduledoc """
  Pushed Authorization Request endpoint (RFC 9126).

  The endpoint authenticates confidential clients and identifies registered
  public clients by `client_id`, stores the submitted authorization request
  parameters behind a `request_uri`, and returns that reference to be used at
  `/oauth/authorize`. The authorization endpoint still performs the normal
  client/redirect/scope/PKCE validation when the reference is resolved.

  This controller is a thin adapter: it parses the request off the `Plug.Conn`,
  authenticates the client via `AttestoPhoenix.ClientAuthentication`
  (RFC 6749 §2.3), lifts the DPoP facts into a `%PAR.Request{}` of plain data,
  and calls `AttestoPhoenix.AuthorizationServer.PAR.store/2`. Every storage,
  credential-stripping, and DPoP-binding decision lives in that conn-free core.
  """

  use AttestoPhoenix.Controller, formats: [:json]

  import Plug.Conn

  alias AttestoPhoenix.AuthorizationServer.PAR
  alias AttestoPhoenix.{ClientAuthentication, Config, OAuthError, RequestContext}
  alias AttestoPhoenix.Controller.QueryParameterGuard

  @dpop_request_header "dpop"

  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, params) do
    config = Config.resolve!(conn)
    conn = OAuthError.no_store(conn, config)

    with :ok <- QueryParameterGuard.reject(conn),
         :ok <- RequestContext.check_https(conn, config),
         {:ok, auth} <- authenticate_client(config, conn, params),
         {:ok, stored} <- PAR.store(config, par_request(config, conn, auth, params)) do
      conn
      |> put_status(:created)
      |> json(stored)
    else
      {:error, :query_parameters_not_allowed} ->
        render_error(conn, config, QueryParameterGuard.error())

      {:error, :insecure_transport} ->
        render_error(conn, config, OAuthError.new(:invalid_request, "TLS required", status: 400))

      {:error, %OAuthError{} = err} ->
        render_error(conn, config, err)
    end
  end

  # RFC 9126 §2.1: PAR applies the token endpoint's client-authentication rules.
  # Confidential clients authenticate with their registered method; registered
  # public clients use `none` and identify themselves with `client_id`. The
  # shared service resolves that client and enforces its registered method, so
  # a confidential client cannot be downgraded onto the public path. A client
  # assertion MUST be audienced to the issuer identifier under the FAPI 2.0
  # Security Profile §5.3.2.1, derived from trusted `Config` (never the
  # request `Host`) - the concrete endpoint URL is NOT accepted as `aud`, so a
  # confused-deputy assertion minted for a different endpoint is rejected. The
  # shared endpoint policy limits the assertion to 300 seconds (RFC 7523 §3).
  defp authenticate_client(config, conn, params) do
    case ClientAuthentication.authenticate_request(conn, params, config, :par) do
      # The whole Result is carried onward, not just the client: the identifier
      # the service resolved and authenticated where applicable is what binds
      # the stored request to its pusher, and the opaque client term alone
      # cannot supply it.
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
        http_uri:
          RequestContext.canonical_url(
            conn,
            config,
            Config.par_endpoint_url(config),
            "pushed_authorization_request_endpoint"
          ),
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
