defmodule AttestoPhoenix.Controller.IntrospectionController do
  @moduledoc """
  `POST /oauth/introspect` - OAuth 2.0 Token Introspection (RFC 7662), with the
  signed-JWT response of RFC 9701 (FAPI 2.0 Message Signing §5.5).

  This is the thin HTTP interface over
  `AttestoPhoenix.AuthorizationServer.Introspection`: it authenticates the
  calling client, extracts the `token` parameter, delegates introspection and
  optional RFC 9701 JWT signing to the conn-free core, and renders the response
  negotiating by the `Accept` header between `application/json` (RFC 7662 §2.2)
  and `application/token-introspection+jwt` (RFC 9701).

  ## Client authentication (RFC 7662 §2.1)

  The endpoint authenticates the caller exactly as the token endpoint does,
  through the shared `AttestoPhoenix.ClientAuthentication` core
  (`client_secret_basic` / `client_secret_post` / `private_key_jwt`). Failure
  is fail-closed `invalid_client` (as the token and PAR endpoints, the shared
  `ClientAuthentication` core returns these with HTTP 400). The authenticated
  `client_id` is the audience of a signed response (RFC 9701 §5).

  ## Caching (RFC 6749 §5.1)

  Every response carries `Cache-Control: no-store` and `Pragma: no-cache`.

  ## Configuration

  Reads `AttestoPhoenix.Config` from the application environment (the same
  source the token endpoint uses): `:load_client` / `:verify_client_secret`
  (client authentication), `:keystore` / `:issuer` (signing the RFC 9701
  response), `:resource_indicators` (trusted RFC 8707 audiences), and
  `:refresh_store` (consulted for opaque refresh tokens).
  """

  use AttestoPhoenix.Controller, formats: [:json]

  import Plug.Conn

  alias AttestoPhoenix.AuthorizationServer.Introspection
  alias AttestoPhoenix.{ClientAuthentication, Config, HTTPAccept, OAuthError}
  alias AttestoPhoenix.Controller.QueryParameterGuard

  # RFC 9701 §4: the media type a caller requests (via Accept) to receive the
  # introspection response as a signed JWT, and the type of that response.
  @signed_media_type "application/token-introspection+jwt"

  # RFC 6749 §5.2 error code, held as the atom `OAuthError.new/3` requires.
  @error_invalid_request :invalid_request

  @doc """
  Handle `POST /oauth/introspect` (RFC 7662 §2.1).

  Authenticates the client, introspects the presented token, and renders the
  RFC 7662 response - as JSON, or as an RFC 9701 signed JWT when the caller's
  `Accept` requests `#{@signed_media_type}`.
  """
  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, params) when is_map(params) do
    config = Config.resolve!(conn)
    conn = OAuthError.no_store(conn, config)

    with :ok <- QueryParameterGuard.reject(conn),
         :ok <- require_https(conn, config, {:error, error(@error_invalid_request, "TLS required")}),
         {:ok, %ClientAuthentication.Result{client_id: client_id}} <-
           authenticate_client(config, conn, params),
         {:ok, token} <- Introspection.fetch_token(params) do
      respond(conn, config, client_id, token, params)
    else
      {:error, :query_parameters_not_allowed} ->
        render_error(conn, config, QueryParameterGuard.error())

      {:error, %OAuthError{} = err} ->
        render_error(conn, config, err)
    end
  end

  defp respond(conn, config, client_id, token, params) do
    response = Introspection.introspect(config, client_id, token, token_type_hint(params))

    if signed_response_requested?(conn) do
      {:ok, jwt} = Introspection.sign_response(config, client_id, response)

      conn
      |> put_resp_header("content-type", @signed_media_type)
      |> send_resp(:ok, jwt)
    else
      json(conn, response)
    end
  end

  defp token_type_hint(%{"token_type_hint" => hint}) when is_binary(hint) and hint != "", do: hint
  defp token_type_hint(_params), do: nil

  # RFC 9701 §4: the signed response is returned only when the caller explicitly
  # asks for `#{@signed_media_type}` in Accept with a non-zero quality (RFC 9110
  # §12.5.1: `q=0` means "not acceptable"); otherwise the plain JSON response is
  # returned. A bare `*/*` or `application/json` does not opt into the signed JWT.
  defp signed_response_requested?(conn) do
    conn
    |> get_req_header("accept")
    |> HTTPAccept.accepts?(@signed_media_type)
  end

  # RFC 6749 §2.3 / RFC 7662 §2.1: authenticate the caller through the shared
  # ClientAuthentication core, the same policy as the token endpoint. The client
  # assertion MUST be audienced to the issuer identifier (FAPI 2.0 §5.3.2.1),
  # derived from trusted Config (never the request Host) - the concrete endpoint
  # URL is not accepted as `aud`.
  defp authenticate_client(config, conn, params) do
    # Return the full Result; the caller reads the authenticated client_id (the
    # RFC 9701 audience) from it.
    ClientAuthentication.authenticate_request(conn, params, config, :introspection)
  end

  defp render_error(conn, config, %OAuthError{} = err) do
    OAuthError.render(conn, err, auth_scheme: :none, config: config)
  end

  # `code` is a compile-time RFC 6749 §5.2 error-code atom, passed straight to
  # `OAuthError.new/3` (no string-to-atom round-trip that could raise).
  defp error(code, description), do: OAuthError.new(code, description, status: 400)
end
