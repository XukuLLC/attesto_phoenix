defmodule AttestoPhoenix.Controller.RevocationController do
  @moduledoc """
  `POST /oauth/revoke` - OAuth 2.0 Token Revocation (RFC 7009).

  A client presents a credential it issued and asks the authorization
  server to invalidate it. This endpoint revokes the *refresh* credential:
  revoking one refresh token tears down its whole family (every token
  descended from the same authorization), via the configured
  `Attesto.RefreshStore`. Access tokens are stateless, short-lived JWTs
  with no server-side state to drop, so a hint pointing at one is honored
  as a no-op success rather than an error (RFC 7009 §2.2).

  ## Client authentication (RFC 7009 §2.1, RFC 6749 §2.3)

  The revocation endpoint applies the same client-authentication rules as the
  token endpoint. A confidential client authenticates with its exact registered
  method, using the configured secret, private-key JWT, mTLS, or attestation
  verification policy. A registered public client uses `none` and supplies its
  `client_id`, as required by RFC 7009. Resolution is fail-closed: unknown,
  revoked, or confidential clients cannot use the public path, and a request
  that names no client is rejected `invalid_client`. Per RFC 6749 §5.2, a failed
  `Authorization` header attempt returns HTTP 401 with the matching challenge;
  body-only and absent credentials return HTTP 400 without a challenge.
  The resolved `client_id` is then threaded into revocation so one client cannot
  revoke another client's tokens (RFC 7009 §2.1).

  Client authentication is delegated to the shared
  `AttestoPhoenix.ClientAuthentication` service, which resolves clients and
  compares secrets through the host's configured callbacks; this controller
  owns no client registry or authentication parser.

  ## No-existence oracle (RFC 7009 §2.2)

  Once the client is authenticated, the response is always `HTTP 200` with
  an empty body, whether or not the presented token existed, was expired,
  or was already revoked. A revocation endpoint must not let a caller probe
  which tokens are live. The only non-200 outcomes are a malformed request
  (`invalid_request`, missing the required `token` parameter) and failed
  client authentication (`invalid_client`).

  ## Caching (RFC 6749 §5.1)

  Every response carries `Cache-Control: no-store` and `Pragma: no-cache`,
  so an intermediary never caches a revocation result.

  ## Configuration

  Built on `AttestoPhoenix.Config`. The callbacks this controller reads:

    * `:load_client` - resolve an OAuth client by `client_id`.
    * `:verify_client_secret` - constant-time client-secret comparison.
    * `:client_auth_method` - the trusted registered authentication method.
    * `:on_event` or `:event_sink` (optional) - audit/telemetry hook; receives a
      `:token_revoked` `AttestoPhoenix.Event` after a successful revocation
      request.

  The configured `AttestoPhoenix.Config` is read from
  `conn.private[:attesto_phoenix_config]`, placed there by the host's
  router pipeline. The `Attesto.RefreshStore` revocation runs over defaults
  to the package's Ecto-backed store; a host pipeline may override it by
  putting a module under `conn.private[:attesto_phoenix_refresh_store]`.
  """

  use AttestoPhoenix.Controller, formats: [:json]

  import Plug.Conn

  alias Attesto.Revocation
  alias AttestoPhoenix.ClientAuthentication
  alias AttestoPhoenix.ClientAuthentication.ErrorContext
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Controller.QueryParameterGuard
  alias AttestoPhoenix.Event
  alias AttestoPhoenix.OAuthError
  alias AttestoPhoenix.RequestContext
  alias AttestoPhoenix.Store.EctoRefreshStore

  # RFC 7009 §2.2: a successful revocation request returns HTTP 200 with an
  # empty body.
  @http_ok 200

  # RFC 6749 §5.2: malformed requests and body-authentication failures use 400;
  # a failed Authorization-header attempt uses 401.
  @http_bad_request 400
  @http_unauthorized 401

  # RFC 6749 §5.2 error codes.
  @error_invalid_request :invalid_request

  # RFC 7009 §2.1: the form parameter carrying the credential to revoke, and
  # the optional hint about its type (RFC 7009 §2.1).
  @token_param "token"
  @token_type_hint_param "token_type_hint"

  # Config.refresh_store selects the Attesto.RefreshStore used for revocation.
  # For compatibility with older host pipelines, conn.private may supply the
  # store only when the validated request config leaves refresh_store unset.
  # The package's Ecto-backed implementation remains the final default.
  @refresh_store_key :attesto_phoenix_refresh_store
  @default_refresh_store EctoRefreshStore

  @doc """
  Handle `POST /oauth/revoke` (RFC 7009 §2.1).

  Authenticates the client, then revokes the presented refresh token and
  its family. Always responds `200` once the client is authenticated,
  regardless of whether the token existed.
  """
  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, params) when is_map(params) do
    config = Config.resolve!(conn)
    # RFC 6749 §5.1: success and error responses alike carry no-store.
    conn = OAuthError.no_store(conn, config)

    with :ok <- QueryParameterGuard.reject(conn),
         :ok <- RequestContext.check_https(conn, config),
         {:ok, %ClientAuthentication.Result{client_id: client_id}} <-
           authenticate_client(config, conn, params),
         {:ok, token} <- fetch_token(params) do
      revoke_token(conn, config, client_id, token, params)
    else
      {:error, :query_parameters_not_allowed} ->
        OAuthError.render(conn, QueryParameterGuard.error(), auth_scheme: :none, config: config)

      {:error, :insecure_transport} ->
        # RFC 6749 §3.1 / §10.1: the client secret and refresh token in this
        # request must never cross a plain-HTTP hop; a credential that did is
        # treated as compromised and the request refused, exactly as every other
        # credential-bearing endpoint does (see `AttestoPhoenix.RequestContext`).
        send_oauth_error(
          conn,
          config,
          @http_bad_request,
          @error_invalid_request,
          "the request must be made over TLS"
        )

      {:error, :invalid_request} ->
        # RFC 7009 §2.1 / RFC 6749 §5.2: the required `token` parameter is
        # missing or otherwise malformed.
        send_oauth_error(
          conn,
          config,
          @http_bad_request,
          @error_invalid_request,
          "the request is missing the required \"token\" parameter"
        )

      {:error, %OAuthError{error: method_error} = error}
      when method_error in [:use_attestation_challenge, :use_fresh_attestation] ->
        OAuthError.render(conn, error, config: config, auth_scheme: :none)

      {:error, %OAuthError{} = error} ->
        OAuthError.render(conn, error, auth_scheme: :from_error_context, config: config)
    end
  end

  defp revoke_token(conn, config, client_id, token, params) do
    # RFC 7009 §2.1: bind the revocation to the authenticated client so a
    # client cannot revoke another client's tokens. `Attesto.Revocation`
    # returns `:ok` for every accepted revocation request, whether the token
    # was unknown, expired, already revoked, or owned by another client. This
    # prevents the endpoint from becoming a token-existence oracle.
    :ok =
      Revocation.revoke(refresh_store(config, conn), token,
        client_id: client_id,
        issuer: config.issuer
      )

    emit_revoked(config, client_id, params)

    conn
    |> send_resp(@http_ok, "")
    |> halt()
  end

  # RFC 7009 §2.1: confidential clients use their registered authentication
  # method, while public clients identify themselves with client_id. The shared
  # policy applies the server allowlist, verifies the registered method, and
  # preserves established Basic-first precedence over redundant body
  # credentials.
  defp authenticate_client(config, conn, params) do
    policy = ClientAuthentication.Policy.for_endpoint(config, :revocation)

    case ClientAuthentication.authenticate_with_context(
           AttestoPhoenix.RequestContext.client_auth_headers(conn, config),
           params,
           config,
           policy
         ) do
      {:ok, %ClientAuthentication.Result{} = result} ->
        {:ok, result}

      {:error, %OAuthError{} = error, %ErrorContext{} = context} ->
        {:error, revocation_client_auth_error(config, error, context)}
    end
  end

  # RFC 7009 §2.1 delegates authentication failures to RFC 6749 §5.2. A failed
  # Authorization-header attempt receives 401 and a challenge for the attempted
  # scheme. Body credentials, a public client_id, and absent credentials remain
  # 400 responses and do not advertise an unrelated authentication method.
  defp revocation_client_auth_error(config, %OAuthError{error: :invalid_client} = error, %ErrorContext{
         authorization_scheme: scheme
       })
       when is_binary(scheme) do
    %{
      error
      | status: @http_unauthorized,
        headers: put_www_authenticate(error.headers, OAuthError.format_challenge(scheme, realm: config.basic_realm))
    }
  end

  defp revocation_client_auth_error(_config, %OAuthError{} = error, _context), do: error

  defp put_www_authenticate(headers, challenge) do
    headers
    |> Enum.reject(fn {key, _value} -> String.downcase(key) == "www-authenticate" end)
    |> Kernel.++([{"www-authenticate", challenge}])
  end

  defp fetch_token(params) do
    case Map.get(params, @token_param) do
      token when is_binary(token) and token != "" ->
        {:ok, token}

      # RFC 7009 §2.1: `token` is REQUIRED.
      _missing ->
        {:error, :invalid_request}
    end
  end

  # Audit/telemetry hook (RFC 7009 leaves auditing to the deployment). The
  # resolved event callback is optional, so a config without one is a silent
  # no-op. The event is emitted only after a successful, authenticated
  # revocation request; its metadata carries the optional `token_type_hint`
  # for context but never the token value.
  defp emit_revoked(%Config{} = config, client_id, params) do
    Event.emit(config, :token_revoked,
      client_id: client_id,
      metadata: %{token_type_hint: Map.get(params, @token_type_hint_param)}
    )
  end

  # RFC 6749 §5.2: non-authentication revocation errors use the shared JSON
  # envelope without adding a challenge.
  defp send_oauth_error(conn, config, status, error, description, opts \\ []) do
    OAuthError.render(
      conn,
      OAuthError.new(error, description, status: status),
      Keyword.merge([config: config, auth_scheme: :none], opts)
    )
  end

  # Compatibility for older host pipelines that staged a store in conn.private:
  # an explicit validated Config.refresh_store always wins. The private seam is
  # used only when the config leaves the store unset.
  defp refresh_store(%Config{refresh_store: nil}, conn),
    do: Map.get(conn.private, @refresh_store_key, @default_refresh_store)

  defp refresh_store(%Config{refresh_store: store}, _conn), do: store
end
