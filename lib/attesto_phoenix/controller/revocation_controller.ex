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

  The revocation endpoint requires the same client authentication as the
  token endpoint. A confidential client authenticates with
  `client_secret_basic` (HTTP Basic) or `client_secret_post` (form
  parameters). Authentication is fail-closed: a request that names a
  client but does not prove the secret is rejected `invalid_client`
  (HTTP 401, RFC 6749 §5.2), and a request that names no client at all is
  likewise rejected, since this endpoint serves confidential clients. The
  authenticated `client_id` is then threaded into revocation so one client
  cannot revoke another client's tokens (RFC 7009 §2.1).

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
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Event
  alias AttestoPhoenix.OAuthError
  alias AttestoPhoenix.RequestContext
  alias AttestoPhoenix.Store.EctoRefreshStore

  # RFC 7009 §2.2: a successful revocation request returns HTTP 200 with an
  # empty body.
  @http_ok 200

  # RFC 6749 §5.2: a malformed request is `400 invalid_request`; failed
  # client authentication is `401 invalid_client`.
  @http_bad_request 400
  @http_unauthorized 401

  # RFC 6749 §5.2 error codes.
  @error_invalid_request :invalid_request
  @error_invalid_client :invalid_client

  # RFC 7009 §2.1: the form parameter carrying the credential to revoke, and
  # the optional hint about its type (RFC 7009 §2.1).
  @token_param "token"
  @token_type_hint_param "token_type_hint"

  # The configured AttestoPhoenix.Config is threaded through the connection's
  # private storage by the host pipeline.
  # The Attesto.RefreshStore module revocation runs over. The package ships
  # an Ecto-backed implementation (parameterized by the configured repo) as
  # the default; the host pipeline may override it through conn.private to
  # select a different Attesto.RefreshStore (e.g. the single-node ETS store).
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

    with :ok <- RequestContext.check_https(conn, config),
         {:ok, %ClientAuthentication.Result{client_id: client_id}} <-
           authenticate_client(config, conn, params),
         {:ok, token} <- fetch_token(params) do
      revoke_token(conn, config, client_id, token, params)
    else
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

      {:error, %OAuthError{}} ->
        # RFC 6749 §5.2: client authentication failed. This endpoint serves
        # confidential clients authenticating with HTTP Basic, so the 401
        # carries a Basic `WWW-Authenticate` challenge.
        send_oauth_error(
          conn,
          config,
          @http_unauthorized,
          @error_invalid_client,
          "client authentication failed",
          auth_scheme: :basic,
          challenge_params: []
        )
    end
  end

  defp revoke_token(conn, config, client_id, token, params) do
    # RFC 7009 §2.1: bind the revocation to the authenticated client so a
    # client cannot revoke another client's tokens. `Attesto.Revocation`
    # returns `:ok` for an unknown, expired, or already-revoked token
    # (no-existence oracle, RFC 7009 §2.2), and `{:error,
    # :unauthorized_client}` when the token is bound to a different client.
    case Revocation.revoke(refresh_store(conn), token, client_id: client_id) do
      :ok ->
        # The token was unknown to this client OR was revoked; either way the
        # response is an indistinguishable empty 200 (no-existence oracle).
        # The audit event is emitted only on this authenticated, accepted
        # revocation request.
        emit_revoked(config, client_id, params)

      {:error, :unauthorized_client} ->
        # RFC 7009 §2.2: the authenticated client does not own this token, so
        # nothing is revoked. The endpoint must NOT reveal that the token
        # exists under another client, so it still answers an empty 200
        # rather than an error, and emits no revocation event.
        :ok
    end

    conn
    |> send_resp(@http_ok, "")
    |> halt()
  end

  # RFC 7009 §2.1: revocation accepts only client_secret_basic and
  # client_secret_post. The shared endpoint policy preserves the established
  # Basic-first precedence and deliberately does not apply the token endpoint's
  # configurable method allowlist, which the legacy revocation endpoint never
  # consulted.
  defp authenticate_client(config, conn, params) do
    policy = ClientAuthentication.Policy.for_endpoint(config, :revocation)

    ClientAuthentication.authenticate(
      AttestoPhoenix.RequestContext.client_auth_headers(conn, config),
      params,
      config,
      policy
    )
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

  # RFC 6749 §5.2: all revocation errors use the shared JSON envelope. The
  # invalid-client branch passes `auth_scheme: :basic` explicitly because this
  # endpoint's established challenge is the bare `Basic` scheme.
  defp send_oauth_error(conn, config, status, error, description, opts \\ []) do
    OAuthError.render(
      conn,
      OAuthError.new(error, description, status: status),
      Keyword.merge([config: config, auth_scheme: :none], opts)
    )
  end

  defp refresh_store(conn) do
    Map.get(conn.private, @refresh_store_key, @default_refresh_store)
  end
end
