defmodule AttestoPhoenix.Controller.UserinfoController do
  @moduledoc """
  OpenID Connect UserInfo endpoint (OpenID Connect Core 1.0 §5.3).

  Returns claims about the authenticated subject as a JSON object. The
  endpoint is a protected resource: the caller presents the access token issued
  during authentication, and the endpoint releases the subject claims the
  token's scopes authorize.

  This controller owns the HTTP framing (`ProtectedResource.authenticate/3`,
  `no-store` headers, and `403 insufficient_scope` `WWW-Authenticate` challenge
  rendering) and delegates `openid` scope verification and OIDC Core §5.4 /
  §5.5 claim shaping to `AttestoPhoenix.AuthorizationServer.Userinfo`.

  ## Authentication

  Verification is delegated to the engine's protected-resource verify path,
  `Attesto.Plug.Authenticate`, which this controller runs at the top of its
  action. That plug parses Bearer credentials from the configured RFC 6750
  §2.1/§2.2 channels (header-only by default) or DPoP credentials from the
  `Authorization` header (RFC 9449 §7.1), verifies the access token through
  `Attesto.Token`, and - for a sender-constrained token - enforces the DPoP / mTLS binding,
  honouring `cnf.jkt` / `cnf.x5t#S256`. A DPoP-bound token presented under the
  Bearer scheme is rejected there, not here. On failure the plug halts the conn
  with the RFC 6750 §3 / RFC 9449 §7.1 `WWW-Authenticate` challenge, which this
  controller returns unchanged.

  Per OpenID Connect Core §5.3.1 both `GET` and `POST` are accepted; the host
  router maps both verbs to the `:userinfo` action.

  ## Authorization

  The verified access token MUST carry the `openid` scope (OpenID Connect Core
  §5.3.1). A token without it is answered `403` with `error="insufficient_scope"`
  and the `scope="openid"` auth-param (RFC 6750 §3.1).

  ## Claims

  The scopes on the access token (its `scope` claim, RFC 9068 §2.2.3) gate which
  claims are released (OpenID Connect Core §5.4):

    * `profile` - the OpenID Connect Core §5.4 profile claim set.
    * `email` - `email` and `email_verified`.
    * `address` - the `address` claim (a JSON object, OpenID Connect Core §5.1.1).
    * `phone` - `phone_number` and `phone_number_verified`.

  The host supplies the claim *values* through the `:build_userinfo_claims`
  callback (see `AttestoPhoenix.Config`); `AttestoPhoenix.AuthorizationServer.Userinfo`
  keeps only the values the granted scopes authorize and always includes `sub`
  (OpenID Connect Core §5.3.2), the stable subject identifier, regardless of
  scope.

  `:userinfo_scope_claims` adds claim names to a scope's set (or gives a
  host-defined scope a set), and `:userinfo_always_claims` names claims
  released for every `openid` token.

  The callback may return `{:error, :invalid_token}` to refuse a subject, for
  example one disabled after the access token was minted. The response is the
  same `401` `invalid_token` challenge a rejected token gets (RFC 6750 §3.1).

  Beyond the scope-implied set, individual claims requested through the OpenID
  Connect `claims` request parameter's `userinfo` member (OpenID Connect Core
  §5.5) are also released when `:claims_parameter_supported` is `true`. With
  the default `false`, a `claims` object on the access token is ignored.

  ## Signed responses (OpenID Connect Core §5.3.2)

  When the host configures `:client_userinfo_signed_response_alg` and it
  returns an algorithm for the client the access token was issued to, the
  response is a JWT (`Content-Type: application/jwt`) signed with this server's
  current signing key and carrying `iss` and `aud` beside the claims. The
  algorithm has to be that key's algorithm. Encrypted responses are not
  implemented.

  ## Configuration contract

  Resolved through `AttestoPhoenix.Config` (see that module for the
  authoritative definitions):

    * `:build_userinfo_claims` - the host's claim source (required to mount
      this endpoint).
    * `:issuer`, `:audience`, `:keystore`, `:access_token_ttl` - claim-level
      policy supplied to the engine verify path as an `Attesto.Config`.
    * `:resource_metadata` / `:resource_metadata_resolver` - the static or
      request-selected RFC 9728 metadata URI included in challenges, or `nil`
      to omit it for this surface.
    * `:send_error`, `:www_authenticate`, `:no_store` - the host's error
      transport hooks, honored by token verification, TLS, revocation, and
      scope failures alike.
    * `:dpop_enabled`, `:dpop_nonce_required`, `:nonce_store`, `:replay_check`,
      `:cert_der`, `:mtls_enabled`, `:htu` - sender-constraint policy and
      stores, threaded into `Attesto.Plug.Authenticate`.
  """

  use AttestoPhoenix.Controller, formats: [:json]

  import Plug.Conn

  alias AttestoPhoenix.AuthorizationServer.Userinfo
  alias AttestoPhoenix.Callback
  alias AttestoPhoenix.{Config, ProtectedResource}
  alias AttestoPhoenix.OAuthError, as: PhoenixOAuthError

  require Logger

  @openid_scope "openid"
  @insufficient_scope_description "The UserInfo endpoint requires the openid scope."

  @doc """
  UserInfo action (OpenID Connect Core §5.3). Handles both `GET` and `POST`
  (OpenID Connect Core §5.3.1).

  Named `userinfo` rather than `call` so it does not collide with the
  `Phoenix.Controller` plug entrypoint (`Phoenix.Controller.Pipeline.call/2`)
  that dispatches the action.
  """
  @spec userinfo(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def userinfo(conn, _params) do
    config = Config.resolve!(conn)

    if Config.openid_provider?(config) do
      resource_metadata = Config.resource_metadata_url(config, conn)

      case ProtectedResource.authenticate(conn, config, resource_metadata) do
        {:ok, conn, claims} ->
          respond(conn, config, resource_metadata, claims)

        {:halt, conn} ->
          conn
      end
    else
      send_resp(conn, :not_found, "")
    end
  end

  defp respond(conn, config, resource_metadata, claims) do
    case Userinfo.resolve_claims(config, claims) do
      {:ok, userinfo} ->
        send_userinfo(conn, config, resource_metadata, claims, userinfo)

      {:error, :insufficient_scope} ->
        insufficient_scope(conn, config, ProtectedResource.scheme_of(claims), resource_metadata)

      # The host's claim source refused the subject. Answer exactly as the
      # verify path answers a token it rejects (RFC 6750 §3.1).
      {:error, :invalid_token} ->
        ProtectedResource.invalid_token(conn, config, resource_metadata, claims)
    end
  end

  # OpenID Connect Core §5.3.2: JSON, or a signed JWT (`application/jwt`) for a
  # client that registered `userinfo_signed_response_alg`. The choice is
  # `Userinfo.response/3`'s.
  defp send_userinfo(conn, config, resource_metadata, claims, userinfo) do
    case Userinfo.response(config, claims, userinfo) do
      :json ->
        conn
        |> PhoenixOAuthError.no_store(config)
        |> json(userinfo)

      {:jwt, jwt} ->
        conn
        |> PhoenixOAuthError.no_store(config)
        |> put_resp_content_type("application/jwt")
        |> send_resp(200, jwt)

      {:error, :client_unavailable} ->
        ProtectedResource.invalid_token(conn, config, resource_metadata, claims)

      {:error, :unsupported_alg} ->
        # The client registered an algorithm this server does not sign with.
        # Registration refuses that, so this is a host data fault; the client
        # is not sent unsigned claims in its place.
        Logger.error("userinfo: the client's userinfo_signed_response_alg is not a supported signing algorithm")

        conn
        |> PhoenixOAuthError.no_store(config)
        |> put_status(:internal_server_error)
        |> json(%{"error" => "server_error"})
    end
  end

  # Preserve the released UserInfo-specific error text while applying the same
  # host transport hooks and validated RFC 9728 pointer as every other failure.
  # The shared core helper intentionally owns a generic description, so this
  # endpoint keeps its established wire contract at the controller boundary.
  defp insufficient_scope(conn, config, scheme, resource_metadata) do
    challenge =
      PhoenixOAuthError.format_challenge(
        scheme,
        [
          {"error", "insufficient_scope"},
          {"error_description", @insufficient_scope_description},
          {"scope", @openid_scope}
        ] ++ resource_metadata_param(resource_metadata)
      )

    body = %{
      "error" => "insufficient_scope",
      "error_description" => @insufficient_scope_description
    }

    conn
    |> apply_no_store(config)
    |> apply_www_authenticate(config, challenge)
    |> send_scope_error(config, body)
  end

  defp apply_no_store(conn, %Config{no_store: nil} = config), do: PhoenixOAuthError.no_store(conn, config)

  defp apply_no_store(conn, %Config{no_store: callback}), do: Callback.invoke(callback, [conn])

  defp apply_www_authenticate(conn, %Config{www_authenticate: nil}, challenge) do
    put_resp_header(conn, "www-authenticate", challenge)
  end

  defp apply_www_authenticate(conn, %Config{www_authenticate: callback}, challenge) do
    Callback.invoke(callback, [conn, challenge])
  end

  defp send_scope_error(conn, %Config{send_error: nil}, body) do
    conn
    |> put_status(:forbidden)
    |> json(body)
  end

  defp send_scope_error(conn, %Config{send_error: callback}, body) do
    Callback.invoke(callback, [conn, 403, body])
  end

  defp resource_metadata_param(url) when is_binary(url), do: [{"resource_metadata", url}]
  defp resource_metadata_param(_url), do: []
end
