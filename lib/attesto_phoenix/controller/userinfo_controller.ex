defmodule AttestoPhoenix.Controller.UserinfoController do
  @moduledoc """
  OpenID Connect UserInfo endpoint (OpenID Connect Core 1.0 §5.3).

  Returns claims about the authenticated subject as a JSON object. The
  endpoint is a protected resource: the caller presents the access token issued
  during authentication, and the endpoint releases the subject claims the
  token's scopes authorize.

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
  callback (see `AttestoPhoenix.Config`); this controller keeps only the values
  the granted scopes authorize and always includes `sub` (OpenID Connect Core
  §5.3.2), the stable subject identifier, regardless of scope.

  Beyond the scope-implied set, individual claims requested through the OpenID
  Connect `claims` request parameter's `userinfo` member (OpenID Connect Core
  §5.5) are also released. The authorization endpoint records that parameter on
  the access token (its `claims` claim) at issuance; the verify path surfaces it
  here, and the named claims are added to the release allow-list so a Relying
  Party can obtain a single claim without requesting the whole scope. A claim
  the host's source does not supply is simply omitted (a UserInfo response need
  not contain every requested claim, OpenID Connect Core §5.5). When the
  provider advertises `claims_parameter_supported: false` (the default, see
  `AttestoPhoenix.Config`), the access token carries no `claims` claim and this
  reduces to scope-gated release.

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

  alias AttestoPhoenix.Callback
  alias AttestoPhoenix.{Config, ProtectedResource}
  alias AttestoPhoenix.OAuthError, as: PhoenixOAuthError

  # OpenID Connect Core §5.3.1: the UserInfo endpoint requires the `openid`
  # scope (OpenID Connect Core §3.1.2.1).
  @openid_scope "openid"
  @insufficient_scope_description "The UserInfo endpoint requires the openid scope."

  # OpenID Connect Core §5.4: the scope -> claim-name mapping. `sub` is handled
  # separately (always returned, OpenID Connect Core §5.3.2) and is not listed.
  @scope_claims %{
    "profile" => ~w(
      name family_name given_name middle_name nickname preferred_username
      profile picture website gender birthdate zoneinfo locale updated_at
    ),
    "email" => ~w(email email_verified),
    "address" => ~w(address),
    "phone" => ~w(phone_number phone_number_verified)
  }

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
    resource_metadata = Config.resource_metadata_url(config, conn)

    case ProtectedResource.authenticate(conn, config, resource_metadata) do
      {:ok, conn, claims} ->
        respond(conn, config, resource_metadata, claims)

      {:halt, conn} ->
        conn
    end
  end

  defp respond(conn, config, resource_metadata, claims) do
    granted_scopes = granted_scopes(claims)

    # OpenID Connect Core §5.3.1: the access token must carry the `openid` scope.
    if @openid_scope in granted_scopes do
      subject = claims["sub"]
      requested_claims = requested_claims(claims)

      userinfo =
        config
        |> Config.build_userinfo_claims(subject, granted_scopes, requested_claims)
        |> shape(granted_scopes, requested_claims)
        # OpenID Connect Core §5.3.2: `sub` is always present and is the
        # verified token subject, never an unverified host-supplied value.
        |> Map.put("sub", subject)

      conn
      |> PhoenixOAuthError.no_store(config)
      |> json(userinfo)
    else
      insufficient_scope(conn, config, ProtectedResource.scheme_of(claims), resource_metadata)
    end
  end

  # OpenID Connect Core §5.4 / §5.5: keep the claims the granted scopes
  # authorize (§5.4) plus any claims individually requested for the UserInfo
  # response through the `claims` request parameter's `userinfo` member (§5.5),
  # which a Relying Party may use to obtain a claim without requesting the whole
  # scope-implied set. `sub` is added by the caller and is not gated here. A
  # claim the host did not supply is simply absent from the result (a UserInfo
  # response need not contain every requested claim, §5.5).
  defp shape(host_claims, granted_scopes, requested_claims) when is_map(host_claims) do
    allowed =
      granted_scopes
      |> Enum.flat_map(fn scope -> Map.get(@scope_claims, scope, []) end)
      |> Enum.concat(individually_requested_claim_names(requested_claims))
      |> MapSet.new()

    Map.take(host_claims, MapSet.to_list(allowed))
  end

  # OpenID Connect Core §5.5: the `claims` parameter is a JSON object whose
  # `userinfo` member names the claims to return from the UserInfo endpoint,
  # each mapped to `null` (default) or a request specification object. Only the
  # member names matter for release; the specification values are the host's to
  # honour. A missing or malformed `userinfo` member names nothing.
  defp individually_requested_claim_names(%{"userinfo" => userinfo}) when is_map(userinfo) do
    Map.keys(userinfo)
  end

  defp individually_requested_claim_names(_requested), do: []

  # RFC 9068 §2.2.3: the access token's `scope` claim is a space-delimited
  # string. An absent or malformed claim grants nothing.
  defp granted_scopes(%{"scope" => scope}) when is_binary(scope) do
    String.split(scope, ~r/\s+/, trim: true)
  end

  defp granted_scopes(_claims), do: []

  # OpenID Connect Core §5.5: individual claims are requested through the
  # `claims` request parameter, which the host may record on the access token.
  # Absent that, no individual claims are requested.
  defp requested_claims(%{"claims" => requested}) when is_map(requested), do: requested
  defp requested_claims(_claims), do: %{}

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
