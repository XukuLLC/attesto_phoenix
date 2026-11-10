defmodule AttestoPhoenix.AuthorizationServer.Userinfo do
  @moduledoc """
  OpenID Connect UserInfo claim resolution and scope-gated release (OpenID
  Connect Core 1.0 §5.3 / §5.4 / §5.5), as conn-free core.

  Verifies that the authenticated access-token claims carry the `openid` scope
  (OIDC Core §5.3.1), invokes the host's `:build_userinfo_claims` callback,
  filters the returned claims to those authorized by the granted scopes (§5.4)
  or individually requested via `claims.userinfo` (§5.5), and pins `sub` to the
  verified token subject (§5.3.2).

  Individually requested claims are honoured only when the provider supports
  the `claims` request parameter (`:claims_parameter_supported`). Otherwise a
  `claims` object recorded on the access token is ignored: the host callback
  receives `%{}` and only the scope-implied claims are released.
  """

  alias Attesto.Scope
  alias AttestoPhoenix.Config

  # OpenID Connect Core §5.3.1: the UserInfo endpoint requires the `openid`
  # scope (OpenID Connect Core §3.1.2.1).
  @openid_scope "openid"

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
  Resolve and shape the UserInfo response map for verified access-token `claims`.

  Returns `{:ok, userinfo_map}` or `{:error, :insufficient_scope}` when the
  access token lacks the `openid` scope.
  """
  @spec resolve_claims(Config.t(), map()) :: {:ok, map()} | {:error, :insufficient_scope}
  def resolve_claims(%Config{} = config, claims) when is_map(claims) do
    granted_scopes = granted_scopes(claims)

    # OpenID Connect Core §5.3.1: the access token must carry the `openid` scope.
    if @openid_scope in granted_scopes do
      subject = claims["sub"]
      requested_claims = requested_claims(config, claims)

      userinfo =
        config
        |> Config.build_userinfo_claims(subject, granted_scopes, requested_claims)
        |> shape(granted_scopes, requested_claims)
        # OpenID Connect Core §5.3.2: `sub` is always present and is the
        # verified token subject, never an unverified host-supplied value.
        |> Map.put("sub", subject)

      {:ok, userinfo}
    else
      {:error, :insufficient_scope}
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
    Scope.parse(scope, whitespace: :ascii_whitespace)
  end

  defp granted_scopes(_claims), do: []

  # OpenID Connect Core §5.5: individual claims are requested through the
  # `claims` request parameter, which the host may record on the access token.
  # A provider that does not support that parameter (OpenID Connect Discovery
  # §3 `claims_parameter_supported`) gives it no effect, so a recorded `claims`
  # object cannot widen the release beyond the granted scopes. Access tokens
  # issued from a refresh family keep the original code's `claims` object, so
  # the check is made here at release and not only where codes are issued.
  defp requested_claims(%Config{claims_parameter_supported: true}, %{"claims" => requested}) when is_map(requested),
    do: requested

  defp requested_claims(_config, _claims), do: %{}
end
