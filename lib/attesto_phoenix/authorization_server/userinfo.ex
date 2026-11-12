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

  The scope-implied set is the OIDC Core §5.4 mapping, widened by the host's
  `:userinfo_scope_claims` (extra claim names per scope) and
  `:userinfo_always_claims` (released for every `openid` token).

  The host callback may also answer `{:error, :invalid_token}` for a subject
  that is no longer entitled to a response, for example one disabled after
  the access token was minted.
  """

  alias Attesto.Scope
  alias Attesto.SignedUserInfo
  alias AttestoPhoenix.AuthorizationServer.SubjectIdentifier
  alias AttestoPhoenix.Callback
  alias AttestoPhoenix.ClientIdMetadata
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
  The OIDC Core §5.4 scope-to-claim mapping, before any host additions.
  """
  @spec standard_scope_claims() :: %{String.t() => [String.t()]}
  def standard_scope_claims, do: @scope_claims

  @doc """
  Validate the host's `:userinfo_scope_claims` and `:userinfo_always_claims`.

  `scope_claims` must be a map from scope to a list of claim names, and
  `always_claims` a list of claim names. `sub` is refused in both: it is always
  released and always the verified token subject (§5.3.2). When
  `claims_supported` is non-empty, every configured name must appear in it.

  Raises `ArgumentError` naming the offending key.
  """
  @spec validate_release!(term(), term(), [String.t()]) :: :ok
  def validate_release!(scope_claims, always_claims, claims_supported) do
    validate_scope_claims!(scope_claims)
    validate_claim_names!(:userinfo_always_claims, always_claims)

    configured = Enum.concat([always_claims | Map.values(scope_claims)])
    validate_advertised!(configured, claims_supported)
  end

  defp validate_scope_claims!(scope_claims) when is_map(scope_claims) do
    Enum.each(scope_claims, fn {scope, names} ->
      if not (is_binary(scope) and scope != "") do
        raise ArgumentError, ":userinfo_scope_claims keys must be non-empty scope strings; got #{inspect(scope)}"
      end

      validate_claim_names!(:userinfo_scope_claims, names)
    end)
  end

  defp validate_scope_claims!(other) do
    raise ArgumentError, ":userinfo_scope_claims must be a map from scope to claim names; got #{inspect(other)}"
  end

  defp validate_claim_names!(key, names) do
    valid? = is_list(names) and Enum.all?(names, &(is_binary(&1) and &1 != ""))

    cond do
      not valid? ->
        raise ArgumentError, ":#{key} claim names must be a list of non-empty strings; got #{inspect(names)}"

      "sub" in names ->
        raise ArgumentError, ":#{key} must not name sub; it is always released as the verified token subject"

      true ->
        :ok
    end
  end

  # `:claims_supported` defaults to `[]`, which says nothing about what the
  # host can return, so there is nothing to check against.
  defp validate_advertised!(_configured, []), do: :ok

  defp validate_advertised!(configured, claims_supported) do
    case Enum.uniq(configured) -- claims_supported do
      [] ->
        :ok

      missing ->
        raise ArgumentError,
              ":userinfo_scope_claims and :userinfo_always_claims name claims absent from " <>
                ":claims_supported: #{inspect(missing)}"
    end
  end

  @doc """
  Resolve and shape the UserInfo response map for verified access-token `claims`.

  Returns `{:ok, userinfo_map}`, `{:error, :insufficient_scope}` when the
  access token lacks the `openid` scope, or `{:error, :invalid_token}` when the
  host's claim source refuses the subject.
  """
  @spec resolve_claims(Config.t(), map()) :: {:ok, map()} | {:error, :insufficient_scope | :invalid_token}
  def resolve_claims(%Config{} = config, claims) when is_map(claims) do
    granted_scopes = granted_scopes(claims)

    # OpenID Connect Core §5.3.1: the access token must carry the `openid` scope.
    if @openid_scope in granted_scopes do
      subject = claims["sub"]
      requested_claims = requested_claims(config, claims)

      config
      |> Config.build_userinfo_claims(subject, granted_scopes, requested_claims)
      |> release(config, claims, granted_scopes, requested_claims)
    else
      {:error, :insufficient_scope}
    end
  end

  defp release({:error, :invalid_token}, _config, _claims, _granted_scopes, _requested_claims),
    do: {:error, :invalid_token}

  # OpenID Connect Core §5.3.2: `sub` is always present and comes from the
  # verified token, never from a host-supplied value. It MUST equal the ID
  # Token's `sub`, so a pairwise client gets the same derived identifier here
  # (§8). When that identifier cannot be established the token is refused; the
  # host subject is not a fallback.
  defp release(host_claims, config, claims, granted_scopes, requested_claims) do
    case SubjectIdentifier.for_client_id(config, claims["client_id"], claims["sub"]) do
      {:ok, sub} ->
        {:ok, host_claims |> shape(config, granted_scopes, requested_claims) |> Map.put("sub", sub)}

      {:error, _reason} ->
        {:error, :invalid_token}
    end
  end

  @doc """
  Whether signed UserInfo responses are possible: the host configured
  `:client_userinfo_signed_response_alg`.
  """
  @spec signed_responses?(Config.t()) :: boolean()
  def signed_responses?(%Config{} = config), do: not is_nil(Config.client_userinfo_signed_response_alg_fun(config))

  @doc """
  The algorithms a UserInfo response can be signed with, or `nil` when signed
  responses are not configured. For `userinfo_signing_alg_values_supported`.
  """
  @spec signing_alg_values(Config.t()) :: [String.t()] | nil
  def signing_alg_values(%Config{} = config) do
    if signed_responses?(config), do: SignedUserInfo.signing_algs(config.keystore)
  end

  @doc """
  Decide the form of the UserInfo response for the client the access token was
  issued to (OpenID Connect Core §5.3.2).

  Returns `:json` for a client with no registered
  `userinfo_signed_response_alg` (and always when the host did not configure
  the callback, in which case no client is loaded), `{:jwt, compact_jws}` for a
  client that registered the algorithm this server signs with, and
  `{:error, :unsupported_alg | :client_unavailable}` when the client
  registered another algorithm or can no longer be loaded. A client that asked
  for a signed response is never answered with unsigned JSON.
  """
  @spec response(Config.t(), map(), map()) ::
          :json | {:jwt, String.t()} | {:error, :unsupported_alg | :client_unavailable}
  def response(%Config{} = config, token_claims, userinfo) when is_map(token_claims) and is_map(userinfo) do
    if signed_responses?(config) do
      signed_response(config, token_claims["client_id"], userinfo)
    else
      :json
    end
  end

  defp signed_response(config, client_id, userinfo) when is_binary(client_id) and client_id != "" do
    # A Client ID Metadata Document client has no registration with this
    # server to carry the algorithm, so it takes JSON.
    if ClientIdMetadata.cimd_client_id?(client_id, config) do
      :json
    else
      case Config.client_store_load(config, client_id) do
        {:ok, client} -> sign_for(config, client, client_id, userinfo)
        {:error, _reason} -> {:error, :client_unavailable}
      end
    end
  end

  defp signed_response(_config, _client_id, _userinfo), do: {:error, :client_unavailable}

  defp sign_for(config, client, client_id, userinfo) do
    case Callback.invoke(Config.client_userinfo_signed_response_alg_fun(config), [client]) do
      nil ->
        :json

      alg ->
        with {:ok, jwt} <- SignedUserInfo.response_jwt(Config.to_attesto_config(config), client_id, userinfo, alg) do
          {:jwt, jwt}
        end
    end
  end

  # OpenID Connect Core §5.4 / §5.5: keep the claims the granted scopes
  # authorize (§5.4) plus any claims individually requested for the UserInfo
  # response through the `claims` request parameter's `userinfo` member (§5.5),
  # which a Relying Party may use to obtain a claim without requesting the whole
  # scope-implied set. `sub` is added by the caller and is not gated here. A
  # claim the host did not supply is simply absent from the result (a UserInfo
  # response need not contain every requested claim, §5.5).
  defp shape(host_claims, config, granted_scopes, requested_claims) when is_map(host_claims) do
    allowed =
      granted_scopes
      |> Enum.flat_map(&scope_claim_names(config, &1))
      |> Enum.concat(config.userinfo_always_claims)
      |> Enum.concat(individually_requested_claim_names(requested_claims))
      |> MapSet.new()

    Map.take(host_claims, MapSet.to_list(allowed))
  end

  # The §5.4 names for a scope plus the host's additions for it. The host can
  # add to a standard scope or give a scope of its own a claim set; it cannot
  # take a standard claim away.
  defp scope_claim_names(%Config{userinfo_scope_claims: extra}, scope) do
    Map.get(@scope_claims, scope, []) ++ Map.get(extra, scope, [])
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
