defmodule AttestoPhoenix.AuthorizationServer.Introspection do
  @moduledoc """
  OAuth 2.0 Token Introspection (RFC 7662) and JWT-Secured Introspection
  Response (RFC 9701), as conn-free core.

  Evaluates token activeness through `Attesto.Introspection`, applies
  `AttestoPhoenix.ProtectedResource.access_token_revoked?/2` to contained access
  tokens, enforces the caller-authorization policy (RFC 7662 §2.2 and §4,
  RFC 9701 §5), and optionally signs the RFC 9701 JWT response via
  `Attesto.SignedIntrospection`.

  ## Caller authorization

  An active response is released only to a caller entitled to the token.
  Without `:introspection_authorize`, the caller must be the client the token
  was issued to (`client_id`) or be named in the token's `aud`. Any other
  authenticated client, including one that registered itself through open
  dynamic registration, receives `%{"active" => false}`. A protected resource
  whose resource identifier is not its `client_id` is authorized through
  `:introspection_authorize`, which replaces this default.
  """

  alias Attesto.{Introspection, SignedIntrospection}
  alias AttestoPhoenix.AuthorizationServer.SubjectIdentifier

  alias AttestoPhoenix.{
    Callback,
    Config,
    OAuthError,
    ProtectedResource,
    ResourceAudiencePolicy
  }

  alias AttestoPhoenix.Store.EctoRefreshStore

  require Logger

  # The Attesto.RefreshStore consulted for opaque refresh tokens, defaulting to
  # the package's Ecto-backed store when the host configures none.
  @default_refresh_store EctoRefreshStore
  @error_invalid_request :invalid_request

  @typedoc "RFC 7662 §2.2 introspection response map (always carries `\"active\"`)."
  @type response :: Introspection.response()

  @doc """
  Extract the required `"token"` parameter from `params`.
  """
  @spec fetch_token(map()) :: {:ok, String.t()} | {:error, OAuthError.t()}
  def fetch_token(%{"token" => token}) when is_binary(token) and token != "", do: {:ok, token}

  def fetch_token(_params) do
    {:error,
     OAuthError.new(
       @error_invalid_request,
       "the request is missing the required \"token\" parameter",
       status: 400
     )}
  end

  @doc """
  Introspect `token` for authenticated `client_id` and return the RFC 7662
  response map.
  """
  @spec introspect(Config.t(), String.t() | nil, String.t(), String.t() | nil) :: response()
  def introspect(%Config{} = config, client_id, token, token_type_hint \\ nil)
      when is_binary(token) and (is_binary(token_type_hint) or is_nil(token_type_hint)) do
    protocol_config = Config.to_attesto_config(config)

    protocol_config
    |> Introspection.introspect(token,
      refresh_store: refresh_store(config),
      issuer: config.issuer,
      token_type_hint: token_type_hint,
      trusted_audiences: ResourceAudiencePolicy.resolver(config),
      authorize: caller_authorize(config, client_id)
    )
    |> suppress_contained_access_token(config)
    |> put_caller_subject(config, client_id)
  end

  # OIDC Core §8: the caller is shown the `sub` it is shown everywhere else. A
  # pairwise caller gets its derived identifier for the token's resource
  # owner, whichever client the token was issued to, so introspection is not a
  # way to learn the host subject. When the identifier cannot be established
  # the token is reported inactive.
  defp put_caller_subject(%{"active" => true, "sub" => subject} = response, config, client_id)
       when is_binary(subject) and subject != "" do
    case SubjectIdentifier.for_client_id(config, client_id, subject) do
      {:ok, sub} -> Map.put(response, "sub", sub)
      {:error, _reason} -> %{"active" => false}
    end
  end

  defp put_caller_subject(response, _config, _client_id), do: response

  @doc """
  Sign an RFC 7662 introspection `response` map as an RFC 9701 JWT audienced to
  `client_id`.
  """
  @spec sign_response(Config.t(), String.t(), response()) :: {:ok, String.t()}
  def sign_response(%Config{} = config, client_id, response) when is_binary(client_id) and is_map(response) do
    protocol_config = Config.to_attesto_config(config)
    # The audience is the authenticated client_id, always present for a
    # successful confidential authentication (this endpoint forbids the public
    # path), so signing never depends on the optional `:client_id` callback.
    SignedIntrospection.response_jwt(protocol_config, client_id, response)
  end

  defp suppress_contained_access_token(%{"active" => true} = response, config) do
    if ProtectedResource.access_token_revoked?(config, response),
      do: %{"active" => false},
      else: response
  end

  defp suppress_contained_access_token(response, _config), do: response

  defp refresh_store(%Config{refresh_store: store}) when is_atom(store) and not is_nil(store), do: store

  defp refresh_store(%Config{}), do: @default_refresh_store

  # RFC 7662 §4 / RFC 9701 §5: build the core's caller-authorization predicate
  # from the host's optional `:introspection_authorize` callback, capturing the
  # authenticated caller's client_id. When the host configures none, no
  # predicate is passed and every authenticated caller may introspect any token
  # (the single-trust-domain default). A deliberate `false` is an ordinary
  # authorization denial. Exceptions and non-boolean returns also downgrade the
  # response to inactive, but emit one fixed warning so a policy integration
  # fault is not mistaken for a deliberate denial.
  defp caller_authorize(%Config{} = config, client_id) do
    case Callback.config_callback(config, :introspection_authorize) do
      nil -> fn response -> default_authorized?(client_id, response) end
      callback -> fn response -> introspection_authorized?(callback, client_id, response) end
    end
  end

  # RFC 7662 §2.2: a caller that is "not allowed to introspect this particular
  # token" gets `active: false`. Without a host policy, the caller is entitled
  # only to tokens issued to it or audienced to it. Letting every authenticated
  # client read any token's subject, scope and audience turns introspection into
  # a token-validation oracle for any party that can obtain client credentials,
  # which open dynamic registration hands out.
  defp default_authorized?(client_id, response) when is_binary(client_id) and client_id != "" do
    Map.get(response, "client_id") == client_id or client_id in List.wrap(Map.get(response, "aud"))
  end

  defp default_authorized?(_client_id, _response), do: false

  defp introspection_authorized?(callback, client_id, response) do
    case Callback.invoke(callback, [client_id, response]) do
      result when is_boolean(result) -> result
      _unexpected -> introspection_policy_fault()
    end
  rescue
    _exception -> introspection_policy_fault()
  catch
    _kind, _reason -> introspection_policy_fault()
  end

  defp introspection_policy_fault do
    Logger.warning("AttestoPhoenix introspection authorization callback failed; token treated as inactive")

    false
  end
end
