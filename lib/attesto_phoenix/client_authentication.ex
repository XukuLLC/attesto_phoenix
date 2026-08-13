defmodule AttestoPhoenix.ClientAuthentication do
  @moduledoc """
  OAuth 2.0 client authentication (RFC 6749 §2.3), as conn-free core.

  This is the single place that turns the request's `Authorization` header and
  body parameters into either an authenticated client or an
  `AttestoPhoenix.OAuthError`. It is shared by the token endpoint
  (RFC 6749 §3.2) and the Pushed Authorization Request endpoint (RFC 9126):
  both authenticate the client identically; only the policy around the
  secretless/public path and the event/wire rendering differ, and those are
  the caller's concern.

  ## Methods

  Accepts HTTP Basic credentials (RFC 6749 §2.3.1, RFC 7617), request-body
  credentials (RFC 6749 §2.3.1), `private_key_jwt` assertions (RFC 7523 / OIDC
  Core §9), RFC 8705 `tls_client_auth` and `self_signed_tls_client_auth`, and
  Client Attestation JWT + PoP header pairs. Presenting more than one
  client-authentication method is rejected (RFC 6749 §2.3).

  A presented client certificate is not inherently a second authentication
  method: RFC 8705 certificate-bound tokens use it independently as
  proof-of-possession. Explicit Basic, post-body, JWT, or attestation
  credentials therefore retain their normal classification while the token
  service consumes the certificate separately as a sender constraint. With no
  other credential, the registered mTLS method authenticates the client; a
  public client may instead remain on the `none` path and use the certificate
  only for binding.

  ## Native apps (RFC 8252 §8.4)

  A client the host marks native (`:client_native?`) may authenticate with
  `none` or with `attest_jwt_client_auth`, whose Wallet Provider attestation and
  per-instance key prove possession without relying on an app-wide secret. A
  native app cannot keep a static credential confidential - its binary is on
  the end user's device - so presenting a client secret or `private_key_jwt`
  assertion is refused with the same generic `invalid_client` message as any
  other failure.

  The one exception is the one §8.4 makes: a native client the host
  *explicitly* classifies as confidential (`:client_public?` returning `false`)
  is taken to hold per-instance credentials from dynamic registration, and keeps
  the secret path. An absent `:client_public?` callback is not that
  classification and resolves to public, so a host that wires `:client_native?`
  alone still gets §8.4 enforcement rather than silently accepting a shipped
  secret.

  `:client_native?` itself defaults to `false`, so none of this affects a host
  that has not classified its clients.

  ## Client ID Metadata Documents (CIMD)

  When CIMD (`draft-ietf-oauth-client-id-metadata-document-01`) is enabled and
  the presented `client_id` is a CIMD URL, the client is dereferenced from that
  URL (`AttestoPhoenix.ClientIdMetadata`) rather than looked up in the host
  registry. A CIMD client carries no shared symmetric secret (the document
  validation strips `client_secret_*` and the symmetric auth methods), so it can
  only authenticate as a **public client** (`none` + PKCE) or with
  **`private_key_jwt`** keyed by the document's `jwks` / `jwks_uri`. The Basic /
  body-secret paths therefore never resolve a CIMD client: a `client_secret`
  presented for a CIMD `client_id` finds no secret to verify and fails with the
  generic `invalid_client` message like any other failed authentication. CIMD
  resolution is consulted only on the secretless (`none`) and `private_key_jwt`
  paths, where the host registry would not hold the URL.

  ## Policy

  The one decision that differs between callers is carried as data on
  `AttestoPhoenix.ClientAuthentication.Policy`:

    * `:allow_public` - whether a client identified without a secret/assertion
      may authenticate as a public client (RFC 6749 §2.1), relying on PKCE
      (RFC 7636) downstream. The token endpoint allows this; the PAR endpoint
      does not, because a request reference established without proof of
      possession of the client secret would let anyone who knows a
      confidential client's `client_id` push requests in its name. When
      `false`, a body `client_id` without a secret is rejected with
      `invalid_client` "client authentication required".
    * `:assertion_audiences` - the acceptable `aud` values for a
      `private_key_jwt` assertion (RFC 7523 §3: the authorization server
      identifier, commonly the issuer or token endpoint URL).
    * `:assertion_max_lifetime` - the maximum assertion lifetime, in seconds,
      and the replay-record TTL (RFC 7523 §3).
    * `:assertion_signing_algs` - the trusted JOSE algorithm allowlist for the
      assertion.
    * `:assertion_enforce_fapi_alg_policy` - whether trusted assertion keys must
      also satisfy FAPI's RSA modulus and Edwards-curve restrictions. `nil`
      preserves the explicit-algorithm behavior of older policy structs.
    * `:allowed_methods` - the authentication methods admitted by the endpoint.
    * `:basic_precedence` - whether a Basic header wins over body credentials.
    * `:honor_configured_methods` - whether the endpoint also applies the
      configured `token_endpoint_auth_methods_supported` allowlist.

  ## Return value

  `authenticate/4` returns `{:ok, %Result{client, client_id, method}}` or
  `{:error, %AttestoPhoenix.OAuthError{}}`. `authenticate_with_context/4`
  keeps the same successful return and adds transport context to errors for
  endpoints that must distinguish `Authorization`-header authentication attempts
  while rendering. Both functions read only data: request header values and
  parsed body params. For backward compatibility, their first argument may be
  the existing list of `Authorization` values. Callers that support
  `attest_jwt_client_auth` pass a map with `:authorization`,
  `:oauth_client_attestation`, and `:oauth_client_attestation_pop` lists. It
  never touches a conn and never emits an event - the caller renders the
  result/error and emits whatever audit event it owns.

  ## Security details preserved

    * On an unknown/revoked client, a dummy `verify_client_secret/2` call
      against `:unknown_client` runs so the lookup-failure path matches the
      wrong-secret path in observable timing (RFC 6749 §2.3 / OWASP).
    * Every client-authentication failure returns the single generic
      `invalid_client` "client authentication failed" message, so an attacker
      cannot tell an unknown client from a wrong secret.
    * Presenting more than one authentication method is rejected with
      `invalid_request` (RFC 6749 §2.3).
  """

  alias Attesto.{ClientAssertion, MTLS, WalletAttestation}
  alias AttestoPhoenix.{Callback, ClientIdMetadata, Config, DPoP.Adapter, OAuthError}
  alias AttestoPhoenix.ClientIdMetadata.Client, as: CIMDClient

  defmodule Policy do
    @moduledoc """
    The per-caller policy for `AttestoPhoenix.ClientAuthentication`.

    See the parent module for the meaning of each field. Expressed as data so
    a caller passes its policy rather than toggling a behaviour flag inside the
    core.
    """

    alias AttestoPhoenix.Config

    @type t :: %__MODULE__{
            allow_public: boolean(),
            assertion_audiences: [String.t()],
            assertion_max_lifetime: pos_integer(),
            assertion_signing_algs: [String.t()],
            assertion_enforce_fapi_alg_policy: boolean() | nil,
            allowed_methods: [method()],
            basic_precedence: boolean(),
            honor_configured_methods: boolean()
          }

    @type method ::
            :client_secret_basic
            | :client_secret_post
            | :private_key_jwt
            | :attest_jwt_client_auth
            | :tls_client_auth
            | :self_signed_tls_client_auth
            | :none

    @all_methods [
      :client_secret_basic,
      :client_secret_post,
      :private_key_jwt,
      :attest_jwt_client_auth,
      :tls_client_auth,
      :self_signed_tls_client_auth,
      :none
    ]

    @enforce_keys [
      :allow_public,
      :assertion_audiences,
      :assertion_max_lifetime,
      :assertion_signing_algs
    ]
    defstruct [
      :allow_public,
      :assertion_audiences,
      :assertion_max_lifetime,
      :assertion_signing_algs,
      :assertion_enforce_fapi_alg_policy,
      allowed_methods: @all_methods,
      basic_precedence: false,
      honor_configured_methods: true
    ]

    @client_assertion_max_lifetime 300

    @type endpoint ::
            :token
            | :par
            | :introspection
            | :device_authorization
            | :backchannel_authentication
            | :revocation

    @doc """
    Build the client-authentication policy for an endpoint.

    This is the authoritative endpoint matrix. The client-authentication
    methods themselves remain the configured Basic, post-body, and
    `private_key_jwt` methods; `allow_public` controls whether the `none`
    method is admitted. Revocation uses the same service with its RFC 7009
    Basic/post-only policy and Basic precedence over body credentials.
    """
    @spec for_endpoint(Config.t(), endpoint()) :: t()
    def for_endpoint(%Config{} = config, endpoint) do
      {allow_public, assertion_audiences} =
        case endpoint do
          :token ->
            {true, Config.client_assertion_audiences(config)}

          :par ->
            {false, [config.issuer]}

          :introspection ->
            {false, [config.issuer]}

          :device_authorization ->
            {true, [config.issuer]}

          :backchannel_authentication ->
            {false,
             [
               config.issuer,
               Config.token_endpoint_url(config),
               Config.backchannel_authentication_endpoint_url(config)
             ]}

          :revocation ->
            {false, []}
        end

      {allowed_methods, basic_precedence, honor_configured_methods} =
        case endpoint do
          :revocation ->
            {[:client_secret_basic, :client_secret_post], true, false}

          _other ->
            {@all_methods, false, true}
        end

      %__MODULE__{
        allow_public: allow_public,
        assertion_audiences: assertion_audiences,
        assertion_max_lifetime: @client_assertion_max_lifetime,
        assertion_signing_algs: config.client_auth_signing_algs,
        assertion_enforce_fapi_alg_policy: config.client_auth_enforce_fapi_alg_policy,
        allowed_methods: allowed_methods,
        basic_precedence: basic_precedence,
        honor_configured_methods: honor_configured_methods
      }
    end
  end

  defmodule Result do
    @moduledoc """
    The authenticated client and how it authenticated.

    `:client` is the opaque host client value returned by `:load_client`,
    `:client_id` is the OAuth identifier (RFC 6749 §2.2) carried by the
    credentials (the Basic/body `client_id` or the assertion `sub`). When the
    host's optional `:client_id` callback supplies an identifier, it must agree
    exactly with the credential-carried value. Library-produced successful
    results therefore always contain a non-empty `client_id`; the field remains
    optional on the public struct for source compatibility. `:method` is the
    RFC 6749 §2.3 / OIDC Core §9 authentication method
    (`:client_secret_basic`, `:client_secret_post`, `:private_key_jwt`,
    `:tls_client_auth`, `:self_signed_tls_client_auth`,
    `:attest_jwt_client_auth`, or `:none` for the public-client path).
    """

    @type method ::
            :client_secret_basic
            | :client_secret_post
            | :private_key_jwt
            | :attest_jwt_client_auth
            | :tls_client_auth
            | :self_signed_tls_client_auth
            | :none

    @type t :: %__MODULE__{
            client: term(),
            client_id: String.t() | nil,
            method: method()
          }

    @enforce_keys [:client, :method]
    defstruct [:client, :client_id, :method]
  end

  defmodule ErrorContext do
    @moduledoc """
    Transport facts known while classifying client authentication.

    `:authorization_scheme` is the request-header authentication scheme the
    client attempted, `"Basic"` for a present but unusable scheme token, or
    `nil` when no `Authorization` header was present. It is intentionally
    detached from the error code: callers decide whether a particular OAuth
    error should be rendered with a challenge.
    """

    @type t :: %__MODULE__{
            authorization_scheme: String.t() | nil
          }

    defstruct [:authorization_scheme]
  end

  # RFC 6749 §5.2 error codes.
  @error_invalid_request "invalid_request"
  @error_invalid_client "invalid_client"

  @auth_scheme_re ~r/\A[!#$%&'*+\-.^_`|~0-9A-Za-z]+\z/

  # Generic, non-revealing message for any failure on the client
  # authentication path (RFC 6749 §2.3): an attacker must not be able to tell
  # an unknown client from a wrong secret.
  @client_auth_failed "client authentication failed"

  @type request_headers ::
          [String.t()]
          | %{
              optional(:authorization) => [String.t()],
              optional(:oauth_client_attestation) => [String.t()],
              optional(:oauth_client_attestation_pop) => [String.t()],
              optional(:client_certificate) => map() | nil
            }

  @doc """
  Authenticate the client from the request's `Authorization` header values and
  body params (RFC 6749 §2.3).

  `request_headers` may be the list of `Authorization` header values (the
  backward-compatible form) or a map containing `:authorization`,
  `:oauth_client_attestation`, and `:oauth_client_attestation_pop` value lists.
  `params` is the parsed request body. Returns `{:ok, %Result{}}` or
  `{:error, %AttestoPhoenix.OAuthError{}}`.
  """
  @spec authenticate(request_headers(), map(), Config.t(), Policy.t()) ::
          {:ok, Result.t()} | {:error, OAuthError.t()}
  def authenticate(request_headers, params, %Config{} = config, %Policy{} = policy)
      when (is_list(request_headers) or is_map(request_headers)) and is_map(params) do
    case authenticate_with_context(request_headers, params, config, policy) do
      {:ok, %Result{} = result} -> {:ok, result}
      {:error, %OAuthError{} = err, %ErrorContext{}} -> {:error, err}
    end
  end

  @doc """
  Authenticates the client and preserves client-authentication transport context
  on errors.

  The successful return matches `authenticate/4`. Error returns add an
  `%ErrorContext{}` naming the `Authorization` scheme when the request attempted
  header authentication; token-endpoint callers use it to apply RFC 6749 §5.2
  401 challenge rules without re-reading the conn.
  """
  @spec authenticate_with_context(request_headers(), map(), Config.t(), Policy.t()) ::
          {:ok, Result.t()} | {:error, OAuthError.t(), ErrorContext.t()}
  def authenticate_with_context(request_headers, params, %Config{} = config, %Policy{} = policy)
      when (is_list(request_headers) or is_map(request_headers)) and is_map(params) do
    request_headers = normalize_request_headers(request_headers)
    context = error_context(request_headers.authorization)

    case do_authenticate(request_headers, params, config, policy) do
      {:ok, %Result{} = result} -> {:ok, result}
      {:error, %OAuthError{} = err} -> {:error, err, context}
    end
  end

  defp do_authenticate(request_headers, params, config, policy) do
    case fetch_client_credentials(request_headers, params, policy) do
      {:ok, :none, client_id} ->
        # RFC 6749 §2.1: identified but unauthenticated. Permitted only for
        # public clients, which must compensate with PKCE (RFC 7636).
        with :ok <- require_client_auth_method(config, policy, :none) do
          load_public_client(config, client_id)
        end

      {:ok, :client_secret_basic, client_id, secret} ->
        with :ok <- require_client_auth_method(config, policy, :client_secret_basic) do
          verify_confidential_client(config, client_id, secret, :client_secret_basic)
        end

      {:ok, :client_secret_post, client_id, secret} ->
        with :ok <- require_client_auth_method(config, policy, :client_secret_post) do
          verify_confidential_client(config, client_id, secret, :client_secret_post)
        end

      {:ok, :private_key_jwt, assertion} ->
        with :ok <- require_client_auth_method(config, policy, :private_key_jwt) do
          verify_private_key_jwt_client(config, policy, assertion)
        end

      {:ok, :attest_jwt_client_auth, attestation, pop, presented_client_id} ->
        with :ok <- require_client_auth_method(config, policy, :attest_jwt_client_auth) do
          verify_attested_client(config, policy, attestation, pop, presented_client_id)
        end

      {:ok, :mtls_client_auth, client_id, certificate} ->
        verify_mtls_client(config, policy, client_id, certificate)

      {:error, _} = err ->
        err
    end
  end

  defp normalize_request_headers(headers) when is_list(headers) do
    %{
      authorization: headers,
      oauth_client_attestation: [],
      oauth_client_attestation_pop: [],
      client_certificate: nil
    }
  end

  defp normalize_request_headers(headers) when is_map(headers) do
    %{
      authorization: header_values(headers, :authorization, "authorization"),
      oauth_client_attestation: header_values(headers, :oauth_client_attestation, "oauth-client-attestation"),
      oauth_client_attestation_pop:
        header_values(headers, :oauth_client_attestation_pop, "oauth-client-attestation-pop"),
      client_certificate: Map.get(headers, :client_certificate, Map.get(headers, "client_certificate"))
    }
  end

  defp header_values(headers, atom_key, string_key) do
    case Map.get(headers, atom_key, Map.get(headers, string_key, [])) do
      values when is_list(values) -> values
      value when is_binary(value) -> [value]
      _other -> []
    end
  end

  defp error_context(headers) do
    %ErrorContext{authorization_scheme: authorization_scheme(headers)}
  end

  defp authorization_scheme([]), do: nil

  defp authorization_scheme([header | _]) when is_binary(header) do
    scheme =
      header
      |> String.trim_leading()
      |> String.split(~r/\s+/, parts: 2)
      |> List.first()
      |> valid_authorization_scheme()

    scheme || "Basic"
  end

  defp authorization_scheme([_header | _]), do: "Basic"
  defp authorization_scheme(_headers), do: nil

  defp valid_authorization_scheme(scheme) when is_binary(scheme) and scheme != "" do
    if Regex.match?(@auth_scheme_re, scheme), do: scheme
  end

  defp valid_authorization_scheme(_scheme), do: nil

  # RFC 6749 §2.3: a client MUST NOT use more than one authentication method.
  #
  # The multiplicity decision turns on a careful reading of RFC 6749 §2.3.1: a
  # bare body `client_id` is *identification* (RFC 6749 §2.3.1, "The client
  # MAY ... include the client identifier"), not a second authentication
  # method. Only a second *credential* (a `client_secret` or a
  # `client_assertion`) alongside Basic is the forbidden double authentication
  # (RFC 6749 §2.3). When Basic is present its userid is the authoritative
  # `client_id`, so a body `client_id` is permitted iff it agrees with it; a
  # conflicting body `client_id` is an internally inconsistent request and is
  # rejected before any credential is verified.
  defp fetch_client_credentials(
         %{authorization: header} = request_headers,
         params,
         %Policy{basic_precedence: true} = policy
       ) do
    case header do
      ["Basic " <> encoded | _rest] ->
        # RFC 7009's established behavior is intentionally Basic-first: body
        # credentials are ignored whenever a Basic header is present, even if
        # the body also carries a client secret or assertion.
        decode_basic_credentials(encoded)

      _other ->
        fetch_non_basic_credentials(request_headers, params, policy)
    end
  end

  defp fetch_client_credentials(request_headers, params, policy) do
    fetch_non_basic_credentials(request_headers, params, policy)
  end

  defp fetch_non_basic_credentials(request_headers, params, policy) do
    header = request_headers.authorization

    cond do
      wallet_attestation_credentials?(request_headers) ->
        fetch_wallet_attestation_credentials(request_headers, params)

      assertion_credentials?(params) ->
        fetch_assertion_credentials(header, params)

      basic_credentials?(header) ->
        fetch_basic_credentials(header, params)

      header != [] ->
        {:error, error(@error_invalid_client, "unsupported client authentication scheme")}

      has_body_secret?(params) ->
        fetch_body_credentials(params, policy)

      mtls_credentials?(request_headers) ->
        fetch_mtls_credentials(request_headers, params)

      true ->
        fetch_body_credentials(params, policy)
    end
  end

  defp mtls_credentials?(%{client_certificate: certificate}), do: not is_nil(certificate)

  defp fetch_mtls_credentials(request_headers, params) do
    case {presented_client_id(params), request_headers.client_certificate} do
      {client_id, %{der: der, proof_of_possession: true} = certificate}
      when is_binary(client_id) and client_id != "" and is_binary(der) and byte_size(der) > 0 ->
        {:ok, :mtls_client_auth, client_id, certificate}

      _other ->
        {:error, error(@error_invalid_client, @client_auth_failed)}
    end
  end

  defp wallet_attestation_credentials?(request_headers) do
    request_headers.oauth_client_attestation != [] or request_headers.oauth_client_attestation_pop != []
  end

  defp fetch_wallet_attestation_credentials(request_headers, params) do
    if request_headers.authorization != [] or has_body_auth_credential?(params) do
      {:error, error(@error_invalid_request, "multiple client authentication methods")}
    else
      case {request_headers.oauth_client_attestation, request_headers.oauth_client_attestation_pop} do
        {[attestation], [pop]} when is_binary(attestation) and attestation != "" and is_binary(pop) and pop != "" ->
          {:ok, :attest_jwt_client_auth, attestation, pop, presented_client_id(params)}

        _other ->
          {:error, error(@error_invalid_client, @client_auth_failed)}
      end
    end
  end

  defp has_body_auth_credential?(params), do: has_body_secret?(params) or assertion_credentials?(params)

  defp presented_client_id(%{"client_id" => client_id}) when is_binary(client_id) and client_id != "", do: client_id
  defp presented_client_id(_params), do: nil

  defp assertion_credentials?(%{"client_assertion" => assertion}) when is_binary(assertion) and assertion != "",
    do: true

  defp assertion_credentials?(_params), do: false

  defp basic_credentials?(["Basic " <> _]), do: true
  defp basic_credentials?(_header), do: false

  defp fetch_assertion_credentials(header, params) do
    if header != [] or has_body_secret?(params) do
      {:error, error(@error_invalid_request, "multiple client authentication methods")}
    else
      fetch_private_key_jwt_credentials(
        params["client_assertion_type"],
        params["client_assertion"]
      )
    end
  end

  # RFC 6749 §2.3: a body `client_secret` alongside Basic is two credentials
  # and is rejected before any verification. (A body `client_assertion` is
  # handled earlier by `fetch_assertion_credentials/2`, which rejects it when
  # Basic is present.) Otherwise the Basic userid is the authoritative
  # `client_id` (RFC 6749 §2.3.1): a body `client_id` is mere identification,
  # permitted only when it agrees with the Basic userid and rejected as an
  # internally inconsistent `invalid_request` when it conflicts.
  defp fetch_basic_credentials(["Basic " <> encoded], params) do
    if has_body_secret?(params) do
      {:error, error(@error_invalid_request, "multiple client authentication methods")}
    else
      reconcile_basic_client_id(decode_basic_credentials(encoded), params)
    end
  end

  defp reconcile_basic_client_id({:ok, :client_secret_basic, basic_id, _secret} = ok, %{"client_id" => body_id})
       when is_binary(body_id) and body_id != "" do
    if body_id == basic_id do
      ok
    else
      {:error, error(@error_invalid_request, "client_id does not match the Basic credentials")}
    end
  end

  defp reconcile_basic_client_id(decoded, _params), do: decoded

  # RFC 6749 §2.1: a client identified by a body `client_id` and a non-empty
  # `client_secret` authenticates via `client_secret_post`. A body `client_id`
  # without a secret is only the public-client path when the caller's policy
  # allows it; otherwise it is a confidential client that failed to
  # authenticate.
  defp fetch_body_credentials(%{"client_id" => client_id} = params, policy)
       when is_binary(client_id) and client_id != "" do
    case params["client_secret"] do
      secret when is_binary(secret) and secret != "" ->
        {:ok, :client_secret_post, client_id, secret}

      _ ->
        if policy.allow_public do
          {:ok, :none, client_id}
        else
          {:error, error(@error_invalid_client, "client authentication required")}
        end
    end
  end

  defp fetch_body_credentials(_params, _policy) do
    {:error, error(@error_invalid_client, "client authentication required")}
  end

  # RFC 7617 §2 / RFC 6749 §2.3.1: the userid and password are
  # `application/x-www-form-urlencoded`-encoded, colon-separated, base64.
  defp decode_basic_credentials(encoded) do
    with {:ok, decoded} <- Base.decode64(encoded),
         [client_id, secret] <- String.split(decoded, ":", parts: 2) do
      {:ok, :client_secret_basic, URI.decode_www_form(client_id), URI.decode_www_form(secret)}
    else
      _ -> {:error, error(@error_invalid_client, "malformed Basic authorization header")}
    end
  end

  defp fetch_private_key_jwt_credentials(assertion_type, assertion) do
    if assertion_type == ClientAssertion.assertion_type() do
      {:ok, :private_key_jwt, assertion}
    else
      {:error, error(@error_invalid_client, @client_auth_failed)}
    end
  end

  defp require_client_auth_method(config, %Policy{} = policy, method) do
    cond do
      method not in policy.allowed_methods ->
        {:error, error(@error_invalid_client, @client_auth_failed)}

      not policy.honor_configured_methods ->
        :ok

      true ->
        require_configured_client_auth_method(config, method)
    end
  end

  defp require_configured_client_auth_method(config, method) do
    case Map.get(config, :token_endpoint_auth_methods_supported) do
      methods when is_list(methods) and methods != [] ->
        if Atom.to_string(method) in methods,
          do: :ok,
          else: {:error, error(@error_invalid_client, @client_auth_failed)}

      _ ->
        :ok
    end
  end

  defp has_body_secret?(%{"client_secret" => secret}) when is_binary(secret) and secret != "", do: true

  defp has_body_secret?(_params), do: false

  # The `:load_client` callback's contract (see `AttestoPhoenix.Config`)
  # carries both existence and the revocation gate: `{:ok, client}`,
  # `{:error, :not_found}`, or `{:error, :revoked}`. Revocation is therefore
  # checked here without a separate predicate (RFC 7009 semantics for an
  # already-revoked client).
  defp verify_confidential_client(config, client_id, secret, method) do
    verify_client_secret = Config.verify_client_secret_fun(config)

    case invoke(Config.load_client_fun(config), [client_id]) do
      {:ok, client} ->
        if invoke(verify_client_secret, [client, secret]) == true do
          result(config, client, client_id, method)
        else
          {:error, error(@error_invalid_client, @client_auth_failed)}
        end

      _other ->
        # RFC 6749 §2.3 / OWASP: do not leak whether the client exists or is
        # revoked. Run a dummy verification so the lookup-failure path matches
        # the wrong-secret path in observable timing, and return one message.
        # The same resolved callback is used for the real and dummy verify so
        # the two paths stay timing-matched.
        _ = invoke(verify_client_secret, [:unknown_client, secret])
        {:error, error(@error_invalid_client, @client_auth_failed)}
    end
  end

  defp verify_private_key_jwt_client(config, policy, assertion) do
    with {:ok, client_id} <- ClientAssertion.peek_client_id(assertion),
         {:ok, client} <- resolve_client(config, client_id),
         {:ok, jwks} <- client_jwks(config, client),
         {:ok, claims} <-
           ClientAssertion.verify(
             assertion,
             client_id,
             policy.assertion_audiences,
             jwks,
             assertion_verify_opts(policy)
           ),
         {:ok, result} <- result(config, client, client_id, :private_key_jwt),
         :ok <- consume_client_assertion_jti(config, policy, client_id, claims) do
      {:ok, result}
    else
      _other -> {:error, error(@error_invalid_client, @client_auth_failed)}
    end
  end

  defp verify_attested_client(config, policy, attestation, pop, presented_client_id) do
    with trusted_jwks when not is_nil(trusted_jwks) <- Config.trusted_wallet_provider_jwks(config),
         {:ok, verified} <-
           WalletAttestation.verify(
             attestation,
             pop,
             wallet_attestation_verify_opts(config, policy, trusted_jwks, presented_client_id)
           ),
         client_id when is_binary(client_id) and client_id != "" <-
           get_in(verified, [:attestation_claims, "sub"]),
         {:ok, client} <- resolve_client(config, client_id),
         {:ok, result} <- result(config, client, client_id, :attest_jwt_client_auth),
         :ok <- consume_wallet_attestation_replay(config, verified) do
      {:ok, result}
    else
      _other -> {:error, error(@error_invalid_client, @client_auth_failed)}
    end
  end

  defp verify_mtls_client(config, policy, client_id, certificate) do
    case resolve_client(config, client_id) do
      {:ok, client} -> authenticate_certificate_client(config, policy, client, client_id, certificate)
      _other -> {:error, error(@error_invalid_client, @client_auth_failed)}
    end
  end

  defp authenticate_certificate_client(config, policy, client, client_id, certificate) do
    case client_mtls_metadata(config, client) do
      {:ok, metadata} -> authenticate_registered_mtls_client(config, policy, client, client_id, certificate, metadata)
      :not_registered -> authenticate_certificate_bearing_public(config, policy, client, client_id)
      {:error, _reason} -> {:error, error(@error_invalid_client, @client_auth_failed)}
    end
  end

  defp authenticate_registered_mtls_client(config, policy, client, client_id, certificate, metadata) do
    with {:ok, method} <- mtls_method(metadata),
         :ok <- require_client_auth_method(config, policy, method),
         :ok <- require_mtls_transport(method, certificate),
         {:ok, metadata} <- maybe_resolve_self_signed_jwks(config, client, method, metadata),
         :ok <- MTLS.authenticate_client(certificate.der, method, metadata),
         {:ok, result} <- result(config, client, client_id, method) do
      {:ok, result}
    else
      _other -> {:error, error(@error_invalid_client, @client_auth_failed)}
    end
  end

  defp authenticate_certificate_bearing_public(config, policy, client, client_id) do
    with true <- policy.allow_public,
         :ok <- require_client_auth_method(config, policy, :none),
         true <- client_public?(config, client),
         {:ok, result} <- result(config, client, client_id, :none) do
      {:ok, result}
    else
      _other -> {:error, error(@error_invalid_client, @client_auth_failed)}
    end
  end

  defp client_mtls_metadata(config, client) do
    case Config.client_mtls_metadata_fun(config) do
      nil ->
        :not_registered

      callback ->
        case invoke(callback, [client]) do
          {:ok, metadata} when is_map(metadata) -> {:ok, metadata}
          metadata when is_map(metadata) -> {:ok, metadata}
          nil -> :not_registered
          {:error, _reason} -> {:error, :metadata_lookup_failed}
          _other -> {:error, :invalid_metadata_result}
        end
    end
  end

  defp mtls_method(metadata) do
    case Map.get(metadata, "token_endpoint_auth_method", Map.get(metadata, :token_endpoint_auth_method)) do
      "tls_client_auth" -> {:ok, :tls_client_auth}
      :tls_client_auth -> {:ok, :tls_client_auth}
      "self_signed_tls_client_auth" -> {:ok, :self_signed_tls_client_auth}
      :self_signed_tls_client_auth -> {:ok, :self_signed_tls_client_auth}
      _other -> {:error, :invalid_mtls_method}
    end
  end

  defp require_mtls_transport(:tls_client_auth, %{proof_of_possession: true, chain_validated: true}), do: :ok
  defp require_mtls_transport(:self_signed_tls_client_auth, %{proof_of_possession: true}), do: :ok
  defp require_mtls_transport(_method, _certificate), do: {:error, :untrusted_client_certificate}

  defp maybe_resolve_self_signed_jwks(_config, _client, :tls_client_auth, metadata), do: {:ok, metadata}

  defp maybe_resolve_self_signed_jwks(config, client, :self_signed_tls_client_auth, metadata) do
    case client_jwks(config, client) do
      {:ok, jwks} -> {:ok, Map.put(metadata, "jwks", jwks)}
      {:error, _reason} = error -> error
    end
  end

  defp wallet_attestation_verify_opts(config, policy, trusted_jwks, presented_client_id) do
    opts = [
      trusted_wallet_provider_jwks: trusted_jwks,
      audience: config.issuer,
      accepted_algs: policy.assertion_signing_algs
    ]

    opts =
      case policy.assertion_enforce_fapi_alg_policy do
        value when is_boolean(value) -> Keyword.put(opts, :enforce_fapi_alg_policy, value)
        nil -> opts
      end

    maybe_put_client_id(opts, presented_client_id)
  end

  defp maybe_put_client_id(opts, client_id) when is_binary(client_id) and client_id != "",
    do: Keyword.put(opts, :client_id, client_id)

  defp maybe_put_client_id(opts, _client_id), do: opts

  defp consume_wallet_attestation_replay(config, %{replay_key: replay_key, replay_ttl: replay_ttl}) do
    replay_check = Adapter.replay_check(config)

    case invoke(replay_check, ["client_attestation:" <> replay_key, replay_ttl]) do
      :ok -> :ok
      _other -> {:error, :attestation_replay}
    end
  end

  defp assertion_verify_opts(%Policy{} = policy) do
    opts = [
      max_lifetime: policy.assertion_max_lifetime,
      accepted_algs: policy.assertion_signing_algs
    ]

    case policy.assertion_enforce_fapi_alg_policy do
      value when is_boolean(value) -> Keyword.put(opts, :enforce_fapi_alg_policy, value)
      nil -> opts
    end
  end

  # A CIMD client's `private_key_jwt` verification keys are the document's
  # `jwks` / `jwks_uri` (RFC 7523 / OIDC Core §9), not the host's `:client_jwks`
  # callback. A document that carried neither has no keys, so `private_key_jwt`
  # is impossible for it and authentication fails closed.
  defp client_jwks(_config, %CIMDClient{metadata: metadata}) do
    case ClientIdMetadata.jwks(metadata) do
      nil -> {:error, :missing_client_jwks}
      jwks -> {:ok, jwks}
    end
  end

  defp client_jwks(config, client) do
    case Config.client_jwks_fun(config) do
      nil ->
        {:error, :missing_client_jwks}

      callback ->
        case invoke(callback, [client]) do
          {:ok, jwks} -> {:ok, jwks}
          jwks when is_map(jwks) or is_list(jwks) -> {:ok, jwks}
          _other -> {:error, :missing_client_jwks}
        end
    end
  end

  defp consume_client_assertion_jti(config, policy, client_id, %{"jti" => jti}) when is_binary(jti) and jti != "" do
    key = client_assertion_replay_key(client_id, jti)

    case invoke(Adapter.replay_check(config), [key, policy.assertion_max_lifetime]) do
      :ok -> :ok
      _other -> {:error, :assertion_replay}
    end
  end

  defp consume_client_assertion_jti(_config, _policy, _client_id, _claims), do: {:error, :missing_jti}

  defp client_assertion_replay_key(client_id, jti) do
    digest = :crypto.hash(:sha256, "#{client_id}\0#{jti}")
    "client_assertion:" <> Base.url_encode64(digest, padding: false)
  end

  # RFC 6749 §2.1: a client identified without a secret may proceed only if
  # it is a public client. A successful `:load_client` is sufficient
  # identification, but a confidential client MUST authenticate with a
  # secret (RFC 6749 §2.3.1): accepting it secretless would let anyone who
  # knows its `client_id` impersonate it, with no PKCE backstop on
  # client_credentials. The host's `:client_public?` callback is the
  # public/confidential discriminator; it MUST return `true` for the
  # secretless path to be allowed. A public client's security then rests on
  # PKCE (RFC 7636), enforced by `Attesto.AuthorizationCode` when the code
  # is redeemed. A revoked or unknown client - and a confidential client
  # presenting no secret - fails closed with the single generic message.
  defp load_public_client(config, client_id) do
    with {:ok, client} <- resolve_client(config, client_id),
         true <- client_public?(config, client),
         {:ok, result} <- result(config, client, client_id, :none) do
      {:ok, result}
    else
      _other -> {:error, error(@error_invalid_client, @client_auth_failed)}
    end
  end

  # Resolve a client through the same registry/CIMD path used by authentication.
  # Besides the secretless (`none`) and `private_key_jwt` paths, signed-token
  # policy lookup reuses this function so a token's original `client_id` has
  # identical resolution semantics. A CIMD `client_id` (an HTTPS URL, with the
  # feature enabled) is dereferenced and wrapped as `%CIMDClient{metadata: metadata}`; any
  # opaque identifier goes to the host's `:load_client` registry. Every failure
  # becomes `:not_found`, revealing neither which path ran nor whether a client
  # was revoked.
  @doc false
  @spec resolve_client(Config.t(), String.t()) :: {:ok, term()} | {:error, :not_found}
  def resolve_client(%Config{} = config, client_id) when is_binary(client_id) and client_id != "" do
    if ClientIdMetadata.cimd_client_id?(client_id, config) do
      case ClientIdMetadata.resolve(client_id, config) do
        {:ok, metadata} -> {:ok, %CIMDClient{metadata: metadata}}
        {:error, _reason} -> {:error, :not_found}
      end
    else
      case invoke(Config.load_client_fun(config), [client_id]) do
        {:ok, client} -> {:ok, client}
        _other -> {:error, :not_found}
      end
    end
  end

  def resolve_client(%Config{}, _client_id), do: {:error, :not_found}

  # The public/confidential discriminator (RFC 6749 §2.1). Read defensively
  # from the configuration; fail closed (treat as confidential, i.e. not
  # public) when the host has not supplied the callback, so a deployment
  # that forgets it cannot accidentally let confidential clients
  # authenticate without a secret.
  # A CIMD client holds no shared symmetric secret (the document validation
  # strips `client_secret_*` and the symmetric auth methods), so it is a public
  # client by construction - it relies on PKCE downstream. A registered client
  # defers to the host's `:client_public?` discriminator.
  defp client_public?(_config, %CIMDClient{metadata: _metadata}), do: true

  # Absent the host's `:client_public?` callback the answer normally fails
  # closed to `false`: an unclassified client must not be admitted on the
  # secretless path, because doing so would let anyone who knows a confidential
  # client's `client_id` authenticate as it.
  #
  # For a client the host marked NATIVE that default flips to `true`, because
  # for a native app the fail-closed direction is the other way. RFC 8252 §8.4
  # says an installed app's statically included secret MUST NOT be accepted as
  # proof of identity, so treating an unclassified native client as
  # confidential would accept exactly the credential §8.4 forbids. Marking a
  # client native is itself the deliberate classification that makes it public;
  # `none` + PKCE is the posture §8.1 prescribes for it.
  #
  # One rule, used by BOTH the secretless gate and the §8.4 secret refusal, so
  # the two cannot disagree. An earlier split - fail-closed-to-false here,
  # fail-closed-to-true for §8.4 - left a native client with no
  # `:client_public?` callback refused on both paths and therefore unable to
  # authenticate at all.
  defp client_public?(config, client) do
    case Config.client_public_fun(config) do
      nil -> client_native?(config, client)
      callback -> Callback.invoke(callback, [client]) == true
    end
  end

  # The authenticated OAuth `client_id` (RFC 6749 §2.2) carried by the
  # credentials is authoritative. A host callback may independently map its
  # opaque client value to an identifier, but accepting a different identifier
  # would authenticate one client while attributing the result to another. An
  # absent mapping leaves the credential-carried identifier in place; a present
  # mapping must agree exactly. CIMD resolution follows the same agreement rule,
  # but obtains the identifier from the validated document and never consults
  # the host callback.
  defp result(config, client, presented_client_id, method)
       when is_binary(presented_client_id) and presented_client_id != "" do
    if native_client_auth_permitted?(config, client, method) do
      case resolved_client_id(config, client) do
        nil -> {:ok, authenticated_result(client, presented_client_id, method)}
        ^presented_client_id -> {:ok, authenticated_result(client, presented_client_id, method)}
        _other -> {:error, error(@error_invalid_client, @client_auth_failed)}
      end
    else
      {:error, error(@error_invalid_client, @client_auth_failed)}
    end
  end

  defp result(_config, _client, _presented_client_id, _method) do
    {:error, error(@error_invalid_client, @client_auth_failed)}
  end

  defp authenticated_result(client, presented_client_id, method) do
    %Result{client: client, client_id: presented_client_id, method: method}
  end

  # RFC 8252 §8.4: an installed native app cannot keep a credential
  # confidential. Its binary is distributed to every user's device, so anything
  # shipped inside it - a `client_secret`, an assertion signing key - is
  # readable by anyone who has the app, and an authorization server that accepts
  # it is authenticating "possession of the app", not "possession of a secret".
  # A client the host marks native (RFC 8252 / `:client_native?`) and public
  # (RFC 6749 §2.1 / `:client_public?`) therefore authenticates with `none`; its
  # security rests on PKCE instead (§8.1, enforced by
  # `AttestoPhoenix.AuthorizationServer.RequestPolicy.require_pkce?/2`).
  #
  # Presenting `client_secret_basic`, `client_secret_post`, or `private_key_jwt`
  # is refused even when the host registry happens to hold a matching credential
  # - silently accepting it would let a secret extracted from one installed copy
  # authenticate as the client forever. The refusal is the single generic
  # `invalid_client` message every other authentication failure returns, so it
  # reveals nothing about the client's registration.
  #
  # RFC 8252 §8.4 carves out exactly one case where a native client may still
  # authenticate: per-instance credentials provisioned by dynamic registration,
  # which are genuinely confidential because no two installs share them. That is
  # the only reason this is scoped to native AND public rather than to native
  # alone, and it is why the host must say so explicitly - see
  # `native_client_public?/2`.
  defp native_client_auth_permitted?(_config, _client, :none), do: true
  defp native_client_auth_permitted?(_config, _client, :attest_jwt_client_auth), do: true

  defp native_client_auth_permitted?(config, client, _method) do
    not native_secret_refused?(config, client)
  end

  # Whether RFC 8252 §8.4 refuses a credential from `client`: true when the host
  # marks it native and it resolves as public.
  #
  # Exposed because the revocation endpoint parses client credentials itself
  # rather than going through `authenticate/4`, and a hand-copied second
  # implementation of this predicate would be free to drift from the one the
  # token, PAR, introspection, device, and CIBA endpoints enforce. There is one
  # rule and one place it lives.
  @doc false
  @spec native_secret_refused?(Config.t(), term()) :: boolean()
  def native_secret_refused?(%Config{} = config, client) do
    client_native?(config, client) and client_public?(config, client)
  end

  # The native-app discriminator (RFC 8252 / BCP 212). A CIMD client is
  # identified by an `https` URL resolving to a document served over the
  # network, not an installed app. A registered client defers to the host's
  # `:client_native?` callback, which defaults to `false`: an unclassified
  # client is not native, so this check cannot refuse an authentication the
  # host never opted into.
  defp client_native?(_config, %CIMDClient{metadata: _metadata}), do: false

  defp client_native?(config, client) do
    Callback.invoke(Config.client_native_fun(config), [client], false) == true
  end

  # A CIMD client's identifier is the URL its document is bound to; a registered
  # client's is the host's `:client_id` callback (falling back to the presented
  # identifier in `result/4` when absent).
  defp resolved_client_id(_config, %CIMDClient{metadata: metadata}), do: ClientIdMetadata.client_id(metadata)

  defp resolved_client_id(config, client) do
    Callback.invoke(Config.client_id_fun(config), [client], nil)
  end

  # Callback invocation delegates to `AttestoPhoenix.Callback`, except that an
  # absent (`nil`) callback is the `:no_callback` sentinel its callers branch
  # on (rather than raising a FunctionClauseError).
  defp invoke(nil, _args), do: :no_callback
  defp invoke(callback, args), do: Callback.invoke(callback, args)

  defp error(code, description) do
    OAuthError.new(code_atom(code), description, status: 400)
  end

  defp code_atom(@error_invalid_request), do: :invalid_request
  defp code_atom(@error_invalid_client), do: :invalid_client
end
