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
  credentials (RFC 6749 §2.3.1), and `private_key_jwt` assertions (RFC 7523 /
  OIDC Core §9). Presenting more than one client-authentication method is
  rejected (RFC 6749 §2.3).

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

  ## Return value

  `authenticate/4` returns `{:ok, %Result{client, client_id, method}}` or
  `{:error, %AttestoPhoenix.OAuthError{}}`. `authenticate_with_context/4`
  keeps the same successful return and adds transport context to errors for
  endpoints that must distinguish `Authorization`-header authentication attempts
  while rendering. Both functions read only data: the
  `Authorization` header values and the parsed body params. It never touches a
  conn and never emits an event - the caller renders the result/error and
  emits whatever audit event it owns.

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

  alias Attesto.ClientAssertion
  alias Attesto.DPoP.ReplayCache
  alias AttestoPhoenix.{Callback, ClientIdMetadata, Config, OAuthError}

  defmodule Policy do
    @moduledoc """
    The per-caller policy for `AttestoPhoenix.ClientAuthentication`.

    See the parent module for the meaning of each field. Expressed as data so
    a caller passes its policy rather than toggling a behaviour flag inside the
    core.
    """

    @type t :: %__MODULE__{
            allow_public: boolean(),
            assertion_audiences: [String.t()],
            assertion_max_lifetime: pos_integer(),
            assertion_signing_algs: [String.t()]
          }

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
      :assertion_signing_algs
    ]
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
    (`:client_secret_basic`, `:client_secret_post`, `:private_key_jwt`, or
    `:none` for the public-client path).
    """

    @type method :: :client_secret_basic | :client_secret_post | :private_key_jwt | :none

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

  @doc """
  Authenticate the client from the request's `Authorization` header values and
  body params (RFC 6749 §2.3).

  `authorization_headers` is the list of `Authorization` header values (as
  returned by `Plug.Conn.get_req_header(conn, "authorization")`). `params` is
  the parsed request body. Returns `{:ok, %Result{}}` or
  `{:error, %AttestoPhoenix.OAuthError{}}`.
  """
  @spec authenticate([String.t()], map(), Config.t(), Policy.t()) ::
          {:ok, Result.t()} | {:error, OAuthError.t()}
  def authenticate(authorization_headers, params, %Config{} = config, %Policy{} = policy)
      when is_list(authorization_headers) and is_map(params) do
    case authenticate_with_context(authorization_headers, params, config, policy) do
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
  @spec authenticate_with_context([String.t()], map(), Config.t(), Policy.t()) ::
          {:ok, Result.t()} | {:error, OAuthError.t(), ErrorContext.t()}
  def authenticate_with_context(authorization_headers, params, %Config{} = config, %Policy{} = policy)
      when is_list(authorization_headers) and is_map(params) do
    context = error_context(authorization_headers)

    case do_authenticate(authorization_headers, params, config, policy) do
      {:ok, %Result{} = result} -> {:ok, result}
      {:error, %OAuthError{} = err} -> {:error, err, context}
    end
  end

  defp do_authenticate(authorization_headers, params, config, policy) do
    case fetch_client_credentials(authorization_headers, params, policy) do
      {:ok, :none, client_id} ->
        # RFC 6749 §2.1: identified but unauthenticated. Permitted only for
        # public clients, which must compensate with PKCE (RFC 7636).
        with :ok <- require_client_auth_method(config, "none") do
          load_public_client(config, client_id)
        end

      {:ok, :client_secret_basic, client_id, secret} ->
        with :ok <- require_client_auth_method(config, "client_secret_basic") do
          verify_confidential_client(config, client_id, secret, :client_secret_basic)
        end

      {:ok, :client_secret_post, client_id, secret} ->
        with :ok <- require_client_auth_method(config, "client_secret_post") do
          verify_confidential_client(config, client_id, secret, :client_secret_post)
        end

      {:ok, :private_key_jwt, assertion} ->
        with :ok <- require_client_auth_method(config, "private_key_jwt") do
          verify_private_key_jwt_client(config, policy, assertion)
        end

      {:error, _} = err ->
        err
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
  defp fetch_client_credentials(header, params, policy) do
    cond do
      assertion_credentials?(params) ->
        fetch_assertion_credentials(header, params)

      basic_credentials?(header) ->
        fetch_basic_credentials(header, params)

      header == [] ->
        fetch_body_credentials(params, policy)

      true ->
        {:error, error(@error_invalid_client, "unsupported client authentication scheme")}
    end
  end

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

  defp require_client_auth_method(config, method) do
    case Map.get(config, :token_endpoint_auth_methods_supported) do
      methods when is_list(methods) and methods != [] ->
        if method in methods,
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
           ClientAssertion.verify(assertion, client_id, policy.assertion_audiences, jwks,
             max_lifetime: policy.assertion_max_lifetime,
             accepted_algs: policy.assertion_signing_algs
           ),
         {:ok, result} <- result(config, client, client_id, :private_key_jwt),
         :ok <- consume_client_assertion_jti(config, policy, client_id, claims) do
      {:ok, result}
    else
      _other -> {:error, error(@error_invalid_client, @client_auth_failed)}
    end
  end

  # A CIMD client's `private_key_jwt` verification keys are the document's
  # `jwks` / `jwks_uri` (RFC 7523 / OIDC Core §9), not the host's `:client_jwks`
  # callback. A document that carried neither has no keys, so `private_key_jwt`
  # is impossible for it and authentication fails closed.
  defp client_jwks(_config, {:cimd, metadata}) do
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

    case invoke(replay_check(config), [key, policy.assertion_max_lifetime]) do
      :ok -> :ok
      _other -> {:error, :assertion_replay}
    end
  end

  defp consume_client_assertion_jti(_config, _policy, _client_id, _claims), do: {:error, :missing_jti}

  defp client_assertion_replay_key(client_id, jti) do
    digest = :crypto.hash(:sha256, "#{client_id}\0#{jti}")
    "client_assertion:" <> Base.url_encode64(digest, padding: false)
  end

  defp replay_check(%Config{replay_check: nil}), do: &ReplayCache.check_and_record/2
  defp replay_check(%Config{replay_check: callback}), do: callback

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
  # feature enabled) is dereferenced and wrapped as `{:cimd, metadata}`; any
  # opaque identifier goes to the host's `:load_client` registry. Every failure
  # becomes `:not_found`, revealing neither which path ran nor whether a client
  # was revoked.
  @doc false
  @spec resolve_client(Config.t(), String.t()) :: {:ok, term()} | {:error, :not_found}
  def resolve_client(%Config{} = config, client_id) when is_binary(client_id) and client_id != "" do
    if ClientIdMetadata.cimd_client_id?(client_id, config) do
      case ClientIdMetadata.resolve(client_id, config) do
        {:ok, metadata} -> {:ok, {:cimd, metadata}}
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
  defp client_public?(_config, {:cimd, _metadata}), do: true

  defp client_public?(config, client) do
    Callback.invoke(Config.client_public_fun(config), [client], false) == true
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
    case resolved_client_id(config, client) do
      nil -> {:ok, authenticated_result(client, presented_client_id, method)}
      ^presented_client_id -> {:ok, authenticated_result(client, presented_client_id, method)}
      _other -> {:error, error(@error_invalid_client, @client_auth_failed)}
    end
  end

  defp result(_config, _client, _presented_client_id, _method) do
    {:error, error(@error_invalid_client, @client_auth_failed)}
  end

  defp authenticated_result(client, presented_client_id, method) do
    %Result{client: client, client_id: presented_client_id, method: method}
  end

  # A CIMD client's identifier is the URL its document is bound to; a registered
  # client's is the host's `:client_id` callback (falling back to the presented
  # identifier in `result/4` when absent).
  defp resolved_client_id(_config, {:cimd, metadata}), do: ClientIdMetadata.client_id(metadata)

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
