defmodule AttestoPhoenix.AuthorizationServer.BackchannelAuthentication do
  @moduledoc """
  CIBA backchannel authentication request processing (OpenID Connect CIBA Core
  1.0 §7), as conn-free core.

  Turns an authenticated confidential client and a parsed backchannel
  authentication request into the §7.3 acknowledgement (`auth_req_id`,
  `expires_in`, `interval`), by:

  1. building the core `Attesto.CIBA.Request.client()` map from the client's
     registered CIBA metadata (`AttestoPhoenix.Config.client_ciba_registration/2` + the shared
     `:client_id` / `:client_jwks` callbacks);
  2. stripping the client-authentication parameters so a signed authentication
     request (§7.1.1) stands alone;
  3. validating the request via `Attesto.CIBA.Request.validate/3` (scope, the
     exactly-one-hint rule, `binding_message`, and - for FAPI-CIBA - the
     mandatory signed `request` JWT against the client's JWKS);
  4. guarding a signed request's `jti` against replay when the host wired a
     `:replay_check` seam (FAPI-CIBA §5.2.2 host obligation);
  5. resolving the request's hint to an end-user through the host
     `:authenticate_ciba_user` callback (CIBA §7.1: the user is identified
     BEFORE the acknowledgement is returned) - which also verifies any
     `user_code`;
  6. minting the `auth_req_id` via `Attesto.CIBA.issue/4`; and
  7. kicking off the out-of-band authentication through the host
     `:notify_ciba_user` callback, fire-and-forget so the acknowledgement never
     waits on it.

  The thin `AttestoPhoenix.Controller.BackchannelAuthenticationController` parses
  the request off the `Plug.Conn`, authenticates the client (confidential only,
  FAPI-CIBA §5.2.2), lifts the conn facts into a `%Request{}` of plain data, and
  calls `request/2`. Every grant decision lives here or in the core.
  """

  alias Attesto.CIBA
  alias AttestoPhoenix.{Callback, Config, OAuthError}

  require Logger

  # Client-authentication parameters are allowed on the wire but MUST be
  # stripped before `Attesto.CIBA.Request.validate/3`, which requires a signed
  # `request` JWT to be the ONLY authentication-request parameter (§7.1.1).
  @client_auth_params ~w(client_id client_assertion client_assertion_type client_secret)

  defmodule Request do
    @moduledoc "Plain-data backchannel authentication request the controller builds from the conn."
    @enforce_keys [:client]
    defstruct [:client, :client_auth_method, :request_client_id, :client_ip, params: %{}]

    @type t :: %__MODULE__{
            client: term(),
            client_auth_method: atom() | nil,
            request_client_id: String.t() | nil,
            client_ip: String.t() | nil,
            params: map()
          }
  end

  @typedoc "The CIBA §7.3 authentication request acknowledgement (atom keys; `:interval` dropped when nil)."
  @type response :: %{required(atom()) => term()}

  @doc """
  Process a backchannel authentication request, returning the §7.3
  acknowledgement or an `AttestoPhoenix.OAuthError` (whose status is the CIBA
  §13 status from `Attesto.CIBA.error_status/1`).
  """
  @spec request(Config.t(), Request.t()) :: {:ok, response()} | {:error, OAuthError.t()}
  def request(%Config{} = config, %Request{} = request) do
    with {:ok, store} <- require_store(config),
         {:ok, client_map} <- build_client_map(config, request),
         :ok <- require_registered_delivery_mode(config, client_map),
         params = strip_client_auth(request.params),
         {:ok, validated} <- validate(config, client_map, params),
         :ok <- guard_replay(config, validated),
         {:ok, subject} <- resolve_user(config, validated),
         {:ok, issued} <- issue(config, store, validated, subject) do
      notify(config, issued.auth_req_id, validated, subject)
      {:ok, acknowledgement(issued)}
    end
  end

  defp require_store(%Config{} = config) do
    case Config.ciba_store(config) do
      store when is_atom(store) and not is_nil(store) -> {:ok, store}
      _ -> {:error, error(:invalid_request, "CIBA is not configured")}
    end
  end

  # Build the core `Attesto.CIBA.Request.client()` map from the authenticated
  # client's registration: the identifier (`:client_id` callback), the JWKS
  # (`:client_jwks` callback, for a signed request), and the CIBA metadata map
  # (`:client_ciba_registration`).
  defp build_client_map(config, %Request{client: client, request_client_id: presented}) do
    case Callback.invoke(Config.client_id_fun(config), [client], nil) || presented do
      client_id when is_binary(client_id) and client_id != "" ->
        registration = Config.client_ciba_registration(config, client)

        {:ok,
         %{
           client_id: client_id,
           token_delivery_mode: Map.get(registration, :token_delivery_mode),
           jwks: client_jwks(config, client),
           request_signing_alg: Map.get(registration, :request_signing_alg),
           user_code_parameter: Map.get(registration, :user_code_parameter, false)
         }}

      _ ->
        {:error, error(:invalid_client, "the client could not be identified")}
    end
  end

  defp client_jwks(config, client) do
    case Config.client_jwks_fun(config) do
      nil ->
        nil

      callback ->
        case Callback.invoke(callback, [client]) do
          {:ok, jwks} -> jwks
          jwks when is_map(jwks) or is_list(jwks) -> jwks
          _other -> nil
        end
    end
  end

  # CIBA Core §4 / FAPI-CIBA §5.2.1: a client may redeem only through a delivery
  # mode this OP advertises (`ciba: [delivery_modes: ...]`, which FAPI-CIBA
  # keeps to `[:poll, :ping]`). A client whose registered
  # `backchannel_token_delivery_mode` is not advertised is not authorized for
  # the grant (`unauthorized_client`). A client with no registered mode is
  # caught by the core's `unauthorized_client` on validate.
  defp require_registered_delivery_mode(config, %{token_delivery_mode: mode}) when not is_nil(mode) do
    if mode in Config.ciba_delivery_modes(config),
      do: :ok,
      else: {:error, error(:unauthorized_client, "the client's token delivery mode is not supported")}
  end

  defp require_registered_delivery_mode(_config, _client_map), do: :ok

  defp strip_client_auth(params), do: Map.drop(params, @client_auth_params)

  defp validate(config, client_map, params) do
    opts = Config.ciba(config)

    validate_opts = [
      issuer: config.issuer,
      require_signed_request: Keyword.get(opts, :require_signed_request, true),
      accepted_algs: Keyword.get(opts, :request_signing_algs, ["PS256", "ES256"]),
      binding_message_max_length: Keyword.get(opts, :binding_message_max_length, 128),
      require_binding_message: Keyword.get(opts, :require_binding_message, false),
      user_code_supported: Keyword.get(opts, :user_code_parameter_supported, false)
    ]

    case CIBA.Request.validate(client_map, params, validate_opts) do
      {:ok, request} -> {:ok, request}
      {:error, reason} -> {:error, error(reason, "the backchannel authentication request is invalid")}
    end
  end

  # FAPI-CIBA §5.2.2 replay defense: the core verifies a signed request's `jti`
  # / `exp` but is stateless by design, so the host MUST reject a repeated
  # `jti` within the request's lifetime. This is opt-in hardening: when the host
  # wired a `:replay_check` seam (the same store-backed callback the DPoP proof
  # cache uses) we record the verified `request_jti` (namespaced so it never
  # collides with a DPoP proof `jti`) until `request_exp`, and a repeat is
  # `invalid_request`. A host that wired none, or a plain (unsigned) request with
  # no `jti`, is not guarded here.
  defp guard_replay(%Config{replay_check: nil}, _request), do: :ok

  defp guard_replay(_config, %CIBA.Request{signed?: false}), do: :ok

  defp guard_replay(config, %CIBA.Request{request_jti: jti, request_exp: exp})
       when is_binary(jti) and is_integer(exp) do
    ttl = max(exp - System.system_time(:second), 1)

    case Callback.to_fun2(config.replay_check).("ciba:" <> jti, ttl) do
      :ok -> :ok
      {:error, :replay} -> {:error, error(:invalid_request, "the signed authentication request was replayed")}
    end
  end

  defp guard_replay(_config, _request), do: :ok

  # CIBA §7.1: resolve the request's hint to an end-user (the host owns the hint
  # format and the user directory) and verify any `user_code`. The host returns
  # `{:ok, subject}` or a §13 error (`unknown_user_id` / `expired_login_hint_token`
  # / `missing_user_code` / `invalid_user_code`).
  defp resolve_user(config, %CIBA.Request{} = request) do
    case Callback.invoke(config.authenticate_ciba_user, [request], :no_callback) do
      {:ok, subject} when is_binary(subject) and subject != "" ->
        {:ok, subject}

      {:error, reason}
      when reason in [:unknown_user_id, :expired_login_hint_token, :missing_user_code, :invalid_user_code] ->
        {:error, error(reason, "the end-user could not be authenticated for the request")}

      _other ->
        {:error, error(:unknown_user_id, "the request's hint did not resolve to a user")}
    end
  end

  defp issue(config, store, %CIBA.Request{} = request, subject) do
    opts = Config.ciba(config)

    case CIBA.issue(store, request, %{subject: subject},
           expires_in: Keyword.get(opts, :expires_in_seconds, 120),
           max_expires_in: Keyword.get(opts, :max_expires_in_seconds, 600),
           interval: Keyword.get(opts, :interval_seconds, 5)
         ) do
      {:ok, issued} -> {:ok, issued}
      {:error, _reason} -> {:error, error(:invalid_request, "could not issue the authentication request")}
    end
  end

  # CIBA §7.1: the host kicks off the out-of-band authentication on the user's
  # authentication device (push, in-app prompt, ...). Fire-and-forget so the
  # §7.3 acknowledgement is not delayed by it; a callback fault is logged and
  # swallowed (the client can still poll / be pinged once the user decides).
  defp notify(config, auth_req_id, %CIBA.Request{} = request, subject) do
    case config.notify_ciba_user do
      nil ->
        :ok

      callback ->
        Task.start(fn ->
          try do
            Callback.invoke(callback, [auth_req_id, request, subject])
          rescue
            e -> Logger.warning("notify_ciba_user failed: #{inspect(e)}")
          end
        end)

        :ok
    end
  end

  defp acknowledgement(%{auth_req_id: auth_req_id, expires_in: expires_in, interval: interval}) do
    base = %{auth_req_id: auth_req_id, expires_in: expires_in}
    # §7.3: `interval` is omitted for a push-mode request (no polling to pace).
    if is_integer(interval), do: Map.put(base, :interval, interval), else: base
  end

  defp error(code, description), do: OAuthError.new(code, description, status: CIBA.error_status(code))
end
