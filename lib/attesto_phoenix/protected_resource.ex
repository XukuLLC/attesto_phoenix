defmodule AttestoPhoenix.ProtectedResource do
  @moduledoc """
  Shared protected-resource authentication for Phoenix endpoints.

  This module owns the transport check, access-token verification wiring, and
  revoked-token check used by protected-resource controllers. Endpoint actions
  receive the verified claims only after this common work succeeds. Every 401
  completes the synchronous `:auth_denied` callback before sending the response;
  hosts must commit audit writes before returning (see `AttestoPhoenix.EventSink`).

  ## DPoP target URI

  A DPoP proof signs the URI of the request it was made for (`htu`, RFC 9449
  §4.3), and the resource compares it with the URI it computes for the
  request. That URI is chosen in this order:

    1. a per-route override passed to `AttestoPhoenix.Plug.Authenticate`:
       core's `:htu` callback or core's `:origin`;
    2. the configuration's `:htu` callback;
    3. the configuration's `:resource_origin` followed by `conn.request_path`;
    4. the URL derived from the request through `:trusted_proxies`, whose host
       is the request `Host` header or the forwarded host.

  The last form follows the request `Host`, so a server that answers more than
  one `Host` accepts a DPoP-bound token together with a proof made for another
  server. Pin the origin with one configuration value:

      config :my_app, AttestoPhoenix.Config,
        issuer: "https://auth.example.com",
        audience: "https://api.example.com",
        resource_origin: "https://api.example.com"

  `:resource_origin` applies to every protected resource that uses this
  configuration, including the bundled UserInfo and credential endpoints. When
  those are served on another origin than the host's resources, set `:htu`
  (or a per-route override) instead.
  """

  alias Attesto.Plug.Authenticate
  alias Attesto.Plug.OAuthError
  alias AttestoPhoenix.{Config, DenialAudit, DPoP.Adapter, RequestContext}

  # The conn assign `Attesto.Plug.Authenticate` writes the verified claims
  # under its default `:claims_key`.
  @claims_key :attesto_claims

  @type result ::
          {:ok, Plug.Conn.t(), map()}
          | {:halt, Plug.Conn.t()}

  @doc """
  Run the protected-resource verification skeleton.

  Returns `{:ok, conn, claims}` when endpoint-specific work may proceed, or
  `{:halt, conn}` when the request has already been answered.
  """
  @spec authenticate(Plug.Conn.t(), Config.t(), String.t() | nil) :: result()
  def authenticate(%Plug.Conn{} = conn, %Config{} = config, resource_metadata) do
    authenticate(conn, config, resource_metadata, [])
  end

  @doc false
  @spec authenticate(Plug.Conn.t(), Config.t(), String.t() | nil, keyword()) :: result()
  def authenticate(%Plug.Conn{} = conn, %Config{} = config, resource_metadata, opts) when is_list(opts) do
    Config.with_request_config(config, fn -> do_authenticate(conn, config, resource_metadata, opts) end)
  end

  defp do_authenticate(%Plug.Conn{} = conn, %Config{} = config, resource_metadata, opts) do
    claims_key = Keyword.get(opts, :claims_key, @claims_key)
    core_overrides = Keyword.get(opts, :core_overrides, [])
    error_overrides = Keyword.get(opts, :error_overrides, [])

    case RequestContext.check_https(conn, config) do
      :ok ->
        authenticate_opts =
          config
          |> authenticate_opts(resource_metadata, core_overrides)
          |> Keyword.put(:claims_key, claims_key)

        conn = Authenticate.call(conn, Authenticate.init(authenticate_opts))

        cond do
          conn.halted ->
            {:halt, conn}

          access_token_revoked?(config, conn.assigns[claims_key]) ->
            {:halt, invalid_token(conn, config, resource_metadata, conn.assigns[claims_key], error_overrides)}

          true ->
            {:ok, conn, conn.assigns[claims_key]}
        end

      {:error, :insecure_transport} ->
        DenialAudit.emit(config, conn, :insecure_transport)

        {:halt,
         OAuthError.unauthorized(
           conn,
           :bearer,
           "invalid_token",
           error_opts(
             config,
             resource_metadata,
             Keyword.put(error_overrides, :description, "TLS required")
           )
         )}
    end
  end

  @doc """
  Answer a request whose verified token is refused after verification, with the
  RFC 6750 §3.1 `invalid_token` challenge under the token's own scheme.

  Used for a revoked token, and by an endpoint whose host callback reports
  that the token's subject is no longer valid.
  """
  @spec invalid_token(Plug.Conn.t(), Config.t(), String.t() | nil, map(), keyword()) :: Plug.Conn.t()
  def invalid_token(%Plug.Conn{} = conn, %Config{} = config, resource_metadata, claims, error_overrides \\ []) do
    DenialAudit.emit(config, conn, :invalid_token)

    OAuthError.unauthorized(
      conn,
      scheme_of(claims),
      "invalid_token",
      error_opts(config, resource_metadata, error_overrides)
    )
  end

  @doc "Build the options consumed by `Attesto.Plug.Authenticate`."
  @spec authenticate_opts(Config.t(), String.t() | nil) :: keyword()
  def authenticate_opts(%Config{} = config, resource_metadata) do
    authenticate_opts(config, resource_metadata, [])
  end

  @doc false
  @spec authenticate_opts(Config.t(), String.t() | nil, keyword()) :: keyword()
  def authenticate_opts(%Config{} = config, resource_metadata, overrides) when is_list(overrides) do
    [config: attesto_config(config), claims_key: @claims_key]
    |> Keyword.put(:bearer_methods, config.bearer_methods_supported)
    |> put_optional(:send_error, config.send_error)
    |> put_optional(:www_authenticate, config.www_authenticate)
    |> put_optional(:no_store, config.no_store)
    |> Keyword.merge(adapter_opts(config, overrides))
    |> Keyword.merge(overrides)
    # RFC 9728 §5.1: the engine verify path renders the auth-failure 401, so it
    # must also carry the protected-resource metadata pointer when configured.
    |> Keyword.put(:resource_metadata, resource_metadata)
    |> DenialAudit.wrap(config)
  end

  @doc "Translate the Phoenix configuration into the core Attesto configuration."
  @spec attesto_config(Config.t()) :: Attesto.Config.t()
  def attesto_config(%Config{} = config), do: Config.to_attesto_config(config)

  @doc "Return the challenge scheme for verified token claims."
  @spec scheme_of(map()) :: :dpop | :bearer
  def scheme_of(%{"cnf" => %{"jkt" => jkt}}) when is_binary(jkt), do: :dpop
  def scheme_of(_claims), do: :bearer

  @doc "Return whether the access token identified by the claims is revoked."
  @spec access_token_revoked?(Config.t(), map()) :: boolean()
  def access_token_revoked?(%Config{code_store: store}, %{"jti" => jti})
      when is_atom(store) and not is_nil(store) and is_binary(jti) do
    case Code.ensure_loaded(store) do
      {:module, ^store} ->
        access_token_revoked_by_store?(store, jti)

      {:error, _reason} ->
        raise RuntimeError, "configured code_store could not be loaded for protected-resource revocation checks"
    end
  end

  def access_token_revoked?(%Config{code_store: store}, %{"jti" => jti}) when not is_nil(store) and is_binary(jti) do
    raise RuntimeError,
          "configured code_store must be a loadable module for protected-resource revocation checks"
  end

  def access_token_revoked?(_config, _claims), do: false

  defp access_token_revoked_by_store?(store, jti) do
    if function_exported?(store, :access_token_revoked?, 1) do
      require_boolean_revocation_result!(store.access_token_revoked?(jti))
    else
      false
    end
  end

  defp require_boolean_revocation_result!(true), do: true
  defp require_boolean_revocation_result!(false), do: false

  defp require_boolean_revocation_result!(_unexpected) do
    raise RuntimeError, "code_store access_token_revoked?/1 must return true or false"
  end

  @doc "Build the transport options for a protected-resource error response."
  @spec error_opts(Config.t(), String.t() | nil, keyword()) :: keyword()
  def error_opts(%Config{} = config, resource_metadata, extra) do
    [
      send_error: config.send_error,
      www_authenticate: config.www_authenticate,
      no_store: config.no_store,
      resource_metadata: resource_metadata
    ]
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Keyword.merge(extra)
  end

  # `Attesto.Plug.Authenticate` takes either `:origin` or `:htu` and raises at
  # `init/1` when given both, and `do_authenticate/4` runs `init/1` on every
  # request. A per-plug core `:origin` is the caller's choice of target URI for
  # this route, so the configured `:htu` callback is left out when one is
  # present.
  defp adapter_opts(config, overrides) do
    opts = Adapter.protected_resource_opts(config)

    if Keyword.has_key?(overrides, :origin), do: Keyword.delete(opts, :htu), else: opts
  end

  defp put_optional(opts, _key, nil), do: opts
  defp put_optional(opts, key, value), do: Keyword.put(opts, key, value)
end
