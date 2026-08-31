defmodule AttestoPhoenix.ProtectedResource do
  @moduledoc """
  Shared protected-resource authentication for Phoenix endpoints.

  This module owns the transport check, access-token verification wiring, and
  revoked-token check used by protected-resource controllers. Endpoint actions
  receive the verified claims only after this common work succeeds.
  """

  alias Attesto.Plug.Authenticate
  alias Attesto.Plug.OAuthError
  alias AttestoPhoenix.{Config, DPoP.Adapter, RequestContext}

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
    Config.with_request_config(config, fn -> do_authenticate(conn, config, resource_metadata) end)
  end

  defp do_authenticate(%Plug.Conn{} = conn, %Config{} = config, resource_metadata) do
    case RequestContext.check_https(conn, config) do
      :ok ->
        conn = Authenticate.call(conn, authenticate_opts(config, resource_metadata))

        cond do
          conn.halted ->
            {:halt, conn}

          access_token_revoked?(config, conn.assigns[@claims_key]) ->
            claims = conn.assigns[@claims_key]

            {:halt,
             OAuthError.unauthorized(
               conn,
               scheme_of(claims),
               "invalid_token",
               error_opts(config, resource_metadata, [])
             )}

          true ->
            {:ok, conn, conn.assigns[@claims_key]}
        end

      {:error, :insecure_transport} ->
        {:halt,
         OAuthError.unauthorized(
           conn,
           :bearer,
           "invalid_token",
           error_opts(config, resource_metadata, description: "TLS required")
         )}
    end
  end

  @doc "Build the options consumed by `Attesto.Plug.Authenticate`."
  @spec authenticate_opts(Config.t(), String.t() | nil) :: keyword()
  def authenticate_opts(%Config{} = config, resource_metadata) do
    [config: attesto_config(config), claims_key: @claims_key]
    |> Keyword.put(:bearer_methods, config.bearer_methods_supported)
    |> put_optional(:send_error, config.send_error)
    |> put_optional(:www_authenticate, config.www_authenticate)
    |> put_optional(:no_store, config.no_store)
    |> Keyword.merge(Adapter.protected_resource_opts(config))
    # RFC 9728 §5.1: the engine verify path renders the auth-failure 401, so it
    # must also carry the protected-resource metadata pointer when configured.
    |> put_optional(:resource_metadata, resource_metadata)
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

  defp put_optional(opts, _key, nil), do: opts
  defp put_optional(opts, key, value), do: Keyword.put(opts, key, value)
end
