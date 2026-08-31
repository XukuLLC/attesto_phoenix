defmodule AttestoPhoenix.Plug.Authenticate do
  @moduledoc """
  Phoenix-friendly protected-resource authentication.

  This plug is a thin integration layer over `Attesto.Plug.Authenticate`. The
  core plug owns the protocol work: parsing Bearer/DPoP credentials, verifying
  the JWT access token, enforcing DPoP and mTLS sender-constraint bindings, and
  rendering RFC 6750 / RFC 9449 failures. This wrapper derives the core options
  from `AttestoPhoenix.Config`, resolves the verified subject through the
  host's `:load_principal` callback, and assigns neutral values for downstream
  Phoenix code.

  Defaults:

    * `:claims_key` - `:attesto_claims`
    * `:principal_key` - `:attesto_principal`
    * `:context_key` - `:attesto_context`

  The context assign is a map with `:subject`, `:client_id`, `:scope`, `:claims`,
  `:cnf`, and `:principal`. It is deliberately protocol-shaped; application
  policy such as accounts, roles, audit actors, and error envelopes belongs in
  the host application.

  Configuration resolution is request-aware. When
  `conn.private[:attesto_phoenix_config]` exists, that validated
  `%AttestoPhoenix.Config{}` is authoritative and the plug's `:config` and
  `:otp_app` options are ignored. When the request-private value is absent, the
  plug uses its `:config` option, then its `:otp_app` option, and finally the
  library's configured `:otp_app`. A malformed request-private value raises
  instead of falling back to global application configuration. Mount
  `AttestoPhoenix.Plug.PutConfig` when a route should use a request-specific
  profile.

  RFC 9728 challenge discovery is selected through
  `AttestoPhoenix.Config.resource_metadata_url/3`: an explicit per-plug
  `:resource_metadata` value (including `nil`) takes precedence on every error
  path and skips the resolver. A non-nil per-plug value is static Plug
  configuration and is validated by `init/1`, which Phoenix runs at compile
  time by default. Otherwise, the existing static
  `:resource_metadata` URL remains the default, while an optional
  `:resource_metadata_resolver` can choose a URL or omit it for each request.
  Invalid runtime resolver results are omitted. A resolver exception is not
  rescued and aborts the request, because resolvers are trusted host
  configuration rather than untrusted request input.
  """

  @behaviour Plug

  import Plug.Conn

  alias Attesto.Plug.Authenticate, as: CoreAuthenticate
  alias Attesto.Plug.OAuthError
  alias AttestoPhoenix.{Callback, Config, DPoP.Adapter, Event, ProtectedResource, RequestContext}

  @claims_key :attesto_claims
  @principal_key :attesto_principal
  @context_key :attesto_context
  @error_option_keys [:send_error, :www_authenticate, :no_store]

  @impl Plug
  def init(opts) when is_list(opts) do
    case Keyword.fetch(opts, :resource_metadata) do
      :error ->
        opts

      {:ok, nil} ->
        opts

      {:ok, candidate} ->
        if Config.valid_resource_metadata_url?(candidate) do
          opts
        else
          raise ArgumentError,
                "AttestoPhoenix.Plug.Authenticate: :resource_metadata, when set, must be an " <>
                  "absolute https URL with a host and no fragment; got #{inspect(candidate)}."
        end
    end
  end

  @impl Plug
  def call(conn, opts) do
    config = resolve_config(conn, opts)

    Config.with_request_config(config, fn -> authenticate_request(conn, opts, config) end)
  end

  defp authenticate_request(conn, opts, config) do
    claims_key = Keyword.get(opts, :claims_key, @claims_key)
    resource_metadata = Config.resource_metadata_url(config, conn, opts)

    case RequestContext.check_https(conn, config) do
      :ok ->
        conn =
          conn
          |> CoreAuthenticate.call(CoreAuthenticate.init(core_opts(config, claims_key, opts, resource_metadata)))

        if conn.halted do
          emit_denied(config, conn, :invalid_token)
          conn
        else
          reject_revoked_or_assign_principal(conn, config, claims_key, opts, resource_metadata)
        end

      {:error, :insecure_transport} ->
        emit_denied(config, conn, :insecure_transport)

        OAuthError.unauthorized(
          conn,
          :bearer,
          "invalid_token",
          error_opts(config, opts, resource_metadata, description: "TLS required")
        )
    end
  end

  defp resolve_config(conn, opts) do
    if Map.has_key?(conn.private, :attesto_phoenix_config) do
      Config.resolve!(conn)
    else
      resolve_config_without_request(conn, opts)
    end
  end

  defp reject_revoked_or_assign_principal(conn, config, claims_key, opts, resource_metadata) do
    claims = conn.assigns[claims_key]

    if ProtectedResource.access_token_revoked?(config, claims) do
      emit_denied(config, conn, :invalid_token)

      OAuthError.unauthorized(
        conn,
        scheme_of(claims),
        "invalid_token",
        error_opts(config, opts, resource_metadata, [])
      )
    else
      assign_principal(conn, config, claims_key, opts, resource_metadata)
    end
  end

  defp assign_principal(conn, config, claims_key, opts, resource_metadata) do
    claims = conn.assigns[claims_key]
    subject = claims["sub"]

    case Callback.invoke(Config.load_principal_fun(config), [subject]) do
      {:ok, principal} ->
        principal_key = Keyword.get(opts, :principal_key, @principal_key)
        context_key = Keyword.get(opts, :context_key, @context_key)

        conn
        |> assign(principal_key, principal)
        |> assign(context_key, context(claims, principal))
        |> tap(fn _conn -> emit_succeeded(config, claims) end)

      {:error, :not_found} ->
        emit_denied(config, conn, :invalid_token)

        OAuthError.unauthorized(
          conn,
          scheme_of(claims),
          "invalid_token",
          error_opts(config, opts, resource_metadata, [])
        )

      _invalid ->
        raise RuntimeError, ":load_principal callback violated its return contract"
    end
  end

  defp context(claims, principal) do
    %{
      subject: claims["sub"],
      client_id: claims["client_id"],
      scope: scope(claims),
      claims: claims,
      cnf: Map.get(claims, "cnf"),
      principal: principal
    }
  end

  defp scope(%{"scope" => scope}) when is_binary(scope), do: String.split(scope, ~r/\s+/, trim: true)

  defp scope(_claims), do: []

  defp scheme_of(%{"cnf" => %{"jkt" => jkt}}) when is_binary(jkt), do: :dpop
  defp scheme_of(_claims), do: :bearer

  defp core_opts(config, claims_key, opts, resource_metadata) do
    overrides =
      opts
      |> Keyword.drop([:config, :otp_app, :claims_key, :principal_key, :context_key])
      |> Keyword.put(:claims_key, claims_key)

    config
    |> configured_core_opts(claims_key, resource_metadata)
    |> Keyword.merge(overrides)
    # Normalize an explicit override (including nil/invalid) after the raw plug
    # options are merged, so the delegated core path sees the same selected URL
    # as the wrapper-owned TLS, revocation, and principal failures.
    |> Keyword.put(:resource_metadata, resource_metadata)
  end

  defp configured_core_opts(config, claims_key, resource_metadata) do
    [config: attesto_config(config), claims_key: claims_key]
    |> Keyword.put(:bearer_methods, config.bearer_methods_supported)
    |> put_optional(:send_error, config.send_error)
    |> put_optional(:www_authenticate, config.www_authenticate)
    |> put_optional(:no_store, config.no_store)
    |> put_optional(:resource_metadata, resource_metadata)
    |> Keyword.merge(Adapter.protected_resource_opts(config))
  end

  defp attesto_config(config), do: Config.to_attesto_config(config)

  defp emit_succeeded(config, claims) do
    Event.emit(config, :auth_succeeded, %{
      subject: claims["sub"],
      client_id: claims["client_id"],
      scope: claims["scope"]
    })
  end

  defp emit_denied(config, conn, result) do
    Event.emit(config, :auth_denied, %{
      result: result,
      metadata: request_metadata(conn, config)
    })
  end

  defp request_metadata(conn, config) do
    %{
      method: conn.method,
      path: conn.request_path,
      client_ip: RequestContext.client_ip(conn, config)
    }
  end

  defp resolve_config_without_request(_conn, opts) do
    case Keyword.get(opts, :config) do
      %Config{} = config ->
        config

      fun when is_function(fun, 0) ->
        fun.()

      nil ->
        opts
        |> Keyword.get(:otp_app, Application.get_env(:attesto_phoenix, :otp_app))
        |> Config.from_otp_app(Config)
    end
  end

  defp put_optional(opts, _key, nil), do: opts
  defp put_optional(opts, key, value), do: Keyword.put(opts, key, value)

  defp error_opts(config, plug_opts, resource_metadata, extra) do
    [
      send_error: config.send_error,
      www_authenticate: config.www_authenticate,
      no_store: config.no_store,
      resource_metadata: resource_metadata
    ]
    |> Keyword.merge(Keyword.take(plug_opts, @error_option_keys))
    |> Keyword.merge(extra)
  end
end
