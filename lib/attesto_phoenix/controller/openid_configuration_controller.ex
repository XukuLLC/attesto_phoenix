defmodule AttestoPhoenix.Controller.OpenIDConfigurationController do
  @moduledoc """
  OpenID Connect Discovery 1.0 - OpenID Provider Metadata endpoint.

  Serves the OpenID Provider configuration document at
  `/.well-known/openid-configuration` (OpenID Connect Discovery §4) so that
  Relying Parties can discover the OpenID Provider: the issuer, the endpoint
  URLs, the response/grant types it supports, the signing algorithms it uses
  for ID Tokens, and the scopes and claims it can return.

  The document is assembled by `Attesto.OpenIDDiscovery.metadata/2`; this
  controller contributes transport concerns only and adds no policy of its
  own. Every protocol member - the issuer, the token endpoint
  (`token_endpoint`), the JWKS location (`jwks_uri`), the PKCE challenge
  methods (`code_challenge_methods_supported`, fixed to `S256` per RFC 7636
  §4.2), the DPoP algorithms (`dpop_signing_alg_values_supported`, RFC 9449),
  and the OIDC-fixed members (`subject_types_supported`,
  `id_token_signing_alg_values_supported`, `claim_types_supported`) - is
  derived by the core builder from the protocol configuration.

  The capability members reflect exactly what the server supports:
  `grant_types_supported` is read from `AttestoPhoenix.Config.grant_types_supported/1`
  (every grant the token endpoint dispatches by default — `authorization_code`,
  `refresh_token`, `client_credentials`, and OAuth token exchange — narrowed when
  the host configures `:grant_types_supported`, and the token endpoint enforces the
  same set); `token_endpoint_auth_methods_supported`
  lists the client-authentication methods it accepts (`client_secret_basic`,
  `client_secret_post`, `private_key_jwt`, and `none` for PKCE-using public
  clients). The OpenID Connect request-parameter flags
  (`request_parameter_supported`, `request_uri_parameter_supported`, both
  OpenID Connect Discovery §3) reflect the authorization endpoint precisely:
  signed request objects (`request`, JAR/RFC 9101) are consumed when the host
  supplies `:client_jwks`; arbitrary OIDC `request_uri` references are not
  advertised even though PAR request URNs are resolved through `/oauth/par`. The
  `claims_parameter_supported` flag (OpenID Connect Discovery §3 / OpenID
  Connect Core §5.5) is host-configurable and defaults to `false`, since the
  authorization endpoint does not consume the `claims` parameter unless the
  host wires it.

  The configurable members - the `authorization_endpoint` (RFC 6749 §3.1),
  derived from the mounted authorization path unless explicitly overridden,
  and `userinfo_endpoint` (OpenID Connect Core §5.3), whose generic
  controllers can be mounted by `AttestoPhoenix.Router` while authentication,
  consent, and claim values remain host callbacks; the supported scopes
  (`scopes_supported`, to which the core builder adds the reserved `openid`
  scope per OpenID Connect Core §3.1.2.1); the supported claims
  (`claims_supported`); the supported ACR values (`acr_values_supported`,
  OpenID Connect Discovery §3) and UI locales (`ui_locales_supported`,
  OpenID Connect Discovery §3), each advertised only when the host configures
  a non-empty list; the `claims_parameter_supported` flag; and the dynamic
  registration endpoint (`registration_endpoint`, RFC 7591, advertised only
  when registration is enabled) - are read from `AttestoPhoenix.Config` and
  passed through, never hardcoded here.

  When `attesto_routes(userinfo: false)` retains this metadata route, the
  router records the removed local path in `conn.private`. A
  `userinfo_endpoint: :derived` value on the issuer origin at a
  route-equivalent path is then omitted. A configured URL is an authoritative
  host declaration and remains advertised, including when the host replaces
  the bundled controller at that same path.

  The response carries no secrets and is identical for every caller, so it is
  served unauthenticated. OpenID Connect Discovery §4 permits caching of the
  configuration response, so a public, cacheable `Cache-Control` header is
  set.

  ## Wiring

  The router pipeline must place the `AttestoPhoenix.Config` under
  `conn.private[:attesto_phoenix_config]` (the same key the other endpoints
  read) and the derived `Attesto.Config` under
  `conn.private[:attesto_protocol_config]`. Both are required; a missing value
  raises rather than serving a partial document, because a partial discovery
  document would misdirect Relying Parties to endpoints that may not exist.
  """

  use Phoenix.Controller, formats: [:json]

  import Plug.Conn, only: [put_resp_header: 3]

  alias Attesto.OpenIDDiscovery
  alias AttestoPhoenix.AuthorizationServer.Metadata
  alias AttestoPhoenix.AuthorizationServer.RequestObjectMetadata
  alias AttestoPhoenix.{Callback, Config}
  alias AttestoPhoenix.URLComparison

  # The router pipeline installs the AttestoPhoenix.Config here. This is the
  # same private key the token and discovery endpoints read.
  @config_key :attesto_phoenix_config

  # The router pipeline installs the derived Attesto.Config (the protocol
  # configuration the core metadata builder reads) here.
  @protocol_config_key :attesto_protocol_config
  @local_userinfo_route_key :attesto_phoenix_local_userinfo_route

  # OpenID Connect Discovery §4: the configuration document is static for a
  # given provider configuration, so it may be cached by Relying Parties and
  # intermediaries. One hour balances picking up configuration changes against
  # request volume, matching the RFC 8414 discovery endpoint.
  @cache_max_age_seconds 3600

  # Shared response type/mode and client-authentication advertisements are
  # owned by Metadata.enrich_common/2.
  @doc """
  Render the OpenID Provider Metadata document as JSON.

  Fails closed with `RuntimeError` when either required configuration value is
  absent from `conn.private`, since serving a document that omits required
  members would misdirect Relying Parties.
  """
  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, _params) do
    config = fetch_config!(conn)
    protocol_config = fetch_protocol_config!(conn)

    metadata =
      protocol_config
      |> OpenIDDiscovery.metadata(discovery_opts(config, conn))
      |> Metadata.enrich_common(config)

    conn
    |> put_cache_control()
    |> json(metadata)
  end

  # Fail closed: a missing config is a wiring error, not a runtime condition to
  # paper over. Raising surfaces the misconfiguration instead of emitting a
  # document that omits required members.
  @spec fetch_config!(Plug.Conn.t()) :: Config.t()
  defp fetch_config!(conn) do
    case conn.private do
      %{@config_key => %Config{} = config} ->
        config

      _ ->
        raise "#{inspect(__MODULE__)}: no %AttestoPhoenix.Config{} found in " <>
                "conn.private[#{inspect(@config_key)}]; wire the host pipeline that assigns it"
    end
  end

  @spec fetch_protocol_config!(Plug.Conn.t()) :: Attesto.Config.t()
  defp fetch_protocol_config!(conn) do
    case conn.private do
      %{@protocol_config_key => %Attesto.Config{} = config} ->
        config

      _ ->
        raise "#{inspect(__MODULE__)}: no %Attesto.Config{} found in " <>
                "conn.private[#{inspect(@protocol_config_key)}]; wire the host pipeline that assigns it"
    end
  end

  # OpenID Connect Discovery §3 `request_uri_parameter_supported`: this server
  # resolves PAR `request_uri` URNs it issued, but does not advertise arbitrary
  # OIDC `request_uri` fetching. `request_parameter_supported` is derived per
  # install from request-object capability (see request_objects_supported?/1).
  @request_uri_parameter_supported false

  # Translate the configured host capabilities into the OpenID Connect
  # Discovery §3 host members understood by Attesto.OpenIDDiscovery.metadata/2.
  # The core builder drops nil-valued members, so optional members advertise
  # only what the provider actually implements. `scopes_supported` is always
  # passed (never collapsed to nil): an OpenID Provider MUST support the
  # reserved `openid` scope (OpenID Connect Core §3.1.2.1), so the core builder
  # adds it to the host's catalog, yielding `["openid"]` even when the host
  # configures no other scopes.
  @spec discovery_opts(Config.t(), Plug.Conn.t()) :: keyword()
  defp discovery_opts(%Config{} = config, %Plug.Conn{} = conn) do
    [
      userinfo_endpoint: userinfo_endpoint(config, conn),
      revocation_endpoint: Config.revocation_endpoint_url(config),
      frontchannel_logout_supported: frontchannel_logout_supported(config),
      frontchannel_logout_session_supported: frontchannel_logout_session_supported(config),
      # OpenID Connect Session Management 1.0 §3.3: the check_session_iframe,
      # advertised only when session management is enabled.
      check_session_iframe: check_session_iframe(config),
      scopes_supported: config.scopes_supported,
      claims_supported: presence(config.claims_supported),
      # OpenID Connect Discovery §3 capability flags reflecting what is wired.
      # `request_parameter_supported` tracks actual capability: the authorization
      # endpoint can verify a signed request object only when the host can
      # resolve a client's trusted JWKS, so an install without that capability
      # advertises `false` rather than a JAR support it cannot honour.
      request_parameter_supported: RequestObjectMetadata.supported?(config),
      request_uri_parameter_supported: @request_uri_parameter_supported,
      claims_parameter_supported: config.claims_parameter_supported,
      # Host catalogs: advertised only when the host configures a non-empty list
      # (the core builder drops the nil the helper returns for `[]`).
      acr_values_supported: presence(config.acr_values_supported),
      ui_locales_supported: presence(config.ui_locales_supported)
    ]
  end

  # Bridge the macro's compile-time local route decision into request-time
  # metadata without overriding a deliberate host declaration. The released
  # nil/string contract remains authoritative; only the explicit `:derived`
  # derivation marker is eligible for stale-local-route suppression.
  defp userinfo_endpoint(%Config{userinfo_endpoint: :derived} = config, %Plug.Conn{} = conn) do
    endpoint = Config.userinfo_endpoint_url(config)

    local_route = Map.get(conn.private, @local_userinfo_route_key)

    if !local_userinfo_endpoint?(
         endpoint,
         config.issuer,
         local_route,
         Map.get(conn, :path_info),
         Map.get(conn, :script_name)
       ),
       do: endpoint
  end

  defp userinfo_endpoint(%Config{userinfo_endpoint: endpoint}, %Plug.Conn{}), do: endpoint

  defp local_userinfo_endpoint?(endpoint, issuer, {local_segments, metadata_segment_count}, path_info, script_name)
       when is_list(local_segments) and is_integer(metadata_segment_count) and metadata_segment_count >= 0 do
    endpoint = Callback.map_value(%{endpoint: endpoint}, :endpoint)
    issuer = Callback.map_value(%{issuer: issuer}, :issuer)

    with true <- is_binary(endpoint) and is_binary(issuer),
         {:ok, endpoint_uri} <- URI.new(endpoint),
         {:ok, issuer_uri} <- URI.new(issuer) do
      URLComparison.same_https_origin?(endpoint_uri, issuer_uri) and
        route_path_matches?(
          endpoint_uri.path,
          local_segments,
          metadata_segment_count,
          path_info,
          script_name
        )
    else
      _error -> false
    end
  end

  defp local_userinfo_endpoint?(_endpoint, _issuer, _local_route, _path_info, _script_name), do: false

  # Reconstruct the concrete client-visible local route from Plug/Phoenix data
  # instead of interpreting Phoenix route syntax. `path_info` contains the
  # realized surrounding scope plus the metadata route; dropping that fixed
  # tail yields concrete static/dynamic scope segments. `script_name` contributes
  # any outer forwarded-router prefix. Both are request segments and decode
  # once; the macro-relative route segments came from Plug's route compiler and
  # remain literal. Dot segments are ordinary data throughout.
  defp route_path_matches?(endpoint_path, local_segments, metadata_segment_count, path_info, script_name) do
    with {:ok, endpoint_segments} <- request_path_segments(endpoint_path),
         {:ok, request_segments} <- decode_request_segments(path_info),
         {:ok, forwarded_segments} <- decode_request_segments(script_name),
         true <- length(request_segments) >= metadata_segment_count do
      surrounding_scope_segments =
        Enum.take(request_segments, length(request_segments) - metadata_segment_count)

      endpoint_segments == forwarded_segments ++ surrounding_scope_segments ++ local_segments
    else
      _error -> false
    end
  end

  defp request_path_segments(path) when is_binary(path) do
    segments =
      for segment <- String.split(path, "/", trim: false), segment != "" do
        URI.decode(segment)
      end

    {:ok, segments}
  rescue
    ArgumentError -> :error
  end

  defp request_path_segments(_path), do: :error

  defp decode_request_segments(segments) when is_list(segments) do
    {:ok, Enum.map(segments, &URI.decode/1)}
  rescue
    ArgumentError -> :error
  end

  defp decode_request_segments(_segments), do: :error

  defp frontchannel_logout_supported(%Config{} = config) do
    if Config.frontchannel_logout_supported?(config), do: true
  end

  defp frontchannel_logout_session_supported(%Config{} = config) do
    if Config.frontchannel_logout_session_supported?(config), do: true
  end

  defp check_session_iframe(%Config{} = config) do
    if Config.session_management_enabled?(config), do: Config.check_session_iframe_url(config)
  end

  # An empty list means "not advertised": collapse it to nil so the core
  # builder omits the member instead of publishing an empty array. Used for the
  # optional `claims_supported` catalog, not for `scopes_supported` (which is
  # always advertised; see discovery_opts/2).
  @spec presence([term()]) :: [term()] | nil
  defp presence([]), do: nil
  defp presence(list) when is_list(list), do: list

  @spec put_cache_control(Plug.Conn.t()) :: Plug.Conn.t()
  defp put_cache_control(conn) do
    put_resp_header(
      conn,
      "cache-control",
      "public, max-age=#{@cache_max_age_seconds}"
    )
  end
end
