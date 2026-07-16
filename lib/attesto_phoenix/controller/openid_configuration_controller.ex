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

  alias Attesto.AuthorizationRequest
  alias Attesto.OpenIDDiscovery
  alias AttestoPhoenix.AuthorizationServer.RequestObjectMetadata
  alias AttestoPhoenix.Config

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

  # RFC 6749 §3.1.1 / §4.1: an authorization-code provider supports the "code"
  # response type. Fixed by protocol, not configured. OpenID Connect Discovery
  # requires response_types_supported; the core builder defaults to this when
  # the host does not override it.
  @response_types_supported ["code"]

  # OpenID Connect Core §3.1.2.5 / RFC 8414 §2 / JARM §2.3 `response_modes_
  # supported`: the response modes the authorization endpoint implements - the
  # RFC 6749 default `query` and the JWT Secured Authorization Response Mode
  # variants (FAPI 2.0 Message Signing §5.4). Sourced from
  # Attesto.AuthorizationRequest so the advertisement never drifts from what the
  # request validator accepts and the controller emits.
  @response_modes_supported AuthorizationRequest.supported_response_modes()

  # RFC 8414 §2 `token_endpoint_auth_methods_supported`: the client
  # authentication methods the token endpoint actually accepts. The controller
  # reads a confidential client's secret from an HTTP Basic header
  # (`client_secret_basic`, RFC 6749 §2.3.1 / RFC 7617), from the request body
  # (`client_secret_post`, RFC 6749 §2.3.1), or from a signed client assertion
  # (`private_key_jwt`, RFC 7523 / OIDC Core §9). It also admits a public
  # client that presents only a `client_id` and relies on PKCE (`none`,
  # RFC 6749 §2.1 / RFC 7636). Fixed by what the controller wires.
  @token_endpoint_auth_methods_supported [
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt",
    "none"
  ]

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
      |> put_fapi_metadata(config)

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
    jar_alg_values = RequestObjectMetadata.signing_alg_values(config)

    [
      response_types_supported: @response_types_supported,
      response_modes_supported: @response_modes_supported,
      grant_types_supported: Config.grant_types_supported(config),
      token_endpoint_auth_methods_supported: token_endpoint_auth_methods_supported(config),
      token_endpoint_auth_signing_alg_values_supported: config.client_auth_signing_algs,
      authorization_response_iss_parameter_supported: authorization_response_iss_parameter_supported(config),
      # RFC 8705 §3.3: advertise certificate-bound access token support only when
      # mTLS `cnf` binding is enabled; nil-dropped otherwise so a non-mTLS OP
      # stays silent (FAPI / FAPI-CIBA read this from the provider metadata).
      tls_client_certificate_bound_access_tokens: tls_client_certificate_bound_access_tokens(config),
      # OpenID Connect Discovery §3 requires this member. Config owns the
      # explicit HTTPS override and the issuer/path-derived fallback.
      authorization_endpoint: config.authorization_endpoint || Config.authorize_endpoint_url(config),
      userinfo_endpoint: userinfo_endpoint(config, conn),
      revocation_endpoint: revocation_endpoint(config),
      introspection_endpoint: Config.introspection_endpoint_url(config),
      introspection_endpoint_auth_methods_supported: introspection_auth_methods(config),
      require_pushed_authorization_requests: require_pushed_authorization_requests(config),
      pushed_authorization_request_endpoint: pushed_authorization_request_endpoint(config),
      # RFC 8628 §4: advertised only when the device grant is enabled.
      device_authorization_endpoint: device_authorization_endpoint(config),
      # OpenID Connect CIBA Core 1.0 §4: the backchannel authentication endpoint
      # and its capability metadata, advertised only when CIBA is enabled
      # (nil-dropped otherwise). FAPI-CIBA reads these from the OpenID Provider
      # Metadata document.
      backchannel_authentication_endpoint: backchannel_authentication_endpoint(config),
      backchannel_token_delivery_modes_supported: backchannel_token_delivery_modes_supported(config),
      backchannel_authentication_request_signing_alg_values_supported:
        backchannel_authentication_request_signing_alg_values_supported(config),
      backchannel_user_code_parameter_supported: backchannel_user_code_parameter_supported(config),
      # OpenID Connect RP-Initiated Logout 1.0 §3 / Back-Channel Logout 1.0
      # §2.1 / Front-Channel Logout 1.0 §3: advertised only when logout is
      # enabled (nil-dropped otherwise).
      end_session_endpoint: end_session_endpoint(config),
      backchannel_logout_supported: backchannel_logout_supported(config),
      backchannel_logout_session_supported: backchannel_logout_session_supported(config),
      frontchannel_logout_supported: frontchannel_logout_supported(config),
      frontchannel_logout_session_supported: frontchannel_logout_session_supported(config),
      # OpenID Connect Session Management 1.0 §3.3: the check_session_iframe,
      # advertised only when session management is enabled.
      check_session_iframe: check_session_iframe(config),
      scopes_supported: config.scopes_supported,
      claims_supported: presence(config.claims_supported),
      registration_endpoint: registration_endpoint(config),
      # OpenID Connect Discovery §3 capability flags reflecting what is wired.
      # `request_parameter_supported` tracks actual capability: the authorization
      # endpoint can verify a signed request object only when the host can
      # resolve a client's trusted JWKS, so an install without that capability
      # advertises `false` rather than a JAR support it cannot honour.
      request_parameter_supported: RequestObjectMetadata.supported?(config),
      request_uri_parameter_supported: @request_uri_parameter_supported,
      claims_parameter_supported: config.claims_parameter_supported,
      # RFC 9101 §10.5 / FAPI 2.0 Message Signing §5.3.1: the request-object
      # signing algorithms accepted, and (only when the policy mandates it) that
      # signed request objects are required. The algorithm list is advertised
      # only when request objects are actually supported, so discovery never
      # drifts from enforcement.
      request_object_signing_alg_values_supported: jar_alg_values,
      require_signed_request_object: RequestObjectMetadata.require_signed(config),
      # Host catalogs: advertised only when the host configures a non-empty list
      # (the core builder drops the nil the helper returns for `[]`).
      acr_values_supported: presence(config.acr_values_supported),
      ui_locales_supported: presence(config.ui_locales_supported),
      # draft-ietf-oauth-client-id-metadata-document-01 §6: advertise CIMD
      # support only when the feature is enabled; nil otherwise so the shared
      # Attesto.Discovery builder drops the member.
      client_id_metadata_document_supported: client_id_metadata_document_supported(config)
    ]
  end

  defp client_id_metadata_document_supported(%Config{} = config) do
    if Config.client_id_metadata_enabled?(config), do: true
  end

  defp token_endpoint_auth_methods_supported(%Config{token_endpoint_auth_methods_supported: methods})
       when is_list(methods) and methods != [], do: methods

  defp token_endpoint_auth_methods_supported(%Config{}), do: @token_endpoint_auth_methods_supported

  # The introspection endpoint authenticates the caller and rejects the public
  # ("none") path (RFC 7662 §2.1), so it advertises the confidential subset of
  # the configured client-authentication methods.
  defp introspection_auth_methods(config) do
    Enum.reject(token_endpoint_auth_methods_supported(config), &(&1 == "none"))
  end

  # RFC 8705 §3.3: `true` iff the OP mTLS-binds access tokens (nil-dropped
  # otherwise by the shared metadata builder).
  defp tls_client_certificate_bound_access_tokens(%Config{mtls_enabled: true}), do: true
  defp tls_client_certificate_bound_access_tokens(%Config{}), do: nil

  defp put_fapi_metadata(metadata, %Config{} = config) do
    metadata
    |> Map.put(
      "token_endpoint_auth_signing_alg_values_supported",
      config.client_auth_signing_algs
    )
    |> put_authorization_signing_alg_values_supported()
    |> put_introspection_signing_alg_values_supported()
    |> put_authorization_response_iss_supported(config)
  end

  # RFC 9701 §10 `introspection_signing_alg_values_supported`: the algorithms the
  # introspection endpoint signs JWT responses with. Signed with the same key as
  # ID Tokens and JARM, so the advertised set is exactly the already-derived
  # id_token_signing_alg_values_supported.
  defp put_introspection_signing_alg_values_supported(metadata) do
    case Map.get(metadata, "id_token_signing_alg_values_supported") do
      nil -> metadata
      algs -> Map.put(metadata, "introspection_signing_alg_values_supported", algs)
    end
  end

  # JARM §3 / FAPI 2.0 Message Signing §5.4 `authorization_signing_alg_values_
  # supported`: the algorithms the authorization endpoint signs JARM responses
  # with. JARM responses are signed with the same keystore key as ID Tokens
  # (Attesto.JARM mirrors Attesto.IDToken), so the advertised set is exactly the
  # already-derived id_token_signing_alg_values_supported.
  defp put_authorization_signing_alg_values_supported(metadata) do
    case Map.get(metadata, "id_token_signing_alg_values_supported") do
      nil -> metadata
      algs -> Map.put(metadata, "authorization_signing_alg_values_supported", algs)
    end
  end

  defp put_authorization_response_iss_supported(metadata, %Config{authorization_response_iss: true}) do
    Map.put(metadata, "authorization_response_iss_parameter_supported", true)
  end

  defp put_authorization_response_iss_supported(metadata, %Config{}), do: metadata

  defp require_pushed_authorization_requests(%Config{require_pushed_authorization_requests: true}), do: true

  defp require_pushed_authorization_requests(%Config{}), do: nil

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
         conn.path_info,
         conn.script_name
       ),
       do: endpoint
  end

  defp userinfo_endpoint(%Config{userinfo_endpoint: endpoint}, %Plug.Conn{}), do: endpoint

  defp local_userinfo_endpoint?(endpoint, issuer, {local_segments, metadata_segment_count}, path_info, script_name)
       when is_list(local_segments) and is_integer(metadata_segment_count) and metadata_segment_count >= 0 do
    with true <- is_binary(endpoint) and is_binary(issuer),
         {:ok, endpoint_uri} <- URI.new(endpoint),
         {:ok, issuer_uri} <- URI.new(issuer) do
      same_https_origin?(endpoint_uri, issuer_uri) and
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

  defp same_https_origin?(
         %URI{scheme: "https", host: left_host} = left,
         %URI{scheme: "https", host: right_host} = right
       )
       when is_binary(left_host) and is_binary(right_host) do
    normalize_host(left_host) == normalize_host(right_host) and
      effective_https_port(left) == effective_https_port(right)
  end

  defp same_https_origin?(_left, _right), do: false

  defp effective_https_port(%URI{port: nil}), do: 443
  defp effective_https_port(%URI{port: port}), do: port

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

  defp normalize_host(host) do
    host
    |> normalize_percent_encoding(&URI.char_unreserved?/1)
    |> String.downcase()
  end

  defp normalize_percent_encoding(value, decoded_char?) do
    Regex.replace(~r/%[0-9A-Fa-f]{2}/, value, fn "%" <> hex ->
      byte = String.to_integer(hex, 16)

      if decoded_char?.(byte), do: <<byte>>, else: "%" <> String.upcase(hex)
    end)
  end

  defp authorization_response_iss_parameter_supported(%Config{authorization_response_iss: true}), do: true

  defp authorization_response_iss_parameter_supported(%Config{}), do: nil

  # RFC 7009 §2 / RFC 8414 §2 `revocation_endpoint`: the revocation endpoint
  # (`AttestoPhoenix.Controller.RevocationController`) is always mounted by the
  # router macro, so it is always advertised. The URL is resolved from the
  # host's configured revocation path (the endpoint members are absolute URLs),
  # so it reflects where the host mounted the endpoint.
  @spec revocation_endpoint(Config.t()) :: String.t()
  defp revocation_endpoint(%Config{} = config), do: Config.revocation_endpoint_url(config)

  defp pushed_authorization_request_endpoint(%Config{} = config), do: Config.par_endpoint_url(config)

  defp device_authorization_endpoint(%Config{} = config) do
    if Config.device_authorization_enabled?(config), do: Config.device_authorization_endpoint_url(config)
  end

  defp backchannel_authentication_endpoint(%Config{} = config) do
    if Config.ciba_enabled?(config), do: Config.backchannel_authentication_endpoint_url(config)
  end

  # CIBA Core §4: the delivery modes advertised as wire strings (FAPI-CIBA
  # keeps these to "poll"/"ping"). Nil when CIBA is disabled.
  defp backchannel_token_delivery_modes_supported(%Config{} = config) do
    if Config.ciba_enabled?(config), do: Enum.map(Config.ciba_delivery_modes(config), &Atom.to_string/1)
  end

  defp backchannel_authentication_request_signing_alg_values_supported(%Config{} = config) do
    if Config.ciba_enabled?(config), do: Keyword.get(Config.ciba(config), :request_signing_algs)
  end

  defp backchannel_user_code_parameter_supported(%Config{} = config) do
    if Config.ciba_enabled?(config), do: Keyword.get(Config.ciba(config), :user_code_parameter_supported, false)
  end

  defp end_session_endpoint(%Config{} = config) do
    if Config.logout_enabled?(config), do: Config.end_session_endpoint_url(config)
  end

  defp backchannel_logout_supported(%Config{} = config) do
    if Config.backchannel_logout_supported?(config), do: true
  end

  defp backchannel_logout_session_supported(%Config{} = config) do
    if Config.backchannel_logout_session_supported?(config), do: true
  end

  defp frontchannel_logout_supported(%Config{} = config) do
    if Config.frontchannel_logout_supported?(config), do: true
  end

  defp frontchannel_logout_session_supported(%Config{} = config) do
    if Config.frontchannel_logout_session_supported?(config), do: true
  end

  defp check_session_iframe(%Config{} = config) do
    if Config.session_management_enabled?(config), do: Config.check_session_iframe_url(config)
  end

  # RFC 7591 §3: advertise the dynamic client registration endpoint only when
  # registration is enabled; otherwise omit the member entirely. The URL is
  # resolved from the host's configured registration path (the endpoint members
  # are absolute URLs), so it reflects where the host mounted the endpoint.
  @spec registration_endpoint(Config.t()) :: String.t() | nil
  defp registration_endpoint(%Config{registration_enabled: true} = config), do: Config.registration_endpoint_url(config)

  defp registration_endpoint(%Config{registration_enabled: false}), do: nil

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
