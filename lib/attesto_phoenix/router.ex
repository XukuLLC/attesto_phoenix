defmodule AttestoPhoenix.Router do
  @moduledoc """
  Router macro that mounts the authorization-server endpoints.

  `use AttestoPhoenix.Router` makes the `attesto_routes/1` macro available
  inside a `Phoenix.Router`. Calling it inside (or alongside) a `scope`
  declares the OAuth 2.0 / OpenID Connect server surface:

    * `GET /.well-known/oauth-authorization-server` - authorization-server
      metadata (RFC 8414 §3).
    * `GET /.well-known/openid-configuration` - OpenID Provider configuration
      (OpenID Connect Discovery 1.0 §4).
    * `GET /.well-known/jwks.json` - the JSON Web Key Set of the verification
      keys (RFC 7517 §5; the discovery document's `jwks_uri` per RFC 8414 §2).
    * `GET /.well-known/oauth-protected-resource` - protected-resource metadata
      (RFC 9728 §3), the discovery target of the §5.1 `WWW-Authenticate`
      challenge the resource-server plugs emit. For a resource identifier that
      carries a path, the §3.1 **path-inserted** form
      (`/.well-known/oauth-protected-resource/mcp`) is mounted via
      `:protected_resource_paths` - see the option below; the root document
      alone does not satisfy clients that derive that form.
    * `GET /oauth/authorize` - the authorization endpoint (RFC 6749 §3.1;
      OpenID Connect Core 1.0 §3.1.2).
    * `POST /oauth/token` - the token endpoint (RFC 6749 §3.2).
    * `POST /oauth/par` - pushed authorization requests (RFC 9126).
    * `POST /oauth/revoke` - the token revocation endpoint (RFC 7009 §2).
    * `POST /oauth/introspect` - the token introspection endpoint (RFC 7662 §2),
      with the RFC 9701 signed-JWT response negotiated by the `Accept` header.
    * `POST /oauth/register` - dynamic client registration (RFC 7591 §3.1),
      mounted only when registration is enabled (see `:registration` below).
    * `DELETE /oauth/register/:client_id` - dynamic client registration
      management cleanup (RFC 7592 §2), mounted with registration.
    * `GET` and `POST /oauth/userinfo` - the UserInfo endpoint (OpenID Connect
      Core 1.0 §5.3); a bearer-authenticated protected resource (RFC 6750 §2.1).
    * `GET` and `POST /oauth/end_session` - the end-session endpoint (OpenID
      Connect RP-Initiated Logout 1.0 §2), mounted only with `logout: true`.
    * `GET /oauth/check_session` - the `check_session_iframe` (OpenID Connect
      Session Management 1.0 §3.3), mounted only with `session_management: true`.

  The macro emits nothing but `Phoenix.Router` route entries pointing at this
  library's controllers; it holds no policy of its own. Every behavioral
  decision (which clients exist, which scopes are granted, whether DPoP / mTLS
  binding is offered, whether registration is open) is owned by the host
  through `AttestoPhoenix.Config`, which the controllers read at request time.

  ## Placement and pipelines

  The discovery, OpenID configuration, and JWKS documents are unauthenticated
  public metadata (RFC 8414 §5; OpenID Connect Discovery 1.0 §4; RFC 8615).
  The authorization endpoint does not authenticate the client (RFC 6749 §3.1):
  the resource owner authenticates through the host's login/consent callbacks,
  so it carries no client-authentication pipeline. The token, revocation, and
  registration endpoints authenticate the client from the request itself
  (RFC 6749 §2.3, RFC 7009 §2, RFC 7591 §3), and the UserInfo endpoint is
  bearer-authenticated from the `Authorization` header (RFC 6750 §2.1) by its
  controller, rather than from a caller session, so they too take no
  session-bearing pipeline. Supply a `:pipeline` to attach transport-level
  concerns the host wants in front of every endpoint (for example an
  HTTPS-enforcing plug), and use `:route_pipelines` when the interactive,
  metadata, and non-browser protocol surfaces need different host pipelines.

      scope "/" do
        attesto_routes()
      end

      # or with a host pipeline and a mount prefix:
      scope "/" do
        attesto_routes(pipeline: :oauth_server, prefix: "/auth")
      end

      # or classify browser-facing routes separately while retaining shared
      # transport policy on every class:
      scope "/" do
        attesto_routes(
          pipeline: :oauth_common,
          route_pipelines: [
            interactive: [:oauth_interactive, :oauth_common]
          ]
        )
      end

  A route-class override is the complete ordered pipeline list for that class;
  Attesto does not append or prepend the `:pipeline` default. The host remains
  responsible for the policy inside those pipelines. In particular, externally
  submitted OAuth POST requests must not accidentally inherit a generic browser
  pipeline that rejects them through CSRF protection or browser-only `Accept`
  negotiation. The `:interactive` name means that those endpoints participate
  in resource-owner/browser interactions; it does not mean Attesto silently
  applies the host's ordinary browser pipeline.

  ## Options

    * `:prefix` - path segment prepended to the `/oauth/*` endpoints (the
      well-known documents always live at the host root per RFC 8615, so the
      prefix does not apply to them). Defaults to `""`.
    * `:pipeline` - a pipeline name (atom) or list of pipeline names to
      `pipe_through` for the mounted routes. Defaults to `[]` (no extra
      pipeline; the surrounding `scope`'s `pipe_through`, if any, still
      applies).
    * `:route_pipelines` - optional route-class overrides. Accepts a keyword
      list whose keys are `:metadata`, `:interactive`, or `:protocol`, and
      whose values are a pipeline atom or an ordered list of pipeline atoms.
      An override replaces `:pipeline` for its class; classes not present keep
      the `:pipeline` default. The classes are:

        * `:metadata` - authorization-server discovery, OpenID configuration,
          JWKS, and protected-resource metadata routes owned by this macro.
        * `:interactive` - authorization, device verification, end-session,
          and check-session routes.
        * `:protocol` - token, PAR, revocation, introspection, registration
          management, UserInfo, device authorization, and CIBA backchannel
          authentication routes.

      Unknown or duplicate class keys and malformed values raise
      `ArgumentError` during router compilation. When this option is absent,
      the legacy single-`:pipeline` route expansion is used unchanged.
    * `:registration` - when `true`, mounts `POST /oauth/register`
      (RFC 7591) and `DELETE /oauth/register/:client_id` (RFC 7592). Defaults
      to `false`. The endpoints still fail closed at request time unless the
      host has wired the registration callbacks in `AttestoPhoenix.Config`;
      this option only controls whether the routes exist, so a deployment that
      never offers registration presents no registration surface at all.
    * `:device` - when `true`, mounts the RFC 8628 device-authorization
      endpoint and verification page. Defaults to `false`.
    * `:ciba` - when `true`, mounts `POST /oauth/bc-authorize`, the OpenID
      Connect CIBA backchannel authentication endpoint. Defaults to `false`.
      The endpoint still fails closed at request time unless the host also
      enables `ciba: [enabled: true]` in `AttestoPhoenix.Config`.
    * `:logout` - when `true`, mounts `GET`/`POST /oauth/end_session` (OpenID
      Connect RP-Initiated Logout 1.0). Defaults to `false`.
    * `:session_management` - when `true`, mounts `GET /oauth/check_session`
      (OpenID Connect Session Management 1.0 §3.3). Defaults to `false`. The
      page answers 404 unless the host also enables
      `session_management: [enabled: true]` in `AttestoPhoenix.Config`.
    * `:protected_resource_paths` - additionally mounts the RFC 9728 §3.1
      **path-inserted** protected-resource metadata URI for the given resource
      path. RFC 9728 §3.1 derives the well-known URI by inserting the
      well-known segment between the origin and the resource path: for the
      resource identifier `https://host.example/mcp` the metadata lives at
      `/.well-known/oauth-protected-resource/mcp`. The root document alone is
      NOT RFC 9728-complete for such a resource: clients that derive the
      path-inserted URI from the resource URL (current MCP clients probe it
      first, before the `WWW-Authenticate` `resource_metadata` fallback) miss
      a host that serves only the root form. Accepts a single-element list
      (`["/mcp"]`; a bare `"mcp"` is normalized to `"/mcp"`). The served
      document must satisfy RFC 9728 §3.3 - its `resource` member must equal
      the identifier the URI was derived from - so the controller fails closed
      at request time when the configured resource identifier's path does not
      match. More than one entry is a compile-time error: one controller
      document cannot equal two identifiers; multi-resource hosts should use
      `attesto_mcp`'s `AttestoMCP.Router.attesto_mcp_protected_resource_metadata/2`,
      which serves per-resource documents. Defaults to `[]` (root only,
      today's behavior).
    * `:protected_resource_root` - when `false`, does not mount the root
      `/.well-known/oauth-protected-resource` document. Use this when PRM
      ownership lives elsewhere: a host that mounts `attesto_mcp`'s
      `attesto_mcp_protected_resource_metadata/2` with its root compatibility
      document enabled should pass `protected_resource_root: false` here so
      exactly one package owns each PRM route. Defaults to `true` (today's
      behavior).

  The library never inspects `:registration` to make a policy decision: it is
  a route-existence toggle. Authorization-server metadata advertised at the
  discovery endpoint is derived from `AttestoPhoenix.Config` by the discovery
  controller, not from these macro options.

  ## How protected-resource discovery actually happens

  A client calls the resource URL and gets a 401 whose `WWW-Authenticate`
  challenge carries a `resource_metadata` pointer (RFC 9728 §5.1). Modern
  clients ALSO - often first - derive the §3.1 path-inserted well-known URI
  from the resource URL itself (`https://host.example/mcp` →
  `/.well-known/oauth-protected-resource/mcp`) and probe it before falling
  back to the challenge pointer. Both URIs must serve the same document, and
  its `resource` member must equal the identifier the URI was derived from
  (§3.3) or the client is required to reject it. A single-resource AS+RS host
  covers all of this with `attesto_routes(protected_resource_paths: ["/mcp"])`;
  a host with multiple protected resources needs per-resource documents and
  should mount them with `attesto_mcp`'s
  `AttestoMCP.Router.attesto_mcp_protected_resource_metadata/2` instead
  (passing `protected_resource_root: false` here if that macro also owns the
  root document, so each PRM route has exactly one owner).
  """

  # Well-known paths are fixed by their registries and are NOT subject to the
  # host's `:prefix`. RFC 8414 §3 pins authorization-server metadata to the
  # `/.well-known/oauth-authorization-server` URI, and RFC 8615 reserves the
  # `/.well-known/` path segment at the host root. RFC 7517 §5 defines the JWK
  # Set document the metadata's `jwks_uri` points at.
  alias AttestoPhoenix.Controller.AuthorizeController
  alias AttestoPhoenix.Controller.BackchannelAuthenticationController
  alias AttestoPhoenix.Controller.CheckSessionController
  alias AttestoPhoenix.Controller.DeviceAuthorizationController
  alias AttestoPhoenix.Controller.DeviceVerificationController
  alias AttestoPhoenix.Controller.DiscoveryController
  alias AttestoPhoenix.Controller.EndSessionController
  alias AttestoPhoenix.Controller.IntrospectionController
  alias AttestoPhoenix.Controller.JWKSController
  alias AttestoPhoenix.Controller.OpenIDConfigurationController
  alias AttestoPhoenix.Controller.PARController
  alias AttestoPhoenix.Controller.ProtectedResourceController
  alias AttestoPhoenix.Controller.RegistrationController
  alias AttestoPhoenix.Controller.RevocationController
  alias AttestoPhoenix.Controller.TokenController
  alias AttestoPhoenix.Controller.UserinfoController

  @discovery_path "/.well-known/oauth-authorization-server"
  @jwks_path "/.well-known/jwks.json"

  # OpenID Connect Discovery 1.0 §4 pins the OpenID Provider configuration
  # document to the `/.well-known/openid-configuration` URI, also anchored at
  # the host root under RFC 8615 and therefore NOT subject to the `:prefix`.
  @openid_configuration_path "/.well-known/openid-configuration"

  # RFC 9728 §3 pins the protected-resource metadata document to the
  # `/.well-known/oauth-protected-resource` URI, anchored at the host root under
  # RFC 8615 and therefore NOT subject to the `:prefix`. It is the discovery
  # target of the RFC 9728 §5.1 `WWW-Authenticate: Bearer ..., resource_metadata`
  # challenge the protected-resource plugs emit.
  @protected_resource_path "/.well-known/oauth-protected-resource"

  # The OAuth endpoints live under the host-chosen `:prefix`. These are the
  # path tails appended to it. They derive from the SAME tail constants
  # `AttestoPhoenix.Config` resolves its advertised endpoint URLs from, joined
  # onto the default OAuth prefix (`"/oauth"`), so the routes this macro mounts
  # and the routes the discovery documents advertise cannot drift: a host that
  # mounts at `/oauth/*` (the default) and configures the matching default
  # `:oauth_path_prefix` advertises exactly the paths mounted here.
  @oauth_prefix "/oauth"
  @authorize_path @oauth_prefix <> AttestoPhoenix.Config.authorize_tail()
  @token_path @oauth_prefix <> AttestoPhoenix.Config.token_tail()
  @par_path @oauth_prefix <> AttestoPhoenix.Config.par_tail()
  @revoke_path @oauth_prefix <> AttestoPhoenix.Config.revocation_tail()
  @introspect_path @oauth_prefix <> AttestoPhoenix.Config.introspection_tail()
  @register_path @oauth_prefix <> AttestoPhoenix.Config.registration_tail()
  @userinfo_path @oauth_prefix <> AttestoPhoenix.Config.userinfo_tail()
  @device_authorization_path @oauth_prefix <> AttestoPhoenix.Config.device_authorization_tail()
  @device_verification_path @oauth_prefix <> AttestoPhoenix.Config.device_verification_tail()
  @backchannel_authentication_path @oauth_prefix <> AttestoPhoenix.Config.backchannel_authentication_tail()
  @end_session_path @oauth_prefix <> AttestoPhoenix.Config.end_session_tail()
  @check_session_path @oauth_prefix <> AttestoPhoenix.Config.check_session_tail()

  @route_pipeline_classes [:metadata, :interactive, :protocol]

  # Controllers that back each endpoint. Named here once so the macro
  # expansion does not scatter controller module references through the
  # callers' router source.
  @discovery_controller DiscoveryController
  @protected_resource_controller ProtectedResourceController
  @openid_configuration_controller OpenIDConfigurationController
  @jwks_controller JWKSController
  @authorize_controller AuthorizeController
  @token_controller TokenController
  @par_controller PARController
  @revocation_controller RevocationController
  @introspection_controller IntrospectionController
  @registration_controller RegistrationController
  @userinfo_controller UserinfoController
  @device_authorization_controller DeviceAuthorizationController
  @device_verification_controller DeviceVerificationController
  @backchannel_authentication_controller BackchannelAuthenticationController
  @end_session_controller EndSessionController
  @check_session_controller CheckSessionController

  @doc false
  defmacro __using__(_opts) do
    quote do
      import AttestoPhoenix.Router, only: [attesto_routes: 0, attesto_routes: 1]
    end
  end

  @doc """
  Mounts the authorization-server endpoints. See the module documentation for
  the route table and the accepted options.
  """
  defmacro attesto_routes(opts \\ []) do
    prefix = Keyword.get(opts, :prefix, "")
    pipelines = opts |> Keyword.get(:pipeline, []) |> List.wrap()
    route_pipelines = normalize_route_pipeline_option!(opts, pipelines)

    registration? = Keyword.get(opts, :registration, false)
    device? = Keyword.get(opts, :device, false)
    ciba? = Keyword.get(opts, :ciba, false)
    logout? = Keyword.get(opts, :logout, false)
    session_management? = Keyword.get(opts, :session_management, false)
    protected_resource_root? = Keyword.get(opts, :protected_resource_root, true)

    inserted_resource_paths =
      opts
      |> Keyword.get(:protected_resource_paths, [])
      |> normalize_protected_resource_paths!()

    discovery_path = @discovery_path
    openid_configuration_path = @openid_configuration_path
    jwks_path = @jwks_path
    authorize_path = @authorize_path
    token_path = @token_path
    par_path = @par_path
    revoke_path = @revoke_path
    introspect_path = @introspect_path
    register_path = @register_path
    userinfo_path = @userinfo_path
    discovery_controller = @discovery_controller
    openid_configuration_controller = @openid_configuration_controller
    jwks_controller = @jwks_controller
    authorize_controller = @authorize_controller
    token_controller = @token_controller
    par_controller = @par_controller
    revocation_controller = @revocation_controller
    introspection_controller = @introspection_controller
    registration_controller = @registration_controller
    userinfo_controller = @userinfo_controller
    device_authorization_path = @device_authorization_path
    device_verification_path = @device_verification_path
    device_authorization_controller = @device_authorization_controller
    device_verification_controller = @device_verification_controller
    backchannel_authentication_path = @backchannel_authentication_path
    backchannel_authentication_controller = @backchannel_authentication_controller
    end_session_path = @end_session_path
    end_session_controller = @end_session_controller
    check_session_path = @check_session_path
    check_session_controller = @check_session_controller

    # `pipe_through/1` is a compile-time `Phoenix.Router` macro: it must be
    # expanded once per pipeline as it is written into the scope, not iterated
    # at runtime. Unroll the requested pipelines into individual quoted calls
    # at macro-expansion time (an empty list yields no calls, piping through
    # nothing extra) so a host that wires a parser / HTTPS pipeline attaches it
    # to this server scope only, never leaking onto unrelated routes.
    pipe_through_calls = pipe_through_calls(pipelines)
    class_pipe_through_calls = pipeline_calls_by_class(route_pipelines)

    # The registration routes are emitted only when the host opts in (RFC 7591
    # §3.1 / RFC 7592 §2), decided here at expansion time so a deployment that
    # never registers clients exposes no registration endpoint at all.
    registration_route =
      if registration? do
        quote do
          post(
            unquote(prefix <> register_path),
            unquote(registration_controller),
            :create
          )

          delete(
            unquote(prefix <> register_path <> "/:client_id"),
            unquote(registration_controller),
            :delete
          )
        end
      end

    # RFC 8628 §3.1: the device authorization endpoint is emitted only when the
    # host opts in (`device: true`), so a deployment that does not offer the
    # device grant exposes no device endpoint at all.
    device_route =
      if device? do
        quote do
          post(
            unquote(prefix <> device_authorization_path),
            unquote(device_authorization_controller),
            :create
          )

          # RFC 8628 §3.3: the user-facing verification page. GET shows the
          # confirm prompt (and pre-fills `?user_code=` from
          # `verification_uri_complete`); POST carries the explicit approve/deny
          # decision (no approval is ever derived from a GET / the URL alone).
          get(
            unquote(prefix <> device_verification_path),
            unquote(device_verification_controller),
            :verify
          )

          post(
            unquote(prefix <> device_verification_path),
            unquote(device_verification_controller),
            :verify
          )
        end
      end

    # Route-class expansion needs to split the device grant's non-browser
    # authorization request from its resource-owner verification page while
    # retaining their legacy order. The legacy branch below continues to use
    # `device_route` exactly as before.
    {device_authorization_route, device_verification_route} =
      classed_device_routes(
        device?,
        prefix,
        device_authorization_path,
        device_authorization_controller,
        device_verification_path,
        device_verification_controller
      )

    # OpenID Connect CIBA Core 1.0 §7.1: the backchannel authentication endpoint
    # is emitted only when the host opts in (`ciba: true`), so a deployment that
    # does not offer CIBA exposes no backchannel endpoint at all. POST only -
    # CIBA has no user-facing GET route (the authentication device is the host's
    # own app/UI, unlike the device grant's verification page).
    ciba_route =
      if ciba? do
        quote do
          post(
            unquote(prefix <> backchannel_authentication_path),
            unquote(backchannel_authentication_controller),
            :create
          )
        end
      end

    # OpenID Connect RP-Initiated Logout 1.0 §2: the end-session endpoint is
    # emitted only when the host opts in (`logout: true`). It accepts both GET
    # (the RP-redirect navigation) and POST (form-submitted logout).
    logout_route =
      if logout? do
        quote do
          get(
            unquote(prefix <> end_session_path),
            unquote(end_session_controller),
            :end_session
          )

          post(
            unquote(prefix <> end_session_path),
            unquote(end_session_controller),
            :end_session
          )
        end
      end

    # RFC 9728 §3: the root protected-resource metadata document. Emitted by
    # default; a host that hands PRM ownership to attesto_mcp's macro (which
    # can mount the root compatibility document itself) opts out with
    # `protected_resource_root: false` so exactly one package owns the route.
    protected_resource_root_route =
      if protected_resource_root? do
        quote do
          get(
            unquote(@protected_resource_path),
            unquote(@protected_resource_controller),
            :show
          )
        end
      end

    # RFC 9728 §3.1: the path-inserted well-known URI for a resource whose
    # identifier carries a path (`https://host.example/mcp` ->
    # `/.well-known/oauth-protected-resource/mcp`). Clients derive this form
    # from the resource URL, so a path-bearing resource served only at the
    # root URI fails their discovery probe. The route carries the inserted
    # path in `conn.private` so the controller can enforce RFC 9728 §3.3
    # (the served `resource` member must equal the identifier the URI was
    # derived from) fail-closed at request time.
    protected_resource_path_routes =
      for inserted_path <- inserted_resource_paths do
        quote do
          get(
            unquote(@protected_resource_path <> inserted_path),
            unquote(@protected_resource_controller),
            :show,
            private: %{attesto_prm_inserted_path: unquote(inserted_path)}
          )
        end
      end

    # OpenID Connect Session Management 1.0 §3.3: the check_session_iframe is
    # emitted only when the host opts in (`session_management: true`), so a
    # deployment without session management exposes no iframe endpoint at all.
    session_management_route =
      if session_management? do
        quote do
          get(
            unquote(prefix <> check_session_path),
            unquote(check_session_controller),
            :show
          )
        end
      end

    if route_pipelines do
      # `pipe_through/1` accumulates for the remainder of its scope and Phoenix
      # has no inverse operation. Isolate every contiguous route-class block in
      # a nested scope so each receives exactly its selected list. Keeping the
      # blocks in catalog order also preserves route ordering when an override
      # is enabled (notably device authorization before verification, followed
      # by CIBA, logout, session management, and finally UserInfo).
      quote do
        scope "/" do
          scope "/" do
            unquote_splicing(Map.fetch!(class_pipe_through_calls, :metadata))

            get(unquote(discovery_path), unquote(discovery_controller), :show)
            get(unquote(openid_configuration_path), unquote(openid_configuration_controller), :show)
            get(unquote(jwks_path), unquote(jwks_controller), :show)
            unquote(protected_resource_root_route)
            unquote_splicing(protected_resource_path_routes)
          end

          scope "/" do
            unquote_splicing(Map.fetch!(class_pipe_through_calls, :interactive))

            get(unquote(prefix <> authorize_path), unquote(authorize_controller), :authorize)
            post(unquote(prefix <> authorize_path), unquote(authorize_controller), :authorize)
          end

          scope "/" do
            unquote_splicing(Map.fetch!(class_pipe_through_calls, :protocol))

            post(unquote(prefix <> token_path), unquote(token_controller), :create)
            post(unquote(prefix <> par_path), unquote(par_controller), :create)
            post(unquote(prefix <> revoke_path), unquote(revocation_controller), :create)
            post(unquote(prefix <> introspect_path), unquote(introspection_controller), :create)
            unquote(registration_route)
            unquote(device_authorization_route)
          end

          scope "/" do
            unquote_splicing(Map.fetch!(class_pipe_through_calls, :interactive))
            unquote(device_verification_route)
          end

          scope "/" do
            unquote_splicing(Map.fetch!(class_pipe_through_calls, :protocol))
            unquote(ciba_route)
          end

          scope "/" do
            unquote_splicing(Map.fetch!(class_pipe_through_calls, :interactive))
            unquote(logout_route)
            unquote(session_management_route)
          end

          scope "/" do
            unquote_splicing(Map.fetch!(class_pipe_through_calls, :protocol))

            get(unquote(prefix <> userinfo_path), unquote(userinfo_controller), :userinfo)
            post(unquote(prefix <> userinfo_path), unquote(userinfo_controller), :userinfo)
          end
        end
      end
    else
      # Compatibility branch: when `:route_pipelines` is absent, retain the
      # original one-scope expansion and its exact route catalog/pipeline data.
      quote do
        scope "/" do
          unquote_splicing(pipe_through_calls)

          # RFC 8615: the well-known documents are anchored at the host root and
          # are not relocated by the host's `:prefix`. RFC 8414 §3 (OAuth
          # authorization-server metadata) and OpenID Connect Discovery 1.0 §4
          # (OpenID Provider configuration) are both unauthenticated public
          # metadata served at their registered URIs.
          get(unquote(discovery_path), unquote(discovery_controller), :show)
          get(unquote(openid_configuration_path), unquote(openid_configuration_controller), :show)
          get(unquote(jwks_path), unquote(jwks_controller), :show)

          # RFC 9728 §3: the protected-resource metadata document is unauthenticated
          # public metadata served at its registered well-known URI at the host
          # root (RFC 8615), so a client following the RFC 9728 §5.1
          # `WWW-Authenticate` challenge can discover the authorization server.
          # The §3.1 path-inserted form is mounted alongside it for a resource
          # identifier that carries a path (see `:protected_resource_paths`).
          unquote(protected_resource_root_route)
          unquote_splicing(protected_resource_path_routes)

          # RFC 6749 §3.1 / OpenID Connect Core 1.0 §3.1.2: the authorization
          # endpoint accepts both GET and POST under the host-chosen prefix. It
          # carries no client-authentication pipeline (RFC 6749 §3.1: the client
          # is not authenticated here; the resource owner authenticates through
          # the host's login/consent callbacks).
          get(unquote(prefix <> authorize_path), unquote(authorize_controller), :authorize)
          post(unquote(prefix <> authorize_path), unquote(authorize_controller), :authorize)

          # RFC 6749 §3.2 / RFC 7009 §2: token issuance and revocation are POST
          # endpoints under the host-chosen prefix. They authenticate the client
          # from the request itself (RFC 6749 §2.3, RFC 7009 §2).
          post(unquote(prefix <> token_path), unquote(token_controller), :create)
          post(unquote(prefix <> par_path), unquote(par_controller), :create)
          post(unquote(prefix <> revoke_path), unquote(revocation_controller), :create)

          # RFC 7662 §2: token introspection is a POST endpoint that authenticates
          # the client from the request (RFC 7662 §2.1); RFC 9701 adds the signed
          # JWT response negotiated by the Accept header.
          post(unquote(prefix <> introspect_path), unquote(introspection_controller), :create)

          unquote(registration_route)
          unquote(device_route)
          unquote(ciba_route)
          unquote(logout_route)
          unquote(session_management_route)

          # OpenID Connect Core 1.0 §5.3.1: the UserInfo endpoint accepts both
          # GET and POST, and is a bearer-authenticated protected resource
          # (RFC 6750 §2.1). The controller verifies the presented access token
          # from the `Authorization` header before returning any claim, so the
          # endpoint authenticates from the request itself rather than from a
          # caller session.
          get(unquote(prefix <> userinfo_path), unquote(userinfo_controller), :userinfo)
          post(unquote(prefix <> userinfo_path), unquote(userinfo_controller), :userinfo)
        end
      end
    end
  end

  defp normalize_route_pipeline_option!(opts, default_pipelines) do
    case Keyword.get_values(opts, :route_pipelines) do
      [] ->
        nil

      [overrides] ->
        normalize_route_pipelines!(overrides, default_pipelines)

      conflicting ->
        raise ArgumentError,
              "attesto_routes/1 route_pipelines: conflicting option values " <>
                "#{inspect(conflicting)}; specify :route_pipelines only once"
    end
  end

  defp pipe_through_calls(pipelines) do
    Enum.map(pipelines, fn attesto_pipeline ->
      quote do
        pipe_through(unquote(attesto_pipeline))
      end
    end)
  end

  defp pipeline_calls_by_class(nil), do: nil

  defp pipeline_calls_by_class(route_pipelines) do
    Map.new(route_pipelines, fn {route_class, pipelines} ->
      {route_class, pipe_through_calls(pipelines)}
    end)
  end

  defp classed_device_routes(
         true,
         prefix,
         authorization_path,
         authorization_controller,
         verification_path,
         verification_controller
       ) do
    authorization_route =
      quote do
        post(
          unquote(prefix <> authorization_path),
          unquote(authorization_controller),
          :create
        )
      end

    verification_route =
      quote do
        get(
          unquote(prefix <> verification_path),
          unquote(verification_controller),
          :verify
        )

        post(
          unquote(prefix <> verification_path),
          unquote(verification_controller),
          :verify
        )
      end

    {authorization_route, verification_route}
  end

  defp classed_device_routes(false, _prefix, _auth_path, _auth_controller, _verify_path, _verify_controller) do
    {nil, nil}
  end

  # Validate the opt-in class map before Phoenix expands any route. A class
  # override is deliberately a replacement, while omitted classes inherit the
  # already-normalized legacy `:pipeline` list.
  @doc false
  @spec normalize_route_pipelines!(term(), term()) :: keyword([atom()])
  def normalize_route_pipelines!(overrides, default_pipelines) when is_list(overrides) do
    if !Keyword.keyword?(overrides) do
      raise ArgumentError,
            "attesto_routes/1 route_pipelines: expected a keyword list with keys " <>
              "#{inspect(@route_pipeline_classes)}, got: #{inspect(overrides)}"
    end

    keys = Keyword.keys(overrides)
    unknown = keys |> Enum.reject(&(&1 in @route_pipeline_classes)) |> Enum.uniq()

    duplicates =
      keys
      |> Enum.frequencies()
      |> Enum.filter(fn {_key, count} -> count > 1 end)
      |> Enum.map(&elem(&1, 0))

    cond do
      unknown != [] ->
        raise ArgumentError,
              "attesto_routes/1 route_pipelines: unknown route class key(s) " <>
                "#{inspect(unknown)}; expected only #{inspect(@route_pipeline_classes)}"

      duplicates != [] ->
        raise ArgumentError,
              "attesto_routes/1 route_pipelines: conflicting duplicate override(s) for " <>
                "#{inspect(duplicates)}; each route class may be specified once"

      true ->
        default = normalize_route_pipeline_value!(default_pipelines, ":pipeline default")

        Enum.map(@route_pipeline_classes, fn route_class ->
          {route_class, route_pipeline_for_class(overrides, route_class, default)}
        end)
    end
  end

  def normalize_route_pipelines!(other, _default_pipelines) do
    raise ArgumentError,
          "attesto_routes/1 route_pipelines: expected a keyword list with keys " <>
            "#{inspect(@route_pipeline_classes)}, got: #{inspect(other)}"
  end

  defp route_pipeline_for_class(overrides, route_class, default) do
    case Keyword.fetch(overrides, route_class) do
      {:ok, value} -> normalize_route_pipeline_value!(value, inspect(route_class))
      :error -> default
    end
  end

  defp normalize_route_pipeline_value!(value, label) do
    pipelines = List.wrap(value)

    if pipeline_atom_list?(pipelines) do
      pipelines
    else
      raise ArgumentError,
            "attesto_routes/1 route_pipelines: #{label} must be a pipeline atom or an " <>
              "ordered list of pipeline atoms, got: #{inspect(value)}"
    end
  end

  defp pipeline_atom_list?([]), do: true
  defp pipeline_atom_list?([pipeline | rest]) when is_atom(pipeline), do: pipeline_atom_list?(rest)
  defp pipeline_atom_list?(_other), do: false

  # Validate and normalize the `:protected_resource_paths` option at macro
  # expansion time. These are author errors in the router source, not runtime
  # input, so each rejection raises `ArgumentError` at compile time.
  #
  # RFC 9728 §3.3 requires the served document's `resource` member to equal the
  # identifier the well-known URI was derived from, and the controller serves a
  # single document, so a list with more than one entry can never be conformant
  # here - it is rejected toward attesto_mcp's per-resource macro instead.
  @doc false
  @spec normalize_protected_resource_paths!(term()) :: [String.t()]
  def normalize_protected_resource_paths!(paths) when is_list(paths) do
    normalized = Enum.map(paths, &normalize_protected_resource_path!/1)

    case normalized do
      [] ->
        []

      [_single] ->
        normalized

      _many ->
        raise ArgumentError,
              "attesto_routes/1 protected_resource_paths: got #{inspect(paths)}, but the " <>
                "protected-resource metadata controller serves a single document whose " <>
                "`resource` member must equal the identifier each well-known URI is derived " <>
                "from (RFC 9728 §3.3), so only one path can be mounted here. For a host with " <>
                "multiple protected resources use attesto_mcp's " <>
                "AttestoMCP.Router.attesto_mcp_protected_resource_metadata/2, which serves " <>
                "per-resource documents."
    end
  end

  def normalize_protected_resource_paths!(other) do
    raise ArgumentError,
          "attesto_routes/1 protected_resource_paths: expected a list of resource path " <>
            "strings (e.g. [\"/mcp\"]), got: #{inspect(other)}"
  end

  defp normalize_protected_resource_path!(path) when is_binary(path) do
    normalized =
      case path do
        "/" <> _rest -> path
        _bare -> "/" <> path
      end

    cond do
      path == "" or normalized == "/" ->
        raise ArgumentError,
              "attesto_routes/1 protected_resource_paths: #{inspect(path)} names no resource " <>
                "path - the root document is already mounted at " <>
                "/.well-known/oauth-protected-resource (RFC 9728 §3.1 inserts the well-known " <>
                "segment between the origin and a non-empty resource path)"

      String.contains?(normalized, "..") or String.contains?(normalized, "?") ->
        raise ArgumentError,
              "attesto_routes/1 protected_resource_paths: #{inspect(path)} is not a plain " <>
                "resource path (no \"..\" segments or query strings)"

      true ->
        normalized
    end
  end

  defp normalize_protected_resource_path!(other) do
    raise ArgumentError,
          "attesto_routes/1 protected_resource_paths: expected a resource path string " <>
            "(e.g. \"/mcp\"), got: #{inspect(other)}"
  end
end
