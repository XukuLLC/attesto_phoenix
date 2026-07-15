defmodule AttestoPhoenix.RouterTest do
  @moduledoc """
  Tests for the `attesto_routes/1` router macro: the mounted route table, the
  optional `:prefix` and `:registration` toggles, and `:pipeline` wiring.
  """

  use ExUnit.Case, async: true

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

  defmodule DefaultRouter do
    use Phoenix.Router
    use AttestoPhoenix.Router

    scope "/" do
      attesto_routes()
    end
  end

  defmodule RegistrationRouter do
    use Phoenix.Router
    use AttestoPhoenix.Router

    scope "/" do
      attesto_routes(registration: true)
    end
  end

  defmodule PrefixedRouter do
    use Phoenix.Router
    use AttestoPhoenix.Router

    scope "/" do
      attesto_routes(prefix: "/auth", registration: true)
    end
  end

  defmodule PipelineRouter do
    use Phoenix.Router
    use AttestoPhoenix.Router

    pipeline :oauth_server do
      plug :accepts, ["json"]
    end

    scope "/" do
      attesto_routes(pipeline: :oauth_server)
    end
  end

  defmodule LegacyAllFeaturesRouter do
    use Phoenix.Router
    use AttestoPhoenix.Router

    pipeline :oauth_server do
      plug :accepts, ["json"]
    end

    scope "/" do
      attesto_routes(
        pipeline: :oauth_server,
        registration: true,
        device: true,
        ciba: true,
        logout: true,
        session_management: true
      )
    end
  end

  defmodule ClassPipelineRouter do
    use Phoenix.Router
    use AttestoPhoenix.Router

    pipeline :oauth_common do
      plug :accepts, ["json"]
    end

    pipeline :oauth_metadata do
      plug :accepts, ["json"]
    end

    pipeline :oauth_interactive do
      plug :accepts, ["html"]
    end

    pipeline :oauth_protocol do
      plug :accepts, ["json"]
    end

    scope "/" do
      attesto_routes(
        pipeline: :oauth_common,
        route_pipelines: [
          metadata: :oauth_metadata,
          interactive: [:oauth_interactive, :oauth_common],
          protocol: [:oauth_protocol, :oauth_common]
        ],
        registration: true,
        device: true,
        ciba: true,
        logout: true,
        session_management: true
      )
    end
  end

  defmodule PrefixedOverrideRouter do
    use Phoenix.Router
    use AttestoPhoenix.Router

    pipeline :oauth_common do
      plug :accepts, ["json"]
    end

    pipeline :oauth_interactive do
      plug :accepts, ["html"]
    end

    scope "/" do
      attesto_routes(
        prefix: "/mcp",
        pipeline: :oauth_common,
        route_pipelines: [interactive: [:oauth_interactive, :oauth_common]],
        protected_resource_paths: ["/mcp/alpha"],
        protected_resource_root: false
      )
    end
  end

  defmodule EmptyMetadataPipelineRouter do
    use Phoenix.Router
    use AttestoPhoenix.Router

    pipeline :oauth_common do
      plug :accepts, ["json"]
    end

    scope "/" do
      attesto_routes(
        pipeline: :oauth_common,
        route_pipelines: [metadata: []]
      )
    end
  end

  defmodule UserInfoDisabledRouter do
    use Phoenix.Router
    use AttestoPhoenix.Router

    scope "/" do
      attesto_routes(userinfo: false)
    end
  end

  defmodule PrefixedUserInfoDisabledRouter do
    use Phoenix.Router
    use AttestoPhoenix.Router

    scope "/" do
      attesto_routes(prefix: "/auth", userinfo: false)
    end
  end

  defmodule ScopedUserInfoDisabledRouter do
    use Phoenix.Router
    use AttestoPhoenix.Router

    scope "/tenant" do
      attesto_routes(userinfo: false)
    end
  end

  defmodule DynamicScopedUserInfoDisabledRouter do
    use Phoenix.Router
    use AttestoPhoenix.Router

    scope "/:tenant" do
      attesto_routes(userinfo: false)
    end
  end

  defmodule OpenIDConfigurationDisabledRouter do
    use Phoenix.Router
    use AttestoPhoenix.Router

    scope "/" do
      attesto_routes(openid_configuration: false)
    end
  end

  defmodule CapabilityInteractionRouter do
    use Phoenix.Router
    use AttestoPhoenix.Router

    pipeline :oauth_metadata do
      plug :accepts, ["json"]
    end

    pipeline :oauth_interactive do
      plug :accepts, ["html"]
    end

    pipeline :oauth_protocol do
      plug :accepts, ["json"]
    end

    scope "/" do
      attesto_routes(
        route_pipelines: [
          metadata: :oauth_metadata,
          interactive: :oauth_interactive,
          protocol: :oauth_protocol
        ],
        registration: true,
        device: true,
        ciba: true,
        logout: true,
        session_management: true,
        userinfo: false,
        openid_configuration: false
      )
    end
  end

  defmodule LogoutRouter do
    use Phoenix.Router
    use AttestoPhoenix.Router

    scope "/" do
      attesto_routes(logout: true, session_management: true)
    end
  end

  defmodule ProtectedResourcePathRouter do
    use Phoenix.Router
    use AttestoPhoenix.Router

    scope "/" do
      # A bare "mcp" normalizes to "/mcp" (leading slash inserted).
      attesto_routes(protected_resource_paths: ["mcp"])
    end
  end

  defmodule ProtectedResourceRootlessRouter do
    use Phoenix.Router
    use AttestoPhoenix.Router

    scope "/" do
      attesto_routes(protected_resource_root: false, protected_resource_paths: ["/mcp"])
    end
  end

  # `Phoenix.Router.routes/1` returns a list of route maps; find the one for a
  # given verb + path so a test can assert presence or inspect its pipeline.
  defp find_route(router, method, path) do
    router
    |> Phoenix.Router.routes()
    |> Enum.find(fn r -> r.verb == method and r.path == path end)
  end

  defp route_pipeline(router, method, path) do
    router
    |> Phoenix.Router.route_info(method |> Atom.to_string() |> String.upcase(), path, "localhost")
    |> Map.fetch!(:pipe_through)
  end

  defp route_signature(router) do
    router
    |> Phoenix.Router.routes()
    |> Enum.map(fn route ->
      {
        route.verb,
        route.path,
        route.plug,
        route.plug_opts,
        route.helper,
        route.metadata,
        route_pipeline(router, route.verb, route.path)
      }
    end)
  end

  defp prepared_route_conn(router, method, path) do
    segments = String.split(path, "/", trim: true)

    {metadata, prepare, _pipeline, _dispatch} =
      router.__match_route__(segments, method |> Atom.to_string() |> String.upcase(), "localhost")

    prepare.(Plug.Test.conn(method, path), metadata)
  end

  describe "attesto_routes/1" do
    test "mounts the discovery document at the well-known path" do
      assert find_route(DefaultRouter, :get, "/.well-known/oauth-authorization-server")
    end

    test "mounts the OpenID Provider configuration at the well-known path" do
      route = find_route(DefaultRouter, :get, "/.well-known/openid-configuration")
      assert route
      assert route.plug == OpenIDConfigurationController
    end

    test "mounts the JWKS document at the well-known path" do
      assert find_route(DefaultRouter, :get, "/.well-known/jwks.json")
    end

    test "mounts the authorization endpoint at both GET and POST (OIDC Core §3.1.2.1)" do
      get_route = find_route(DefaultRouter, :get, "/oauth/authorize")
      post_route = find_route(DefaultRouter, :post, "/oauth/authorize")

      assert get_route
      assert post_route
      assert get_route.plug == AuthorizeController
      assert post_route.plug == AuthorizeController
    end

    test "mounts the token endpoint" do
      assert find_route(DefaultRouter, :post, "/oauth/token")
    end

    test "mounts the pushed authorization request endpoint" do
      route = find_route(DefaultRouter, :post, "/oauth/par")
      assert route
      assert route.plug == PARController
    end

    test "mounts the UserInfo endpoint at both GET and POST (OIDC Core §5.3.1)" do
      get_route = find_route(DefaultRouter, :get, "/oauth/userinfo")
      post_route = find_route(DefaultRouter, :post, "/oauth/userinfo")

      assert get_route
      assert post_route
      assert get_route.plug == UserinfoController
      assert post_route.plug == UserinfoController
    end

    test "UserInfo and OpenID configuration are independently controllable" do
      refute find_route(UserInfoDisabledRouter, :get, "/oauth/userinfo")
      refute find_route(UserInfoDisabledRouter, :post, "/oauth/userinfo")

      assert find_route(
               UserInfoDisabledRouter,
               :get,
               "/.well-known/openid-configuration"
             )

      refute find_route(
               OpenIDConfigurationDisabledRouter,
               :get,
               "/.well-known/openid-configuration"
             )

      assert find_route(OpenIDConfigurationDisabledRouter, :get, "/oauth/userinfo")
      assert find_route(OpenIDConfigurationDisabledRouter, :post, "/oauth/userinfo")
    end

    test "userinfo opt-out marks the retained Provider Metadata route without changing the default route" do
      disabled =
        prepared_route_conn(
          UserInfoDisabledRouter,
          :get,
          "/.well-known/openid-configuration"
        )

      default =
        prepared_route_conn(
          DefaultRouter,
          :get,
          "/.well-known/openid-configuration"
        )

      prefixed =
        prepared_route_conn(
          PrefixedUserInfoDisabledRouter,
          :get,
          "/.well-known/openid-configuration"
        )

      scoped =
        prepared_route_conn(
          ScopedUserInfoDisabledRouter,
          :get,
          "/tenant/.well-known/openid-configuration"
        )

      dynamic =
        prepared_route_conn(
          DynamicScopedUserInfoDisabledRouter,
          :get,
          "/acme/.well-known/openid-configuration"
        )

      assert disabled.private.attesto_phoenix_local_userinfo_path == "/oauth/userinfo"
      assert prefixed.private.attesto_phoenix_local_userinfo_path == "/auth/oauth/userinfo"
      assert scoped.private.attesto_phoenix_local_userinfo_path == "/tenant/oauth/userinfo"
      assert dynamic.private.attesto_phoenix_local_userinfo_path == "/:tenant/oauth/userinfo"
      assert dynamic.path_params == %{"tenant" => "acme"}
      refute Map.has_key?(default.private, :attesto_phoenix_local_userinfo_path)
    end

    test "route-mount opt-outs compose mechanically with existing optional routes and route classes" do
      # This is macro-expansion coverage, not a claim that every combination of
      # OIDC feature routes and omitted Provider Metadata is a conformant
      # deployment; the public route docs spell out that runtime obligation.
      refute find_route(CapabilityInteractionRouter, :get, "/.well-known/openid-configuration")
      refute find_route(CapabilityInteractionRouter, :get, "/oauth/userinfo")
      refute find_route(CapabilityInteractionRouter, :post, "/oauth/userinfo")

      assert route_pipeline(
               CapabilityInteractionRouter,
               :get,
               "/.well-known/oauth-authorization-server"
             ) == [:oauth_metadata]

      assert route_pipeline(CapabilityInteractionRouter, :get, "/oauth/authorize") == [
               :oauth_interactive
             ]

      for {method, path} <- [
            {:post, "/oauth/token"},
            {:post, "/oauth/par"},
            {:post, "/oauth/revoke"},
            {:post, "/oauth/introspect"},
            {:post, "/oauth/register"},
            {:post, "/oauth/device_authorization"},
            {:post, "/oauth/bc-authorize"}
          ] do
        assert route_pipeline(CapabilityInteractionRouter, method, path) == [:oauth_protocol]
      end

      for {method, path} <- [
            {:get, "/oauth/device_verification"},
            {:get, "/oauth/end_session"},
            {:get, "/oauth/check_session"}
          ] do
        assert route_pipeline(CapabilityInteractionRouter, method, path) == [:oauth_interactive]
      end
    end

    test "mounts the revocation endpoint" do
      assert find_route(DefaultRouter, :post, "/oauth/revoke")
    end

    test "does not mount registration by default" do
      refute find_route(DefaultRouter, :post, "/oauth/register")
      refute find_route(DefaultRouter, :delete, "/oauth/register/:client_id")
    end

    test "mounts registration when enabled" do
      assert find_route(RegistrationRouter, :post, "/oauth/register")
      assert find_route(RegistrationRouter, :delete, "/oauth/register/:client_id")
    end

    test "applies the prefix to the oauth endpoints" do
      assert find_route(PrefixedRouter, :get, "/auth/oauth/authorize")
      assert find_route(PrefixedRouter, :post, "/auth/oauth/authorize")
      assert find_route(PrefixedRouter, :post, "/auth/oauth/token")
      assert find_route(PrefixedRouter, :post, "/auth/oauth/par")
      assert find_route(PrefixedRouter, :post, "/auth/oauth/register")
      assert find_route(PrefixedRouter, :delete, "/auth/oauth/register/:client_id")
      assert find_route(PrefixedRouter, :get, "/auth/oauth/userinfo")
      assert find_route(PrefixedRouter, :post, "/auth/oauth/userinfo")
    end

    test "keeps the well-known documents at the root even with a prefix" do
      assert find_route(PrefixedRouter, :get, "/.well-known/oauth-authorization-server")
      assert find_route(PrefixedRouter, :get, "/.well-known/openid-configuration")
      assert find_route(PrefixedRouter, :get, "/.well-known/jwks.json")
    end

    test "with a pipeline pipes the mounted routes through the named pipeline" do
      info = Phoenix.Router.route_info(PipelineRouter, "POST", "/oauth/token", "localhost")
      assert info.pipe_through == [:oauth_server]
    end

    test "legacy pipeline applies identically to every generated route" do
      assert Enum.all?(Phoenix.Router.routes(LegacyAllFeaturesRouter), fn route ->
               route_pipeline(LegacyAllFeaturesRouter, route.verb, route.path) == [:oauth_server]
             end)
    end

    test "complete default route table and pipeline data remain unchanged" do
      metadata = %{log: :debug}

      assert route_signature(DefaultRouter) == [
               {:get, "/.well-known/oauth-authorization-server", DiscoveryController, :show, "discovery", metadata, []},
               {:get, "/.well-known/openid-configuration", OpenIDConfigurationController, :show,
                "open_id_configuration", metadata, []},
               {:get, "/.well-known/jwks.json", JWKSController, :show, "jwks", metadata, []},
               {:get, "/.well-known/oauth-protected-resource", ProtectedResourceController, :show, "protected_resource",
                metadata, []},
               {:get, "/oauth/authorize", AuthorizeController, :authorize, "authorize", metadata, []},
               {:post, "/oauth/authorize", AuthorizeController, :authorize, "authorize", metadata, []},
               {:post, "/oauth/token", TokenController, :create, "token", metadata, []},
               {:post, "/oauth/par", PARController, :create, "par", metadata, []},
               {:post, "/oauth/revoke", RevocationController, :create, "revocation", metadata, []},
               {:post, "/oauth/introspect", IntrospectionController, :create, "introspection", metadata, []},
               {:get, "/oauth/userinfo", UserinfoController, :userinfo, "userinfo", metadata, []},
               {:post, "/oauth/userinfo", UserinfoController, :userinfo, "userinfo", metadata, []}
             ]
    end

    test "complete legacy all-feature route table remains unchanged" do
      metadata = %{log: :debug}

      assert route_signature(LegacyAllFeaturesRouter) == [
               {:get, "/.well-known/oauth-authorization-server", DiscoveryController, :show, "discovery", metadata,
                [:oauth_server]},
               {:get, "/.well-known/openid-configuration", OpenIDConfigurationController, :show,
                "open_id_configuration", metadata, [:oauth_server]},
               {:get, "/.well-known/jwks.json", JWKSController, :show, "jwks", metadata, [:oauth_server]},
               {:get, "/.well-known/oauth-protected-resource", ProtectedResourceController, :show, "protected_resource",
                metadata, [:oauth_server]},
               {:get, "/oauth/authorize", AuthorizeController, :authorize, "authorize", metadata, [:oauth_server]},
               {:post, "/oauth/authorize", AuthorizeController, :authorize, "authorize", metadata, [:oauth_server]},
               {:post, "/oauth/token", TokenController, :create, "token", metadata, [:oauth_server]},
               {:post, "/oauth/par", PARController, :create, "par", metadata, [:oauth_server]},
               {:post, "/oauth/revoke", RevocationController, :create, "revocation", metadata, [:oauth_server]},
               {:post, "/oauth/introspect", IntrospectionController, :create, "introspection", metadata,
                [:oauth_server]},
               {:post, "/oauth/register", RegistrationController, :create, "registration", metadata, [:oauth_server]},
               {:delete, "/oauth/register/:client_id", RegistrationController, :delete, "registration", metadata,
                [:oauth_server]},
               {:post, "/oauth/device_authorization", DeviceAuthorizationController, :create, "device_authorization",
                metadata, [:oauth_server]},
               {:get, "/oauth/device_verification", DeviceVerificationController, :verify, "device_verification",
                metadata, [:oauth_server]},
               {:post, "/oauth/device_verification", DeviceVerificationController, :verify, "device_verification",
                metadata, [:oauth_server]},
               {:post, "/oauth/bc-authorize", BackchannelAuthenticationController, :create,
                "backchannel_authentication", metadata, [:oauth_server]},
               {:get, "/oauth/end_session", EndSessionController, :end_session, "end_session", metadata,
                [:oauth_server]},
               {:post, "/oauth/end_session", EndSessionController, :end_session, "end_session", metadata,
                [:oauth_server]},
               {:get, "/oauth/check_session", CheckSessionController, :show, "check_session", metadata,
                [:oauth_server]},
               {:get, "/oauth/userinfo", UserinfoController, :userinfo, "userinfo", metadata, [:oauth_server]},
               {:post, "/oauth/userinfo", UserinfoController, :userinfo, "userinfo", metadata, [:oauth_server]}
             ]
    end

    test "route-class overrides replace only their class and preserve pipeline order" do
      metadata_routes = [
        {:get, "/.well-known/oauth-authorization-server"},
        {:get, "/.well-known/openid-configuration"},
        {:get, "/.well-known/jwks.json"},
        {:get, "/.well-known/oauth-protected-resource"}
      ]

      interactive_routes = [
        {:get, "/oauth/authorize"},
        {:post, "/oauth/authorize"},
        {:get, "/oauth/device_verification"},
        {:post, "/oauth/device_verification"},
        {:get, "/oauth/end_session"},
        {:post, "/oauth/end_session"},
        {:get, "/oauth/check_session"}
      ]

      protocol_routes = [
        {:post, "/oauth/token"},
        {:post, "/oauth/par"},
        {:post, "/oauth/revoke"},
        {:post, "/oauth/introspect"},
        {:post, "/oauth/register"},
        {:delete, "/oauth/register/:client_id"},
        {:post, "/oauth/device_authorization"},
        {:post, "/oauth/bc-authorize"},
        {:get, "/oauth/userinfo"},
        {:post, "/oauth/userinfo"}
      ]

      for {method, path} <- metadata_routes do
        assert route_pipeline(ClassPipelineRouter, method, path) == [:oauth_metadata]
      end

      for {method, path} <- interactive_routes do
        assert route_pipeline(ClassPipelineRouter, method, path) == [
                 :oauth_interactive,
                 :oauth_common
               ]
      end

      for {method, path} <- protocol_routes do
        assert route_pipeline(ClassPipelineRouter, method, path) == [
                 :oauth_protocol,
                 :oauth_common
               ]
      end

      assert route_pipeline(
               EmptyMetadataPipelineRouter,
               :get,
               "/.well-known/oauth-authorization-server"
             ) == []

      assert route_pipeline(EmptyMetadataPipelineRouter, :post, "/oauth/token") == [
               :oauth_common
             ]
    end

    test "class expansion retains the complete legacy route order and catalog" do
      legacy = Enum.map(route_signature(LegacyAllFeaturesRouter), &Tuple.delete_at(&1, 6))
      classed = Enum.map(route_signature(ClassPipelineRouter), &Tuple.delete_at(&1, 6))

      assert classed == legacy
    end

    test "prefix and protected-resource root options keep working with overrides" do
      refute find_route(
               PrefixedOverrideRouter,
               :get,
               "/.well-known/oauth-protected-resource"
             )

      assert find_route(
               PrefixedOverrideRouter,
               :get,
               "/.well-known/oauth-protected-resource/mcp/alpha"
             )

      assert find_route(PrefixedOverrideRouter, :get, "/.well-known/oauth-authorization-server")
      assert find_route(PrefixedOverrideRouter, :get, "/.well-known/openid-configuration")
      assert find_route(PrefixedOverrideRouter, :get, "/.well-known/jwks.json")
      assert find_route(PrefixedOverrideRouter, :get, "/mcp/oauth/authorize")
      assert find_route(PrefixedOverrideRouter, :post, "/mcp/oauth/token")

      assert route_pipeline(
               PrefixedOverrideRouter,
               :get,
               "/.well-known/oauth-protected-resource/mcp/alpha"
             ) == [:oauth_common]

      assert route_pipeline(PrefixedOverrideRouter, :get, "/mcp/oauth/authorize") == [
               :oauth_interactive,
               :oauth_common
             ]

      assert route_pipeline(PrefixedOverrideRouter, :post, "/mcp/oauth/token") == [
               :oauth_common
             ]
    end

    test "unknown and malformed class overrides fail during router compilation" do
      assert_raise ArgumentError, ~r/unknown route class.*browser/s, fn ->
        defmodule UnknownRoutePipelineClassRouter do
          use Phoenix.Router
          use AttestoPhoenix.Router

          scope "/" do
            attesto_routes(route_pipelines: [browser: :browser])
          end
        end
      end

      assert_raise ArgumentError, ~r/expected a keyword list/, fn ->
        defmodule NonKeywordRoutePipelinesRouter do
          use Phoenix.Router
          use AttestoPhoenix.Router

          scope "/" do
            attesto_routes(route_pipelines: [:metadata])
          end
        end
      end

      assert_raise ArgumentError, ~r/ordered list of pipeline atoms/, fn ->
        defmodule MalformedRoutePipelineValueRouter do
          use Phoenix.Router
          use AttestoPhoenix.Router

          scope "/" do
            attesto_routes(route_pipelines: [metadata: [:metadata, "not_an_atom"]])
          end
        end
      end

      assert_raise ArgumentError, ~r/ordered list of pipeline atoms.*nil/s, fn ->
        defmodule NilRoutePipelineValueRouter do
          use Phoenix.Router
          use AttestoPhoenix.Router

          scope "/" do
            attesto_routes(route_pipelines: [metadata: nil])
          end
        end
      end

      assert_raise ArgumentError, ~r/must use literal pipeline atoms/, fn ->
        defmodule AttributeRoutePipelineValueRouter do
          use Phoenix.Router
          use AttestoPhoenix.Router

          @metadata_pipeline :metadata

          scope "/" do
            attesto_routes(route_pipelines: [metadata: @metadata_pipeline])
          end
        end
      end

      assert_raise ArgumentError, ~r/ordered list of pipeline atoms/, fn ->
        defmodule ImproperRoutePipelineListRouter do
          use Phoenix.Router
          use AttestoPhoenix.Router

          scope "/" do
            attesto_routes(route_pipelines: [interactive: [:interactive | :improper_tail]])
          end
        end
      end

      assert_raise ArgumentError, ~r/conflicting duplicate override/, fn ->
        defmodule DuplicateRoutePipelineClassRouter do
          use Phoenix.Router
          use AttestoPhoenix.Router

          scope "/" do
            attesto_routes(route_pipelines: [metadata: :one, metadata: :two])
          end
        end
      end

      assert_raise ArgumentError, ~r/conflicting option values/, fn ->
        defmodule DuplicateRoutePipelinesOptionRouter do
          use Phoenix.Router
          use AttestoPhoenix.Router

          scope "/" do
            attesto_routes(
              route_pipelines: [metadata: :one],
              route_pipelines: [metadata: :two]
            )
          end
        end
      end
    end

    test "endpoint opt-outs validate at macro expansion" do
      assert_raise ArgumentError, ~r/route-mount control :userinfo must be a literal boolean/, fn ->
        defmodule MalformedUserInfoCapabilityRouter do
          use Phoenix.Router
          use AttestoPhoenix.Router

          scope "/" do
            attesto_routes(userinfo: :disabled)
          end
        end
      end

      assert_raise ArgumentError, ~r/route-mount control :openid_configuration has conflicting option values/, fn ->
        defmodule DuplicateOpenIDConfigurationCapabilityRouter do
          use Phoenix.Router
          use AttestoPhoenix.Router

          scope "/" do
            attesto_routes(openid_configuration: false, openid_configuration: true)
          end
        end
      end
    end

    test "does not mount the end-session or check-session endpoints by default" do
      refute find_route(DefaultRouter, :get, "/oauth/end_session")
      refute find_route(DefaultRouter, :get, "/oauth/check_session")
    end

    test "mounts the end-session endpoint (GET + POST) with logout: true" do
      assert find_route(LogoutRouter, :get, "/oauth/end_session")
      assert find_route(LogoutRouter, :post, "/oauth/end_session")
    end

    test "mounts the check-session iframe with session_management: true" do
      route = find_route(LogoutRouter, :get, "/oauth/check_session")
      assert route
      assert route.plug == CheckSessionController
    end
  end

  describe "attesto_routes/1 protected-resource metadata (RFC 9728)" do
    test "mounts only the root document by default (RFC 9728 §3, backward compat)" do
      assert find_route(DefaultRouter, :get, "/.well-known/oauth-protected-resource")
      refute find_route(DefaultRouter, :get, "/.well-known/oauth-protected-resource/mcp")
    end

    test "protected_resource_paths mounts the §3.1 path-inserted URI (bare path normalized)" do
      route =
        find_route(ProtectedResourcePathRouter, :get, "/.well-known/oauth-protected-resource/mcp")

      assert route
      assert route.plug == ProtectedResourceController
      # The root document is still mounted alongside it.
      assert find_route(ProtectedResourcePathRouter, :get, "/.well-known/oauth-protected-resource")
    end

    # That the route stages the inserted path for the §3.3 controller guard is
    # proven end-to-end (through a router call, mismatch raising) in
    # ProtectedResourceControllerTest - Phoenix.Router.routes/1 does not expose
    # route privates for direct table introspection.

    test "protected_resource_root: false omits the root document" do
      refute find_route(
               ProtectedResourceRootlessRouter,
               :get,
               "/.well-known/oauth-protected-resource"
             )

      assert find_route(
               ProtectedResourceRootlessRouter,
               :get,
               "/.well-known/oauth-protected-resource/mcp"
             )
    end

    test "more than one path is a compile-time error pointing at attesto_mcp's macro" do
      assert_raise ArgumentError, ~r/attesto_mcp_protected_resource_metadata/, fn ->
        defmodule TwoPathRouter do
          use Phoenix.Router
          use AttestoPhoenix.Router

          scope "/" do
            attesto_routes(protected_resource_paths: ["/mcp", "/files"])
          end
        end
      end
    end

    test "path normalization accepts bare and slashed forms, rejects degenerate paths" do
      normalize = &AttestoPhoenix.Router.normalize_protected_resource_paths!/1

      assert normalize.(["mcp"]) == ["/mcp"]
      assert normalize.(["/mcp"]) == ["/mcp"]
      assert normalize.([]) == []

      assert_raise ArgumentError, ~r/names no resource path/, fn -> normalize.([""]) end
      assert_raise ArgumentError, ~r/names no resource path/, fn -> normalize.(["/"]) end
      assert_raise ArgumentError, ~r/not a plain resource path/, fn -> normalize.(["a/../b"]) end
      assert_raise ArgumentError, ~r/not a plain resource path/, fn -> normalize.(["/mcp?x=1"]) end
      assert_raise ArgumentError, ~r/expected a resource path string/, fn -> normalize.([:mcp]) end
      assert_raise ArgumentError, ~r/expected a list/, fn -> normalize.("/mcp") end
    end
  end
end
