defmodule AttestoPhoenix.RouterTest do
  @moduledoc """
  Tests for the `attesto_routes/1` router macro: the mounted route table, the
  optional `:prefix` and `:registration` toggles, and `:pipeline` wiring.
  """

  use ExUnit.Case, async: true

  alias AttestoPhoenix.Controller.AuthorizeController
  alias AttestoPhoenix.Controller.CheckSessionController
  alias AttestoPhoenix.Controller.OpenIDConfigurationController
  alias AttestoPhoenix.Controller.PARController
  alias AttestoPhoenix.Controller.ProtectedResourceController
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
