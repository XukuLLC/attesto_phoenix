defmodule AttestoPhoenix.Controller.ProtectedResourceControllerTest do
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias Attesto.Config, as: ProtocolConfig
  alias Attesto.PrincipalKind
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Controller.ProtectedResourceController
  alias Plug.Conn.WrapperError

  @issuer "https://issuer.example"
  @audience "https://api.example.com"

  # A keystore module reference is all Attesto.Config validation requires (it
  # checks the value is a module, not that it implements anything).
  defmodule StubKeystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @pem JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_pem() |> elem(1)

    @impl true
    def signing_pem, do: @pem

    @impl true
    def verification_pems, do: [@pem]
  end

  defmodule StubRepo do
    @moduledoc false
  end

  # Build the host-facing AttestoPhoenix.Config. Only the members the
  # protected-resource document sources from it are varied by the tests.
  defp host_config(overrides \\ []) do
    Config.new(
      Keyword.merge(
        [
          issuer: @issuer,
          audience: @audience,
          keystore: StubKeystore,
          repo: StubRepo,
          scopes_supported: ["openid", "profile", "api.read"],
          load_client: fn _ -> {:error, :not_found} end,
          verify_client_secret: fn _, _ -> false end,
          load_principal: fn _ -> {:error, :not_found} end
        ],
        overrides
      )
    )
  end

  # The protocol-level Attesto.Config the core metadata builder reads. Its
  # audience is the resource identifier the RFC 9728 `resource` defaults to.
  defp protocol_config(audience \\ @audience) do
    ProtocolConfig.new(
      issuer: @issuer,
      audience: audience,
      keystore: StubKeystore,
      principal_kinds: [
        PrincipalKind.new("client", "oc_", required_claims: [{"client_id", :non_empty_string}])
      ]
    )
  end

  # Invoke the controller action directly with both configs placed where the
  # action expects them, mirroring what a router pipeline installs.
  defp call_show(host, protocol) do
    conn(:get, "/.well-known/oauth-protected-resource")
    |> put_private(:attesto_phoenix_config, host)
    |> put_private(:attesto_protocol_config, protocol)
    |> ProtectedResourceController.show(%{})
  end

  defp decode_body(conn), do: JSON.decode!(conn.resp_body)

  describe "show/2" do
    test "renders the RFC 9728 §2 members as JSON" do
      conn = call_show(host_config(), protocol_config())
      body = decode_body(conn)

      assert conn.status == 200
      # RFC 9728 §2: resource (REQUIRED) defaults to the access-token audience.
      assert body["resource"] == @audience
      # An AS that is also the protected resource issues its own tokens, so the
      # issuer is the authorization server for this resource.
      assert body["authorization_servers"] == [@issuer]
      # RFC 6750 §2.1: the default matching AttestoPhoenix.Plug.Authenticate is
      # header-only.
      assert body["bearer_methods_supported"] == ["header"]
      assert body["scopes_supported"] == ["openid", "profile", "api.read"]
    end

    test "advertises only the host-configured bearer_methods_supported (RFC 9728 §2)" do
      body = call_show(host_config(bearer_methods_supported: ["header", "body"]), protocol_config()) |> decode_body()

      assert body["bearer_methods_supported"] == ["header", "body"]
    end

    test "resource follows the protocol audience (the resource identifier)" do
      body =
        call_show(host_config(), protocol_config("https://other.example/api")) |> decode_body()

      assert body["resource"] == "https://other.example/api"
    end

    test "omits scopes_supported when the host advertises none (RFC 9728 §2: OPTIONAL)" do
      body = call_show(host_config(scopes_supported: []), protocol_config()) |> decode_body()

      refute Map.has_key?(body, "scopes_supported")
      # The REQUIRED member is still present.
      assert body["resource"] == @audience
    end

    test "sets a public, cacheable Cache-Control header (RFC 9728 §3.1)" do
      conn = call_show(host_config(), protocol_config())

      assert get_resp_header(conn, "cache-control") == ["public, max-age=3600"]
    end

    test "fails closed when the AttestoPhoenix.Config is absent (wiring error)" do
      assert_raise RuntimeError, ~r/attesto_phoenix_config/, fn ->
        conn(:get, "/.well-known/oauth-protected-resource")
        |> put_private(:attesto_protocol_config, protocol_config())
        |> ProtectedResourceController.show(%{})
      end
    end

    test "fails closed when the protocol Attesto.Config is absent (wiring error)" do
      assert_raise RuntimeError, ~r/attesto_protocol_config/, fn ->
        conn(:get, "/.well-known/oauth-protected-resource")
        |> put_private(:attesto_phoenix_config, host_config())
        |> ProtectedResourceController.show(%{})
      end
    end
  end

  # The RFC 9728 §3.1 path-inserted form: `attesto_routes/1` stages the
  # inserted resource path under `conn.private[:attesto_prm_inserted_path]`,
  # and the controller must serve the same document as the root URI - or fail
  # closed when the configured resource identifier's path disagrees (§3.3).
  describe "show/2 at the path-inserted well-known URI" do
    defp call_show_inserted(host, protocol, inserted_path) do
      conn(:get, "/.well-known/oauth-protected-resource" <> inserted_path)
      |> put_private(:attesto_phoenix_config, host)
      |> put_private(:attesto_protocol_config, protocol)
      |> put_private(:attesto_prm_inserted_path, inserted_path)
      |> ProtectedResourceController.show(%{})
    end

    test "serves the same document as the root URI when the resource path matches" do
      protocol = protocol_config("https://api.example.com/mcp")

      root = call_show(host_config(), protocol)
      inserted = call_show_inserted(host_config(), protocol, "/mcp")

      assert inserted.status == 200
      # Decoded-equal to the root document, same cache-control (RFC 9728 §3.1).
      assert decode_body(inserted) == decode_body(root)
      assert get_resp_header(inserted, "cache-control") == get_resp_header(root, "cache-control")
      assert decode_body(inserted)["resource"] == "https://api.example.com/mcp"
    end

    test "fails closed when the resource identifier's path disagrees (RFC 9728 §3.3)" do
      # Configured identifier path is /api/mcp; the route was mounted for /mcp.
      protocol = protocol_config("https://api.example.com/api/mcp")

      error =
        assert_raise RuntimeError, fn ->
          call_show_inserted(host_config(), protocol, "/mcp")
        end

      # The message names both values so the wiring error is diagnosable.
      assert error.message =~ ~s("/mcp")
      assert error.message =~ "https://api.example.com/api/mcp"
      assert error.message =~ "RFC 9728 §3.3"
    end

    test "fails closed when the resource identifier carries no path at all" do
      assert_raise RuntimeError, ~r/RFC 9728 §3\.3/, fn ->
        call_show_inserted(host_config(), protocol_config("https://api.example.com"), "/mcp")
      end
    end
  end

  # End-to-end §3.1 derivation through a real router: derive the well-known
  # URL from the served document's own `resource` member, fetch it, and the
  # `resource` must round-trip identically - the exact client behavior that
  # motivated mounting the path-inserted form.
  describe "path-inserted discovery through the router" do
    @mcp_resource "https://api.example.com/mcp"

    defmodule InstallConfigs do
      @moduledoc false
      import Plug.Conn

      def init(opts), do: opts

      # `Router.call/2` under `Plug.Test` runs in the test process, so the
      # configs staged in its process dictionary are directly readable here.
      def call(conn, _opts) do
        %{host: host, protocol: protocol} = Process.get(:attesto_prm_configs)

        conn
        |> put_private(:attesto_phoenix_config, host)
        |> put_private(:attesto_protocol_config, protocol)
      end
    end

    defmodule DerivationRouter do
      use Phoenix.Router
      use AttestoPhoenix.Router

      pipeline :oauth do
        plug InstallConfigs
      end

      scope "/" do
        attesto_routes(pipeline: :oauth, protected_resource_paths: ["/mcp"])
      end
    end

    test "the document's own resource member derives a URL that serves it back" do
      Process.put(:attesto_prm_configs, %{
        host: host_config(),
        protocol: protocol_config(@mcp_resource)
      })

      fetch = fn url ->
        uri = URI.parse(url)

        conn(:get, uri.path)
        |> DerivationRouter.call(DerivationRouter.init([]))
      end

      # Client-side §3.1 derivation: insert the well-known segment between the
      # origin and the resource path.
      resource_uri = URI.parse(@mcp_resource)

      derived =
        "#{resource_uri.scheme}://#{resource_uri.host}/.well-known/oauth-protected-resource#{resource_uri.path}"

      conn = fetch.(derived)

      assert conn.status == 200
      body = JSON.decode!(conn.resp_body)
      # §3.3: the retrieved document's resource is identical to the identifier
      # the URI was derived from.
      assert body["resource"] == @mcp_resource
    end

    test "the route stages the inserted path: a mismatched identifier raises through the router" do
      # Proves attesto_routes/1 actually delivers :attesto_prm_inserted_path
      # into conn.private (the negative controller tests stage it by hand).
      Process.put(:attesto_prm_configs, %{
        host: host_config(),
        protocol: protocol_config("https://api.example.com/api/mcp")
      })

      assert_raise WrapperError, ~r/RFC 9728 §3\.3/, fn ->
        conn(:get, "/.well-known/oauth-protected-resource/mcp")
        |> DerivationRouter.call(DerivationRouter.init([]))
      end
    end
  end
end
