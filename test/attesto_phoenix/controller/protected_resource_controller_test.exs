defmodule AttestoPhoenix.Controller.ProtectedResourceControllerTest do
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias Attesto.Config, as: ProtocolConfig
  alias Attesto.PrincipalKind
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Controller.ProtectedResourceController

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
      # RFC 6750 §2.1/§2.2: the default (matching AttestoPhoenix.Plug.Authenticate)
      # advertises both the Authorization header and the POST form-body token.
      assert body["bearer_methods_supported"] == ["header", "body"]
      assert body["scopes_supported"] == ["openid", "profile", "api.read"]
    end

    test "advertises only the host-configured bearer_methods_supported (RFC 9728 §2)" do
      # A header-only resource server must not advertise the body method it rejects.
      body = call_show(host_config(bearer_methods_supported: ["header"]), protocol_config()) |> decode_body()

      assert body["bearer_methods_supported"] == ["header"]
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
end
