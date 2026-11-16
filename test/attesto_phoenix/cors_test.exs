defmodule AttestoPhoenix.CORSTest do
  @moduledoc false
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias Attesto.{PrincipalKind, Token}
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Plug.Authenticate
  alias AttestoPhoenix.Plug.CORS
  alias Phoenix.Router.NoRouteError
  alias Plug.Conn.WrapperError

  @issuer "https://issuer.example"
  @audience "https://api.example"
  @origin "https://app.example"

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

  defmodule ASRouter do
    use Phoenix.Router
    use AttestoPhoenix.Router

    scope "/" do
      attesto_routes(
        registration: true,
        device: true,
        credential_issuance: true,
        federation: true,
        status_list: true,
        presentation: true,
        ciba: true,
        logout: true
      )
    end
  end

  defmodule ResourceRouter do
    use Phoenix.Router
    use AttestoPhoenix.Router

    attesto_protected_resource_metadata("/documents",
      base_url: "https://api.example",
      issuer: "https://issuer.example",
      cors_origins: false
    )
  end

  defp host_config(overrides \\ []) do
    Config.new(
      Keyword.merge(
        [
          issuer: @issuer,
          audience: @audience,
          keystore: StubKeystore,
          repo: StubRepo,
          principal_kinds: [
            PrincipalKind.new("user", "ou_", required_claims: [{"client_id", :non_empty_string}])
          ],
          load_client: fn _ -> {:error, :not_found} end,
          verify_client_secret: fn _, _ -> false end,
          load_principal: fn sub -> {:ok, %{sub: sub}} end
        ],
        overrides
      )
    )
  end

  defp protocol_config(config) do
    Config.to_attesto_config(config)
  end

  defp call_as(method, path, config, headers \\ [{"origin", @origin}]) do
    conn =
      Enum.reduce(headers, conn(method, path), fn {k, v}, acc -> put_req_header(acc, k, v) end)
      |> put_private(:attesto_phoenix_config, config)
      |> put_private(:attesto_protocol_config, protocol_config(config))

    ASRouter.call(conn, [])
  end

  describe "authorization server CORS headers (RFC 10017 §6.3.3.4)" do
    test "metadata and token endpoints emit CORS headers on cross-origin requests" do
      config = host_config()

      for path <- [
            "/.well-known/oauth-authorization-server",
            "/.well-known/jwks.json",
            "/.well-known/oauth-protected-resource"
          ] do
        conn = call_as(:get, path, config)
        assert conn.status == 200
        assert get_resp_header(conn, "access-control-allow-origin") == ["*"]
      end

      token_conn = call_as(:post, "/oauth/token", config)
      assert get_resp_header(token_conn, "access-control-allow-origin") == ["*"]
    end

    test "handles OPTIONS preflight on AS protocol and metadata endpoints" do
      config = host_config()

      preflight =
        call_as(:options, "/oauth/token", config, [
          {"origin", @origin},
          {"access-control-request-method", "POST"},
          {"access-control-request-headers", "authorization, dpop, content-type"}
        ])

      assert preflight.status == 204
      assert get_resp_header(preflight, "access-control-allow-origin") == ["*"]
      assert [allow_headers] = get_resp_header(preflight, "access-control-allow-headers")
      assert allow_headers =~ "authorization"
      assert allow_headers =~ "dpop"
    end

    test "allowlist origins match with Vary: origin, reject unknown origins, and opt-out omits CORS headers" do
      allowlist = host_config(cors_origins: [@origin])

      allowed = call_as(:get, "/.well-known/oauth-authorization-server", allowlist)
      assert allowed.status == 200
      assert get_resp_header(allowed, "access-control-allow-origin") == [@origin]
      assert get_resp_header(allowed, "vary") == ["origin"]

      denied = call_as(:get, "/.well-known/oauth-authorization-server", allowlist, [{"origin", "https://evil.example"}])
      assert denied.status == 200
      assert get_resp_header(denied, "access-control-allow-origin") == []

      disabled = host_config(cors_origins: false)
      no_cors = call_as(:get, "/.well-known/oauth-authorization-server", disabled)
      assert get_resp_header(no_cors, "access-control-allow-origin") == []

      interactive = call_as(:get, "/oauth/authorize", host_config())
      assert get_resp_header(interactive, "access-control-allow-origin") == []
    end
  end

  test "disabled preflights use the same host error renderer as every unmounted path" do
    parent = self()

    config =
      host_config(
        cors_origins: false,
        load_client: fn id ->
          send(parent, {:client_lookup, id})
          if id == "registered", do: {:ok, %{id: id}}, else: {:error, :not_found}
        end
      )

    expected = render_missing_route(fn -> call_as(:options, "/unmounted", config) end)
    assert expected == {404, "host missing route"}

    paths =
      ASRouter.__routes__()
      |> Enum.filter(&(&1.verb == :options))
      |> Enum.flat_map(fn route ->
        if String.contains?(route.path, ":"),
          do: [
            Regex.replace(~r/:[^\/]+/, route.path, "registered"),
            Regex.replace(~r/:[^\/]+/, route.path, "unregistered")
          ],
          else: [route.path]
      end)

    assert "/oauth/token" in paths
    assert Enum.any?(paths, &String.ends_with?(&1, "/registered"))

    for path <- paths do
      assert render_missing_route(fn -> call_as(:options, path, config) end) == expected
    end

    refute_received {:client_lookup, _}
  end

  test "a resource's disabled CORS overrides the default and uses missing-route rendering" do
    config = host_config()
    expected = render_missing_route(fn -> ResourceRouter.call(conn(:options, "/unmounted"), []) end)

    for path <- ["/.well-known/oauth-protected-resource/documents", "/.well-known/oauth-protected-resource"] do
      request = conn(:options, path) |> put_private(:attesto_phoenix_config, config)
      assert render_missing_route(fn -> ResourceRouter.call(request, []) end) == expected
    end
  end

  test "disabled preflight outside a router sends an empty 404 and halts" do
    result = CORS.preflight(conn(:options, "/token"), origins: false)
    assert {result.status, result.resp_body, result.halted} == {404, "", true}
    assert get_resp_header(result, "access-control-allow-origin") == []
  end

  defp render_missing_route(call) do
    call.()
    flunk("expected missing route")
  rescue
    error in NoRouteError ->
      assert error.router in [ASRouter, ResourceRouter]
      assert error.conn.method == "OPTIONS"
      {Plug.Exception.status(error), "host missing route"}

    error in WrapperError ->
      assert %NoRouteError{} = error.reason
      assert error.reason.router in [ASRouter, ResourceRouter]
      {Plug.Exception.status(error.reason), "host missing route"}
  end

  describe "resource server CORS headers (RFC 10017 §6.3.3.4)" do
    test "protected resource plug emits CORS headers on authenticated and rejected responses" do
      config = host_config(keystore: StubKeystore, dpop_enabled: false)
      protocol = protocol_config(config)

      {:ok, %{access_token: token}} =
        Token.mint(
          protocol,
          %{kind: "user", sub: "ou_123", scopes: ["read"], claims: %{"client_id" => "c1"}},
          []
        )

      auth =
        :get
        |> conn("https://api.example/api/resource")
        |> put_req_header("origin", @origin)
        |> put_req_header("authorization", "Bearer " <> token)
        |> put_private(:attesto_phoenix_config, config)
        |> put_private(:attesto_protocol_config, protocol)
        |> Authenticate.call(Authenticate.init([]))

      refute auth.halted
      assert get_resp_header(auth, "access-control-allow-origin") == ["*"]

      unauth =
        :get
        |> conn("https://api.example/api/resource")
        |> put_req_header("origin", @origin)
        |> put_private(:attesto_phoenix_config, config)
        |> put_private(:attesto_protocol_config, protocol)
        |> Authenticate.call(Authenticate.init([]))

      assert unauth.status == 401
      assert get_resp_header(unauth, "access-control-allow-origin") == ["*"]
      assert Enum.join(get_resp_header(unauth, "access-control-expose-headers"), ", ") =~ "www-authenticate"

      allowlist = host_config(keystore: StubKeystore, dpop_enabled: false, cors_origins: [@origin])

      restricted =
        :get
        |> conn("https://api.example/api/resource")
        |> put_req_header("origin", @origin)
        |> put_req_header("authorization", "Bearer " <> token)
        |> put_private(:attesto_phoenix_config, allowlist)
        |> put_private(:attesto_protocol_config, protocol_config(allowlist))
        |> Authenticate.call(Authenticate.init([]))

      assert get_resp_header(restricted, "access-control-allow-origin") == [@origin]
      assert get_resp_header(restricted, "vary") == ["origin"]

      denied =
        :get
        |> conn("https://api.example/api/resource")
        |> put_req_header("origin", "https://evil.example")
        |> put_req_header("authorization", "Bearer " <> token)
        |> put_private(:attesto_phoenix_config, allowlist)
        |> put_private(:attesto_protocol_config, protocol_config(allowlist))
        |> Authenticate.call(Authenticate.init([]))

      assert get_resp_header(denied, "access-control-allow-origin") == []

      disabled = host_config(keystore: StubKeystore, dpop_enabled: false, cors_origins: false)

      no_cors =
        :get
        |> conn("https://api.example/api/resource")
        |> put_req_header("origin", @origin)
        |> put_private(:attesto_phoenix_config, disabled)
        |> put_private(:attesto_protocol_config, protocol_config(disabled))
        |> Authenticate.call(Authenticate.init([]))

      assert no_cors.status == 401
      assert get_resp_header(no_cors, "access-control-allow-origin") == []
    end
  end
end
