defmodule AttestoPhoenix.ResourceRoutesTest do
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias Attesto.Plug.ProtectResource
  alias AttestoPhoenix.Controller.ResourceMetadataController

  defmodule Keys do
    @behaviour Attesto.Keystore

    @pem JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_pem() |> elem(1)
    @impl true
    def signing_pem, do: @pem
    @impl true
    def verification_pems, do: [@pem]
  end

  def config do
    Attesto.Config.new(
      issuer: "https://auth.example.com",
      audience: "https://api.example.com",
      keystore: Keys,
      principal_kinds: [Attesto.PrincipalKind.new("user", "usr_")]
    )
  end

  def documents_principal(claims, _sender), do: {:ok, %{documents_user: claims["sub"]}}
  def archives_principal(claims, _sender), do: {:ok, %{archives_user: claims["sub"]}}

  defmodule Endpoint do
    use Phoenix.Controller, formats: [:json]

    def show(conn, _params), do: json(conn, conn.assigns.attesto_context.principal)
  end

  defmodule Router do
    use Phoenix.Router
    use AttestoPhoenix.Router

    pipeline :documents do
      plug ProtectResource,
        config: {AttestoPhoenix.ResourceRoutesTest, :config},
        resource_path: "/documents",
        base_url: "https://api.example.com",
        resource_audience: :resource,
        scopes: ["documents.read"],
        principal: {AttestoPhoenix.ResourceRoutesTest, :documents_principal}
    end

    pipeline :archives do
      plug ProtectResource,
        config: {AttestoPhoenix.ResourceRoutesTest, :config},
        resource_path: "/archives",
        base_url: "https://api.example.com",
        resource_audience: :resource,
        scopes: ["archives.read", "offline_access"],
        principal: {AttestoPhoenix.ResourceRoutesTest, :archives_principal}
    end

    scope "/" do
      attesto_protected_resource_metadata("/documents",
        base_url: "https://api.example.com",
        issuer: "https://auth.example.com",
        scopes: ["documents.read"],
        root: false
      )

      attesto_protected_resource_metadata("/archives",
        base_url: "https://api.example.com",
        issuer: "https://auth.example.com",
        scopes: ["archives.read", "offline_access"],
        root: false
      )
    end

    scope "/" do
      pipe_through :documents
      get "/documents", Endpoint, :show
    end

    scope "/" do
      pipe_through :archives
      get "/archives", Endpoint, :show
    end
  end

  test "two resources have independent audiences, scope catalogs and principal loaders" do
    for {path, scopes, principal} <- [
          {"/documents", ["documents.read"], "documents_user"},
          {"/archives", ["archives.read", "offline_access"], "archives_user"}
        ] do
      metadata = request("/.well-known/oauth-protected-resource" <> path)
      assert metadata.status == 200
      assert get_resp_header(metadata, "cache-control") == ["public, max-age=3600"]

      assert %{
               "resource" => resource,
               "scopes_supported" => ^scopes,
               "authorization_servers" => ["https://auth.example.com"]
             } = JSON.decode!(metadata.resp_body)

      assert resource == "https://api.example.com" <> path
      token = token(path, scopes)
      response = request(path, token)
      assert response.status == 200
      assert JSON.decode!(response.resp_body) == %{principal => "usr_123"}
      other = if path == "/documents", do: "/archives", else: "/documents"
      assert request(other, token).status == 401
    end
  end

  test "scope failures point at the current resource metadata and list all required scopes" do
    response = request("/archives", token("/archives", ["archives.read"]))
    assert response.status == 403
    assert [challenge] = get_resp_header(response, "www-authenticate")
    assert challenge =~ "scope=\"archives.read offline_access\""
    assert challenge =~ "https://api.example.com/.well-known/oauth-protected-resource/archives"
  end

  test "host authority cannot select the audience or alter advertised metadata" do
    response = request("/documents", token("/documents", ["documents.read"], "https://hostile.example"))
    assert response.status == 401
    metadata = request("/.well-known/oauth-protected-resource/documents")
    assert JSON.decode!(metadata.resp_body)["resource"] == "https://api.example.com/documents"
  end

  test "discovery never loads a principal and missing credentials point to that resource" do
    response = request("/documents")
    assert response.status == 401
    assert [challenge] = get_resp_header(response, "www-authenticate")
    assert challenge =~ "https://api.example.com/.well-known/oauth-protected-resource/documents"
  end

  test "each resource document answers browser clients like the root document" do
    for path <- ["/documents", "/archives"] do
      metadata = request("/.well-known/oauth-protected-resource" <> path)
      assert get_resp_header(metadata, "access-control-allow-origin") == ["*"]
      assert get_resp_header(metadata, "access-control-allow-credentials") == []

      preflight =
        :options
        |> conn("https://hostile.example/.well-known/oauth-protected-resource" <> path)
        |> put_req_header("origin", "https://app.example")
        |> put_req_header("access-control-request-method", "GET")
        |> Router.call(Router.init([]))

      assert preflight.status == 204
      assert get_resp_header(preflight, "access-control-allow-origin") == ["*"]
      assert [methods] = get_resp_header(preflight, "access-control-allow-methods")
      assert methods =~ "GET"
    end
  end

  test "a resource document's :cors_origins option restricts or disables its CORS headers" do
    assert :ok = AttestoPhoenix.Router.validate_resource_cors_origins!(["https://app.example"])
    assert :ok = AttestoPhoenix.Router.validate_resource_cors_origins!(false)

    assert_raise ArgumentError, ~r/:cors_origins/, fn ->
      AttestoPhoenix.Router.validate_resource_cors_origins!("https://app.example")
    end

    private = %{attesto_resource_path: "/documents", attesto_resource_metadata_opts: metadata_opts()}

    disabled =
      :get
      |> conn("/.well-known/oauth-protected-resource/documents")
      |> Plug.Conn.put_private(:attesto_resource_cors_origins, false)
      |> Map.update!(:private, &Map.merge(&1, private))
      |> ResourceMetadataController.show(%{})

    assert disabled.status == 200
    assert get_resp_header(disabled, "access-control-allow-origin") == []

    listed =
      :get
      |> conn("/.well-known/oauth-protected-resource/documents")
      |> put_req_header("origin", "https://app.example")
      |> Plug.Conn.put_private(:attesto_resource_cors_origins, ["https://app.example"])
      |> Map.update!(:private, &Map.merge(&1, private))
      |> ResourceMetadataController.show(%{})

    assert get_resp_header(listed, "access-control-allow-origin") == ["https://app.example"]
    assert get_resp_header(listed, "vary") |> Enum.join(",") =~ "origin"
  end

  defp metadata_opts do
    [base_url: "https://api.example.com", issuer: "https://auth.example.com", scopes: ["documents.read"]]
  end

  defp request(path, token \\ nil) do
    conn = conn(:get, "https://hostile.example" <> path)
    conn = if token, do: put_req_header(conn, "authorization", "Bearer " <> token), else: conn
    Router.call(conn, Router.init([]))
  end

  defp token(path, scopes, origin \\ "https://api.example.com") do
    {:ok, token} =
      Attesto.Token.mint(config(), %{kind: "user", sub: "usr_123", scopes: scopes, claims: %{"client_id" => "client"}},
        audience: origin <> path
      )

    token.access_token
  end
end
