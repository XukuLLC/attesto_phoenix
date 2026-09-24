defmodule AttestoPhoenix.Plug.RequireScopesTest do
  @moduledoc false
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias Attesto.Keystore.Static
  alias AttestoPhoenix.Plug.RequireScopes

  test "accepts a single scope string for Phoenix router ergonomics" do
    conn =
      :get
      |> conn("/reports")
      |> assign(:attesto_claims, %{"scope" => "openid read:reports"})
      |> RequireScopes.call(RequireScopes.init("read:reports"))

    refute conn.halted
  end

  test "delegates insufficient-scope errors to the core scope plug" do
    conn =
      :get
      |> conn("/reports")
      |> assign(:attesto_claims, %{"scope" => "openid"})
      |> RequireScopes.call(RequireScopes.init("read:reports"))

    assert conn.halted
    assert conn.status == 403
    assert JSON.decode!(conn.resp_body)["error"] == "insufficient_scope"
  end

  test "explicit config records the denial before a custom transport" do
    config = audit_config(fn event -> send(self(), {:event, event}) end)

    transport = fn conn, status, body ->
      assert_received {:event, %AttestoPhoenix.Event{name: :auth_denied}}
      conn |> send_resp(status, JSON.encode!(body)) |> halt()
    end

    response =
      conn(:get, "/reports")
      |> RequireScopes.call(RequireScopes.init(scopes: ["openid"], config: fn -> config end, send_error: transport))

    assert response.status == 401
    assert response.halted
    refute_received {:event, _}
  end

  test "scope refusals do not emit authentication denials" do
    config = audit_config(fn _ -> flunk("403 must not emit auth_denied") end)

    response =
      conn(:get, "/reports")
      |> assign(:attesto_claims, %{"scope" => "openid"})
      |> RequireScopes.call(RequireScopes.init(scopes: ["admin"], config: config))

    assert response.status == 403
    assert response.halted
  end

  test "request-private config is authoritative for the denial audit" do
    config = audit_config(fn event -> send(self(), {:event, event}) end)

    response =
      conn(:get, "/reports")
      |> put_private(:attesto_phoenix_config, config)
      |> register_before_send(fn response ->
        assert_received {:event, %AttestoPhoenix.Event{name: :auth_denied}}
        response
      end)
      |> RequireScopes.call(RequireScopes.init(scopes: ["openid"], config: fn -> flunk("fallback ran") end))

    assert response.status == 401
    assert response.halted
  end

  test "audit exceptions stop an unauthenticated request before sending" do
    config = audit_config(fn _ -> raise "audit unavailable" end)
    request = conn(:get, "/reports")

    assert_raise RuntimeError, "audit unavailable", fn ->
      RequireScopes.call(request, RequireScopes.init(scopes: ["openid"], config: config))
    end

    assert_raise RuntimeError, ~r/no sent response/, fn -> sent_resp(request) end
  end

  defp audit_config(on_event) do
    AttestoPhoenix.Config.new(
      issuer: "https://issuer.example",
      audience: "https://api.example",
      keystore: Static,
      repo: __MODULE__.Repo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      on_event: on_event
    )
  end
end
