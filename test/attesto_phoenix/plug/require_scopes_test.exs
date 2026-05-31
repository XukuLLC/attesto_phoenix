defmodule AttestoPhoenix.Plug.RequireScopesTest do
  @moduledoc false
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

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
end
