defmodule AttestoPhoenix.Controller.CheckSessionControllerTest do
  @moduledoc """
  Tests for the `check_session_iframe` (OpenID Connect Session Management 1.0
  §3.3): the page is served only when the host enabled session management, and
  its script embeds the pieces the §3.2 postMessage protocol needs — the
  configured browser-state cookie name, the SHA-256 recomputation, and the
  `unchanged` / `changed` / `error` replies.
  """

  use ExUnit.Case, async: false

  import Plug.Test

  alias AttestoPhoenix.Controller.CheckSessionController, as: Controller

  @config_key AttestoPhoenix.Config

  defmodule StubKeystore do
    @moduledoc false
  end

  setup do
    prev_otp = Application.get_env(:attesto_phoenix, :otp_app)
    Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)

    base = [
      issuer: "https://issuer.example",
      audience: "https://issuer.example",
      keystore: StubKeystore,
      repo: __MODULE__.StubRepo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _c, _s -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      session_management: [enabled: true]
    ]

    Application.put_env(:attesto_phoenix, @config_key, base)

    on_exit(fn ->
      Application.delete_env(:attesto_phoenix, @config_key)

      if prev_otp,
        do: Application.put_env(:attesto_phoenix, :otp_app, prev_otp),
        else: Application.delete_env(:attesto_phoenix, :otp_app)
    end)

    {:ok, base: base}
  end

  defp call do
    :get
    |> conn("/oauth/check_session")
    |> Controller.show(%{})
  end

  test "serves the postMessage iframe page" do
    conn = call()

    assert conn.status == 200
    assert conn |> Plug.Conn.get_resp_header("content-type") |> List.first() =~ "text/html"

    # The §3.2 protocol pieces: the message listener, the SHA-256
    # recomputation over "client_id origin opbs salt", and the three replies.
    assert conn.resp_body =~ ~s(addEventListener("message")
    assert conn.resp_body =~ "SHA-256"
    assert conn.resp_body =~ ~s("unchanged")
    assert conn.resp_body =~ ~s("changed")
    assert conn.resp_body =~ ~s("error")

    # The default browser-state cookie name is embedded for the script.
    assert conn.resp_body =~ ~s("attesto_op_browser_state")
  end

  test "the page is cacheable (it embeds no per-user state)" do
    conn = call()
    assert conn |> Plug.Conn.get_resp_header("cache-control") |> List.first() =~ "max-age"
  end

  test "a configured cookie name is embedded instead of the default", %{base: base} do
    Application.put_env(
      :attesto_phoenix,
      @config_key,
      Keyword.put(base, :session_management, enabled: true, browser_state_cookie: "my_opbs")
    )

    conn = call()
    assert conn.resp_body =~ ~s("my_opbs")
    refute conn.resp_body =~ "attesto_op_browser_state"
  end

  test "404 when session management is disabled", %{base: base} do
    Application.put_env(
      :attesto_phoenix,
      @config_key,
      Keyword.put(base, :session_management, enabled: false)
    )

    conn = call()
    assert conn.status == 404
  end
end
