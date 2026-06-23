defmodule AttestoPhoenix.Controller.DeviceVerificationControllerTest do
  @moduledoc false
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias Attesto.DeviceCode
  alias Attesto.DeviceCodeStore.ETS, as: Store
  alias AttestoPhoenix.Controller.DeviceVerificationController, as: Controller

  @config_key AttestoPhoenix.Config

  setup do
    start_supervised!(Store)
    Store.reset()

    prev_otp = Application.get_env(:attesto_phoenix, :otp_app)
    Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)

    base = [
      issuer: "https://issuer.example",
      audience: "https://issuer.example",
      keystore: __MODULE__.Keystore,
      repo: __MODULE__.Repo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _c, _g -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      device_code_store: Store,
      device_authorization: [enabled: true],
      # Host login: a fixed signed-in user.
      authenticate_device_user: fn _conn -> {:ok, %{subject: "user-1", claims: %{"acr" => "phr"}}} end,
      # Host renderer: echo the stage as JSON so the test can assert on it.
      render_device_verification: fn conn, view ->
        conn |> put_status(200) |> Phoenix.Controller.json(%{stage: view.stage, user_code: view.user_code})
      end
    ]

    Application.put_env(:attesto_phoenix, @config_key, base)

    on_exit(fn ->
      Application.delete_env(:attesto_phoenix, @config_key)

      if prev_otp,
        do: Application.put_env(:attesto_phoenix, :otp_app, prev_otp),
        else: Application.delete_env(:attesto_phoenix, :otp_app)
    end)

    {:ok, %{device_code: dc, user_code: uc}} = DeviceCode.issue(Store, %{client_id: "cli-1", scope: ["read"]})
    {:ok, device_code: dc, user_code: uc}
  end

  defmodule Keystore do
    @moduledoc false
  end

  defmodule Repo do
    @moduledoc false
  end

  defp call(method, params) do
    method
    |> conn("/oauth/device_verification", params)
    |> Controller.verify(params)
  end

  defp body(conn), do: JSON.decode!(conn.resp_body)

  test "GET with a user_code shows the confirm prompt (no approval)", %{user_code: uc, device_code: dc} do
    conn = call(:get, %{"user_code" => uc})
    assert conn.status == 200
    assert body(conn)["stage"] == "prompt"

    # No auto-approval: the code is still pending.
    assert {:error, :authorization_pending} = DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, interval: 0)
  end

  test "POST decision=approve approves the code", %{user_code: uc, device_code: dc} do
    conn = call(:post, %{"user_code" => uc, "decision" => "approve"})
    assert body(conn)["stage"] == "approved"

    assert {:ok, grant} = DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, interval: 0)
    assert grant.subject == "user-1"
    assert grant.scope == ["read"]
    assert grant.claims == %{"acr" => "phr"}
  end

  test "POST decision=deny denies the code", %{user_code: uc, device_code: dc} do
    conn = call(:post, %{"user_code" => uc, "decision" => "deny"})
    assert body(conn)["stage"] == "denied"
    assert {:error, :access_denied} = DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, interval: 0)
  end

  test "an unknown / malformed user_code renders :invalid" do
    assert body(call(:post, %{"user_code" => "BCDFGHJK", "decision" => "approve"}))["stage"] == "invalid"
    assert body(call(:get, %{"user_code" => "not-a-code"}))["stage"] == "invalid"
  end

  test "a halt from the login callback takes over the connection" do
    Application.put_env(
      :attesto_phoenix,
      @config_key,
      Keyword.put(Application.get_env(:attesto_phoenix, @config_key), :authenticate_device_user, fn conn ->
        {:halt, Plug.Conn.send_resp(conn, 302, "login")}
      end)
    )

    conn = call(:get, %{"user_code" => "BCDF-GHJK"})
    assert conn.status == 302
  end
end
