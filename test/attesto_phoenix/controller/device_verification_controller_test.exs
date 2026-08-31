defmodule AttestoPhoenix.Controller.DeviceVerificationControllerTest do
  @moduledoc false
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias Attesto.DeviceCode
  alias Attesto.DeviceCodeStore.ETS
  alias Attesto.DeviceCodeStore.ETS, as: Store
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Controller.DeviceVerificationController, as: Controller

  @config_key AttestoPhoenix.Config

  defmodule FaultStore do
    @moduledoc false
    @behaviour Attesto.DeviceCodeStore

    def return_next(operation, value) do
      Process.put({__MODULE__, operation}, {:return, value})
      :ok
    end

    def reset do
      for operation <- [:lookup, :approve, :deny], do: Process.delete({__MODULE__, operation})
      :ok
    end

    @impl true
    def put(entry), do: ETS.put(entry)

    @impl true
    def lookup_user_code(user_code), do: next(:lookup, fn -> ETS.lookup_user_code(user_code) end)

    @impl true
    def get(device_code_hash), do: ETS.get(device_code_hash)

    @impl true
    def approve(user_code, approval, opts) do
      send(self(), {__MODULE__, :approve_called})
      next(:approve, fn -> ETS.approve(user_code, approval, opts) end)
    end

    @impl true
    def deny(user_code, opts), do: next(:deny, fn -> ETS.deny(user_code, opts) end)

    @impl true
    def poll(device_code_hash, opts), do: ETS.poll(device_code_hash, opts)

    @impl true
    def consume(device_code_hash, opts), do: ETS.consume(device_code_hash, opts)

    defp next(operation, fallback) do
      case Process.delete({__MODULE__, operation}) do
        {:return, value} -> value
        nil -> fallback.()
      end
    end
  end

  setup do
    start_supervised!(Store)
    Store.reset()
    FaultStore.reset()

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
      require_https: false,
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
    |> put_private(:attesto_phoenix_config, Config.new(Application.fetch_env!(:attesto_phoenix, @config_key)))
    |> Controller.verify(params)
  end

  defp body(conn), do: JSON.decode!(conn.resp_body)

  defp use_store(store) do
    config = Application.fetch_env!(:attesto_phoenix, @config_key)
    Application.put_env(:attesto_phoenix, @config_key, Keyword.put(config, :device_code_store, store))
  end

  defp set_user_code_length(length) do
    config = Application.fetch_env!(:attesto_phoenix, @config_key)
    device_opts = config |> Keyword.fetch!(:device_authorization) |> Keyword.put(:user_code_length, length)
    Application.put_env(:attesto_phoenix, @config_key, Keyword.put(config, :device_authorization, device_opts))
  end

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

  test "a lookup integration failure cannot reach the approval transition", %{
    user_code: uc,
    device_code: dc
  } do
    use_store(FaultStore)
    FaultStore.return_next(:lookup, {:error, :store_unavailable})

    error =
      assert_raise RuntimeError, fn ->
        call(:post, %{"user_code" => uc, "decision" => "approve"})
      end

    assert Exception.message(error) ==
             "Attesto.DeviceCode.lookup/2 violated its return contract"

    refute Exception.message(error) =~ "store_unavailable"
    refute_received {FaultStore, :approve_called}
    assert {:ok, %{status: :pending, scope: ["read"]}} = DeviceCode.lookup(Store, uc)

    assert {:error, :authorization_pending} =
             DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, interval: 0)
  end

  test "malformed lookup, approval, and denial returns fail loudly without values", %{user_code: uc} do
    use_store(FaultStore)

    FaultStore.return_next(:lookup, {:ok, %{status: :pending, scope: :malformed_lookup_secret}})

    lookup_error =
      assert_raise RuntimeError, fn ->
        call(:get, %{"user_code" => uc})
      end

    assert Exception.message(lookup_error) ==
             "Attesto.DeviceCode.lookup/2 violated its return contract"

    refute Exception.message(lookup_error) =~ "malformed_lookup_secret"

    FaultStore.return_next(:approve, :malformed_approval_secret)

    approval_error =
      assert_raise RuntimeError, fn ->
        call(:post, %{"user_code" => uc, "decision" => "approve"})
      end

    assert Exception.message(approval_error) ==
             "Attesto.DeviceCode.approve/3 violated its return contract"

    refute Exception.message(approval_error) =~ "malformed_approval_secret"

    FaultStore.return_next(:deny, :malformed_denial_secret)

    denial_error =
      assert_raise RuntimeError, fn ->
        call(:post, %{"user_code" => uc, "decision" => "deny"})
      end

    assert Exception.message(denial_error) ==
             "Attesto.DeviceCode.deny/2 violated its return contract"

    refute Exception.message(denial_error) =~ "malformed_denial_secret"
  end

  test "documented approval and denial outcomes remain ordinary invalid-code UI", %{user_code: uc} do
    use_store(FaultStore)

    FaultStore.return_next(:approve, {:error, :expired})
    assert body(call(:post, %{"user_code" => uc, "decision" => "approve"}))["stage"] == "invalid"

    FaultStore.return_next(:deny, {:error, :already_decided})
    assert body(call(:post, %{"user_code" => uc, "decision" => "deny"}))["stage"] == "invalid"
  end

  test "POST decision=deny denies the code", %{user_code: uc, device_code: dc} do
    conn = call(:post, %{"user_code" => uc, "decision" => "deny"})
    assert body(conn)["stage"] == "denied"
    assert {:error, :access_denied} = DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, interval: 0)
  end

  test "configured twelve-character codes can be looked up and approved" do
    set_user_code_length(12)

    assert {:ok, %{device_code: device_code, user_code: user_code}} =
             DeviceCode.issue(Store, %{client_id: "cli-1", scope: ["read"]}, user_code_length: 12)

    assert String.length(String.replace(user_code, "-", "")) == 12
    assert body(call(:get, %{"user_code" => user_code}))["stage"] == "prompt"
    assert body(call(:post, %{"user_code" => user_code, "decision" => "approve"}))["stage"] == "approved"

    assert {:ok, %{subject: "user-1"}} =
             DeviceCode.redeem(Store, device_code, %{client_id: "cli-1"}, interval: 0)
  end

  test "configured twelve-character codes can be denied" do
    set_user_code_length(12)

    assert {:ok, %{user_code: user_code}} =
             DeviceCode.issue(Store, %{client_id: "cli-1", scope: ["read"]}, user_code_length: 12)

    assert body(call(:post, %{"user_code" => user_code, "decision" => "deny"}))["stage"] == "denied"
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
