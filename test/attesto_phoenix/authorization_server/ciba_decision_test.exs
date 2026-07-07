defmodule AttestoPhoenix.AuthorizationServer.CIBADecisionTest do
  @moduledoc """
  Tests for the CIBA decision helper (approve/deny + §10.2 ping delivery),
  including the conformance-locked ping semantics of the default `Req`
  deliverer (no retry on 401, no redirect following).
  """
  use ExUnit.Case, async: false

  alias Attesto.CIBA
  alias Attesto.CIBAStore.ETS, as: Store
  alias AttestoPhoenix.AuthorizationServer.CIBADecision
  alias AttestoPhoenix.CIBAPing
  alias AttestoPhoenix.Config
  alias Plug.Conn

  @endpoint "https://client.example/ciba/ping"

  defmodule StubKeystore do
    @moduledoc false
  end

  defmodule StubRepo do
    @moduledoc false
  end

  defmodule StubPing do
    @moduledoc false
    @behaviour AttestoPhoenix.CIBAPing

    @impl true
    def post(endpoint, token, auth_req_id) do
      send(Application.fetch_env!(:attesto_phoenix, :test_ping_pid), {:ping, endpoint, token, auth_req_id})
      :ok
    end
  end

  setup do
    start_supervised!(Store)
    Store.reset()
    Application.put_env(:attesto_phoenix, :test_ping_pid, self())
    on_exit(fn -> Application.delete_env(:attesto_phoenix, :test_ping_pid) end)
    :ok
  end

  defp config(overrides \\ []) do
    [
      issuer: "https://issuer.example",
      audience: "https://issuer.example",
      keystore: StubKeystore,
      repo: StubRepo,
      load_client: fn "cli-1" -> {:ok, %{id: "cli-1", ciba: %{client_notification_endpoint: @endpoint}}} end,
      verify_client_secret: fn _c, _g -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      client_ciba_registration: fn c -> Map.get(c, :ciba, %{}) end,
      authenticate_ciba_user: fn _ -> {:ok, "user:alice"} end,
      ciba_store: Store,
      ciba_ping_http_client: StubPing,
      ciba: [enabled: true]
    ]
    |> Keyword.merge(overrides)
    |> Config.new()
  end

  defp issue(delivery_mode, token) do
    req = %CIBA.Request{
      client_id: "cli-1",
      delivery_mode: delivery_mode,
      hint: {:login_hint, "alice@example.test"},
      scope: ["openid"],
      client_notification_token: token
    }

    {:ok, issued} = CIBA.issue(Store, req, %{subject: "user:alice"})
    issued.auth_req_id
  end

  test "approve on a ping request POSTs the notification with the bearer token + auth_req_id" do
    auth_req_id = issue(:ping, "cnt-abcdefghijklmnopqrstuv")

    assert {:ok, _decision} = CIBADecision.approve(config(), auth_req_id, %{subject: "user:alice"})

    assert_receive {:ping, @endpoint, "cnt-abcdefghijklmnopqrstuv", ^auth_req_id}, 1_000
  end

  test "deny on a ping request also fires the notification (§10.2 fires on denial)" do
    auth_req_id = issue(:ping, "cnt-abcdefghijklmnopqrstuv")

    assert {:ok, _decision} = CIBADecision.deny(config(), auth_req_id)

    assert_receive {:ping, @endpoint, _token, ^auth_req_id}, 1_000
  end

  test "approve on a poll request sends no notification" do
    auth_req_id = issue(:poll, nil)

    assert {:ok, _decision} = CIBADecision.approve(config(), auth_req_id, %{subject: "user:alice"})

    refute_receive {:ping, _endpoint, _token, _auth_req_id}, 200
  end

  describe "default Req deliverer conformance-locked semantics" do
    setup do
      bypass = Bypass.open()
      {:ok, bypass: bypass, url: "http://localhost:#{bypass.port}/ciba/ping"}
    end

    test "POSTs the bearer token + JSON body and treats 2xx as success", %{bypass: bypass, url: url} do
      pid = self()

      Bypass.expect_once(bypass, "POST", "/ciba/ping", fn conn ->
        [auth] = Conn.get_req_header(conn, "authorization")
        {:ok, raw, conn} = Conn.read_body(conn)
        send(pid, {:got, auth, JSON.decode!(raw)})
        Conn.resp(conn, 204, "")
      end)

      assert :ok = CIBAPing.Req.post(url, "the-token", "arid-123")
      assert_receive {:got, "Bearer the-token", %{"auth_req_id" => "arid-123"}}
    end

    test "does not retry on 401 (returns the status; flow is unaffected)", %{bypass: bypass, url: url} do
      pid = self()

      Bypass.expect(bypass, "POST", "/ciba/ping", fn conn ->
        send(pid, :hit)
        Conn.resp(conn, 401, "")
      end)

      assert {:error, {:status, 401}} = CIBAPing.Req.post(url, "t", "arid")

      # Exactly one hit — no retry.
      assert_receive :hit
      refute_receive :hit, 200
    end

    test "does not follow a 3xx redirect from the notification endpoint (SSRF posture)", %{bypass: bypass, url: url} do
      Bypass.expect_once(bypass, "POST", "/ciba/ping", fn conn ->
        conn
        |> Conn.put_resp_header("location", "https://attacker.example/")
        |> Conn.resp(302, "")
      end)

      assert {:error, {:status, 302}} = CIBAPing.Req.post(url, "t", "arid")
    end
  end
end
