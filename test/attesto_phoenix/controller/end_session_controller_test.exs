defmodule AttestoPhoenix.Controller.EndSessionControllerTest do
  @moduledoc """
  Integration tests for the end-session endpoint (OpenID Connect RP-Initiated
  Logout 1.0 + Back-Channel Logout 1.0).

  Exercises the controller against a real signing keystore (so `id_token_hint`
  verification and `logout_token` minting are genuine) and the Ecto-backed
  logout-session store, with a stub HTTP deliverer capturing the back-channel
  fan-out. Tagged `:ecto` for the SQL backend.
  """

  use AttestoPhoenix.DataCase, async: false

  import Plug.Conn
  import Plug.Test

  alias Attesto.IDToken
  alias Attesto.Keystore.Static
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Controller.EndSessionController, as: Controller
  alias AttestoPhoenix.Store.EctoLogoutSessionStore, as: Store

  @moduletag :ecto

  @config_key AttestoPhoenix.Config
  @issuer "https://issuer.example"
  @client_id "rp-a"
  @subject "user-1"
  @sid "sess-1"

  defmodule StubHTTP do
    @moduledoc false
    @behaviour AttestoPhoenix.BackChannelLogout

    @impl true
    def post(uri, logout_token) do
      pid = Application.get_env(:attesto_phoenix, :test_bc_pid)
      send(pid, {:bc_post, uri, logout_token})
      :ok
    end
  end

  setup do
    pem = rsa_pem()
    Application.put_env(:attesto, Static, signing_pem: pem)
    Application.put_env(:attesto_phoenix, :test_bc_pid, self())

    prev_otp = Application.get_env(:attesto_phoenix, :otp_app)
    Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)

    base = [
      issuer: @issuer,
      audience: @issuer,
      keystore: Static,
      repo: AttestoPhoenix.TestRepo,
      principal_kinds: [Attesto.PrincipalKind.new("user", "usr_")],
      load_client: fn
        @client_id -> {:ok, %{id: @client_id, post_logout: ["https://rp.example/after"]}}
        _ -> {:error, :not_found}
      end,
      verify_client_secret: fn _c, _g -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      client_post_logout_redirect_uris: fn client -> client.post_logout end,
      logout_session_store: Store,
      logout: [enabled: true, http_client: StubHTTP],
      require_https: false,
      # The host is the session authority: it validates the request against the
      # current session and returns the confirmed (sid, subject) that scopes the
      # back-channel fan-out.
      terminate_session: fn conn, ctx ->
        {:ok, put_private(conn, :terminated, true), %{sid: ctx.sid, subject: ctx.subject}}
      end,
      render_logged_out: fn conn, _ctx ->
        conn |> put_status(200) |> Phoenix.Controller.json(%{logged_out: true})
      end
    ]

    Application.put_env(:attesto_phoenix, @config_key, base)

    on_exit(fn ->
      Application.delete_env(:attesto_phoenix, @config_key)
      Application.delete_env(:attesto_phoenix, :test_bc_pid)

      if prev_otp,
        do: Application.put_env(:attesto_phoenix, :otp_app, prev_otp),
        else: Application.delete_env(:attesto_phoenix, :otp_app)
    end)

    config = Config.new(base)
    {:ok, hint} = IDToken.mint(Config.to_attesto_config(config), @subject, @client_id, sid: @sid)
    {:ok, config: config, hint: hint}
  end

  defp rsa_pem do
    priv = :public_key.generate_key({:rsa, 2048, 65_537})
    :public_key.pem_encode([:public_key.pem_entry_encode(:RSAPrivateKey, priv)])
  end

  defp call(method, params) do
    method
    |> conn("/oauth/end_session", params)
    |> Controller.end_session(params)
  end

  defp call_html(method, params) do
    method
    |> conn("/oauth/end_session", params)
    |> put_req_header("accept", "text/html,application/xhtml+xml")
    |> Controller.end_session(params)
  end

  defp body(conn), do: JSON.decode!(conn.resp_body)

  defp logout_payload(jwt) do
    [_h, p | _] = String.split(jwt, ".")
    {:ok, decoded} = Base.url_decode64(p, padding: false)
    JSON.decode!(decoded)
  end

  describe "RP-initiated redirect" do
    test "valid hint + registered uri redirects with state and terminates the session", %{hint: hint} do
      conn =
        call(:get, %{
          "id_token_hint" => hint,
          "post_logout_redirect_uri" => "https://rp.example/after",
          "state" => "xyz"
        })

      assert conn.status in 302..303
      assert conn.private[:terminated] == true
      location = conn |> get_resp_header("location") |> List.first()
      assert location == "https://rp.example/after?state=xyz"
    end

    test "an unregistered uri is refused before any session is touched", %{hint: hint} do
      conn =
        call(:get, %{
          "id_token_hint" => hint,
          "post_logout_redirect_uri" => "https://evil.example/steal"
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_request"
      refute conn.private[:terminated]
    end

    test "no return uri renders the host logged-out page", %{hint: hint} do
      conn = call(:get, %{"id_token_hint" => hint})
      assert conn.status == 200
      assert body(conn)["logged_out"] == true
      assert conn.private[:terminated] == true
    end

    test "a browser (Accept: text/html) gets an HTML error page, not JSON", %{hint: hint} do
      conn =
        call_html(:get, %{"id_token_hint" => hint, "post_logout_redirect_uri" => "https://evil.example/steal"})

      assert conn.status == 400
      assert conn |> get_resp_header("content-type") |> List.first() =~ "text/html"
      assert conn.resp_body =~ "<html"
      assert conn.resp_body =~ "invalid post_logout_redirect_uri"
    end

    test "a tampered hint is a 400", %{hint: hint} do
      conn = call(:get, %{"id_token_hint" => hint <> "tamper"})
      assert conn.status == 400
    end
  end

  describe "back-channel fan-out" do
    test "POSTs a valid logout_token to each RP holding the session and clears it", %{hint: hint} do
      now = System.system_time(:second)

      :ok =
        Store.record(%{
          sid: @sid,
          subject: @subject,
          client_id: "rp-b",
          backchannel_logout_uri: "https://rp-b.example/bc",
          session_required: true,
          expires_at: now + 3600
        })

      conn = call(:get, %{"id_token_hint" => hint})
      assert conn.status == 200

      assert_received {:bc_post, "https://rp-b.example/bc", token}
      claims = logout_payload(token)
      assert claims["aud"] == "rp-b"
      assert claims["sid"] == @sid
      assert claims["sub"] == @subject
      assert claims["events"] == %{"http://schemas.openid.net/event/backchannel-logout" => %{}}
      refute Map.has_key?(claims, "nonce")

      # the session row is gone after the fan-out
      assert [] = Store.targets(%{sid: @sid})
    end

    test "logout enabled without :terminate_session fails config validation (no fail-open)", %{config: _config} do
      base = Application.get_env(:attesto_phoenix, @config_key)
      no_terminate = Keyword.delete(base, :terminate_session)

      assert_raise ArgumentError, ~r/:terminate_session is required when logout is enabled/, fn ->
        Config.new(no_terminate)
      end
    end

    test "disabled logout endpoint is a 404" do
      Application.put_env(
        :attesto_phoenix,
        @config_key,
        Application.get_env(:attesto_phoenix, @config_key) |> Keyword.put(:logout, enabled: false)
      )

      conn = call(:get, %{})
      assert conn.status == 404
    end
  end
end
