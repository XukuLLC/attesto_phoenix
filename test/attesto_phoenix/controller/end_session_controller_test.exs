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

  import Ecto.Query, only: [from: 2]
  import ExUnit.CaptureLog
  import Plug.Conn
  import Plug.Test

  alias Attesto.IDToken
  alias Attesto.Keystore.Static
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Controller.EndSessionController, as: Controller
  alias AttestoPhoenix.Schema.LogoutSession
  alias AttestoPhoenix.Store.EctoLogoutSessionStore, as: Store
  alias AttestoPhoenix.Store.Sweeper

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

  defmodule ErrorHTTP do
    @moduledoc false
    @behaviour AttestoPhoenix.BackChannelLogout

    @impl true
    def post(_uri, _logout_token) do
      send(Application.fetch_env!(:attesto_phoenix, :test_bc_pid), :bc_error_attempted)
      {:error, {:transport, "logout-http-private-sentinel"}}
    end
  end

  defmodule RaisingFirstHTTP do
    @moduledoc false
    @behaviour AttestoPhoenix.BackChannelLogout

    @impl true
    def post("https://rp-raise.example/bc", _logout_token), do: raise("delivery-private-sentinel")

    def post(uri, logout_token) do
      pid = Application.fetch_env!(:attesto_phoenix, :test_bc_pid)
      send(pid, {:bc_post, uri, logout_token})
      :ok
    end
  end

  defmodule ConcurrentHTTP do
    @moduledoc false
    @behaviour AttestoPhoenix.BackChannelLogout

    @impl true
    def post(uri, _logout_token) do
      owner = Application.fetch_env!(:attesto_phoenix, :test_bc_pid)
      send(owner, {:bc_delivery_started, uri, self()})

      receive do
        {:continue_bc_delivery, ^owner} -> :ok
      after
        1_000 -> :ok
      end
    end
  end

  defmodule SelectiveHTTP do
    @moduledoc false
    @behaviour AttestoPhoenix.BackChannelLogout

    @impl true
    def post(uri, _logout_token) do
      send(Application.fetch_env!(:attesto_phoenix, :test_bc_pid), {:bc_selective_attempt, uri})

      if String.contains?(uri, "failed"),
        do: {:error, :unavailable},
        else: :ok
    end
  end

  defmodule OrderedTargetsStore do
    @moduledoc false
    @behaviour Attesto.LogoutSessionStore

    @impl true
    def record(_entry), do: :ok

    @impl true
    def targets(_criteria), do: []

    @impl true
    def delete(_criteria), do: :ok

    @impl true
    def take_targets(_criteria), do: []

    @impl true
    def lease_targets(_criteria, _lease_id, _now, _lease_expires_at) do
      [
        %{
          delivery_id: "delivery-raise",
          sid: "sess-raise",
          client_id: "rp-raise",
          backchannel_logout_uri: "https://rp-raise.example/bc",
          frontchannel_logout_uri: nil
        },
        %{
          delivery_id: "delivery-after",
          sid: "sess-after",
          client_id: "rp-after",
          backchannel_logout_uri: "https://rp-after.example/bc",
          frontchannel_logout_uri: nil
        }
      ]
    end

    @impl true
    def acknowledge_targets(_lease_id, _delivery_ids), do: :ok

    @impl true
    def release_targets(_lease_id, _delivery_ids), do: :ok
  end

  defmodule ErrorStore do
    @moduledoc false
    @behaviour Attesto.LogoutSessionStore

    @impl true
    def record(_entry), do: :ok

    @impl true
    def targets(_criteria), do: []

    @impl true
    def delete(_criteria), do: :ok

    @impl true
    def take_targets(_criteria), do: []

    @impl true
    def lease_targets(_criteria, _lease_id, _now, _lease_expires_at), do: raise("logout-store-private-sentinel")

    @impl true
    def acknowledge_targets(_lease_id, _delivery_ids), do: :ok

    @impl true
    def release_targets(_lease_id, _delivery_ids), do: :ok
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
      sweep_interval_ms: 60_000,
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
    |> put_private(
      :attesto_phoenix_config,
      Config.new(Application.fetch_env!(:attesto_phoenix, @config_key))
    )
    |> Controller.end_session(params)
  end

  defp call_html(method, params) do
    method
    |> conn("/oauth/end_session", params)
    |> put_private(
      :attesto_phoenix_config,
      Config.new(Application.fetch_env!(:attesto_phoenix, @config_key))
    )
    |> put_req_header("accept", "text/html,application/xhtml+xml")
    |> Controller.end_session(params)
  end

  defp body(conn), do: JSON.decode!(conn.resp_body)

  defp persisted_targets(sid) do
    from(l in LogoutSession, where: l.sid == ^sid)
    |> AttestoPhoenix.TestRepo.all()
    |> Enum.map(&LogoutSession.to_target/1)
  end

  defp eventually(fun, attempts \\ 50)
  defp eventually(fun, 0), do: fun.()

  defp eventually(fun, attempts) do
    case fun.() do
      true ->
        true

      _other ->
        Process.sleep(10)
        eventually(fun, attempts - 1)
    end
  end

  defp with_app_config(overrides, fun) do
    original = Application.fetch_env!(:attesto_phoenix, @config_key)
    Application.put_env(:attesto_phoenix, @config_key, Keyword.merge(original, overrides))

    try do
      fun.()
    after
      Application.put_env(:attesto_phoenix, @config_key, original)
    end
  end

  defp logout_payload(jwt) do
    [_h, p | _] = String.split(jwt, ".")
    {:ok, decoded} = Base.url_decode64(p, padding: false)
    JSON.decode!(decoded)
  end

  describe "RP-initiated redirect" do
    test "valid hint + registered uri redirects with state and terminates the session", %{
      hint: hint
    } do
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
        call_html(:get, %{
          "id_token_hint" => hint,
          "post_logout_redirect_uri" => "https://evil.example/steal"
        })

      assert conn.status == 400
      assert conn |> get_resp_header("content-type") |> List.first() =~ "text/html"
      assert conn.resp_body =~ "<html"
      assert conn.resp_body =~ "invalid post_logout_redirect_uri"
    end

    test "an explicit text/html q=0 preference keeps errors in JSON", %{hint: hint} do
      conn =
        :get
        |> conn("/oauth/end_session", %{})
        |> put_private(
          :attesto_phoenix_config,
          Config.new(Application.fetch_env!(:attesto_phoenix, @config_key))
        )
        |> put_req_header("accept", "text/html;q=0, application/json")
        |> Controller.end_session(%{
          "id_token_hint" => hint,
          "post_logout_redirect_uri" => "https://evil.example/steal"
        })

      assert conn.status == 400
      assert conn |> get_resp_header("content-type") |> List.first() =~ "application/json"
      assert body(conn)["error"] == "invalid_request"
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

      assert_receive {:bc_post, "https://rp-b.example/bc", token}, 1_000
      claims = logout_payload(token)
      assert claims["aud"] == "rp-b"
      assert claims["sid"] == @sid
      assert claims["sub"] == @subject
      assert claims["events"] == %{"http://schemas.openid.net/event/backchannel-logout" => %{}}
      refute Map.has_key?(claims, "nonce")

      # the session row is acknowledged after the successful handoff
      assert eventually(fn ->
               not AttestoPhoenix.TestRepo.exists?(from(l in LogoutSession, where: l.sid == ^@sid))
             end)
    end

    test "a slow RP cannot serialize another RP's back-channel notification", %{hint: hint} do
      with_app_config(
        [
          logout_session_store: OrderedTargetsStore,
          logout: [enabled: true, http_client: ConcurrentHTTP]
        ],
        fn ->
          conn = call(:get, %{"id_token_hint" => hint})
          assert conn.status == 200

          assert_receive {:bc_delivery_started, first_uri, first_pid}
          assert_receive {:bc_delivery_started, second_uri, second_pid}

          assert MapSet.new([first_uri, second_uri]) ==
                   MapSet.new(["https://rp-raise.example/bc", "https://rp-after.example/bc"])

          send(first_pid, {:continue_bc_delivery, self()})
          send(second_pid, {:continue_bc_delivery, self()})
        end
      )
    end

    test "a row recorded for a front-channel-only RP produces no back-channel POST", %{hint: hint} do
      now = System.system_time(:second)

      :ok =
        Store.record(%{
          sid: @sid,
          subject: @subject,
          client_id: "rp-fc",
          frontchannel_logout_uri: "https://rp-fc.example/fc",
          expires_at: now + 3600
        })

      conn = call(:get, %{"id_token_hint" => hint})
      assert conn.status == 200

      refute_received {:bc_post, _uri, _token}
      # A non-browser cannot perform the front-channel handoff, so the target
      # is released for a later browser-driven retry.
      assert [_] = persisted_targets(@sid)
    end

    test "a logout-session store exception fails visibly without leaking exception data", %{hint: hint} do
      log =
        with_app_config([logout_session_store: ErrorStore], fn ->
          capture_log(fn ->
            conn = call(:get, %{"id_token_hint" => hint})
            assert conn.status == 503
            assert body(conn)["error"] == "server_error"
          end)
        end)

      assert log =~ "logout session store lease failed; verify the Attesto Phoenix 4.2 migration is applied"
      refute log =~ "logout-store-private-sentinel"
    end

    test "a back-channel delivery error is logged without error data", %{hint: hint} do
      now = System.system_time(:second)

      :ok =
        Store.record(%{
          sid: @sid,
          subject: @subject,
          client_id: "rp-error",
          backchannel_logout_uri: "https://rp-error.example/bc",
          session_required: true,
          expires_at: now + 3600
        })

      log =
        with_app_config([logout: [enabled: true, http_client: ErrorHTTP]], fn ->
          capture_log(fn ->
            conn = call(:get, %{"id_token_hint" => hint})
            assert conn.status == 200
            assert_receive :bc_error_attempted, 1_000
            assert eventually(fn -> length(persisted_targets(@sid)) == 1 end)
          end)
        end)

      assert log =~ "back-channel logout delivery failed"
      refute log =~ "logout-http-private-sentinel"
    end

    test "a partial fan-out acknowledges successes and releases failures", %{hint: hint} do
      now = System.system_time(:second)

      Enum.each([{"rp-ok", "https://rp.example/ok"}, {"rp-failed", "https://rp.example/failed"}], fn
        {client_id, uri} ->
          :ok =
            Store.record(%{
              sid: @sid,
              subject: @subject,
              client_id: client_id,
              backchannel_logout_uri: uri,
              expires_at: now + 3_600
            })
      end)

      with_app_config([logout: [enabled: true, http_client: SelectiveHTTP]], fn ->
        assert call(:get, %{"id_token_hint" => hint}).status == 200
        assert_receive {:bc_selective_attempt, "https://rp.example/ok"}, 1_000
        assert_receive {:bc_selective_attempt, "https://rp.example/failed"}, 1_000
      end)

      assert eventually(fn ->
               case persisted_targets(@sid) do
                 [%{client_id: "rp-failed"}] -> true
                 _other -> false
               end
             end)
    end

    test "the sweeper retries released work without touching an unrelated live session", %{hint: hint} do
      now = System.system_time(:second)

      :ok =
        Store.record(%{
          sid: @sid,
          subject: @subject,
          client_id: "rp-retry",
          backchannel_logout_uri: "https://rp.example/retry",
          expires_at: now + 3_600
        })

      :ok =
        Store.record(%{
          sid: "untouched-session",
          subject: "untouched-user",
          client_id: "rp-untouched",
          backchannel_logout_uri: "https://rp.example/untouched",
          expires_at: now + 3_600
        })

      with_app_config(
        [
          logout: [
            enabled: true,
            http_client: ErrorHTTP,
            retry_initial_delay_seconds: 1,
            retry_max_delay_seconds: 1
          ]
        ],
        fn ->
          assert call(:get, %{"id_token_hint" => hint}).status == 200
          assert_receive :bc_error_attempted, 1_000
        end
      )

      assert eventually(fn -> length(persisted_targets(@sid)) == 1 end)
      Process.sleep(1_100)

      with_app_config([logout: [enabled: true, http_client: StubHTTP]], fn ->
        config = Config.new(Application.fetch_env!(:attesto_phoenix, @config_key))
        {:ok, sweeper} = Sweeper.start_link(config: config, name: nil)
        on_exit(fn -> if Process.alive?(sweeper), do: GenServer.stop(sweeper) end)

        assert is_map(Sweeper.sweep_now(sweeper))
        assert_receive {:bc_post, "https://rp.example/retry", _token}, 1_000
        refute_receive {:bc_post, "https://rp.example/untouched", _token}, 100
      end)

      assert eventually(fn -> Store.targets(%{sid: @sid}) == [] end)
      assert [%{client_id: "rp-untouched"}] = Store.targets(%{sid: "untouched-session"})
    end

    test "an exception delivering to one RP does not skip later RPs", %{hint: hint} do
      with_app_config(
        [
          logout_session_store: OrderedTargetsStore,
          logout: [enabled: true, http_client: RaisingFirstHTTP]
        ],
        fn ->
          conn = call(:get, %{"id_token_hint" => hint})
          assert conn.status == 200
          assert_receive {:bc_post, "https://rp-after.example/bc", _token}, 1_000
        end
      )
    end

    test "logout enabled without :terminate_session fails config validation (no fail-open)", %{
      config: _config
    } do
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

  defp record_front_channel(client_id, uri, opts \\ []) do
    now = System.system_time(:second)

    :ok =
      %{
        sid: @sid,
        subject: @subject,
        client_id: client_id,
        frontchannel_logout_uri: uri,
        frontchannel_session_required: Keyword.get(opts, :session_required, true),
        expires_at: now + 3600
      }
      |> Map.merge(Map.new(Keyword.get(opts, :extra, [])))
      |> Store.record()
  end

  describe "front-channel logout (Front-Channel Logout 1.0 §3)" do
    test "a browser gets a page with a hidden iframe per RP, carrying iss AND sid", %{hint: hint} do
      record_front_channel("rp-fc-1", "https://rp-fc-1.example/fc")
      record_front_channel("rp-fc-2", "https://rp-fc-2.example/fc?x=1")

      conn = call_html(:get, %{"id_token_hint" => hint})

      assert conn.status == 200
      assert conn |> get_resp_header("content-type") |> List.first() =~ "text/html"
      assert conn |> get_resp_header("cache-control") |> List.first() == "no-store"

      # Front-Channel Logout 1.0 §2: iss and sid ride together as query params.
      encoded_iss = URI.encode_www_form(@issuer)

      assert conn.resp_body =~
               ~s(<iframe src="https://rp-fc-1.example/fc?iss=#{encoded_iss}&amp;sid=#{@sid}")

      assert conn.resp_body =~
               ~s(<iframe src="https://rp-fc-2.example/fc?x=1&amp;iss=#{encoded_iss}&amp;sid=#{@sid}")

      # the rows are consumed by the render
      assert [] = Store.targets(%{sid: @sid})
    end

    test "with a validated post_logout_redirect_uri the page continues there (JS + meta refresh + link)",
         %{hint: hint} do
      record_front_channel("rp-fc", "https://rp-fc.example/fc")

      conn =
        call_html(:get, %{
          "id_token_hint" => hint,
          "post_logout_redirect_uri" => "https://rp.example/after",
          "state" => "abc123"
        })

      # The iframe page IS the response; the redirect happens from the page,
      # after the iframes load, so both notifications and the RP return happen.
      assert conn.status == 200
      continue = "https://rp.example/after?state=abc123"
      assert conn.resp_body =~ ~s(data-continue="#{continue}")
      assert conn.resp_body =~ ~s(<meta http-equiv="refresh" content="7;url=#{continue}">)
      assert conn.resp_body =~ ~s(<a href="#{continue}">)
      assert conn.resp_body =~ "window.location.replace"
    end

    test "with no return URI the iframe page itself is the logged-out page", %{hint: hint} do
      record_front_channel("rp-fc", "https://rp-fc.example/fc")

      conn = call_html(:get, %{"id_token_hint" => hint})

      assert conn.status == 200
      assert conn.resp_body =~ "You are now signed out."
      assert conn.resp_body =~ ~s(<iframe src="https://rp-fc.example/fc?)
      refute conn.resp_body =~ "data-continue"
      refute conn.resp_body =~ "http-equiv=\"refresh\""
    end

    test "a non-browser caller cannot run iframes: plain completion, targets skipped", %{
      hint: hint
    } do
      record_front_channel("rp-fc", "https://rp-fc.example/fc")

      conn =
        call(:get, %{
          "id_token_hint" => hint,
          "post_logout_redirect_uri" => "https://rp.example/after",
          "state" => "xyz"
        })

      assert conn.status in 302..303

      assert conn |> get_resp_header("location") |> List.first() ==
               "https://rp.example/after?state=xyz"
    end

    test "a session with both channels POSTs the logout_token AND renders the iframe", %{
      hint: hint
    } do
      record_front_channel("rp-both", "https://rp-both.example/fc",
        extra: [backchannel_logout_uri: "https://rp-both.example/bc", session_required: true]
      )

      conn = call_html(:get, %{"id_token_hint" => hint})

      assert conn.status == 200
      assert_receive {:bc_post, "https://rp-both.example/bc", token}, 1_000
      claims = logout_payload(token)
      assert claims["aud"] == "rp-both"
      assert conn.resp_body =~ ~s(<iframe src="https://rp-both.example/fc?)
    end

    test "no front-channel RPs in the session: the browser gets the plain redirect", %{hint: hint} do
      conn =
        call_html(:get, %{
          "id_token_hint" => hint,
          "post_logout_redirect_uri" => "https://rp.example/after",
          "state" => "xyz"
        })

      assert conn.status in 302..303

      assert conn |> get_resp_header("location") |> List.first() ==
               "https://rp.example/after?state=xyz"
    end
  end

  describe "session management browser state (Session Management 1.0 §3.2)" do
    test "logout expires the OP browser-state cookie when session management is enabled", %{
      hint: hint
    } do
      base = Application.get_env(:attesto_phoenix, @config_key)

      Application.put_env(
        :attesto_phoenix,
        @config_key,
        Keyword.put(base, :session_management,
          enabled: true,
          browser_state_secret: :crypto.strong_rand_bytes(32)
        )
      )

      conn = call(:get, %{"id_token_hint" => hint})

      assert conn.status == 200
      # The __Host- cookie is expired; because it carries no Domain, expiring the
      # host cookie fully clears it (no parent-domain shadow can survive).
      cookie = conn.resp_cookies["__Host-attesto_op_browser_state"]
      assert cookie.max_age == 0
    end

    test "without session management no browser-state cookie is touched", %{hint: hint} do
      conn = call(:get, %{"id_token_hint" => hint})

      assert conn.status == 200
      refute Map.has_key?(conn.resp_cookies, "__Host-attesto_op_browser_state")
    end
  end
end
