defmodule AttestoPhoenix.Controller.RevocationControllerTest do
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Controller.RevocationController

  # A stub Attesto.RefreshStore that records the revoked family (and the
  # client_id revocation was bound to) so tests can assert on RFC 7009 §2.1
  # binding and the §2.2 no-existence-oracle behavior without a database.
  defmodule StubStore do
    @behaviour Attesto.RefreshStore

    @impl true
    def insert(_entry), do: :ok

    @impl true
    def get(token_hash), do: Process.get({:record, token_hash}, :error)

    @impl true
    def rotate(_parent_hash, _child, _successor, _opts), do: :error

    @impl true
    def revoke_family(family_id) do
      send(self(), {:revoked, family_id})
      :ok
    end
  end

  defmodule StubEventSink do
    @behaviour AttestoPhoenix.EventSink

    @impl true
    def on_event(event) do
      send(self(), {:event_sink, event})
      :ok
    end
  end

  defmodule RoutedRouter do
    @moduledoc false

    use Phoenix.Router

    post "/oauth/revoke", RevocationController, :create
  end

  @client_id "client-123"
  @client_secret "s3cr3t"

  # A known refresh token whose record StubStore returns; revoking it must
  # tear down its family.
  @live_token "live-refresh-token"
  @live_family "family-abc"

  # A refresh token the store has never seen; revoking it is a no-op success.
  @unknown_token "never-issued"

  defp build_config(overrides) do
    base = [
      issuer: "https://issuer.test",
      audience: "https://api.example.com",
      keystore: __MODULE__.Keystore,
      repo: __MODULE__.Repo,
      load_client: fn
        @client_id -> {:ok, %{id: @client_id}}
        _other -> {:error, :not_found}
      end,
      verify_client_secret: fn
        %{id: @client_id}, presented -> presented == @client_secret
        # The endpoint runs a dummy verify against :unknown_client on a lookup
        # failure to equalize timing (RFC 6749 §2.3); it must always fail.
        :unknown_client, _presented -> false
      end,
      load_principal: fn _subject -> {:error, :not_found} end
    ]

    Config.new(Keyword.merge(base, overrides))
  end

  defp put_record(token, record) do
    record =
      Map.merge(
        %{token_hash: Attesto.Secret.hash(token), consumed: false},
        record
      )

    Process.put({:record, Attesto.Secret.hash(token)}, {:ok, record})
  end

  defp build_conn(params, opts) do
    config = Keyword.get(opts, :config) || build_config([])

    # The endpoint requires TLS (config.require_https defaults true): a client
    # secret + refresh token must never cross a plain-HTTP hop.
    %{conn(:post, "/oauth/revoke", params) | scheme: :https}
    |> put_private(:attesto_phoenix_config, config)
    |> put_private(:attesto_phoenix_refresh_store, StubStore)
    |> maybe_basic_auth(opts)
  end

  defp maybe_basic_auth(conn, opts) do
    case Keyword.get(opts, :basic) do
      {:encoded, encoded} ->
        put_req_header(conn, "authorization", "Basic " <> Base.encode64(encoded))

      {id, secret} ->
        creds = Base.encode64("#{id}:#{secret}")
        put_req_header(conn, "authorization", "Basic #{creds}")

      :raw_header ->
        put_req_header(conn, "authorization", "Basic !!!not-base64!!!")

      nil ->
        conn
    end
  end

  describe "successful revocation (RFC 7009 §2.1)" do
    test "router dispatch invokes the revoke operation and event exactly once" do
      put_record(@live_token, %{
        family_id: @live_family,
        data: %{client_id: @client_id},
        expires_at: System.system_time(:second) + 1_000
      })

      test_pid = self()

      config =
        build_config(
          on_event: fn event ->
            send(test_pid, {:event, event})
            :ok
          end
        )

      params = %{
        "token" => @live_token,
        "client_id" => @client_id,
        "client_secret" => @client_secret
      }

      conn =
        params
        |> build_conn(config: config)
        |> RoutedRouter.call(RoutedRouter.init([]))

      assert conn.status == 200
      assert conn.resp_body == ""
      assert_received {:revoked, @live_family}
      refute_received {:revoked, _family}
      assert_received {:event, %AttestoPhoenix.Event{name: :token_revoked}}
      refute_received {:event, _event}
    end

    test "pins the revocation endpoint's accepted and rejected auth methods" do
      for {method, expected_status} <- [
            {:client_secret_basic, 200},
            {:client_secret_post, 200},
            {:client_secret_basic_with_body_credentials, 200},
            {:none, 401},
            {:private_key_jwt, 401}
          ] do
        base_params = %{"token" => @unknown_token}

        {conn, params} =
          case method do
            :client_secret_basic ->
              {build_conn(base_params, basic: {@client_id, @client_secret}), base_params}

            :client_secret_post ->
              params = Map.merge(base_params, %{"client_id" => @client_id, "client_secret" => @client_secret})
              {build_conn(params, []), params}

            :client_secret_basic_with_body_credentials ->
              params = Map.merge(base_params, %{"client_id" => @client_id, "client_secret" => @client_secret})
              {build_conn(params, basic: {@client_id, @client_secret}), params}

            :none ->
              {build_conn(base_params, []), base_params}

            :private_key_jwt ->
              params = Map.put(base_params, "client_assertion", "not-used-by-revocation")
              {build_conn(params, []), params}
          end

        conn = RevocationController.create(conn, params)

        assert conn.status == expected_status

        if expected_status == 200 do
          assert conn.resp_body == ""
        else
          assert JSON.decode!(conn.resp_body) == %{
                   "error" => "invalid_client",
                   "error_description" => "client authentication failed"
                 }

          assert get_resp_header(conn, "www-authenticate") == ["Basic"]
        end
      end
    end

    test "revokes the family of a live refresh token and returns 200, no body" do
      put_record(@live_token, %{
        family_id: @live_family,
        data: %{client_id: @client_id},
        expires_at: System.system_time(:second) + 1_000
      })

      params = %{
        "token" => @live_token,
        "client_id" => @client_id,
        "client_secret" => @client_secret
      }

      conn = RevocationController.create(build_conn(params, []), params)

      assert conn.status == 200
      assert conn.resp_body == ""
      assert conn.halted
      assert_received {:revoked, @live_family}
    end

    test "authenticates via HTTP Basic (client_secret_basic, RFC 6749 §2.3.1)" do
      put_record(@live_token, %{
        family_id: @live_family,
        data: %{client_id: @client_id},
        expires_at: System.system_time(:second) + 1_000
      })

      params = %{"token" => @live_token}

      conn =
        params
        |> build_conn(basic: {@client_id, @client_secret})
        |> RevocationController.create(params)

      assert conn.status == 200
      assert_received {:revoked, @live_family}
    end

    test "form-decodes HTTP Basic credentials before verification" do
      cfg =
        build_config(
          load_client: fn
            "client space" -> {:ok, %{id: "client space"}}
            _other -> {:error, :not_found}
          end,
          verify_client_secret: fn
            %{id: "client space"}, "p+ss:word" -> true
            _client, _secret -> false
          end
        )

      params = %{"token" => @unknown_token}

      conn =
        params
        |> build_conn(config: cfg, basic: {:encoded, "client%20space:p%2Bss%3Aword"})
        |> RevocationController.create(params)

      assert conn.status == 200
      assert conn.resp_body == ""
    end

    test "sets no-store cache headers (RFC 6749 §5.1)" do
      params = %{
        "token" => @unknown_token,
        "client_id" => @client_id,
        "client_secret" => @client_secret
      }

      conn = RevocationController.create(build_conn(params, []), params)

      assert get_resp_header(conn, "cache-control") == ["no-store"]
      assert get_resp_header(conn, "pragma") == ["no-cache"]
    end
  end

  describe "no-existence oracle (RFC 7009 §2.2)" do
    test "returns 200 for an unknown token and revokes nothing" do
      params = %{
        "token" => @unknown_token,
        "client_id" => @client_id,
        "client_secret" => @client_secret
      }

      conn = RevocationController.create(build_conn(params, []), params)

      assert conn.status == 200
      assert conn.resp_body == ""
      refute_received {:revoked, _family}
    end

    test "returns 200 for an expired token and revokes its family" do
      put_record(@live_token, %{
        family_id: @live_family,
        data: %{client_id: @client_id},
        expires_at: System.system_time(:second) - 1
      })

      params = %{
        "token" => @live_token,
        "client_id" => @client_id,
        "client_secret" => @client_secret
      }

      conn = RevocationController.create(build_conn(params, []), params)

      assert conn.status == 200
      assert_received {:revoked, @live_family}
    end
  end

  describe "client binding (RFC 7009 §2.1)" do
    test "a different client may not revoke another client's token" do
      put_record(@live_token, %{
        family_id: @live_family,
        data: %{client_id: "other-client"},
        expires_at: System.system_time(:second) + 1_000
      })

      params = %{
        "token" => @live_token,
        "client_id" => @client_id,
        "client_secret" => @client_secret
      }

      # The endpoint still answers 200 (no-existence oracle), but the
      # mismatched binding means the family is NOT revoked.
      conn = RevocationController.create(build_conn(params, []), params)

      assert conn.status == 200
      refute_received {:revoked, _family}
    end
  end

  describe "client authentication failures (RFC 6749 §5.2)" do
    test "wrong client secret is invalid_client (401)" do
      params = %{
        "token" => @live_token,
        "client_id" => @client_id,
        "client_secret" => "wrong"
      }

      conn = RevocationController.create(build_conn(params, []), params)

      assert conn.status == 401
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_client"
      assert get_resp_header(conn, "www-authenticate") == ["Basic"]
    end

    test "unknown client is invalid_client (401)" do
      params = %{
        "token" => @live_token,
        "client_id" => "ghost",
        "client_secret" => @client_secret
      }

      conn = RevocationController.create(build_conn(params, []), params)

      assert conn.status == 401
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_client"
    end

    test "no client credentials at all is invalid_client (401)" do
      params = %{"token" => @live_token}

      conn = RevocationController.create(build_conn(params, []), params)

      assert conn.status == 401
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_client"
    end

    test "malformed Basic credential is invalid_client (401), no body fallback" do
      params = %{
        "token" => @live_token,
        "client_id" => @client_id,
        "client_secret" => @client_secret
      }

      conn =
        params
        |> build_conn(basic: :raw_header)
        |> RevocationController.create(params)

      assert conn.status == 401
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_client"
    end
  end

  describe "malformed request (RFC 7009 §2.1)" do
    test "missing token parameter is invalid_request (400)" do
      params = %{
        "client_id" => @client_id,
        "client_secret" => @client_secret
      }

      conn = RevocationController.create(build_conn(params, []), params)

      assert conn.status == 400
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_request"
    end

    test "empty token parameter is invalid_request (400)" do
      params = %{
        "token" => "",
        "client_id" => @client_id,
        "client_secret" => @client_secret
      }

      conn = RevocationController.create(build_conn(params, []), params)

      assert conn.status == 400
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_request"
    end
  end

  describe "audit event (:on_event)" do
    test "emits a :token_revoked event after a successful request" do
      test_pid = self()

      cfg =
        build_config(
          on_event: fn event ->
            send(test_pid, {:event, event})
            :ok
          end
        )

      params = %{
        "token" => @unknown_token,
        "client_id" => @client_id,
        "client_secret" => @client_secret,
        "token_type_hint" => "refresh_token"
      }

      conn = RevocationController.create(build_conn(params, config: cfg), params)

      assert conn.status == 200

      assert_received {:event, event}
      assert event.name == :token_revoked
      assert event.client_id == @client_id
      assert event.metadata.token_type_hint == "refresh_token"
      # The event never carries the raw token value.
      refute Map.has_key?(event, :token)
      refute event.subject
    end

    test "resolves :token_revoked through a configured event-sink module" do
      cfg = build_config(event_sink: StubEventSink)

      params = %{
        "token" => @unknown_token,
        "client_id" => @client_id,
        "client_secret" => @client_secret,
        "token_type_hint" => "refresh_token"
      }

      conn = RevocationController.create(build_conn(params, config: cfg), params)

      assert conn.status == 200
      assert_received {:event_sink, event}
      assert event.name == :token_revoked
      assert event.client_id == @client_id
      assert event.metadata.token_type_hint == "refresh_token"
    end

    test "does not emit an event when client authentication fails" do
      test_pid = self()

      cfg =
        build_config(
          on_event: fn event ->
            send(test_pid, {:event, event})
            :ok
          end
        )

      params = %{
        "token" => @live_token,
        "client_id" => @client_id,
        "client_secret" => "wrong"
      }

      conn = RevocationController.create(build_conn(params, config: cfg), params)

      assert conn.status == 401
      refute_received {:event, _event}
    end
  end

  # RFC 8252 §8.4. The shared client-authentication service applies the same
  # native-client secret refusal used by the other credential endpoints.
  describe "native clients (RFC 8252 §8.4)" do
    defp revoke_as_native(overrides) do
      cfg = build_config([client_native?: fn _client -> true end] ++ overrides)

      params = %{
        "token" => @live_token,
        "client_id" => @client_id,
        "client_secret" => @client_secret
      }

      RevocationController.create(build_conn(params, config: cfg), params)
    end

    test "refuses a correct secret from a native public client" do
      assert revoke_as_native(client_public?: fn _client -> true end).status == 401
    end

    test "refuses a correct secret from a native client with no :client_public? callback" do
      # Same default flip as `ClientAuthentication`: an unclassified native
      # client is public, so its shipped secret is not proof of identity.
      assert revoke_as_native([]).status == 401
    end

    test "still accepts a native client the host EXPLICITLY marks confidential" do
      # RFC 8252 §8.4's per-instance-credential carve-out.
      assert revoke_as_native(client_public?: fn _client -> false end).status == 200
    end

    test "a non-native client is unaffected" do
      cfg = build_config(client_native?: fn _client -> false end, client_public?: fn _client -> true end)

      params = %{
        "token" => @live_token,
        "client_id" => @client_id,
        "client_secret" => @client_secret
      }

      assert RevocationController.create(build_conn(params, config: cfg), params).status == 200
    end

    test "a deployment with no :client_native? callback is unaffected" do
      params = %{
        "token" => @live_token,
        "client_id" => @client_id,
        "client_secret" => @client_secret
      }

      assert RevocationController.create(build_conn(params, []), params).status == 200
    end
  end

  test "raises when no config is wired into conn.private" do
    params = %{"token" => @live_token}

    bare = conn(:post, "/oauth/revoke", params)

    assert_raise ArgumentError, ~r/expected conn\.private\[:attesto_phoenix_config\]/, fn ->
      RevocationController.create(bare, params)
    end
  end
end
