defmodule AttestoPhoenix.AuthorizationServer.BackchannelAuthenticationTest do
  @moduledoc """
  Conn-free tests for CIBA backchannel authentication request processing
  (OpenID Connect CIBA Core 1.0 §7), mirroring the device-authorization AS test:
  build a `%Config{}` + client, call `BackchannelAuthentication.request/2`, and
  assert the §7.3 acknowledgement (or the §13 error).
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Attesto.CIBA
  alias Attesto.CIBAStore.ETS, as: Store
  alias AttestoPhoenix.AuthorizationServer.BackchannelAuthentication
  alias AttestoPhoenix.AuthorizationServer.BackchannelAuthentication.Request
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.OAuthError

  @issuer "https://issuer.example"

  defmodule StubKeystore do
    @moduledoc false
  end

  defmodule StubRepo do
    @moduledoc false
  end

  setup do
    start_supervised!(Store)
    Store.reset()
    :ok
  end

  defp config(overrides \\ []) do
    [
      issuer: @issuer,
      audience: "https://api.example.com",
      keystore: StubKeystore,
      repo: StubRepo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _c, _g -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      client_id: fn client -> Map.get(client, :id) end,
      client_jwks: fn client -> Map.get(client, :jwks) end,
      client_ciba_registration: fn client -> Map.get(client, :ciba, %{}) end,
      authenticate_ciba_user: fn _request -> {:ok, "user:alice"} end,
      ciba_store: Store,
      replay_check: fn _key, _ttl -> :ok end,
      ciba: [enabled: true, require_signed_request: false]
    ]
    |> Keyword.merge(overrides)
    |> Config.new()
  end

  defp request(client, params, overrides \\ []) do
    struct!(
      %Request{
        client: client,
        client_auth_method: :private_key_jwt,
        request_client_id: Map.get(client, :id),
        params: params
      },
      overrides
    )
  end

  defp poll_client(overrides \\ %{}), do: Map.merge(%{id: "cli-1", ciba: %{token_delivery_mode: :poll}}, overrides)

  describe "request/2 happy path" do
    test "poll mode returns the §7.3 acknowledgement and creates a pending request" do
      config = config()

      assert {:ok, ack} =
               BackchannelAuthentication.request(
                 config,
                 request(poll_client(), %{
                   "scope" => "openid profile",
                   "login_hint" => "alice@example.test"
                 })
               )

      assert is_binary(ack.auth_req_id)
      assert ack.expires_in == 120
      assert ack.interval == 5

      # The bound request is redeemable (pending) at the token endpoint.
      assert {:error, :authorization_pending} =
               CIBA.redeem(Store, ack.auth_req_id, %{client_id: "cli-1"}, [])
    end

    test "ping mode carries the client_notification_token and fires notify_ciba_user" do
      pid = self()
      client = poll_client(%{ciba: %{token_delivery_mode: :ping}})

      config =
        config(
          notify_ciba_user: fn auth_req_id, _req, subject ->
            send(pid, {:notified, auth_req_id, subject})
            :ok
          end
        )

      params = %{
        "scope" => "openid",
        "login_hint" => "alice@example.test",
        "client_notification_token" => "abcdefghijklmnopqrstuvwxyz"
      }

      assert {:ok, ack} = BackchannelAuthentication.request(config, request(client, params))
      assert ack.interval == 5

      assert_receive {:notified, auth_req_id, "user:alice"}, 1_000
      assert auth_req_id == ack.auth_req_id
    end

    test "async notify callback receives the request-scoped config" do
      test_pid = self()

      config =
        config(
          schema_prefix: "tenant_notify",
          notify_ciba_user: fn _auth_req_id, _request, _subject ->
            send(test_pid, {:notify_config, Config.request_config()})
            :ok
          end
        )

      params = %{"scope" => "openid", "login_hint" => "alice@example.test"}

      assert {:ok, _ack} =
               BackchannelAuthentication.request(config, request(poll_client(), params))

      assert_receive {:notify_config, ^config}, 1_000
    end

    test "an explicit notification error is observable while the request remains pending" do
      test_pid = self()

      notify = fn auth_req_id, _request, _subject ->
        send(test_pid, {:notify_started, self(), auth_req_id})

        receive do
          :finish_notification -> {:error, :gateway_secret}
        end
      end

      config = config(notify_ciba_user: notify)
      params = %{"scope" => "openid", "login_hint" => "alice@example.test"}

      log =
        capture_log(fn ->
          assert {:ok, ack} =
                   BackchannelAuthentication.request(config, request(poll_client(), params))

          Process.put(:failed_notify_auth_req_id, ack.auth_req_id)

          assert_receive {:notify_started, task_pid, auth_req_id}, 1_000
          assert auth_req_id == ack.auth_req_id

          monitor = Process.monitor(task_pid)
          send(task_pid, :finish_notification)
          assert_receive {:DOWN, ^monitor, :process, ^task_pid, :normal}, 1_000
          Logger.flush()
        end)

      auth_req_id = Process.delete(:failed_notify_auth_req_id)

      assert log =~
               "AttestoPhoenix notify_ciba_user callback failed; authentication request remains pending"

      refute log =~ "gateway_secret"
      refute log =~ auth_req_id

      assert {:error, :authorization_pending} =
               CIBA.redeem(Store, auth_req_id, %{client_id: "cli-1"}, [])
    end

    test "an unexpected notification result is observable while the request remains pending" do
      test_pid = self()

      notify = fn auth_req_id, _request, _subject ->
        send(test_pid, {:notify_started, self(), auth_req_id})
        :error
      end

      config = config(notify_ciba_user: notify)
      params = %{"scope" => "openid", "login_hint" => "alice@example.test"}

      log =
        capture_log(fn ->
          assert {:ok, ack} =
                   BackchannelAuthentication.request(config, request(poll_client(), params))

          Process.put(:unexpected_notify_auth_req_id, ack.auth_req_id)

          assert_receive {:notify_started, task_pid, auth_req_id}, 1_000
          assert auth_req_id == ack.auth_req_id

          monitor = Process.monitor(task_pid)
          assert_receive {:DOWN, ^monitor, :process, ^task_pid, :normal}, 1_000
          Logger.flush()
        end)

      auth_req_id = Process.delete(:unexpected_notify_auth_req_id)

      assert log =~
               "AttestoPhoenix notify_ciba_user callback failed; authentication request remains pending"

      refute log =~ auth_req_id

      assert {:error, :authorization_pending} =
               CIBA.redeem(Store, auth_req_id, %{client_id: "cli-1"}, [])
    end
  end

  describe "request/2 request-shape errors (CIBA §13)" do
    test "a missing hint is invalid_request" do
      assert {:error, %OAuthError{error: :invalid_request}} =
               BackchannelAuthentication.request(
                 config(),
                 request(poll_client(), %{"scope" => "openid"})
               )
    end

    test "more than one hint is invalid_request" do
      params = %{"scope" => "openid", "login_hint" => "a@x", "id_token_hint" => "b@x"}

      assert {:error, %OAuthError{error: :invalid_request}} =
               BackchannelAuthentication.request(config(), request(poll_client(), params))
    end

    test "a scope without openid is invalid_scope" do
      params = %{"scope" => "profile", "login_hint" => "alice@example.test"}

      assert {:error, %OAuthError{error: :invalid_scope}} =
               BackchannelAuthentication.request(config(), request(poll_client(), params))
    end

    test "a client whose delivery mode is not advertised is unauthorized_client" do
      client = poll_client(%{ciba: %{token_delivery_mode: :push}})

      assert {:error, %OAuthError{error: :unauthorized_client}} =
               BackchannelAuthentication.request(
                 config(),
                 request(client, %{"scope" => "openid", "login_hint" => "alice@example.test"})
               )
    end

    test "a client not registered for CIBA is unauthorized_client" do
      client = %{id: "cli-1", ciba: %{}}

      assert {:error, %OAuthError{error: :unauthorized_client}} =
               BackchannelAuthentication.request(
                 config(),
                 request(client, %{"scope" => "openid", "login_hint" => "alice@example.test"})
               )
    end
  end

  describe "request/2 hint resolution (host callback)" do
    test "an unknown user maps to unknown_user_id" do
      config = config(authenticate_ciba_user: fn _ -> {:error, :unknown_user_id} end)

      assert {:error, %OAuthError{error: :unknown_user_id, status: 400}} =
               BackchannelAuthentication.request(
                 config,
                 request(poll_client(), %{
                   "scope" => "openid",
                   "login_hint" => "ghost@example.test"
                 })
               )
    end

    test "a missing user_code maps to missing_user_code" do
      config = config(authenticate_ciba_user: fn _ -> {:error, :missing_user_code} end)

      assert {:error, %OAuthError{error: :missing_user_code}} =
               BackchannelAuthentication.request(
                 config,
                 request(poll_client(), %{
                   "scope" => "openid",
                   "login_hint" => "alice@example.test"
                 })
               )
    end

    test "an unexpected user-resolution failure is loud and stores no authentication request" do
      config = config(authenticate_ciba_user: fn _ -> {:error, :store_unavailable} end)

      error =
        assert_raise RuntimeError, fn ->
          BackchannelAuthentication.request(
            config,
            request(poll_client(), %{"scope" => "openid", "login_hint" => "alice@example.test"})
          )
        end

      assert Exception.message(error) ==
               "AttestoPhoenix.Config :authenticate_ciba_user callback violated its return contract"

      refute Exception.message(error) =~ "store_unavailable"
      assert :ets.info(Store, :size) == 0
    end
  end

  describe "request/2 signed authentication request (§7.1.1, FAPI-CIBA §5.2.2)" do
    test "accepts a valid ES256-signed request and rejects an unsigned one when required" do
      {jwk, pub_map} = es256_key()

      client = %{
        id: "cli-1",
        jwks: %{"keys" => [pub_map]},
        ciba: %{token_delivery_mode: :poll, request_signing_alg: "ES256"}
      }

      config = config(ciba: [enabled: true, require_signed_request: true])

      jwt =
        signed_request(jwk, %{
          "iss" => "cli-1",
          "aud" => @issuer,
          "scope" => "openid",
          "login_hint" => "alice@example.test"
        })

      assert {:ok, ack} =
               BackchannelAuthentication.request(config, request(client, %{"request" => jwt}))

      assert is_binary(ack.auth_req_id)

      # A plain (unsigned) request is rejected when signing is mandatory.
      assert {:error, %OAuthError{error: :invalid_request}} =
               BackchannelAuthentication.request(
                 config,
                 request(client, %{"scope" => "openid", "login_hint" => "alice@example.test"})
               )
    end

    test "rejects a repeated signed request through the configured replay boundary" do
      {jwk, pub_map} = es256_key()

      client = %{
        id: "cli-1",
        jwks: %{"keys" => [pub_map]},
        ciba: %{token_delivery_mode: :poll, request_signing_alg: "ES256"}
      }

      counter = :atomics.new(1, [])
      parent = self()

      replay_check = fn key, ttl ->
        send(parent, {:ciba_replay_key, key, ttl})
        if :atomics.add_get(counter, 1, 1) == 1, do: :ok, else: {:error, :replay}
      end

      config =
        config(
          ciba: [enabled: true, require_signed_request: true],
          replay_check: replay_check
        )

      request = request(client, %{"request" => signed_request(jwk, signed_claims())})

      assert {:ok, _ack} = BackchannelAuthentication.request(config, request)

      assert {:error, %OAuthError{error: :invalid_request}} =
               BackchannelAuthentication.request(config, request)

      assert_receive {:ciba_replay_key, first_key, first_ttl}
      assert_receive {:ciba_replay_key, second_key, second_ttl}
      assert first_key == second_key
      assert String.starts_with?(first_key, "ciba:")
      assert byte_size(first_key) == 48
      assert first_ttl in 1..300
      assert second_ttl in 1..first_ttl
    end

    test "scopes bounded replay keys by client even for a long shared jti" do
      shared_jti = String.duplicate("long-jti-", 512)
      parent = self()

      replay_check = fn key, _ttl ->
        send(parent, {:client_scoped_replay_key, key})
        :ok
      end

      config =
        config(
          ciba: [enabled: true, require_signed_request: true],
          replay_check: replay_check
        )

      {first_jwk, first_public} = es256_key()
      {second_jwk, second_public} = es256_key()

      first_client = es256_client("client-one", first_public)
      second_client = es256_client("client-two", second_public)

      first_jwt =
        signed_request(first_jwk, Map.put(signed_claims("client-one"), "jti", shared_jti))

      second_jwt =
        signed_request(second_jwk, Map.put(signed_claims("client-two"), "jti", shared_jti))

      assert {:ok, _ack} =
               BackchannelAuthentication.request(
                 config,
                 request(first_client, %{"request" => first_jwt})
               )

      assert {:ok, _ack} =
               BackchannelAuthentication.request(
                 config,
                 request(second_client, %{"request" => second_jwt})
               )

      assert_receive {:client_scoped_replay_key, first_key}
      assert_receive {:client_scoped_replay_key, second_key}
      assert byte_size(first_key) == 48
      assert byte_size(second_key) == 48
      refute first_key == second_key
    end

    test "rejects an optional signed request when replay protection is unavailable" do
      {jwk, pub_map} = es256_key()

      client = %{
        id: "cli-1",
        jwks: %{"keys" => [pub_map]},
        ciba: %{token_delivery_mode: :poll, request_signing_alg: "ES256"}
      }

      config = config(ciba: [enabled: true, require_signed_request: false], replay_check: nil)
      request = request(client, %{"request" => signed_request(jwk, signed_claims())})

      assert {:error, %OAuthError{error: :invalid_request}} =
               BackchannelAuthentication.request(config, request)
    end

    test "raises a clear configuration error for an invalid replay callback result" do
      {jwk, pub_map} = es256_key()

      client = %{
        id: "cli-1",
        jwks: %{"keys" => [pub_map]},
        ciba: %{token_delivery_mode: :poll, request_signing_alg: "ES256"}
      }

      config =
        config(
          ciba: [enabled: true, require_signed_request: true],
          replay_check: fn _key, _ttl -> :unexpected end
        )

      request = request(client, %{"request" => signed_request(jwk, signed_claims())})

      assert_raise ArgumentError, ~r/:replay_check must return :ok or/, fn ->
        BackchannelAuthentication.request(config, request)
      end
    end

    test "rejects weak PS256 by default and preserves an explicit non-FAPI opt-in" do
      jwk = JOSE.JWK.generate_key({:rsa, 1024})
      client = signing_client(jwk, "PS256")
      jwt = signed_request(jwk, signed_claims(), "PS256")
      request = request(client, %{"request" => jwt})

      assert {:error, %OAuthError{error: :invalid_request}} =
               BackchannelAuthentication.request(
                 config(ciba: [enabled: true, require_signed_request: true]),
                 request
               )

      assert {:error, %OAuthError{error: :invalid_request}} =
               BackchannelAuthentication.request(
                 config(
                   ciba: [
                     enabled: true,
                     require_signed_request: true,
                     request_signing_algs: ["PS256"],
                     enforce_fapi_alg_policy: true
                   ]
                 ),
                 request
               )

      assert {:ok, _ack} =
               BackchannelAuthentication.request(
                 config(
                   ciba: [
                     enabled: true,
                     require_signed_request: true,
                     request_signing_algs: ["PS256"]
                   ]
                 ),
                 request
               )
    end

    test "legacy EdDSA over Ed448 requires an explicit non-FAPI policy" do
      enable_ed448_support()
      jwk = JOSE.JWK.generate_key({:okp, :Ed448})
      client = signing_client(jwk, "EdDSA")
      jwt = signed_request(jwk, signed_claims(), "EdDSA")
      request = request(client, %{"request" => jwt})

      assert_raise ArgumentError, ~r/outside the enforced FAPI-CIBA signing algorithm set/, fn ->
        config(
          ciba: [
            enabled: true,
            require_signed_request: true,
            request_signing_algs: ["EdDSA"],
            enforce_fapi_alg_policy: true
          ]
        )
      end

      assert {:ok, _ack} =
               BackchannelAuthentication.request(
                 config(
                   ciba: [
                     enabled: true,
                     require_signed_request: true,
                     request_signing_algs: ["EdDSA"]
                   ]
                 ),
                 request
               )
    end
  end

  defp es256_key do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, pub_map} = JOSE.JWK.to_public_map(jwk)
    {jwk, pub_map}
  end

  defp signing_client(jwk, alg) do
    {_, public} = JOSE.JWK.to_public_map(jwk)

    %{
      id: "cli-1",
      jwks: %{"keys" => [Map.merge(public, %{"alg" => alg, "kid" => JOSE.JWK.thumbprint(jwk)})]},
      ciba: %{token_delivery_mode: :poll, request_signing_alg: alg}
    }
  end

  defp es256_client(id, public) do
    %{
      id: id,
      jwks: %{"keys" => [Map.put(public, "alg", "ES256")]},
      ciba: %{token_delivery_mode: :poll, request_signing_alg: "ES256"}
    }
  end

  defp signed_claims(client_id \\ "cli-1") do
    %{
      "iss" => client_id,
      "aud" => @issuer,
      "scope" => "openid",
      "login_hint" => "alice@example.test"
    }
  end

  defp signed_request(jwk, claims, alg \\ "ES256") do
    now = System.system_time(:second)

    payload =
      Map.merge(
        %{
          "iat" => now,
          "nbf" => now,
          "exp" => now + 300,
          "jti" => Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
        },
        claims
      )

    {_, compact} = JOSE.JWS.compact(JOSE.JWT.sign(jwk, %{"alg" => alg}, payload))
    compact
  end

  defp enable_ed448_support do
    previous = JOSE.crypto_fallback()
    JOSE.crypto_fallback(true)
    on_exit(fn -> JOSE.crypto_fallback(previous) end)
  end
end
