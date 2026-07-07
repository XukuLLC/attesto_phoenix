defmodule AttestoPhoenix.AuthorizationServer.BackchannelAuthenticationTest do
  @moduledoc """
  Conn-free tests for CIBA backchannel authentication request processing
  (OpenID Connect CIBA Core 1.0 §7), mirroring the device-authorization AS test:
  build a `%Config{}` + client, call `BackchannelAuthentication.request/2`, and
  assert the §7.3 acknowledgement (or the §13 error).
  """

  use ExUnit.Case, async: false

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
                 request(poll_client(), %{"scope" => "openid profile", "login_hint" => "alice@example.test"})
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
        config(notify_ciba_user: fn auth_req_id, _req, subject -> send(pid, {:notified, auth_req_id, subject}) end)

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
  end

  describe "request/2 request-shape errors (CIBA §13)" do
    test "a missing hint is invalid_request" do
      assert {:error, %OAuthError{error: :invalid_request}} =
               BackchannelAuthentication.request(config(), request(poll_client(), %{"scope" => "openid"}))
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
                 request(poll_client(), %{"scope" => "openid", "login_hint" => "ghost@example.test"})
               )
    end

    test "a missing user_code maps to missing_user_code" do
      config = config(authenticate_ciba_user: fn _ -> {:error, :missing_user_code} end)

      assert {:error, %OAuthError{error: :missing_user_code}} =
               BackchannelAuthentication.request(
                 config,
                 request(poll_client(), %{"scope" => "openid", "login_hint" => "alice@example.test"})
               )
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

      assert {:ok, ack} = BackchannelAuthentication.request(config, request(client, %{"request" => jwt}))
      assert is_binary(ack.auth_req_id)

      # A plain (unsigned) request is rejected when signing is mandatory.
      assert {:error, %OAuthError{error: :invalid_request}} =
               BackchannelAuthentication.request(
                 config,
                 request(client, %{"scope" => "openid", "login_hint" => "alice@example.test"})
               )
    end
  end

  defp es256_key do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, pub_map} = JOSE.JWK.to_public_map(jwk)
    {jwk, pub_map}
  end

  defp signed_request(jwk, claims) do
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

    {_, compact} = JOSE.JWS.compact(JOSE.JWT.sign(jwk, %{"alg" => "ES256"}, payload))
    compact
  end
end
