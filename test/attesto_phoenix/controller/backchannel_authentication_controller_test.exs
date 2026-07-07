defmodule AttestoPhoenix.Controller.BackchannelAuthenticationControllerTest do
  @moduledoc """
  Tests for the CIBA backchannel authentication endpoint (OpenID Connect CIBA
  Core 1.0 §7.1). Exercises the controller-owned framing: confidential client
  authentication (FAPI-CIBA §5.2.2), the §7.3 acknowledgement body, and §13
  error rendering. Host policy is a real `%AttestoPhoenix.Config{}` resolved
  from the application environment, as a deployment supplies it.
  """
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias Attesto.CIBAStore.ETS, as: Store
  alias AttestoPhoenix.Controller.BackchannelAuthenticationController, as: Controller

  @config_key AttestoPhoenix.Config
  @path "/oauth/bc-authorize"

  defmodule Keystore do
    @moduledoc false
  end

  defmodule Repo do
    @moduledoc false
  end

  setup do
    start_supervised!(Store)
    Store.reset()

    {jwk, pub_map} = es256_key()
    Application.put_env(:attesto_phoenix, :test_jwk, jwk)

    client = %{id: "cli-1", secret: "s3cr3t", jwks: %{"keys" => [pub_map]}, ciba: %{token_delivery_mode: :poll}}
    ping_client = %{client | id: "ping-1", ciba: %{token_delivery_mode: :ping}}

    prev_otp = Application.get_env(:attesto_phoenix, :otp_app)
    Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)

    base = [
      issuer: "https://issuer.example",
      audience: "https://issuer.example",
      keystore: __MODULE__.Keystore,
      repo: __MODULE__.Repo,
      load_client: fn
        "cli-1" -> {:ok, client}
        "ping-1" -> {:ok, ping_client}
        _ -> {:error, :not_found}
      end,
      verify_client_secret: fn
        %{secret: s}, given -> s == given
        _no_secret, _given -> false
      end,
      load_principal: fn _ -> {:error, :not_found} end,
      client_public?: fn c -> Map.get(c, :public?, false) end,
      client_id: fn c -> Map.get(c, :id) end,
      client_jwks: fn c -> Map.get(c, :jwks) end,
      client_ciba_registration: fn c -> Map.get(c, :ciba, %{}) end,
      authenticate_ciba_user: fn _ -> {:ok, "user:alice"} end,
      require_https: false,
      ciba_store: Store,
      ciba: [enabled: true, require_signed_request: false]
    ]

    Application.put_env(:attesto_phoenix, @config_key, base)

    on_exit(fn ->
      Application.delete_env(:attesto_phoenix, @config_key)
      Application.delete_env(:attesto_phoenix, :test_jwk)

      if prev_otp,
        do: Application.put_env(:attesto_phoenix, :otp_app, prev_otp),
        else: Application.delete_env(:attesto_phoenix, :otp_app)
    end)

    :ok
  end

  test "poll happy path returns the §7.3 acknowledgement" do
    conn =
      call(%{"scope" => "openid profile", "login_hint" => "alice@example.test"}, [basic("cli-1", "s3cr3t")])

    assert conn.status == 200
    body = body(conn)
    assert is_binary(body["auth_req_id"])
    assert body["expires_in"] == 120
    assert body["interval"] == 5
    # No-store cache headers (CIBA §7.3 / RFC 7234 §5.2).
    assert get_resp_header(conn, "cache-control") == ["no-store"]
  end

  test "ping happy path carries the client_notification_token" do
    params = %{
      "scope" => "openid",
      "login_hint" => "alice@example.test",
      "client_notification_token" => "abcdefghijklmnopqrstuvwxyz"
    }

    conn = call(params, [basic("ping-1", "s3cr3t")])
    assert conn.status == 200
    assert is_binary(body(conn)["auth_req_id"])
  end

  test "a request with no client credentials is rejected (invalid_client, confidential-only)" do
    conn = call(%{"scope" => "openid", "login_hint" => "alice@example.test"}, [])
    assert conn.status in [400, 401]
    assert body(conn)["error"] == "invalid_client"
  end

  test "a missing hint is invalid_request" do
    conn = call(%{"scope" => "openid"}, [basic("cli-1", "s3cr3t")])
    assert conn.status == 400
    assert body(conn)["error"] == "invalid_request"
  end

  test "accepts a signed authentication request (§7.1.1)" do
    jwt =
      signed_request(%{
        "iss" => "cli-1",
        "aud" => "https://issuer.example",
        "scope" => "openid",
        "login_hint" => "alice@example.test"
      })

    conn = call(%{"request" => jwt}, [basic("cli-1", "s3cr3t")])
    assert conn.status == 200
    assert is_binary(body(conn)["auth_req_id"])
  end

  defp call(params, headers) do
    conn =
      :post
      |> conn(@path, params)
      |> put_req_header("content-type", "application/x-www-form-urlencoded")

    conn = Enum.reduce(headers, conn, fn {k, v}, c -> put_req_header(c, k, v) end)
    Controller.create(conn, params)
  end

  defp basic(id, secret), do: {"authorization", "Basic " <> Base.encode64(id <> ":" <> secret)}

  defp body(conn), do: JSON.decode!(conn.resp_body)

  defp es256_key do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, pub_map} = JOSE.JWK.to_public_map(jwk)
    {jwk, pub_map}
  end

  defp signed_request(claims) do
    jwk = Application.fetch_env!(:attesto_phoenix, :test_jwk)
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
