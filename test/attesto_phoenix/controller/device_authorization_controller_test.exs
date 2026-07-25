defmodule AttestoPhoenix.Controller.DeviceAuthorizationControllerTest do
  @moduledoc false
  use ExUnit.Case, async: false

  import Plug.Test

  alias Attesto.DeviceCodeStore.ETS
  alias AttestoPhoenix.Controller.DeviceAuthorizationController

  @client_id "device-client"

  defmodule StubKeystore do
    @moduledoc false
  end

  defmodule StubRepo do
    @moduledoc false
  end

  setup do
    Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)

    on_exit(fn ->
      Application.delete_env(:attesto_phoenix, :otp_app)
      Application.delete_env(:attesto_phoenix, AttestoPhoenix.Config)
    end)

    :ok
  end

  test "private_key_jwt rejects a weak PS256 key under the default FAPI policy" do
    client_key = JOSE.JWK.generate_key({:rsa, 1024})
    client_jwks = %{"keys" => [public_jwk(client_key, "PS256")]}

    Application.put_env(:attesto_phoenix, AttestoPhoenix.Config,
      issuer: "https://issuer.example",
      audience: "https://api.example.com",
      keystore: StubKeystore,
      repo: StubRepo,
      load_client: fn @client_id -> {:ok, %{id: @client_id}} end,
      verify_client_secret: fn _client, _secret -> false end,
      load_principal: fn _subject -> {:error, :not_found} end,
      client_id: fn client -> client.id end,
      client_jwks: fn %{id: @client_id} -> client_jwks end,
      device_code_store: ETS,
      device_authorization: [enabled: true],
      require_https: false
    )

    params = %{
      "scope" => "read",
      "client_assertion_type" => Attesto.ClientAssertion.assertion_type(),
      "client_assertion" => client_assertion(client_key, "PS256")
    }

    conn =
      :post
      |> conn("/oauth/device_authorization", params)
      |> DeviceAuthorizationController.create(params)

    assert conn.status == 400
    assert JSON.decode!(conn.resp_body)["error"] == "invalid_client"
  end

  defp client_assertion(jwk, alg) do
    now = System.system_time(:second)

    claims = %{
      "iss" => @client_id,
      "sub" => @client_id,
      "aud" => "https://issuer.example",
      "iat" => now,
      "exp" => now + 60,
      "jti" => Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
    }

    header = %{"alg" => alg, "kid" => JOSE.JWK.thumbprint(jwk)}
    {_header, compact} = jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    compact
  end

  defp public_jwk(jwk, alg) do
    {_kty, map} = JOSE.JWK.to_public_map(jwk)
    Map.merge(map, %{"kid" => JOSE.JWK.thumbprint(jwk), "alg" => alg, "use" => "sig"})
  end
end
