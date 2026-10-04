defmodule AttestoPhoenix.SecurityBoundaryRegressionTest do
  @moduledoc false

  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias AttestoPhoenix.AuthorizationServer.JwtBearer
  alias AttestoPhoenix.ClientAuthentication
  alias AttestoPhoenix.ClientAuthentication.{Policy, Result}
  alias AttestoPhoenix.{Config, DuplicateParameterGuard, OAuthError}
  alias AttestoPhoenix.Controller.RegistrationController

  @issuer "https://issuer.example"
  @trusted_idp "https://idp.example"
  @attacker_idp "https://attacker-idp.example"
  @attacker_audience "https://attacker.example/resource"
  @client_id "client-1"
  @client %{id: @client_id, public?: false}

  test "private_key_jwt and ID-JAG do not collide when their raw jti is identical" do
    client_key = JOSE.JWK.generate_key({:ec, "P-256"})
    idp_key = JOSE.JWK.generate_key({:rsa, 2048})
    replay_state = start_supervised!({Agent, fn -> MapSet.new() end})

    replay_check = fn key, _ttl ->
      Agent.get_and_update(replay_state, fn seen ->
        if MapSet.member?(seen, key) do
          {{:error, :replay}, seen}
        else
          {:ok, MapSet.put(seen, key)}
        end
      end)
    end

    config = security_config(client_key, idp_key, replay_check)
    shared_jti = "same-wire-jti"
    client_params = client_assertion_params(client_key, shared_jti)
    id_jag_params = %{"assertion" => id_jag(idp_key, "RS256", @trusted_idp, @issuer, shared_jti)}

    assert {:ok, %Result{method: :private_key_jwt}} =
             ClientAuthentication.authenticate([], client_params, config, Policy.for_endpoint(config, :token))

    assert {:ok, %{claims: %{"jti" => ^shared_jti}}} =
             JwtBearer.authorize(config, @client_id, id_jag_params)

    replay_keys = Agent.get(replay_state, & &1)
    assert MapSet.size(replay_keys) == 2
    assert Enum.any?(replay_keys, &String.starts_with?(&1, "client_assertion:"))
    assert Enum.any?(replay_keys, &String.starts_with?(&1, "idjag:"))

    assert {:error, %OAuthError{error: :invalid_client}} =
             ClientAuthentication.authenticate([], client_params, config, Policy.for_endpoint(config, :token))

    assert {:error, :replay} = JwtBearer.authorize(config, @client_id, id_jag_params)
    assert MapSet.size(Agent.get(replay_state, & &1)) == 2
  end

  test "dynamic client metadata cannot become ID-JAG issuer or audience policy" do
    client_key = JOSE.JWK.generate_key({:ec, "P-256"})
    idp_key = JOSE.JWK.generate_key({:rsa, 2048})
    test_pid = self()

    config =
      security_config(client_key, idp_key, fn _key, _ttl -> :ok end,
        register_client: fn attrs ->
          send(test_pid, {:registered, attrs})
          {:ok, attrs}
        end
      )

    attempted_policy = %{
      "jwt_bearer" => %{
        "issuers" => %{@attacker_idp => %{"jwks" => public_jwks(client_key, "ES256")}}
      },
      "jwt_bearer_issuers" => [@attacker_idp],
      "id_jag_trusted_issuers" => [@attacker_idp],
      "id_jag_audience" => @attacker_audience,
      "identity_assertion_issuer" => @attacker_idp,
      "identity_assertion_audience" => @attacker_audience
    }

    metadata =
      Map.merge(attempted_policy, %{
        "grant_types" => ["client_credentials"],
        "token_endpoint_auth_method" => "private_key_jwt",
        "jwks" => public_jwks(client_key, "ES256")
      })

    conn = post_registration(config, metadata)

    assert conn.status == 201
    assert_receive {:registered, registered}
    assert registered["jwks"] == metadata["jwks"]

    for key <- Map.keys(attempted_policy) do
      refute Map.has_key?(registered, key)
      refute Map.has_key?(JSON.decode!(conn.resp_body), key)
    end

    attacker_assertion = id_jag(client_key, "ES256", @attacker_idp, @attacker_audience, "attacker-jti")
    assert {:error, :untrusted_issuer} = JwtBearer.prepare(config, @client_id, %{"assertion" => attacker_assertion})

    registered_key_assertion = id_jag(client_key, "ES256", @trusted_idp, @issuer, "registered-key-jti")

    assert {:error, :invalid_assertion} =
             JwtBearer.prepare(config, @client_id, %{"assertion" => registered_key_assertion})

    wrong_audience = id_jag(idp_key, "RS256", @trusted_idp, @attacker_audience, "wrong-audience-jti")
    assert {:error, :invalid_assertion} = JwtBearer.prepare(config, @client_id, %{"assertion" => wrong_audience})

    trusted_assertion = id_jag(idp_key, "RS256", @trusted_idp, @issuer, "trusted-jti")

    assert {:ok, %{claims: %{"iss" => @trusted_idp, "aud" => @issuer}}} =
             JwtBearer.prepare(config, @client_id, %{"assertion" => trusted_assertion})
  end

  test "Plug.Parsers cannot turn an empty or non-object JSON document into a client registration" do
    test_pid = self()

    config =
      registration_config(
        register_client: fn attrs ->
          send(test_pid, {:unexpected_registration, attrs})
          {:ok, attrs}
        end
      )

    for raw_json <- ["", "null", "[]", ~s("not-an-object"), "42", "true"] do
      conn = post_raw_registration(config, raw_json)
      response = JSON.decode!(conn.resp_body)

      assert conn.status == 400
      assert response["error"] in ["invalid_client_metadata", "invalid_redirect_uri"]
      refute Map.has_key?(response, "client_id")
      refute Map.has_key?(response, "client_secret")
      refute_received {:unexpected_registration, _attrs}
    end
  end

  test "dynamic registration rejects multiple Content-Type headers" do
    test_pid = self()

    config =
      registration_config(
        register_client: fn attrs ->
          send(test_pid, {:unexpected_registration, attrs})
          {:ok, attrs}
        end
      )

    metadata = %{"grant_types" => ["client_credentials"]}

    conn =
      :post
      |> conn("/oauth/register", metadata)
      |> Map.put(:scheme, :https)
      |> prepend_req_headers([
        {"content-type", "application/json"},
        {"content-type", "application/json"}
      ])
      |> Map.put(:body_params, metadata)
      |> put_private(:attesto_phoenix_config, config)
      |> RegistrationController.create(%{})

    assert conn.status == 400
    assert JSON.decode!(conn.resp_body)["error"] == "invalid_client_metadata"
    refute_received {:unexpected_registration, _attrs}
  end

  test "registration management rejects multiple Authorization headers" do
    test_pid = self()
    token = "valid-registration-token"

    config =
      registration_config(
        load_client: fn @client_id -> {:ok, @client} end,
        client_registration_access_token_hash: fn @client -> Attesto.Secret.hash(token) end,
        unregister_client: fn client ->
          send(test_pid, {:unexpected_deletion, client})
          :ok
        end
      )

    conn =
      :delete
      |> conn("/oauth/register/#{@client_id}")
      |> Map.put(:scheme, :https)
      |> prepend_req_headers([
        {"authorization", "Bearer #{token}"},
        {"authorization", "Bearer another-token"}
      ])
      |> put_private(:attesto_phoenix_config, config)
      |> RegistrationController.delete(%{"client_id" => @client_id})

    assert conn.status == 401
    assert JSON.decode!(conn.resp_body)["error"] == "invalid_token"
    refute_received {:unexpected_deletion, _client}
  end

  test "dynamic registration applies its HTTPS-only policy to post-logout redirects" do
    config = registration_config()

    conn =
      post_registration(config, %{
        "grant_types" => ["client_credentials"],
        "post_logout_redirect_uris" => ["http://client.example/after-logout"]
      })

    assert conn.status == 400
    assert JSON.decode!(conn.resp_body)["error"] == "invalid_client_metadata"
  end

  test "mounted registration routes fail cleanly when runtime registration is unavailable" do
    configs = [
      registration_config(registration_enabled: false, register_client: nil),
      registration_config(registration_enabled: true, register_client: nil)
    ]

    for config <- configs do
      create_conn =
        post_registration(config, %{
          "grant_types" => ["client_credentials"]
        })

      delete_conn =
        :delete
        |> conn("/oauth/register/#{@client_id}")
        |> Map.put(:scheme, :https)
        |> put_req_header("authorization", "Bearer registration-token")
        |> put_private(:attesto_phoenix_config, config)
        |> RegistrationController.delete(%{"client_id" => @client_id})

      for response <- [create_conn, delete_conn] do
        assert response.status == 400
        assert JSON.decode!(response.resp_body)["error"] == "invalid_client_metadata"
      end
    end
  end

  defp security_config(client_key, idp_key, replay_check, overrides \\ []) do
    base = %{
      issuer: @issuer,
      audience: @issuer,
      keystore: :unused,
      repo: :unused,
      load_client: fn
        @client_id -> {:ok, @client}
        _other -> {:error, :not_found}
      end,
      verify_client_secret: fn _client, _secret -> false end,
      load_principal: fn _subject -> {:error, :not_found} end,
      client_id: fn client -> client.id end,
      client_public?: fn _client -> false end,
      client_auth_method: fn _client -> "private_key_jwt" end,
      client_jwks: fn _client -> public_jwks(client_key, "ES256") end,
      client_auth_signing_algs: ["ES256"],
      client_auth_enforce_fapi_alg_policy: true,
      token_endpoint_auth_methods_supported: ["private_key_jwt"],
      replay_check: replay_check,
      resolve_jwt_bearer_subject: fn claims -> {:ok, claims["sub"]} end,
      register_client: fn attrs -> {:ok, attrs} end,
      registration_enabled: true,
      openid_provider: false,
      scopes_supported: [],
      jwt_bearer: [
        enabled: true,
        issuers: %{@trusted_idp => [jwks: public_jwks(idp_key, "RS256"), allowed_algs: ["RS256"]]},
        assertion_max_lifetime_seconds: 300
      ]
    }

    struct(Config, Map.merge(base, Map.new(overrides)))
  end

  defp registration_config(overrides \\ []) do
    base = %{
      issuer: @issuer,
      audience: @issuer,
      keystore: :unused,
      repo: :unused,
      load_client: fn _client_id -> {:error, :not_found} end,
      verify_client_secret: fn _client, _secret -> false end,
      load_principal: fn _subject -> {:error, :not_found} end,
      register_client: fn attrs -> {:ok, attrs} end,
      registration_enabled: true,
      token_endpoint_auth_methods_supported: ["client_secret_basic"],
      openid_provider: false,
      scopes_supported: []
    }

    struct(Config, Map.merge(base, Map.new(overrides)))
  end

  defp client_assertion_params(key, jti) do
    now = System.system_time(:second)

    claims = %{
      "iss" => @client_id,
      "sub" => @client_id,
      "aud" => @issuer,
      "exp" => now + 60,
      "iat" => now,
      "jti" => jti
    }

    %{
      "client_assertion_type" => Attesto.ClientAssertion.assertion_type(),
      "client_assertion" => sign(key, "ES256", "JWT", claims)
    }
  end

  defp id_jag(key, alg, issuer, audience, jti) do
    now = System.system_time(:second)

    claims = %{
      "iss" => issuer,
      "sub" => "user-123",
      "aud" => audience,
      "client_id" => @client_id,
      "jti" => jti,
      "exp" => now + 60,
      "iat" => now
    }

    sign(key, alg, "oauth-id-jag+jwt", claims)
  end

  defp sign(key, alg, typ, claims) do
    header = %{"alg" => alg, "kid" => JOSE.JWK.thumbprint(key), "typ" => typ}
    {_jws, compact} = key |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    compact
  end

  defp public_jwks(key, alg) do
    {_kty, public} = JOSE.JWK.to_public_map(key)

    %{
      "keys" => [Map.merge(public, %{"alg" => alg, "kid" => JOSE.JWK.thumbprint(key), "use" => "sig"})]
    }
  end

  defp post_registration(config, metadata) do
    :post
    |> conn("/oauth/register", metadata)
    |> Map.put(:scheme, :https)
    |> put_req_header("content-type", "application/json")
    |> Map.put(:body_params, metadata)
    |> put_private(:attesto_phoenix_config, config)
    |> RegistrationController.create(%{})
  end

  defp post_raw_registration(config, raw_json) do
    parser_opts =
      Plug.Parsers.init(
        parsers: [:json],
        pass: ["application/json"],
        json_decoder: JSON,
        body_reader: {DuplicateParameterGuard, :read_body, []}
      )

    parsed =
      :post
      |> conn("/oauth/register", raw_json)
      |> Map.put(:scheme, :https)
      |> put_req_header("content-type", "application/json")
      |> Plug.Parsers.call(parser_opts)
      |> put_private(:attesto_phoenix_config, config)

    RegistrationController.call(parsed, :create)
  end
end
