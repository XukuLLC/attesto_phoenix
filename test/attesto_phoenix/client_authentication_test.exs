defmodule AttestoPhoenix.ClientAuthenticationTest do
  @moduledoc """
  Direct unit tests for the conn-free client-authentication core
  (RFC 6749 §2.3), shared by the token (RFC 6749 §3.2) and PAR (RFC 9126)
  endpoints.

  These exercise `AttestoPhoenix.ClientAuthentication.authenticate/4` against
  data only (the `Authorization` header values and the parsed body params),
  with no conn involved. The focus is the RFC 6749 §2.3 / §2.3.1 multiplicity
  classification: a bare body `client_id` is identification, not a second
  authentication method, so the only newly-accepted case (Basic + redundant
  matching body `client_id`) still authenticates via the Basic secret, while
  every genuine two-credential combination is rejected. Each classification
  row is covered under both `allow_public: true` (token-endpoint policy) and
  `allow_public: false` (PAR-endpoint policy).
  """
  use ExUnit.Case, async: true

  alias AttestoPhoenix.{ClientAuthentication, Config, OAuthError}
  alias AttestoPhoenix.ClientAuthentication.{Policy, Result}

  @confidential %{id: "confidential-1", secret: "s3cr3t"}
  @public %{id: "public-1", public?: true}

  defmodule StubKeystore do
    @moduledoc false
  end

  defmodule StubRepo do
    @moduledoc false
  end

  setup do
    clients = Map.new([@confidential, @public], &{&1.id, &1})

    config = %Config{
      issuer: "https://issuer.example",
      audience: "https://api.example.com",
      keystore: StubKeystore,
      repo: StubRepo,
      load_client: fn
        "revoked-1" -> {:error, :revoked}
        id -> Map.fetch(clients, id) |> normalize_lookup()
      end,
      verify_client_secret: fn
        %{secret: secret}, given -> secret == given
        _unknown, _given -> false
      end,
      load_principal: fn _ -> {:error, :not_found} end,
      client_id: fn client -> client.id end,
      client_public?: fn client -> Map.get(client, :public?, false) end,
      replay_check: fn _key, _ttl -> :ok end
    }

    {:ok, config: config}
  end

  describe "classification: Basic header, no body credential (allow_public: true)" do
    test "Basic + no body params -> client_secret_basic", %{config: config} do
      assert {:ok, %Result{client: @confidential, client_id: "confidential-1", method: method}} =
               authenticate(basic("confidential-1", "s3cr3t"), %{}, config, allow_public: true)

      assert method == :client_secret_basic
    end

    test "Basic + matching body client_id -> client_secret_basic (redundant id allowed)", %{
      config: config
    } do
      params = %{"client_id" => "confidential-1"}

      assert {:ok, %Result{client: @confidential, method: :client_secret_basic}} =
               authenticate(basic("confidential-1", "s3cr3t"), params, config, allow_public: true)
    end

    test "Basic + conflicting body client_id -> invalid_request", %{config: config} do
      params = %{"client_id" => "someone-else"}

      assert {:error, %OAuthError{error: :invalid_request}} =
               authenticate(basic("confidential-1", "s3cr3t"), params, config, allow_public: true)
    end

    test "Basic + body client_secret -> invalid_request (two credentials)", %{config: config} do
      params = %{"client_id" => "confidential-1", "client_secret" => "s3cr3t"}

      assert {:error, %OAuthError{error: :invalid_request}} =
               authenticate(basic("confidential-1", "s3cr3t"), params, config, allow_public: true)
    end

    test "Basic + client_assertion -> invalid_request (two credentials)", %{config: config} do
      params = %{
        "client_assertion_type" => Attesto.ClientAssertion.assertion_type(),
        "client_assertion" => "header.body.sig"
      }

      assert {:error, %OAuthError{error: :invalid_request}} =
               authenticate(basic("confidential-1", "s3cr3t"), params, config, allow_public: true)
    end
  end

  describe "classification: Basic header, no body credential (allow_public: false)" do
    test "Basic + no body params -> client_secret_basic", %{config: config} do
      assert {:ok, %Result{client: @confidential, method: :client_secret_basic}} =
               authenticate(basic("confidential-1", "s3cr3t"), %{}, config, allow_public: false)
    end

    test "Basic + matching body client_id -> client_secret_basic (redundant id allowed)", %{
      config: config
    } do
      params = %{"client_id" => "confidential-1"}

      assert {:ok, %Result{client: @confidential, method: :client_secret_basic}} =
               authenticate(basic("confidential-1", "s3cr3t"), params, config, allow_public: false)
    end

    test "Basic + conflicting body client_id -> invalid_request", %{config: config} do
      params = %{"client_id" => "someone-else"}

      assert {:error, %OAuthError{error: :invalid_request}} =
               authenticate(basic("confidential-1", "s3cr3t"), params, config, allow_public: false)
    end

    test "Basic + body client_secret -> invalid_request (two credentials)", %{config: config} do
      params = %{"client_id" => "confidential-1", "client_secret" => "s3cr3t"}

      assert {:error, %OAuthError{error: :invalid_request}} =
               authenticate(basic("confidential-1", "s3cr3t"), params, config, allow_public: false)
    end

    test "Basic + client_assertion -> invalid_request (two credentials)", %{config: config} do
      params = %{
        "client_assertion_type" => Attesto.ClientAssertion.assertion_type(),
        "client_assertion" => "header.body.sig"
      }

      assert {:error, %OAuthError{error: :invalid_request}} =
               authenticate(basic("confidential-1", "s3cr3t"), params, config, allow_public: false)
    end
  end

  describe "classification: body client_secret + client_assertion (two credentials)" do
    test "rejected with invalid_request under allow_public: true", %{config: config} do
      params = %{
        "client_id" => "confidential-1",
        "client_secret" => "s3cr3t",
        "client_assertion_type" => Attesto.ClientAssertion.assertion_type(),
        "client_assertion" => "header.body.sig"
      }

      assert {:error, %OAuthError{error: :invalid_request}} =
               authenticate([], params, config, allow_public: true)
    end

    test "rejected with invalid_request under allow_public: false", %{config: config} do
      params = %{
        "client_id" => "confidential-1",
        "client_secret" => "s3cr3t",
        "client_assertion_type" => Attesto.ClientAssertion.assertion_type(),
        "client_assertion" => "header.body.sig"
      }

      assert {:error, %OAuthError{error: :invalid_request}} =
               authenticate([], params, config, allow_public: false)
    end
  end

  describe "body credentials: client_secret_post and the public path" do
    test "body client_id + client_secret -> client_secret_post (allow_public: true)", %{
      config: config
    } do
      params = %{"client_id" => "confidential-1", "client_secret" => "s3cr3t"}

      assert {:ok, %Result{client: @confidential, method: :client_secret_post}} =
               authenticate([], params, config, allow_public: true)
    end

    test "body client_id + client_secret -> client_secret_post (allow_public: false)", %{
      config: config
    } do
      params = %{"client_id" => "confidential-1", "client_secret" => "s3cr3t"}

      assert {:ok, %Result{client: @confidential, method: :client_secret_post}} =
               authenticate([], params, config, allow_public: false)
    end

    test "body client_id, no secret -> public client when allow_public: true", %{config: config} do
      params = %{"client_id" => "public-1"}

      assert {:ok, %Result{client: @public, client_id: "public-1", method: :none}} =
               authenticate([], params, config, allow_public: true)
    end

    test "body client_id, no secret -> invalid_client when allow_public: false", %{config: config} do
      # RFC 6749 §2.3.1: with the public path closed, a body client_id without
      # a secret is a confidential client that failed to authenticate.
      params = %{"client_id" => "confidential-1"}

      assert {:error, %OAuthError{error: :invalid_client, error_description: description}} =
               authenticate([], params, config, allow_public: false)

      assert description == "client authentication required"
    end

    test "a non-public client on the secretless path fails closed even when allow_public: true",
         %{config: config} do
      # A client the host does not mark public cannot ride the secretless path.
      params = %{"client_id" => "confidential-1"}

      assert {:error, %OAuthError{error: :invalid_client}} =
               authenticate([], params, config, allow_public: true)
    end

    test "no credentials at all -> invalid_client", %{config: config} do
      assert {:error, %OAuthError{error: :invalid_client}} =
               authenticate([], %{}, config, allow_public: true)
    end
  end

  describe "confidential verification (generic failure, no existence oracle)" do
    test "wrong secret -> generic invalid_client", %{config: config} do
      params = %{"client_id" => "confidential-1", "client_secret" => "nope"}

      assert {:error,
              %OAuthError{
                error: :invalid_client,
                error_description: "client authentication failed"
              }} =
               authenticate([], params, config, allow_public: true)
    end

    test "unknown client -> same generic invalid_client message", %{config: config} do
      params = %{"client_id" => "does-not-exist", "client_secret" => "whatever"}

      assert {:error,
              %OAuthError{
                error: :invalid_client,
                error_description: "client authentication failed"
              }} =
               authenticate([], params, config, allow_public: true)
    end

    test "revoked client -> same generic invalid_client message", %{config: config} do
      params = %{"client_id" => "revoked-1", "client_secret" => "anything"}

      assert {:error,
              %OAuthError{
                error: :invalid_client,
                error_description: "client authentication failed"
              }} =
               authenticate([], params, config, allow_public: true)
    end

    test "Basic credentials reject a conflicting host client_id", %{config: config} do
      config = %{config | client_id: fn _client -> "different-client" end}

      assert_generic_invalid_client(authenticate(basic("confidential-1", "s3cr3t"), %{}, config, allow_public: true))
    end

    test "body credentials reject a conflicting host client_id", %{config: config} do
      config = %{config | client_id: fn _client -> "different-client" end}
      params = %{"client_id" => "confidential-1", "client_secret" => "s3cr3t"}

      assert_generic_invalid_client(authenticate([], params, config, allow_public: true))
    end

    test "Basic credentials never produce a successful result with an empty client_id", %{
      config: config
    } do
      config = %{
        config
        | load_client: fn "" -> {:ok, @confidential} end,
          client_id: nil
      }

      assert_generic_invalid_client(authenticate(basic("", "s3cr3t"), %{}, config, allow_public: true))
    end

    test "public credentials reject a conflicting host client_id", %{config: config} do
      config = %{config | client_id: fn _client -> "different-client" end}

      assert_generic_invalid_client(authenticate([], %{"client_id" => "public-1"}, config, allow_public: true))
    end

    test "an absent host client_id callback preserves the credential-carried identifier", %{
      config: config
    } do
      config = %{config | client_id: nil}

      assert {:ok,
              %Result{
                client: @confidential,
                client_id: "confidential-1",
                method: :client_secret_basic
              }} = authenticate(basic("confidential-1", "s3cr3t"), %{}, config, allow_public: true)
    end
  end

  describe "private_key_jwt identity agreement" do
    test "rejects a conflicting host client_id after verification without consuming jti", %{
      config: config
    } do
      client_key = JOSE.JWK.generate_key({:ec, "P-256"})
      client_jwks = %{"keys" => [public_jwk(client_key)]}
      test_process = self()

      config = %{
        config
        | client_id: fn _client -> "different-client" end,
          client_jwks: fn @confidential -> client_jwks end,
          replay_check: fn _key, _ttl -> send(test_process, :jti_consumed) end
      }

      params = %{
        "client_assertion_type" => Attesto.ClientAssertion.assertion_type(),
        "client_assertion" => client_assertion(client_key, "confidential-1")
      }

      assert_generic_invalid_client(authenticate([], params, config, allow_public: true))
      refute_received :jti_consumed
    end
  end

  defp authenticate(headers, params, config, opts) do
    policy = %Policy{
      allow_public: Keyword.fetch!(opts, :allow_public),
      assertion_audiences: [config.issuer],
      assertion_max_lifetime: 300,
      assertion_signing_algs: config.client_auth_signing_algs || Attesto.SigningAlg.fapi_algs()
    }

    ClientAuthentication.authenticate(headers, params, config, policy)
  end

  defp basic(client_id, secret) do
    ["Basic " <> Base.encode64("#{client_id}:#{secret}")]
  end

  defp assert_generic_invalid_client(result) do
    assert {:error,
            %OAuthError{
              error: :invalid_client,
              error_description: "client authentication failed"
            }} = result
  end

  defp client_assertion(jwk, client_id) do
    now = System.system_time(:second)

    claims = %{
      "iss" => client_id,
      "sub" => client_id,
      "aud" => "https://issuer.example",
      "iat" => now,
      "exp" => now + 60,
      "jti" => Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
    }

    header = %{"alg" => "ES256", "kid" => JOSE.JWK.thumbprint(jwk)}
    {_header, compact} = jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    compact
  end

  defp public_jwk(jwk) do
    {_kty, map} = JOSE.JWK.to_public_map(jwk)
    Map.merge(map, %{"kid" => JOSE.JWK.thumbprint(jwk), "alg" => "ES256", "use" => "sig"})
  end

  defp normalize_lookup({:ok, client}), do: {:ok, client}
  defp normalize_lookup(:error), do: {:error, :not_found}
end
