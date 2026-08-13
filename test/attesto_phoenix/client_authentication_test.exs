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
  use ExUnit.Case, async: false

  alias AttestoPhoenix.{ClientAuthentication, Config, OAuthError}
  alias AttestoPhoenix.ClientAuthentication.{Policy, Result}

  @confidential %{id: "confidential-1", secret: "s3cr3t"}
  @public %{id: "public-1", public?: true}
  @pki_mtls %{id: "pki-mtls-1"}
  @self_signed_mtls %{id: "self-signed-mtls-1"}

  # RFC 8252 §8.4. The native public client is deliberately given a secret the
  # host registry WILL verify: the point is that a correct secret is still
  # refused, because a native app cannot hold one confidentially. The native
  # confidential client is the host's (contradictory) classification, which §8.4
  # as written does not reach.
  @native_public %{id: "native-public-1", secret: "shipped-in-the-binary", public?: true, native?: true}
  @native_confidential %{id: "native-confidential-1", secret: "s3cr3t", native?: true}

  defmodule StubKeystore do
    @moduledoc false
  end

  defmodule StubRepo do
    @moduledoc false
  end

  setup do
    clients =
      Map.new(
        [@confidential, @public, @native_public, @native_confidential, @pki_mtls, @self_signed_mtls],
        &{&1.id, &1}
      )

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
      client_native?: fn client -> Map.get(client, :native?, false) end,
      replay_check: fn _key, _ttl -> :ok end
    }

    {:ok, config: config}
  end

  describe "RFC 8705 mutual-TLS client authentication" do
    test "authenticates tls_client_auth only with a validated chain and matching registered identity", %{
      config: config
    } do
      der = mtls_certificate_der()

      config =
        %{
          config
          | token_endpoint_auth_methods_supported: ["tls_client_auth"],
            client_mtls_metadata: fn @pki_mtls ->
              %{
                "token_endpoint_auth_method" => "tls_client_auth",
                "tls_client_auth_san_dns" => "client.example.com"
              }
            end
        }

      assert {:ok, %Result{client: @pki_mtls, method: :tls_client_auth}} =
               authenticate(
                 mtls_headers(der, chain_validated: true),
                 %{"client_id" => @pki_mtls.id},
                 config,
                 allow_public: false
               )

      assert_generic_invalid_client(
        authenticate(
          mtls_headers(der, chain_validated: false),
          %{"client_id" => @pki_mtls.id},
          config,
          allow_public: false
        )
      )
    end

    test "authenticates self_signed_tls_client_auth against the registered x5c leaf", %{config: config} do
      der = mtls_certificate_der()
      other_der = mtls_certificate_der("other.example.com")

      config =
        %{
          config
          | token_endpoint_auth_methods_supported: ["self_signed_tls_client_auth"],
            client_mtls_metadata: fn @self_signed_mtls ->
              %{"token_endpoint_auth_method" => "self_signed_tls_client_auth"}
            end,
            client_jwks: fn @self_signed_mtls ->
              %{"keys" => [%{"kty" => "EC", "x5c" => [Base.encode64(der)]}]}
            end
        }

      assert {:ok, %Result{client: @self_signed_mtls, method: :self_signed_tls_client_auth}} =
               authenticate(
                 mtls_headers(der, chain_validated: false),
                 %{"client_id" => @self_signed_mtls.id},
                 config,
                 allow_public: false
               )

      assert_generic_invalid_client(
        authenticate(
          mtls_headers(other_der, chain_validated: false),
          %{"client_id" => @self_signed_mtls.id},
          config,
          allow_public: false
        )
      )
    end

    test "treats a certificate as sender constraint when another client credential authenticates", %{config: config} do
      der = mtls_certificate_der()

      assert {:ok, %Result{method: :client_secret_post}} =
               authenticate(
                 mtls_headers(der),
                 %{"client_id" => @confidential.id, "client_secret" => @confidential.secret},
                 config,
                 allow_public: true
               )

      assert {:ok, %Result{method: :client_secret_basic}} =
               authenticate(
                 Map.put(mtls_headers(der), :authorization, basic(@confidential.id, @confidential.secret)),
                 %{"client_id" => @confidential.id},
                 config,
                 allow_public: true
               )
    end

    test "allows a public client to use a certificate only as proof of possession", %{config: config} do
      assert {:ok, %Result{client: @public, method: :none}} =
               authenticate(
                 mtls_headers(mtls_certificate_der()),
                 %{"client_id" => @public.id},
                 config,
                 allow_public: true
               )
    end

    test "treats only nil mTLS metadata as an unregistered public client", %{config: config} do
      config = %{config | client_mtls_metadata: fn @public -> nil end}

      assert {:ok, %Result{client: @public, method: :none}} =
               authenticate(
                 mtls_headers(mtls_certificate_der()),
                 %{"client_id" => @public.id},
                 config,
                 allow_public: true
               )
    end

    test "fails closed when the mTLS metadata store fails or returns malformed output", %{config: config} do
      client = Map.put(@pki_mtls, :public?, true)

      config = %{
        config
        | load_client: fn "pki-mtls-1" -> client end,
          client_mtls_metadata: fn ^client -> {:error, :db_timeout} end
      }

      assert_generic_invalid_client(
        authenticate(
          mtls_headers(mtls_certificate_der()),
          %{"client_id" => @pki_mtls.id},
          config,
          allow_public: true
        )
      )

      config = %{config | client_mtls_metadata: fn ^client -> :malformed end}

      assert_generic_invalid_client(
        authenticate(
          mtls_headers(mtls_certificate_der()),
          %{"client_id" => @pki_mtls.id},
          config,
          allow_public: true
        )
      )
    end

    test "a certificate cannot make a public client eligible when the endpoint forbids public clients", %{
      config: config
    } do
      for endpoint <- [:par, :introspection, :backchannel_authentication] do
        assert_generic_invalid_client(
          ClientAuthentication.authenticate(
            mtls_headers(mtls_certificate_der()),
            %{"client_id" => @public.id},
            config,
            Policy.for_endpoint(config, endpoint)
          )
        )
      end
    end
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

  describe "private_key_jwt key-bound algorithm policy" do
    test "the default FAPI policy rejects weak PS256 while an explicit non-FAPI policy can opt in", %{
      config: config
    } do
      key = JOSE.JWK.generate_key({:rsa, 1024})
      trusted = public_jwk(key, %{"alg" => "PS256"})
      config = %{config | client_jwks: fn @confidential -> %{"keys" => [trusted]} end}
      params = assertion_params(key, "PS256")

      assert_generic_invalid_client(
        authenticate([], params, config,
          allow_public: false,
          assertion_signing_algs: ["PS256"],
          assertion_enforce_fapi_alg_policy: true
        )
      )

      assert {:ok, %Result{method: :private_key_jwt}} =
               authenticate([], params, config,
                 allow_public: false,
                 assertion_signing_algs: ["PS256"]
               )
    end

    test "the default policy accepts legacy and exact Ed25519 identifiers", %{config: config} do
      key = JOSE.JWK.generate_key({:okp, :Ed25519})

      for alg <- ["EdDSA", "Ed25519"] do
        trusted = public_jwk(key, %{"alg" => alg})
        configured = %{config | client_jwks: fn @confidential -> %{"keys" => [trusted]} end}

        assert {:ok, %Result{method: :private_key_jwt}} =
                 authenticate([], assertion_params(key, alg), configured,
                   allow_public: false,
                   assertion_signing_algs: Attesto.SigningAlg.fapi_algs(),
                   assertion_enforce_fapi_alg_policy: true
                 )
      end
    end

    test "legacy EdDSA over Ed448 requires an explicit non-FAPI policy", %{config: config} do
      enable_ed448_support()
      key = JOSE.JWK.generate_key({:okp, :Ed448})
      trusted = public_jwk(key, %{"alg" => "EdDSA"})
      config = %{config | client_jwks: fn @confidential -> %{"keys" => [trusted]} end}
      params = assertion_params(key, "EdDSA")

      assert_generic_invalid_client(
        authenticate([], params, config,
          allow_public: false,
          assertion_signing_algs: ["EdDSA"],
          assertion_enforce_fapi_alg_policy: true
        )
      )

      assert {:ok, %Result{method: :private_key_jwt}} =
               authenticate([], params, config,
                 allow_public: false,
                 assertion_signing_algs: ["EdDSA"]
               )
    end
  end

  describe "native apps: client authentication must be none (RFC 8252 §8.4)" do
    test "a native public client presenting client_secret_basic is rejected", %{config: config} do
      # The secret is correct - `verify_client_secret` returns true for it - and
      # the authentication is still refused, with the generic message that
      # reveals nothing about the client's registration.
      assert_generic_invalid_client(
        authenticate(basic("native-public-1", "shipped-in-the-binary"), %{}, config, allow_public: true)
      )
    end

    test "a native public client presenting client_secret_post is rejected", %{config: config} do
      params = %{"client_id" => "native-public-1", "client_secret" => "shipped-in-the-binary"}

      assert_generic_invalid_client(authenticate([], params, config, allow_public: true))
    end

    test "a native public client authenticating with none succeeds", %{config: config} do
      assert {:ok, %Result{client: @native_public, client_id: "native-public-1", method: :none}} =
               authenticate([], %{"client_id" => "native-public-1"}, config, allow_public: true)
    end

    test "a native public client cannot use PAR at all", %{config: config} do
      # Under the PAR policy `allow_public: false` already rejects the
      # secretless path. The load-bearing half is the SECRET path: without the
      # §8.4 check that would authenticate, since the secret verifies.
      assert {:error, %OAuthError{error: :invalid_client}} =
               authenticate([], %{"client_id" => "native-public-1"}, config, allow_public: false)

      assert_generic_invalid_client(
        authenticate(basic("native-public-1", "shipped-in-the-binary"), %{}, config, allow_public: false)
      )

      # Control: the same PAR policy accepts an ordinary confidential client's
      # secret, so the rejection above is the native rule and not the policy.
      assert {:ok, %Result{method: :client_secret_basic}} =
               authenticate(basic("confidential-1", "s3cr3t"), %{}, config, allow_public: false)
    end

    # RFC 8252 §8.4 carves out per-instance credentials provisioned by dynamic
    # registration; those are genuinely confidential. The host claims that case
    # by explicitly classifying the native client as confidential.
    test "a native client the host EXPLICITLY marks confidential still authenticates by secret", %{config: config} do
      assert {:ok, %Result{client: @native_confidential, method: :client_secret_basic}} =
               authenticate(basic("native-confidential-1", "s3cr3t"), %{}, config, allow_public: true)
    end

    # The footgun: a host that wires :client_native? but not :client_public?.
    # `client_public?/2`'s own fail-closed default is `false` (confidential),
    # which here would mean "accept the shipped secret" - the exact thing §8.4
    # forbids. For the native check the default must flip to public.
    test "a native client is refused a secret when :client_public? is not configured", %{config: config} do
      config = %{config | client_public?: nil}

      assert_generic_invalid_client(
        authenticate(basic("native-confidential-1", "s3cr3t"), %{}, config, allow_public: true)
      )

      assert_generic_invalid_client(
        authenticate(basic("native-public-1", "shipped-in-the-binary"), %{}, config, allow_public: true)
      )

      # A non-native client is unaffected by that default.
      assert {:ok, %Result{method: :client_secret_basic}} =
               authenticate(basic("confidential-1", "s3cr3t"), %{}, config, allow_public: true)
    end

    # The refusal above must not leave the client unable to authenticate AT ALL.
    # `none` is the method RFC 8252 §8.1/§8.4 prescribe for a native app, so the
    # same "unclassified native client is public" rule has to admit it here -
    # otherwise marking a client native without also wiring `:client_public?`
    # would brick it on every path.
    test "a native client with no :client_public? callback still authenticates with none", %{config: config} do
      config = %{config | client_public?: nil}

      assert {:ok, %Result{client_id: "native-public-1", method: :none}} =
               authenticate([], %{"client_id" => "native-public-1"}, config, allow_public: true)

      # The default flips only for native clients: an unclassified NON-native
      # client is still confidential, so the secretless path stays closed to it.
      assert_generic_invalid_client(authenticate([], %{"client_id" => "confidential-1"}, config, allow_public: true))
    end

    test "a native public client presenting private_key_jwt is rejected", %{config: config} do
      # A private key shipped inside an installed app is no more confidential
      # than a shared secret, so the assertion path is closed too: the client
      # authenticates with `none` and relies on PKCE (§8.1).
      client_key = JOSE.JWK.generate_key({:ec, "P-256"})
      config = %{config | client_jwks: fn @native_public -> %{"keys" => [public_jwk(client_key)]} end}

      params = %{
        "client_assertion_type" => Attesto.ClientAssertion.assertion_type(),
        "client_assertion" => client_assertion(client_key, "native-public-1")
      }

      assert_generic_invalid_client(authenticate([], params, config, allow_public: true))
    end

    test "an ordinary public client is unaffected", %{config: config} do
      assert {:ok, %Result{client: @public, method: :none}} =
               authenticate([], %{"client_id" => "public-1"}, config, allow_public: true)
    end

    test "an ordinary confidential client is unaffected", %{config: config} do
      assert {:ok, %Result{client: @confidential, method: :client_secret_basic}} =
               authenticate(basic("confidential-1", "s3cr3t"), %{}, config, allow_public: true)
    end

    test "a host that exposes no :client_native? callback sees no change", %{config: config} do
      config = %{config | client_native?: nil}

      assert {:ok, %Result{client: @native_public, method: :client_secret_basic}} =
               authenticate(basic("native-public-1", "shipped-in-the-binary"), %{}, config, allow_public: true)
    end
  end

  describe "current endpoint client-authentication policy matrix" do
    @endpoint_matrix [
      {:token, true},
      {:par, false},
      {:introspection, false},
      {:device_authorization, true},
      {:backchannel_authentication, false}
    ]

    @all_methods [
      :client_secret_basic,
      :client_secret_post,
      :private_key_jwt,
      :attest_jwt_client_auth,
      :none
    ]

    test "pins the accepted and rejected methods for every policy endpoint", %{config: config} do
      config = %{
        config
        | client_auth_signing_algs: Attesto.SigningAlg.fapi_algs(),
          client_auth_enforce_fapi_alg_policy: true
      }

      for {endpoint, allow_public} <- @endpoint_matrix do
        policy = Policy.for_endpoint(config, endpoint)
        expected_methods = if allow_public, do: @all_methods, else: @all_methods -- [:none]

        assert policy.allow_public == allow_public
        assert policy.assertion_max_lifetime == 300
        assert policy.assertion_signing_algs == config.client_auth_signing_algs
        assert policy.assertion_enforce_fapi_alg_policy == config.client_auth_enforce_fapi_alg_policy

        expected_audiences =
          case endpoint do
            :token ->
              Config.client_assertion_audiences(config)

            :backchannel_authentication ->
              [
                config.issuer,
                Config.token_endpoint_url(config),
                Config.backchannel_authentication_endpoint_url(config)
              ]

            _other ->
              [config.issuer]
          end

        assert policy.assertion_audiences == expected_audiences

        for method <- @all_methods do
          result = authenticate_endpoint_method(method, policy, config)

          if method in expected_methods do
            assert {:ok, %Result{method: ^method}} = result
          else
            assert {:error,
                    %OAuthError{
                      error: :invalid_client,
                      error_description: "client authentication required"
                    }} = result
          end
        end
      end
    end

    defp authenticate_endpoint_method(:client_secret_basic, policy, config) do
      config = %{config | token_endpoint_auth_methods_supported: ["client_secret_basic"]}
      ClientAuthentication.authenticate(basic("confidential-1", "s3cr3t"), %{}, config, policy)
    end

    defp authenticate_endpoint_method(:client_secret_post, policy, config) do
      config = %{config | token_endpoint_auth_methods_supported: ["client_secret_post"]}

      ClientAuthentication.authenticate(
        [],
        %{"client_id" => "confidential-1", "client_secret" => "s3cr3t"},
        config,
        policy
      )
    end

    defp authenticate_endpoint_method(:private_key_jwt, policy, config) do
      client_key = JOSE.JWK.generate_key({:ec, "P-256"})

      config = %{
        config
        | token_endpoint_auth_methods_supported: ["private_key_jwt"],
          client_jwks: fn @confidential -> %{"keys" => [public_jwk(client_key)]} end
      }

      ClientAuthentication.authenticate([], assertion_params(client_key, "ES256"), config, policy)
    end

    defp authenticate_endpoint_method(:attest_jwt_client_auth, policy, config) do
      wallet_provider_key = JOSE.JWK.generate_key({:ec, "P-256"})
      instance_key = JOSE.JWK.generate_key({:ec, "P-256"})

      config = %{
        config
        | token_endpoint_auth_methods_supported: ["attest_jwt_client_auth"],
          trusted_wallet_provider_jwks: %{"keys" => [public_jwk(wallet_provider_key)]}
      }

      ClientAuthentication.authenticate(
        wallet_attestation_headers(wallet_provider_key, instance_key, "confidential-1"),
        %{},
        config,
        policy
      )
    end

    defp authenticate_endpoint_method(:none, policy, config) do
      config = %{config | token_endpoint_auth_methods_supported: ["none"]}

      ClientAuthentication.authenticate(
        [],
        %{"client_id" => "public-1"},
        config,
        policy
      )
    end
  end

  describe "attest_jwt_client_auth" do
    test "authenticates as the verified attestation sub", %{config: config} do
      wallet_provider_key = JOSE.JWK.generate_key({:ec, "P-256"})
      instance_key = JOSE.JWK.generate_key({:ec, "P-256"})
      config = trust_wallet_provider(config, wallet_provider_key)

      assert {:ok,
              %Result{
                client: @confidential,
                client_id: "confidential-1",
                method: :attest_jwt_client_auth
              }} =
               authenticate(
                 wallet_attestation_headers(wallet_provider_key, instance_key, "confidential-1"),
                 %{},
                 config,
                 allow_public: false
               )
    end

    test "allows a native public wallet because the attestation proves an instance key", %{config: config} do
      wallet_provider_key = JOSE.JWK.generate_key({:ec, "P-256"})
      instance_key = JOSE.JWK.generate_key({:ec, "P-256"})
      config = trust_wallet_provider(config, wallet_provider_key)

      assert {:ok, %Result{client: @native_public, method: :attest_jwt_client_auth}} =
               authenticate(
                 wallet_attestation_headers(wallet_provider_key, instance_key, "native-public-1"),
                 %{},
                 config,
                 allow_public: false
               )
    end

    test "rejects wrong-key and expired attestations and an invalid PoP", %{config: config} do
      wallet_provider_key = JOSE.JWK.generate_key({:ec, "P-256"})
      wrong_provider_key = JOSE.JWK.generate_key({:ec, "P-256"})
      instance_key = JOSE.JWK.generate_key({:ec, "P-256"})
      wrong_instance_key = JOSE.JWK.generate_key({:ec, "P-256"})
      config = trust_wallet_provider(config, wallet_provider_key)

      invalid_headers = [
        wallet_attestation_headers(wrong_provider_key, instance_key, "confidential-1"),
        wallet_attestation_headers(wallet_provider_key, instance_key, "confidential-1", %{"exp" => 0}),
        wallet_attestation_headers(
          wallet_provider_key,
          instance_key,
          "confidential-1",
          %{},
          wrong_instance_key
        )
      ]

      for headers <- invalid_headers do
        headers
        |> authenticate(%{}, config, allow_public: false)
        |> assert_generic_invalid_client()
      end
    end

    test "requires both headers and rejects mixing with another authentication method", %{config: config} do
      wallet_provider_key = JOSE.JWK.generate_key({:ec, "P-256"})
      instance_key = JOSE.JWK.generate_key({:ec, "P-256"})
      config = trust_wallet_provider(config, wallet_provider_key)
      headers = wallet_attestation_headers(wallet_provider_key, instance_key, "confidential-1")

      headers
      |> Map.put(:oauth_client_attestation_pop, [])
      |> authenticate(%{}, config, allow_public: false)
      |> assert_generic_invalid_client()

      assert {:error, %OAuthError{error: :invalid_request}} =
               headers
               |> Map.put(:authorization, basic("confidential-1", "s3cr3t"))
               |> authenticate(%{}, config, allow_public: false)
    end

    test "absent attestation headers leave Basic authentication unchanged", %{config: config} do
      wallet_provider_key = JOSE.JWK.generate_key({:ec, "P-256"})
      config = trust_wallet_provider(config, wallet_provider_key)

      assert {:ok, %Result{method: :client_secret_basic}} =
               authenticate(basic("confidential-1", "s3cr3t"), %{}, config, allow_public: false)
    end
  end

  describe "revocation endpoint client-authentication policy" do
    test "allows only Basic/post and gives Basic precedence over body credentials", %{
      config: config
    } do
      policy = Policy.for_endpoint(config, :revocation)

      assert policy.allow_public == false
      assert policy.assertion_audiences == []
      assert policy.allowed_methods == [:client_secret_basic, :client_secret_post]
      assert policy.basic_precedence == true
      # Revocation historically accepted Basic/post independently of the
      # token endpoint's configured method advertisement.
      assert policy.honor_configured_methods == false

      config = %{config | token_endpoint_auth_methods_supported: ["private_key_jwt"]}

      assert {:ok, %Result{method: :client_secret_basic}} =
               ClientAuthentication.authenticate(
                 basic("confidential-1", "s3cr3t"),
                 %{
                   "client_id" => "confidential-1",
                   "client_secret" => "wrong",
                   "client_assertion" => "ignored"
                 },
                 config,
                 policy
               )

      assert {:ok, %Result{method: :client_secret_post}} =
               ClientAuthentication.authenticate(
                 [],
                 %{"client_id" => "confidential-1", "client_secret" => "s3cr3t"},
                 config,
                 policy
               )

      assert {:error, %OAuthError{error: :invalid_client}} =
               ClientAuthentication.authenticate(
                 [],
                 %{
                   "client_id" => "confidential-1",
                   "client_assertion_type" => Attesto.ClientAssertion.assertion_type(),
                   "client_assertion" => "not-used-by-revocation"
                 },
                 config,
                 policy
               )
    end
  end

  defp authenticate(headers, params, config, opts) do
    policy = %Policy{
      allow_public: Keyword.fetch!(opts, :allow_public),
      assertion_audiences: [config.issuer],
      assertion_max_lifetime: 300,
      assertion_signing_algs:
        Keyword.get(opts, :assertion_signing_algs, config.client_auth_signing_algs || Attesto.SigningAlg.fapi_algs()),
      assertion_enforce_fapi_alg_policy:
        Keyword.get(opts, :assertion_enforce_fapi_alg_policy, config.client_auth_enforce_fapi_alg_policy)
    }

    ClientAuthentication.authenticate(headers, params, config, policy)
  end

  defp basic(client_id, secret) do
    ["Basic " <> Base.encode64("#{client_id}:#{secret}")]
  end

  defp mtls_headers(der, opts \\ []) do
    %{
      authorization: [],
      oauth_client_attestation: [],
      oauth_client_attestation_pop: [],
      client_certificate: %{
        der: der,
        source: :tls_socket,
        proof_of_possession: true,
        chain_validated: Keyword.get(opts, :chain_validated, true)
      }
    }
  end

  defp mtls_certificate_der(dns \\ "client.example.com") do
    extension = {:Extension, {2, 5, 29, 17}, false, [{:dNSName, String.to_charlist(dns)}]}

    :public_key.pkix_test_data(%{
      root: [],
      intermediates: [],
      peer: [extensions: [extension]]
    })[:cert]
  end

  defp assert_generic_invalid_client(result) do
    assert {:error,
            %OAuthError{
              error: :invalid_client,
              error_description: "client authentication failed"
            }} = result
  end

  defp assertion_params(jwk, alg) do
    %{
      "client_assertion_type" => Attesto.ClientAssertion.assertion_type(),
      "client_assertion" => client_assertion(jwk, "confidential-1", alg)
    }
  end

  defp client_assertion(jwk, client_id, alg \\ "ES256") do
    now = System.system_time(:second)

    claims = %{
      "iss" => client_id,
      "sub" => client_id,
      "aud" => "https://issuer.example",
      "iat" => now,
      "exp" => now + 60,
      "jti" => Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
    }

    header = %{"alg" => alg, "kid" => JOSE.JWK.thumbprint(jwk)}
    {_header, compact} = jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    compact
  end

  defp trust_wallet_provider(config, wallet_provider_key) do
    %{config | trusted_wallet_provider_jwks: %{"keys" => [public_jwk(wallet_provider_key)]}}
  end

  defp wallet_attestation_headers(
         wallet_provider_key,
         instance_key,
         client_id,
         attestation_overrides \\ %{},
         pop_signing_key \\ nil
       ) do
    now = System.system_time(:second)
    pop_signing_key = pop_signing_key || instance_key

    attestation_claims =
      Map.merge(
        %{
          "sub" => client_id,
          "iat" => now,
          "exp" => now + 300,
          "cnf" => %{"jwk" => public_jwk(instance_key)}
        },
        attestation_overrides
      )

    attestation =
      sign_jwt(
        wallet_provider_key,
        %{
          "alg" => "ES256",
          "typ" => "oauth-client-attestation+jwt",
          "kid" => JOSE.JWK.thumbprint(wallet_provider_key)
        },
        attestation_claims
      )

    pop =
      sign_jwt(
        pop_signing_key,
        %{"alg" => "ES256", "typ" => "oauth-client-attestation-pop+jwt"},
        %{
          "aud" => "https://issuer.example",
          "iat" => now,
          "jti" => Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
        }
      )

    %{
      authorization: [],
      oauth_client_attestation: [attestation],
      oauth_client_attestation_pop: [pop]
    }
  end

  defp sign_jwt(jwk, header, claims) do
    {_header, compact} = jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    compact
  end

  defp public_jwk(jwk, overrides \\ %{}) do
    {_kty, map} = JOSE.JWK.to_public_map(jwk)

    Map.merge(
      map,
      Map.merge(%{"kid" => JOSE.JWK.thumbprint(jwk), "alg" => "ES256", "use" => "sig"}, overrides)
    )
  end

  defp enable_ed448_support do
    previous = JOSE.crypto_fallback()
    JOSE.crypto_fallback(true)
    on_exit(fn -> JOSE.crypto_fallback(previous) end)
  end

  defp normalize_lookup({:ok, client}), do: {:ok, client}
  defp normalize_lookup(:error), do: {:error, :not_found}
end
