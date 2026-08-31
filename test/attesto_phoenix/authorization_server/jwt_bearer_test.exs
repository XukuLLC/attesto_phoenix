defmodule AttestoPhoenix.AuthorizationServer.JwtBearerTest do
  @moduledoc """
  Data-level tests for the ID-JAG `jwt-bearer` authorization grant
  (`draft-ietf-oauth-identity-assertion-authz-grant-04`), driven through the
  conn-free token core `AttestoPhoenix.AuthorizationServer.Token.issue/2`.
  """
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Attesto.DPoP.ReplayCache
  alias AttestoPhoenix.AuthorizationServer.JwtBearer, as: JwtBearerGrant
  alias AttestoPhoenix.AuthorizationServer.JwtBearerTest
  alias AttestoPhoenix.AuthorizationServer.Token
  alias AttestoPhoenix.AuthorizationServer.Token.Request
  alias AttestoPhoenix.{Config, OAuthError}

  @grant "urn:ietf:params:oauth:grant-type:jwt-bearer"
  @as_issuer "https://issuer.example"
  @idp "https://idp.example"
  @cid "client-1"

  @signing_pem JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_pem() |> elem(1)
  # The IdP's signing key (fixed for the suite).
  @idp_key JOSE.JWK.generate_key({:rsa, 2048})

  defmodule Keystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem do
      :attesto_phoenix |> Application.fetch_env!(__MODULE__) |> Keyword.fetch!(:signing_pem)
    end

    @impl true
    def verification_pems, do: [signing_pem()]
  end

  defmodule StubRepo do
    @moduledoc false
  end

  @client_kind Attesto.PrincipalKind.new("user", "u_", required_claims: [{"client_id", :non_empty_string}])
  @client %{id: @cid, public?: false}

  setup do
    Application.put_env(:attesto_phoenix, __MODULE__.Keystore, signing_pem: @signing_pem)
    on_exit(fn -> Application.delete_env(:attesto_phoenix, __MODULE__.Keystore) end)
    start_supervised!({ReplayCache, multi_node_acknowledged?: true})
    :ok
  end

  defp idp_jwks do
    {_kty, map} = JOSE.JWK.to_public_map(@idp_key)
    %{"keys" => [Map.merge(map, %{"kid" => JOSE.JWK.thumbprint(@idp_key), "alg" => "RS256"})]}
  end

  defp config(overrides \\ []) do
    {jwt_bearer_overrides, overrides} = Keyword.pop(overrides, :jwt_bearer, [])

    jwt_bearer =
      Keyword.merge(
        [
          enabled: true,
          issuers: %{@idp => [jwks: idp_jwks(), allowed_algs: ["RS256"]]}
        ],
        jwt_bearer_overrides
      )

    [
      issuer: @as_issuer,
      audience: @as_issuer,
      keystore: __MODULE__.Keystore,
      repo: StubRepo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _client, _given -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      client_public?: fn client -> Map.get(client, :public?, false) end,
      client_id: fn client -> Map.get(client, :id) end,
      authorize_scope: fn _client, requested -> {:ok, requested} end,
      principal_kinds: [@client_kind],
      resolve_jwt_bearer_subject: fn claims -> {:ok, claims["sub"]} end,
      build_principal: fn client, subject, scope ->
        %{
          kind: "user",
          sub: ensure_sub(subject),
          scopes: scope,
          claims: %{"client_id" => Map.get(client, :id, "unknown")}
        }
      end,
      jwt_bearer: jwt_bearer
    ]
    |> Keyword.merge(overrides)
    |> Config.new()
  end

  defp ensure_sub("u_" <> _ = sub), do: sub
  defp ensure_sub(sub), do: "u_" <> to_string(sub)

  defp claims(overrides) do
    now = System.system_time(:second)

    Map.merge(
      %{
        "iss" => @idp,
        "sub" => "user-123",
        "aud" => @as_issuer,
        "client_id" => @cid,
        "jti" => "jti-#{System.unique_integer([:positive])}",
        "exp" => now + 300,
        "iat" => now
      },
      overrides
    )
  end

  defp assertion(claim_overrides \\ %{}, header_overrides \\ %{}, key \\ @idp_key) do
    header =
      Map.merge(
        %{"alg" => "RS256", "kid" => JOSE.JWK.thumbprint(@idp_key), "typ" => "oauth-id-jag+jwt"},
        header_overrides
      )

    {_h, jwt} = key |> JOSE.JWT.sign(header, claims(claim_overrides)) |> JOSE.JWS.compact()
    jwt
  end

  defp request(config, params, overrides) do
    fields =
      [
        config: config,
        client: @client,
        client_auth_method: :client_secret_basic,
        grant_type: @grant,
        params: params,
        sender_constraint_input: %{
          dpop_proof: nil,
          mtls_cert_der: nil,
          http_uri: "#{@as_issuer}/oauth/token",
          http_method: "POST"
        },
        client_ip: "203.0.113.7",
        request_client_id: @cid
      ]
      |> Keyword.merge(overrides)

    struct!(Request, fields)
  end

  defp issue(config, params, req_overrides \\ []) do
    Token.issue(config, request(config, params, req_overrides))
  end

  defp dpop_proof_and_jkt do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, public_map} = JOSE.JWK.to_public_map(jwk)

    payload = %{
      "htm" => "POST",
      "htu" => "#{@as_issuer}/oauth/token",
      "iat" => System.system_time(:second),
      "jti" => Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
    }

    header = %{"alg" => "ES256", "typ" => "dpop+jwt", "jwk" => public_map}
    {_, compact} = JOSE.JWS.compact(JOSE.JWT.sign(jwk, header, payload))
    {compact, Attesto.DPoP.compute_jkt(public_map)}
  end

  defp dpop_request_input(proof) do
    %{
      dpop_proof: proof,
      mtls_cert_der: nil,
      http_uri: "#{@as_issuer}/oauth/token",
      http_method: "POST"
    }
  end

  # Read the minted access token's `aud`. The token is signed by the suite's
  # keystore, so the signature-verifying peek suffices (we assert on `aud`, not
  # on `aud`-equality, which `verify/3` would itself enforce against
  # config.audience and so could not observe an RFC 8707 resource override).
  defp access_token_aud(config, %{access_token: token}) do
    {:ok, claims} = Attesto.Token.peek_signed_claims(Config.to_attesto_config(config), token)
    claims["aud"]
  end

  describe "happy path" do
    test "a valid assertion issues an access token" do
      config = config()

      assert {:ok, response, [event]} = issue(config, %{"assertion" => assertion()})
      assert is_binary(response.access_token)
      assert response.token_type == "Bearer"
      assert event.name == :token_issued
      assert event.grant_type == @grant
    end

    test "the assertion scope claim is the granted-scope ceiling" do
      config = config()
      params = %{"assertion" => assertion(%{"scope" => "mcp:read mcp:write"})}

      assert {:ok, response, _} = issue(config, params)
      assert response.scope == "mcp:read mcp:write"
    end

    test "a requested scope within the assertion ceiling is honoured" do
      config = config()
      params = %{"assertion" => assertion(%{"scope" => "mcp:read mcp:write"}), "scope" => "mcp:read"}

      assert {:ok, response, _} = issue(config, params)
      assert response.scope == "mcp:read"
    end

    # RFC 7523 §4 / draft-ietf-oauth-identity-assertion-authz-grant-04: this
    # grant issues NO refresh token - access is re-derived from a fresh
    # assertion each time. A refresh token would outlive enterprise IdP
    # policy/deprovisioning. This holds even when a `refresh_store` is wired and
    # the assertion carries `offline_access` (the signal that triggers refresh
    # issuance for the authorization_code grant).
    test "never issues a refresh token, even with offline_access and a refresh_store" do
      config = config(refresh_store: __MODULE__.StubRefreshStore)
      params = %{"assertion" => assertion(%{"scope" => "openid offline_access"})}

      assert {:ok, response, events} = issue(config, params)
      refute Map.has_key?(response, :refresh_token)
      refute Enum.any?(events, &(&1.name == :refresh_issued))
      assert Enum.any?(events, &(&1.name == :token_issued))
    end
  end

  describe "RFC 8707 resource indicator → access-token aud" do
    test "an allow-listed resource sets the access token aud to that resource" do
      resource = "https://api.example/mcp"
      config = config(resource_indicators: [allowed_resources: [resource]])
      params = %{"assertion" => assertion(), "resource" => resource}

      assert {:ok, response, _} = issue(config, params)
      assert access_token_aud(config, response) == resource
    end

    test "the server's own audience is always an allowed resource" do
      config = config()
      params = %{"assertion" => assertion(), "resource" => @as_issuer}

      assert {:ok, response, _} = issue(config, params)
      assert access_token_aud(config, response) == @as_issuer
    end

    test "a resource that is neither config.audience nor allow-listed is invalid_target" do
      # RFC 8707 §2.2: an authenticated client must not mint a token audienced to
      # an arbitrary resource the AS does not serve.
      config = config(resource_indicators: [allowed_resources: ["https://known.example/api"]])
      params = %{"assertion" => assertion(), "resource" => "https://attacker.example/api"}

      assert {:error, %OAuthError{error: :invalid_target}, _} = issue(config, params)
    end

    test "an absent resource falls back to config.audience" do
      config = config()

      assert {:ok, response, _} = issue(config, %{"assertion" => assertion()})
      assert access_token_aud(config, response) == @as_issuer
    end

    test "an absent request resource uses the assertion's signed resource" do
      resource = "https://api.example/signed"
      config = config(resource_indicators: [allowed_resources: [resource]])
      params = %{"assertion" => assertion(%{"resource" => resource})}

      assert {:ok, response, _} = issue(config, params)
      assert access_token_aud(config, response) == resource
    end

    test "a request may narrow but not widen the assertion's signed resources" do
      a = "https://api.example/a"
      b = "https://api.example/b"
      config = config(resource_indicators: [allowed_resources: [a, b]])

      narrow = %{
        "assertion" => assertion(%{"resource" => [a, b]}),
        "resource" => a
      }

      assert {:ok, response, _} = issue(config, narrow)
      assert access_token_aud(config, response) == a

      widen = %{
        "assertion" => assertion(%{"resource" => a}),
        "resource" => b
      }

      assert {:error, %OAuthError{error: :invalid_target}, _} = issue(config, widen)
    end

    test "a resource with a fragment is invalid_target" do
      config = config()
      params = %{"assertion" => assertion(), "resource" => "https://api.example/mcp#frag"}

      assert {:error, %OAuthError{error: :invalid_target}, _} = issue(config, params)
    end

    test "a relative (non-absolute) resource URI is invalid_target" do
      config = config()
      params = %{"assertion" => assertion(), "resource" => "/mcp"}

      assert {:error, %OAuthError{error: :invalid_target}, _} = issue(config, params)
    end

    test "multiple allow-listed resources mint an aud array (RFC 8707 §2.2)" do
      a = "https://a.example/api"
      b = "https://b.example/api"
      config = config(resource_indicators: [allowed_resources: [a, b]])
      params = %{"assertion" => assertion(), "resource" => [a, b]}

      assert {:ok, response, _} = issue(config, params)
      assert access_token_aud(config, response) == [a, b]
    end

    test "a multi-resource request including one the server does not serve is invalid_target" do
      config = config(resource_indicators: [allowed_resources: ["https://a.example/api"]])
      params = %{"assertion" => assertion(), "resource" => ["https://a.example/api", "https://evil.example"]}

      assert {:error, %OAuthError{error: :invalid_target}, _} = issue(config, params)
    end

    test "a single resource repeated (one distinct value) is honoured" do
      resource = "https://api.example/mcp"
      config = config(resource_indicators: [allowed_resources: [resource]])
      params = %{"assertion" => assertion(), "resource" => [resource, resource]}

      assert {:ok, response, _} = issue(config, params)
      assert access_token_aud(config, response) == resource
    end

    test "a configured resource with invalid percent-encoding fails at boot" do
      # RFC 3986 §2.1: a bad `%HH` triplet must never reach access-token
      # issuance. Static policy is trusted configuration, so reject it while
      # building Config instead of waiting for the first request.
      assert_raise ArgumentError, ~r/every :resource_indicators :allowed_resources entry/, fn ->
        config(resource_indicators: [allowed_resources: ["https://api.example/%ZZ"]])
      end
    end

    test "a present-but-empty resource is invalid_target, not silently absent" do
      # RFC 8707 §2.1: `resource=` is malformed (not an absolute URI) and must
      # fail closed rather than fall back to config.audience as if unset.
      for blank <- ["", [""], ["https://a.example", ""]] do
        params = %{"assertion" => assertion(), "resource" => blank}

        assert {:error, %OAuthError{error: :invalid_target}, _} = issue(config(), params),
               "expected :invalid_target for resource=#{inspect(blank)}"
      end
    end
  end

  describe "assertion validation → invalid_grant (draft §6.1)" do
    test "untrusted issuer" do
      assert {:error, %OAuthError{error: :invalid_grant}, _} =
               issue(config(), %{"assertion" => assertion(%{"iss" => "https://evil.example"})})
    end

    test "wrong audience" do
      assert {:error, %OAuthError{error: :invalid_grant}, _} =
               issue(config(), %{"assertion" => assertion(%{"aud" => "https://other.example"})})
    end

    test "bad signature (assertion signed by a different key)" do
      other = JOSE.JWK.generate_key({:rsa, 2048})

      assert {:error, %OAuthError{error: :invalid_grant}, _} =
               issue(config(), %{"assertion" => assertion(%{}, %{}, other)})
    end

    test "expired assertion" do
      now = System.system_time(:second)

      assert {:error, %OAuthError{error: :invalid_grant}, _} =
               issue(config(), %{"assertion" => assertion(%{"iat" => now - 600, "exp" => now - 300})})
    end

    test "client_id claim does not match the authenticated client" do
      assert {:error, %OAuthError{error: :invalid_grant}, _} =
               issue(config(), %{"assertion" => assertion(%{"client_id" => "someone-else"})})
    end

    test "wrong typ header" do
      assert {:error, %OAuthError{error: :invalid_grant}, _} =
               issue(config(), %{"assertion" => assertion(%{}, %{"typ" => "JWT"})})
    end

    test "a replayed jti is rejected the second time" do
      config = config()
      jwt = assertion(%{"jti" => "fixed-jti-once"})

      assert {:ok, _response, _} = issue(config, %{"assertion" => jwt})

      assert {:error, %OAuthError{error: :invalid_grant}, _} =
               issue(config, %{"assertion" => jwt})
    end

    test "the public authorize API still commits replay before returning" do
      config = config()
      params = %{"assertion" => assertion(%{"jti" => "direct-api-jti"})}

      assert {:ok, result} = JwtBearerGrant.authorize(config, @cid, params)
      refute Map.has_key?(result, :replay_claim)
      assert {:error, :replay} = JwtBearerGrant.authorize(config, @cid, params)
    end

    test "unexpected replay callback results fail loudly instead of impersonating a replay" do
      for invalid <- [nil, :unexpected, {:error, :storage_unavailable}] do
        config = config(replay_check: fn _key, _ttl -> invalid end)
        params = %{"assertion" => assertion()}

        assert_raise ArgumentError,
                     ~r/:replay_check must return :ok or \{:error, :replay\}/,
                     fn -> JwtBearerGrant.authorize(config, @cid, params) end
      end
    end

    test "the same jti from two trusted issuers does not collide" do
      second_idp = "https://second-idp.example"

      config =
        config(
          jwt_bearer: [
            issuers: %{
              @idp => [jwks: idp_jwks(), allowed_algs: ["RS256"]],
              second_idp => [jwks: idp_jwks(), allowed_algs: ["RS256"]]
            }
          ]
        )

      assert {:ok, _, _} =
               issue(config, %{"assertion" => assertion(%{"jti" => "shared-idp-jti"})})

      assert {:ok, _, _} =
               issue(config, %{
                 "assertion" => assertion(%{"iss" => second_idp, "jti" => "shared-idp-jti"})
               })
    end

    test "a subject-resolution deny is invalid_grant" do
      config = config(resolve_jwt_bearer_subject: fn _claims -> {:error, :no_such_user} end)

      assert {:error, %OAuthError{error: :invalid_grant}, _} =
               issue(config, %{"assertion" => assertion()})
    end
  end

  describe "request & policy errors" do
    test "a missing assertion parameter is invalid_request" do
      assert {:error, %OAuthError{error: :invalid_request}, _} = issue(config(), %{})
    end

    test "a scope beyond the assertion ceiling is invalid_scope" do
      config = config()
      params = %{"assertion" => assertion(%{"scope" => "mcp:read"}), "scope" => "mcp:read mcp:admin"}

      assert {:error, %OAuthError{error: :invalid_scope}, _} = issue(config, params)
    end

    test "a failed policy check does not consume an otherwise valid assertion" do
      config = config()
      jwt = assertion(%{"scope" => "mcp:read"})

      assert {:error, %OAuthError{error: :invalid_scope}, _} =
               issue(config, %{"assertion" => jwt, "scope" => "mcp:admin"})

      assert {:ok, response, _} = issue(config, %{"assertion" => jwt, "scope" => "mcp:read"})
      assert response.scope == "mcp:read"
    end

    test "invalid binding, resource, and scope requests do not invoke the subject resolver" do
      test_pid = self()
      resource = "https://api.example/signed"

      config =
        config(
          dpop_enabled: true,
          resource_indicators: [allowed_resources: [resource]],
          resolve_jwt_bearer_subject: fn claims ->
            send(test_pid, {:resolved, claims["jti"]})
            {:ok, claims["sub"]}
          end
        )

      {_proof, jkt} = dpop_proof_and_jkt()

      assert {:error, %OAuthError{error: :invalid_grant}, _} =
               issue(config, %{
                 "assertion" => assertion(%{"jti" => "bad-binding", "cnf" => %{"jkt" => jkt}})
               })

      assert {:error, %OAuthError{error: :invalid_target}, _} =
               issue(config, %{
                 "assertion" => assertion(%{"jti" => "bad-resource", "resource" => resource}),
                 "resource" => @as_issuer
               })

      assert {:error, %OAuthError{error: :invalid_scope}, _} =
               issue(config, %{
                 "assertion" => assertion(%{"jti" => "bad-scope", "scope" => "mcp:read"}),
                 "scope" => "mcp:admin"
               })

      refute_received {:resolved, _jti}

      assert {:ok, _response, _events} =
               issue(config, %{
                 "assertion" => assertion(%{"jti" => "valid-policy", "scope" => "mcp:read"}),
                 "scope" => "mcp:read"
               })

      assert_received {:resolved, "valid-policy"}
    end

    test "host scope policy cannot widen the signed or requested ceiling" do
      config = config(authorize_scope: fn _client, _requested -> {:ok, ["mcp:admin"]} end)

      params = %{
        "assertion" => assertion(%{"scope" => "mcp:read mcp:write"}),
        "scope" => "mcp:read"
      }

      assert {:error, %OAuthError{error: :invalid_scope}, _} = issue(config, params)
    end

    test "cnf.jkt requires a matching DPoP proof and binds the issued token" do
      {proof, jkt} = dpop_proof_and_jkt()
      jwt = assertion(%{"cnf" => %{"jkt" => jkt}})
      config = config(dpop_enabled: true)

      assert {:error, %OAuthError{error: :invalid_grant}, _} =
               issue(config, %{"assertion" => jwt})

      assert {:ok, response, _} =
               issue(config, %{"assertion" => jwt}, sender_constraint_input: dpop_request_input(proof))

      assert response.token_type == "DPoP"
      {:ok, claims} = Attesto.Token.peek_signed_claims(Config.to_attesto_config(config), response.access_token)
      assert claims["cnf"] == %{"jkt" => jkt}
    end

    test "cnf.jkt rejects a proof made with a different key" do
      {_matching_proof, expected_jkt} = dpop_proof_and_jkt()
      {wrong_proof, _wrong_jkt} = dpop_proof_and_jkt()
      config = config(dpop_enabled: true)

      assert {:error, %OAuthError{error: :invalid_grant}, _} =
               issue(
                 config,
                 %{"assertion" => assertion(%{"cnf" => %{"jkt" => expected_jkt}})},
                 sender_constraint_input: dpop_request_input(wrong_proof)
               )
    end

    test "the grant is rejected when the client is not registered for it" do
      config = config(client_grant_types: fn _client -> ["authorization_code"] end)

      assert {:error, %OAuthError{error: :unsupported_grant_type}, _} =
               issue(config, %{"assertion" => assertion()})
    end

    test "a public client cannot use the grant" do
      config = config()

      assert {:error, %OAuthError{error: :invalid_client}, _} =
               issue(config, %{"assertion" => assertion()},
                 client: %{id: @cid, public?: true},
                 client_auth_method: :none
               )
    end

    test "the grant is unsupported when the feature is disabled" do
      config = config(jwt_bearer: [enabled: false])

      assert {:error, %OAuthError{error: :unsupported_grant_type}, _} =
               issue(config, %{"assertion" => assertion()})
    end
  end

  describe "discovery metadata gating" do
    test "grant_types_supported advertises jwt-bearer only when enabled" do
      assert @grant in Config.grant_types_supported(config())
      refute @grant in Config.grant_types_supported(config(jwt_bearer: [enabled: false]))
    end
  end

  describe "config validation (fail closed at boot)" do
    test "enabling without issuers or a resolver raises" do
      assert_raise ArgumentError, ~r/non-empty :issuers map/, fn ->
        config(jwt_bearer: [enabled: true, issuers: %{}])
      end
    end

    test "enabling without a subject-resolution callback raises" do
      assert_raise ArgumentError, ~r/:resolve_jwt_bearer_subject is required/, fn ->
        config(resolve_jwt_bearer_subject: nil)
      end
    end
  end

  describe "JWKS resolution via jwks_uri (SSRF-guarded fetcher seam)" do
    defmodule StubFetcher do
      @moduledoc false
      @behaviour AttestoPhoenix.ClientIdMetadata.Fetcher

      @impl true
      def fetch(_url, _opts) do
        {_kty, map} =
          JOSE.JWK.to_public_map(JwtBearerTest.idp_key())

        jwks = %{
          "keys" => [
            Map.merge(map, %{
              "kid" => JOSE.JWK.thumbprint(JwtBearerTest.idp_key()),
              "alg" => "RS256"
            })
          ]
        }

        {:ok, %{body: JSON.encode!(jwks), cache_control: [max_age: 600]}}
      end
    end

    defmodule FailingFetcher do
      @moduledoc false
      @behaviour AttestoPhoenix.ClientIdMetadata.Fetcher

      @impl true
      def fetch(_url, _opts), do: {:error, {:transport, "private_fetch_reason"}}
    end

    defmodule FaultCache do
      @moduledoc false
      @behaviour AttestoPhoenix.ClientIdMetadata.Cache

      def script(get_result, put_result \\ :ok) do
        Process.put({__MODULE__, :get}, get_result)
        Process.put({__MODULE__, :put}, put_result)
      end

      @impl true
      def get(_url), do: respond(Process.get({__MODULE__, :get}, :miss))

      @impl true
      def put(_url, _metadata, _expires_at), do: respond(Process.get({__MODULE__, :put}, :ok))

      defp respond({:raise, message}), do: raise(message)
      defp respond(result), do: result
    end

    defp remote_jwks_config(cache, fetcher \\ __MODULE__.StubFetcher, uri \\ "https://idp.example/jwks.json") do
      config(
        jwt_bearer: [
          issuers: %{@idp => [jwks_uri: uri, allowed_algs: ["RS256"]]},
          jwks_fetcher: fetcher,
          jwks_cache: cache
        ]
      )
    end

    test "fetches and verifies against the issuer's jwks_uri" do
      config = remote_jwks_config(nil)

      assert {:ok, response, _} = issue(config, %{"assertion" => assertion()})
      assert is_binary(response.access_token)
    end

    test "a fetch failure warning excludes the URI and callback reason" do
      uri = "https://idp.example/jwks.json?api_key=private_uri_secret"
      config = remote_jwks_config(nil, __MODULE__.FailingFetcher, uri)

      log =
        capture_log(fn ->
          assert {:error, %OAuthError{error: :invalid_grant}, _} =
                   issue(config, %{"assertion" => assertion()})
        end)

      assert log =~ "AttestoPhoenix JWT-bearer JWKS fetch failed; keys unavailable"
      refute log =~ uri
      refute log =~ "private_uri_secret"
      refute log =~ "private_fetch_reason"
    end

    test "a cache read error is visible and falls back to freshly fetched keys" do
      FaultCache.script({:error, :private_backend_detail})
      config = remote_jwks_config(FaultCache)

      log =
        capture_log(fn ->
          assert {:ok, response, _} = issue(config, %{"assertion" => assertion()})
          assert is_binary(response.access_token)
        end)

      assert log =~ "AttestoPhoenix JWT-bearer JWKS cache failed; fetching fresh keys"
      refute log =~ "private_backend_detail"
      refute log =~ "https://idp.example/jwks.json"
    end

    test "a malformed cache hit is visible and cannot supply verification keys" do
      FaultCache.script({:ok, [:private_unvalidated_value]})
      config = remote_jwks_config(FaultCache)

      log =
        capture_log(fn ->
          assert {:ok, response, _} = issue(config, %{"assertion" => assertion()})
          assert is_binary(response.access_token)
        end)

      assert log =~ "AttestoPhoenix JWT-bearer JWKS cache failed; fetching fresh keys"
      refute log =~ "private_unvalidated_value"
    end

    test "a cached map without a keys list is visible and cannot supply verification keys" do
      FaultCache.script({:ok, %{"private" => "unvalidated"}})
      config = remote_jwks_config(FaultCache)

      log =
        capture_log(fn ->
          assert {:ok, response, _} = issue(config, %{"assertion" => assertion()})
          assert is_binary(response.access_token)
        end)

      assert log =~ "AttestoPhoenix JWT-bearer JWKS cache failed; fetching fresh keys"
      refute log =~ "private"
      refute log =~ "unvalidated"
    end

    test "a cache write error is visible without rejecting freshly verified keys" do
      FaultCache.script(:miss, {:error, :private_backend_detail})
      config = remote_jwks_config(FaultCache)

      log =
        capture_log(fn ->
          assert {:ok, response, _} = issue(config, %{"assertion" => assertion()})
          assert is_binary(response.access_token)
        end)

      assert log =~ "AttestoPhoenix JWT-bearer JWKS cache failed; fresh keys were not cached"
      refute log =~ "private_backend_detail"
      refute log =~ "https://idp.example/jwks.json"
    end

    test "a cache exception is visible and degrades to an uncached fresh fetch" do
      FaultCache.script({:raise, "private backend exception"}, {:raise, "private write exception"})
      config = remote_jwks_config(FaultCache)

      log =
        capture_log(fn ->
          assert {:ok, response, _} = issue(config, %{"assertion" => assertion()})
          assert is_binary(response.access_token)
        end)

      assert log =~ "AttestoPhoenix JWT-bearer JWKS cache failed; fetching fresh keys"
      assert log =~ "AttestoPhoenix JWT-bearer JWKS cache failed; fresh keys were not cached"
      refute log =~ "private backend exception"
      refute log =~ "private write exception"
    end
  end

  # Exposed so the StubFetcher (a nested module) can reach the suite's IdP key.
  def idp_key, do: @idp_key

  defmodule StubRefreshStore do
    @moduledoc false
    @behaviour Attesto.RefreshStore

    @impl true
    def insert(_entry), do: :ok
    @impl true
    def get(_hash), do: :error
    @impl true
    def rotate(_hash, _child, _successor, _opts), do: :error
    @impl true
    def revoke_family(_family_id), do: :ok
  end
end
