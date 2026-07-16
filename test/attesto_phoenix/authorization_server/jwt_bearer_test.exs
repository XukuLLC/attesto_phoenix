defmodule AttestoPhoenix.AuthorizationServer.JwtBearerTest do
  @moduledoc """
  Data-level tests for the ID-JAG `jwt-bearer` authorization grant
  (`draft-ietf-oauth-identity-assertion-authz-grant-04`), driven through the
  conn-free token core `AttestoPhoenix.AuthorizationServer.Token.issue/2`.
  """
  use ExUnit.Case, async: false

  alias Attesto.DPoP.ReplayCache
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

    test "fetches and verifies against the issuer's jwks_uri" do
      config =
        config(
          jwt_bearer: [
            issuers: %{@idp => [jwks_uri: "https://idp.example/jwks.json", allowed_algs: ["RS256"]]},
            jwks_fetcher: __MODULE__.StubFetcher,
            jwks_cache: nil
          ]
        )

      assert {:ok, response, _} = issue(config, %{"assertion" => assertion()})
      assert is_binary(response.access_token)
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
    def consume(_hash, _opts), do: :error
    @impl true
    def remember_successor(_hash, _successor, _opts), do: :ok
    @impl true
    def revoke_family(_family_id), do: :ok
  end
end
