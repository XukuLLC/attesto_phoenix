defmodule AttestoPhoenix.AuthorizationServer.TokenTest do
  @moduledoc """
  Direct, data-level unit tests for the conn-free token core
  (RFC 6749 §3.2 / §4).

  These exercise `AttestoPhoenix.AuthorizationServer.Token.issue/2` against a
  `%Request{}` of plain data - no `Plug.Conn`, no controller. The focus is the
  contract the controller depends on: the function returns the RFC 6749 §5.1
  response body (or an `OAuthError`) together with the audit events it produced
  *as data* (the core emits nothing itself), and it never touches a conn.
  """
  use ExUnit.Case, async: false

  alias Attesto.CodeStore.ETS
  alias AttestoPhoenix.AuthorizationServer.Token
  alias AttestoPhoenix.AuthorizationServer.Token.Request
  alias AttestoPhoenix.{Config, Event, OAuthError}

  # A throwaway RSA keypair for the minting paths.
  @signing_pem JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_pem() |> elem(1)
  @code_verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  @code_challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
  @redirect_uri "https://client.example/cb"
  @grant_token_exchange "urn:ietf:params:oauth:grant-type:token-exchange"
  @subject_token_type_access_token "urn:ietf:params:oauth:token-type:access_token"

  defmodule Keystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem do
      :attesto_phoenix
      |> Application.fetch_env!(__MODULE__)
      |> Keyword.fetch!(:signing_pem)
    end

    @impl true
    def verification_pems, do: [signing_pem()]
  end

  defmodule StubRepo do
    @moduledoc false
  end

  # One principal kind so `Attesto.Token.mint/3` has a kind to issue under.
  @client_kind Attesto.PrincipalKind.new("client", "oc_", required_claims: [{"client_id", :non_empty_string}])

  @client %{id: "client-1", public?: false}

  setup do
    Application.put_env(:attesto_phoenix, __MODULE__.Keystore, signing_pem: @signing_pem)
    on_exit(fn -> Application.delete_env(:attesto_phoenix, __MODULE__.Keystore) end)
    :ok
  end

  defp config(overrides \\ []) do
    [
      issuer: "https://issuer.example",
      audience: "https://issuer.example",
      keystore: __MODULE__.Keystore,
      repo: StubRepo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _client, _given -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      client_public?: fn client -> Map.get(client, :public?, false) end,
      client_id: fn client -> Map.get(client, :id) end,
      authorize_scope: fn _client, requested -> {:ok, requested} end,
      principal_kinds: [@client_kind],
      build_principal: fn client, subject, scope ->
        %{
          kind: "client",
          sub: ensure_sub(subject),
          scopes: scope,
          claims: %{"client_id" => Map.get(client, :id, "unknown")}
        }
      end
    ]
    |> Keyword.merge(overrides)
    |> Config.new()
  end

  defp ensure_sub("oc_" <> _ = sub), do: sub
  defp ensure_sub(sub), do: "oc_" <> to_string(sub)

  # Decode the unverified JWT payload's `aud` claim (string or array).
  defp aud!(jwt) when is_binary(jwt) do
    [_header, payload | _] = String.split(jwt, ".")
    {:ok, json} = Base.url_decode64(payload, padding: false)
    JSON.decode!(json)["aud"]
  end

  defp claim!(jwt, key) when is_binary(jwt) do
    [_header, payload | _] = String.split(jwt, ".")
    {:ok, json} = Base.url_decode64(payload, padding: false)
    JSON.decode!(json)[key]
  end

  defp start_code_store(subject, scope) do
    case start_supervised(ETS) do
      {:ok, _pid} -> :ok
      {:error, {:already_started, _pid}} -> :ok
    end

    ETS.reset()

    {:ok, code} =
      Attesto.AuthorizationCode.issue(ETS, %{
        client_id: "client-1",
        redirect_uri: @redirect_uri,
        scope: scope,
        subject: subject,
        code_challenge: @code_challenge,
        code_challenge_method: "S256"
      })

    Process.put(:auth_code, code)
    ETS
  end

  # A code carrying the RFC 9470 authentication context the authorize controller
  # would have recorded (acr/auth_time in the code's claims).
  defp start_code_store_with_auth_context(subject, scope, acr, auth_time) do
    case start_supervised(ETS) do
      {:ok, _pid} -> :ok
      {:error, {:already_started, _pid}} -> :ok
    end

    ETS.reset()

    {:ok, code} =
      Attesto.AuthorizationCode.issue(ETS, %{
        client_id: "client-1",
        redirect_uri: @redirect_uri,
        scope: scope,
        subject: subject,
        code_challenge: @code_challenge,
        code_challenge_method: "S256",
        claims: %{"acr" => acr, "auth_time" => auth_time}
      })

    Process.put(:auth_code, code)
    ETS
  end

  defp start_refresh_store do
    case start_supervised(Attesto.RefreshStore.ETS) do
      {:ok, _pid} -> :ok
      {:error, {:already_started, _pid}} -> :ok
    end

    Attesto.RefreshStore.ETS.reset()
    Attesto.RefreshStore.ETS
  end

  defp dpop_proof_and_jkt do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, public_map} = JOSE.JWK.to_public_map(jwk)

    payload = %{
      "htm" => "POST",
      "htu" => "https://issuer.example/oauth/token",
      "iat" => System.system_time(:second),
      "jti" => 16 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
    }

    header = %{"alg" => "ES256", "typ" => "dpop+jwt", "jwk" => public_map}
    {_, compact} = jwk |> JOSE.JWT.sign(header, payload) |> JOSE.JWS.compact()
    {compact, Attesto.DPoP.compute_jkt(public_map)}
  end

  defp self_signed_cert_der do
    %{cert: der} = :public_key.pkix_test_root_cert(~c"CN=attesto-test", [])
    der
  end

  defp request(config, overrides) do
    fields =
      [
        config: config,
        client: @client,
        # Confidential by default; client_credentials/token-exchange require it.
        # Tests of the public-client gate override this with :none.
        client_auth_method: :client_secret_basic,
        grant_type: "client_credentials",
        params: %{},
        sender_constraint_input: %{
          dpop_proof: nil,
          mtls_cert_der: nil,
          http_uri: "https://issuer.example/oauth/token",
          http_method: "POST"
        },
        client_ip: "203.0.113.7",
        request_client_id: nil
      ]
      |> Keyword.merge(overrides)

    struct!(Request, fields)
  end

  describe "client_credentials grant (RFC 6749 §4.4)" do
    test "returns the RFC 6749 §5.1 body and a :token_issued event as data" do
      config = config()
      request = request(config, params: %{"scope" => "read write"})

      assert {:ok, response, events} = Token.issue(config, request)

      assert is_binary(response.access_token)
      assert response.token_type == "Bearer"
      assert is_integer(response.expires_in)
      assert response.scope == "read write"
      # RFC 6749 §4.4.3: no refresh token for client_credentials.
      refute Map.has_key?(response, :refresh_token)

      assert [%Event{} = event] = events

      assert %Event{
               name: :token_issued,
               client_id: "client-1",
               grant_type: "client_credentials",
               scope: "read write"
             } = event

      assert event.metadata == %{
               client_ip: "203.0.113.7",
               token_type: "Bearer",
               sender_constraint: :none,
               cnf: nil
             }
    end

    test "RFC 8707: an allow-listed resource sets the access token aud to that resource" do
      resource = "https://api.example/mcp"
      config = config(resource_indicators: [allowed_resources: [resource]])
      request = request(config, params: %{"scope" => "read", "resource" => resource})

      assert {:ok, response, _} = Token.issue(config, request)
      assert aud!(response.access_token) == resource
    end

    test "RFC 8707: multiple allow-listed resources mint an aud array" do
      a = "https://a.example/api"
      b = "https://b.example/api"
      config = config(resource_indicators: [allowed_resources: [a, b]])
      request = request(config, params: %{"scope" => "read", "resource" => [a, b]})

      assert {:ok, response, _} = Token.issue(config, request)
      assert aud!(response.access_token) == [a, b]
    end

    test "RFC 8707: a resource the server does not serve is invalid_target" do
      config = config()
      request = request(config, params: %{"scope" => "read", "resource" => "https://evil.example/api"})

      assert {:error, %OAuthError{error: :invalid_target}, _} = Token.issue(config, request)
    end

    test "RFC 8707: without a resource the aud falls back to config.audience" do
      config = config()
      request = request(config, params: %{"scope" => "read"})

      assert {:ok, response, _} = Token.issue(config, request)
      assert aud!(response.access_token) == "https://issuer.example"
    end

    test "a DPoP-bound token_issued event carries the token type and jkt" do
      {proof, jkt} = dpop_proof_and_jkt()

      config =
        config(
          dpop_enabled: true,
          replay_check: fn _key, _ttl -> :ok end
        )

      request =
        request(config,
          params: %{"scope" => "read"},
          sender_constraint_input: %{
            dpop_proof: proof,
            mtls_cert_der: nil,
            http_uri: "https://issuer.example/oauth/token",
            http_method: "POST"
          }
        )

      assert {:ok, response, [%Event{name: :token_issued} = event]} = Token.issue(config, request)
      assert response.token_type == "DPoP"

      assert event.metadata == %{
               client_ip: "203.0.113.7",
               token_type: "DPoP",
               sender_constraint: :dpop,
               cnf: %{"jkt" => jkt}
             }
    end

    test "an mTLS-bound token_issued event carries the bearer type and certificate thumbprint" do
      der = self_signed_cert_der()
      {:ok, thumbprint} = Attesto.MTLS.compute_thumbprint(der)
      config = config(mtls_enabled: true, cert_der: fn _conn -> der end)

      request =
        request(config,
          params: %{"scope" => "read"},
          sender_constraint_input: %{
            dpop_proof: nil,
            mtls_cert_der: der,
            http_uri: "https://issuer.example/oauth/token",
            http_method: "POST"
          }
        )

      assert {:ok, response, [%Event{name: :token_issued} = event]} = Token.issue(config, request)
      assert response.token_type == "Bearer"

      assert event.metadata == %{
               client_ip: "203.0.113.7",
               token_type: "Bearer",
               sender_constraint: :mtls,
               cnf: %{"x5t#S256" => thumbprint}
             }
    end

    test "the core emits nothing itself: a configured :on_event is not invoked" do
      test_pid = self()
      config = config(on_event: fn event -> send(test_pid, {:event, event}) end)
      request = request(config, params: %{"scope" => "read"})

      assert {:ok, _response, [_event]} = Token.issue(config, request)
      refute_received {:event, _}
    end
  end

  describe "authorization_code grant (RFC 6749 §4.1)" do
    test "a token_issued event carries bearer sender metadata" do
      code_store = start_code_store("oc_user-1", ["openid"])
      config = config(code_store: code_store)

      request =
        request(config,
          grant_type: "authorization_code",
          params: %{
            "code" => Process.get(:auth_code),
            "code_verifier" => @code_verifier,
            "redirect_uri" => @redirect_uri
          }
        )

      assert {:ok, response, [%Event{name: :token_issued} = event]} = Token.issue(config, request)
      assert response.token_type == "Bearer"

      assert event.grant_type == "authorization_code"

      assert event.metadata == %{
               client_ip: "203.0.113.7",
               token_type: "Bearer",
               sender_constraint: :none,
               cnf: nil
             }
    end

    test "a refresh_issued event carries bearer sender metadata" do
      code_store = start_code_store("oc_user-1", ["read", "offline_access"])
      refresh_store = start_refresh_store()
      config = config(code_store: code_store, refresh_store: refresh_store)

      request =
        request(config,
          grant_type: "authorization_code",
          params: %{
            "code" => Process.get(:auth_code),
            "code_verifier" => @code_verifier,
            "redirect_uri" => @redirect_uri
          }
        )

      assert {:ok, response, events} = Token.issue(config, request)
      assert is_binary(response.refresh_token)

      assert [
               %Event{name: :token_issued},
               %Event{name: :refresh_issued, grant_type: "authorization_code"} = event
             ] = events

      assert event.metadata == %{
               client_ip: "203.0.113.7",
               token_type: "Bearer",
               sender_constraint: :none,
               cnf: nil
             }
    end
  end

  describe "refresh_token grant (RFC 6749 §6)" do
    test "a DPoP refresh_rotated event carries the token type and jkt" do
      {proof, jkt} = dpop_proof_and_jkt()
      refresh_store = start_refresh_store()

      {:ok, %{token: refresh_token}} =
        Attesto.RefreshToken.issue(refresh_store, %{
          subject: "oc_user-1",
          scope: ["read"],
          client_id: "client-1",
          dpop_jkt: jkt
        })

      config =
        config(
          refresh_store: refresh_store,
          dpop_enabled: true,
          replay_check: fn _key, _ttl -> :ok end
        )

      public_client = Map.put(@client, :public?, true)

      request =
        request(config,
          client: public_client,
          client_auth_method: :none,
          grant_type: "refresh_token",
          params: %{"refresh_token" => refresh_token},
          sender_constraint_input: %{
            dpop_proof: proof,
            mtls_cert_der: nil,
            http_uri: "https://issuer.example/oauth/token",
            http_method: "POST"
          }
        )

      assert {:ok, response, [%Event{name: :refresh_rotated} = event]} = Token.issue(config, request)
      assert response.token_type == "DPoP"
      assert is_binary(response.refresh_token)

      assert event.metadata == %{
               client_ip: "203.0.113.7",
               token_type: "DPoP",
               sender_constraint: :dpop,
               cnf: %{"jkt" => jkt}
             }
    end

    test "RFC 9470: a refresh preserves the ORIGINAL auth_time (never re-stamped)" do
      original_auth_time = 1_600_000_000
      refresh_store = start_refresh_store()

      {:ok, %{token: refresh_token}} =
        Attesto.RefreshToken.issue(refresh_store, %{
          subject: "oc_user-1",
          scope: ["read"],
          client_id: "client-1",
          acr: "phr",
          auth_time: original_auth_time
        })

      config = config(refresh_store: refresh_store)
      request = request(config, grant_type: "refresh_token", params: %{"refresh_token" => refresh_token})

      assert {:ok, response, _} = Token.issue(config, request)
      # The refreshed access token reports the original authentication event,
      # not "now" — a refresh cannot launder a one-time strong auth into
      # perpetual freshness.
      assert claim!(response.access_token, "acr") == "phr"
      assert claim!(response.access_token, "auth_time") == original_auth_time
    end
  end

  describe "RFC 9470 step-up authentication context" do
    test "the authorization_code grant mints acr/auth_time from the code's claims" do
      auth_time = 1_700_000_000
      code_store = start_code_store_with_auth_context("oc_user-1", ["read"], "phr", auth_time)
      config = config(code_store: code_store)

      request =
        request(config,
          grant_type: "authorization_code",
          params: %{
            "code" => Process.get(:auth_code),
            "code_verifier" => @code_verifier,
            "redirect_uri" => @redirect_uri
          }
        )

      assert {:ok, response, _} = Token.issue(config, request)
      assert claim!(response.access_token, "acr") == "phr"
      assert claim!(response.access_token, "auth_time") == auth_time
    end

    test "a machine grant (client_credentials) mints no acr/auth_time" do
      config = config()
      request = request(config, params: %{"scope" => "read"})

      assert {:ok, response, _} = Token.issue(config, request)
      refute claim!(response.access_token, "acr")
      refute claim!(response.access_token, "auth_time")
    end
  end

  describe "token exchange grant (RFC 8693)" do
    test "a token_exchange token_issued event carries bearer sender metadata" do
      config = config()
      subject_request = request(config, params: %{"scope" => "read write"})
      assert {:ok, subject_response, [%Event{name: :token_issued}]} = Token.issue(config, subject_request)

      exchange_request =
        request(config,
          grant_type: @grant_token_exchange,
          params: %{
            "subject_token" => subject_response.access_token,
            "subject_token_type" => @subject_token_type_access_token,
            "scope" => "read"
          }
        )

      assert {:ok, response, [%Event{name: :token_issued} = event]} =
               Token.issue(config, exchange_request)

      assert response.token_type == "Bearer"
      assert response.issued_token_type == @subject_token_type_access_token
      assert response.scope == "read"
      assert event.grant_type == "token_exchange"

      assert event.metadata == %{
               client_ip: "203.0.113.7",
               token_type: "Bearer",
               sender_constraint: :none,
               cnf: nil
             }
    end

    test "RFC 8707: token exchange cannot widen audience beyond the subject token" do
      a = "https://api.example/a"
      b = "https://api.example/b"
      config = config(resource_indicators: [allowed_resources: [a, b]])

      # Subject token audienced to the AS audience + resource A (so it verifies
      # AND carries A); it was never granted resource B.
      subject_request =
        request(config, params: %{"scope" => "read", "resource" => ["https://issuer.example", a]})

      assert {:ok, subject_response, _} = Token.issue(config, subject_request)

      exchange = fn resource ->
        request(config,
          grant_type: @grant_token_exchange,
          params: %{
            "subject_token" => subject_response.access_token,
            "subject_token_type" => @subject_token_type_access_token,
            "scope" => "read",
            "resource" => resource
          }
        )
      end

      # A is within the subject token's aud → honored.
      assert {:ok, ok_response, _} = Token.issue(config, exchange.(a))
      assert aud!(ok_response.access_token) == a

      # B is an allow-listed server resource but NOT in the subject token's aud,
      # so exchanging for it would widen authority — refused.
      assert {:error, %OAuthError{error: :invalid_target}, _} = Token.issue(config, exchange.(b))
    end
  end

  describe "denials (RFC 6749 §5.2)" do
    test "an unsupported grant type returns an OAuthError and a :token_denied event" do
      config = config()
      request = request(config, grant_type: "password", params: %{"scope" => "read"})

      assert {:error, %OAuthError{error: :unsupported_grant_type, status: 400}, events} =
               Token.issue(config, request)

      assert [%Event{name: :token_denied} = event] = events
      assert event.client_id == "client-1"
      assert event.grant_type == "password"
      assert event.scope == "read"
      assert event.result == "unsupported_grant_type"
      assert event.metadata.client_id == "client-1"
      assert event.metadata.reason == :unsupported_grant_type
      assert event.metadata.error == "unsupported_grant_type"
      assert event.metadata.http_status == 400
      assert event.metadata.client_ip == "203.0.113.7"
      assert event.metadata.token_type == "Bearer"
      assert event.metadata.sender_constraint == :none
      assert event.metadata.cnf == nil
    end

    test "an invalid scope decision (RFC 6749 §5.2) surfaces invalid_scope" do
      config = config(authorize_scope: fn _client, _requested -> {:error, :invalid_scope} end)
      request = request(config, params: %{"scope" => "admin"})

      assert {:error, %OAuthError{error: :invalid_scope}, [event]} = Token.issue(config, request)
      assert event.name == :token_denied
      assert event.result == "invalid_scope"
      assert event.scope == "admin"
      assert event.metadata.client_id == "client-1"
      assert event.metadata.reason == :invalid_scope
      assert event.metadata.token_type == "Bearer"
      assert event.metadata.sender_constraint == :none
      assert event.metadata.cnf == nil
    end

    test "the request-derived client_id is the denial fallback when no :client_id callback" do
      config = config(client_id: nil)

      request =
        request(config,
          grant_type: "password",
          request_client_id: "from-request"
        )

      assert {:error, %OAuthError{}, [event]} = Token.issue(config, request)
      assert event.client_id == "from-request"
    end
  end

  describe "registered grant types (RFC 6749 §4)" do
    test "a grant the client is not registered for is rejected before dispatch" do
      config = config(client_grant_types: fn _client -> ["authorization_code"] end)
      request = request(config, grant_type: "client_credentials")

      assert {:error, %OAuthError{error: :unsupported_grant_type}, [event]} =
               Token.issue(config, request)

      assert event.name == :token_denied
    end

    test "a registered grant proceeds to dispatch and mints a token" do
      config = config(client_grant_types: fn _client -> ["client_credentials"] end)
      request = request(config, params: %{"scope" => "read"})

      assert {:ok, %{access_token: token}, [%Event{name: :token_issued}]} =
               Token.issue(config, request)

      assert is_binary(token)
    end
  end

  # The token core's `@error_*` codes are compile-time atoms passed straight to
  # `OAuthError.new/3`. They were once strings resolved with
  # `String.to_existing_atom/1` at runtime, which raises `ArgumentError` for a
  # code whose atom does not yet exist - turning a clean RFC 6749 §5.2 body into
  # a 500. These tests pin that the resolution is now total by construction.
  describe "RFC 6749 §5.2 error-code resolution is total (no String.to_existing_atom round-trip)" do
    test "an unsupported grant_type returns a clean OAuthError, never raising" do
      config = config()
      request = request(config, grant_type: "totally-unsupported-grant", params: %{})

      # No `assert_raise ArgumentError` escape hatch: the call returns the typed
      # error directly.
      assert {:error, %OAuthError{error: :unsupported_grant_type, status: 400}, _events} =
               Token.issue(config, request)
    end

    test "every emittable error code is a compile-time atom" do
      # The wire codes the token endpoint can emit (RFC 6749 §5.2). Each must
      # already exist as an atom at compile time so no runtime resolution is
      # needed; `OAuthError.new/3` requires an atom and accepts each.
      for code <- [
            :invalid_request,
            :invalid_client,
            :invalid_grant,
            :invalid_scope,
            :unsupported_grant_type
          ] do
        assert is_atom(code)
        assert %OAuthError{error: ^code} = OAuthError.new(code, "desc", status: 400)
      end
    end

    test "the old String.to_existing_atom mechanism genuinely raises on an unknown code" do
      # A string whose atom is deliberately never created anywhere in the build.
      # The retired `error_code/1` did exactly this round-trip; it would have
      # raised here, proving the latent 500 was real rather than hypothetical.
      assert_raise ArgumentError, fn ->
        String.to_existing_atom("attesto_never_created_error_code_xyz")
      end
    end
  end
end
