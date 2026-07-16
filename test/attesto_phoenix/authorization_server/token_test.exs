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
      assert claim!(response.access_token, "client_id") == "client-1"
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
    test "one authenticated client_id snapshot binds code, ID Token, refresh family, and rotation" do
      code_store = start_code_store("oc_user-1", ["openid", "offline_access"])
      refresh_store = start_refresh_store()

      config =
        config(
          code_store: code_store,
          refresh_store: refresh_store,
          client_id: nil
        )

      code_request =
        request(config,
          request_client_id: "client-1",
          grant_type: "authorization_code",
          params: %{
            "code" => Process.get(:auth_code),
            "code_verifier" => @code_verifier,
            "redirect_uri" => @redirect_uri
          }
        )

      assert {:ok, response, _events} = Token.issue(config, code_request)
      assert claim!(response.access_token, "client_id") == "client-1"
      assert claim!(response.id_token, "aud") == "client-1"
      assert is_binary(response.refresh_token)

      refresh_request =
        request(config,
          request_client_id: "client-1",
          grant_type: "refresh_token",
          params: %{"refresh_token" => response.refresh_token}
        )

      assert {:ok, refreshed, [%Event{name: :refresh_rotated, client_id: "client-1"}]} =
               Token.issue(config, refresh_request)

      assert claim!(refreshed.access_token, "client_id") == "client-1"
    end

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

  describe "device authorization grant (RFC 8628 §3.4 / §3.5)" do
    setup do
      start_supervised!(Attesto.DeviceCodeStore.ETS)
      Attesto.DeviceCodeStore.ETS.reset()
      :ok
    end

    defp device_config(overrides \\ []) do
      config(
        [
          device_code_store: Attesto.DeviceCodeStore.ETS,
          device_authorization: [enabled: true, poll_interval_seconds: 0],
          authorize_scope: fn _client, requested -> {:ok, requested} end
        ] ++ overrides
      )
    end

    defp issue_device_code(scope \\ ["read"]) do
      {:ok, issued} =
        Attesto.DeviceCode.issue(Attesto.DeviceCodeStore.ETS, %{client_id: "client-1", scope: scope})

      issued
    end

    defp device_request(config, device_code) do
      request(config,
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        params: %{"device_code" => device_code}
      )
    end

    test "pending → authorization_pending (NOT invalid_grant)" do
      config = device_config()
      %{device_code: dc} = issue_device_code()

      assert {:error, %OAuthError{error: :authorization_pending}, _} = Token.issue(config, device_request(config, dc))
    end

    test "denied → access_denied" do
      config = device_config()
      %{device_code: dc, user_code: uc} = issue_device_code()
      :ok = Attesto.DeviceCode.deny(Attesto.DeviceCodeStore.ETS, uc)

      assert {:error, %OAuthError{error: :access_denied}, _} = Token.issue(config, device_request(config, dc))
    end

    test "an unknown device_code → invalid_grant" do
      config = device_config()
      assert {:error, %OAuthError{error: :invalid_grant}, _} = Token.issue(config, device_request(config, "nope"))
    end

    test "approved → mints an access token with the granted scope" do
      config = device_config()
      %{device_code: dc, user_code: uc} = issue_device_code(["read"])
      :ok = Attesto.DeviceCode.approve(Attesto.DeviceCodeStore.ETS, uc, %{subject: "user-1", scope: ["read"]})

      assert {:ok, response, [%Event{name: :token_issued, grant_type: "device_code"}]} =
               Token.issue(config, device_request(config, dc))

      assert is_binary(response.access_token)
      assert response.scope == "read"
      assert claim!(response.access_token, "sub") == "oc_user-1"
    end

    test "an authenticated snapshot redeems without a host client_id callback" do
      config = device_config(client_id: nil)
      %{device_code: dc, user_code: uc} = issue_device_code(["read"])
      :ok = Attesto.DeviceCode.approve(Attesto.DeviceCodeStore.ETS, uc, %{subject: "user-1", scope: ["read"]})

      request = %{device_request(config, dc) | request_client_id: "client-1"}

      assert {:ok, response, [%Event{client_id: "client-1"}]} = Token.issue(config, request)
      assert claim!(response.access_token, "client_id") == "client-1"
    end

    test "a consumed device_code cannot be redeemed twice" do
      config = device_config()
      %{device_code: dc, user_code: uc} = issue_device_code()
      :ok = Attesto.DeviceCode.approve(Attesto.DeviceCodeStore.ETS, uc, %{subject: "user-1", scope: ["read"]})

      assert {:ok, _, _} = Token.issue(config, device_request(config, dc))
      assert {:error, %OAuthError{error: :invalid_grant}, _} = Token.issue(config, device_request(config, dc))
    end
  end

  describe "CIBA grant (OpenID Connect CIBA Core 1.0 §10.1 / §11)" do
    setup do
      start_supervised!(Attesto.CIBAStore.ETS)
      Attesto.CIBAStore.ETS.reset()
      :ok
    end

    defp ciba_config(overrides \\ []) do
      config(
        [
          ciba_store: Attesto.CIBAStore.ETS,
          ciba: [enabled: true, interval_seconds: 0],
          # Required by config validation when CIBA is enabled (the token
          # endpoint itself never calls it - it is the backchannel endpoint's).
          authenticate_ciba_user: fn _request -> {:ok, "user-1"} end,
          authorize_scope: fn _client, requested -> {:ok, requested} end
        ] ++ overrides
      )
    end

    defp issue_ciba(scope \\ ["openid"], opts \\ []) do
      req = %Attesto.CIBA.Request{
        client_id: "client-1",
        delivery_mode: :poll,
        hint: {:login_hint, "alice@example.test"},
        scope: scope
      }

      {:ok, issued} = Attesto.CIBA.issue(Attesto.CIBAStore.ETS, req, %{subject: "user-1"}, opts)
      issued
    end

    defp ciba_request(config, auth_req_id) do
      request(config,
        grant_type: "urn:openid:params:grant-type:ciba",
        params: %{"auth_req_id" => auth_req_id}
      )
    end

    test "pending → authorization_pending (NOT invalid_grant)" do
      config = ciba_config()
      %{auth_req_id: arid} = issue_ciba()

      assert {:error, %OAuthError{error: :authorization_pending}, _} = Token.issue(config, ciba_request(config, arid))
    end

    test "denied → access_denied" do
      config = ciba_config()
      %{auth_req_id: arid} = issue_ciba()
      {:ok, _} = Attesto.CIBA.deny(Attesto.CIBAStore.ETS, arid)

      assert {:error, %OAuthError{error: :access_denied}, _} = Token.issue(config, ciba_request(config, arid))
    end

    test "expired → expired_token" do
      config = ciba_config()
      # Issue with a 1s lifetime already elapsed at redemption.
      %{auth_req_id: arid} = issue_ciba(["openid"], expires_in: 1, now: System.system_time(:second) - 10)

      assert {:error, %OAuthError{error: :expired_token}, _} = Token.issue(config, ciba_request(config, arid))
    end

    test "an unknown auth_req_id → invalid_grant" do
      config = ciba_config()
      assert {:error, %OAuthError{error: :invalid_grant}, _} = Token.issue(config, ciba_request(config, "nope"))
    end

    test "approved → mints an access token AND an ID Token carrying acr/auth_time" do
      config = ciba_config()
      %{auth_req_id: arid} = issue_ciba(["openid", "profile"])
      auth_time = System.system_time(:second)

      {:ok, _} =
        Attesto.CIBA.approve(Attesto.CIBAStore.ETS, arid, %{
          subject: "user-1",
          acr: "urn:mace:incommon:iap:silver",
          scope: ["openid", "profile"],
          auth_time: auth_time
        })

      assert {:ok, response, [%Event{name: :token_issued, grant_type: "ciba"}]} =
               Token.issue(config, ciba_request(config, arid))

      assert is_binary(response.access_token)
      assert is_binary(response.id_token)
      assert response.scope == "openid profile"
      # OIDC Core §2: the ID Token carries the authenticated subject + auth ctx.
      assert claim!(response.id_token, "sub") == "user-1"
      assert claim!(response.id_token, "acr") == "urn:mace:incommon:iap:silver"
      assert claim!(response.id_token, "auth_time") == auth_time
      # RFC 9470: the access token carries acr for step-up enforcement.
      assert claim!(response.access_token, "acr") == "urn:mace:incommon:iap:silver"
    end

    test "an authenticated snapshot binds CIBA access and ID Tokens without a host callback" do
      config = ciba_config(client_id: nil)
      %{auth_req_id: arid} = issue_ciba(["openid"])
      {:ok, _} = Attesto.CIBA.approve(Attesto.CIBAStore.ETS, arid, %{subject: "user-1", scope: ["openid"]})

      request = %{ciba_request(config, arid) | request_client_id: "client-1"}

      assert {:ok, response, [%Event{client_id: "client-1"}]} = Token.issue(config, request)
      assert claim!(response.access_token, "client_id") == "client-1"
      assert claim!(response.id_token, "aud") == "client-1"
    end

    test "a consumed auth_req_id cannot be redeemed twice (single use)" do
      config = ciba_config()
      %{auth_req_id: arid} = issue_ciba()
      {:ok, _} = Attesto.CIBA.approve(Attesto.CIBAStore.ETS, arid, %{subject: "user-1", scope: ["openid"]})

      assert {:ok, _, _} = Token.issue(config, ciba_request(config, arid))
      assert {:error, %OAuthError{error: :invalid_grant}, _} = Token.issue(config, ciba_request(config, arid))
    end

    test "a different client cannot redeem another client's auth_req_id → invalid_grant" do
      config = ciba_config()
      %{auth_req_id: arid} = issue_ciba()
      {:ok, _} = Attesto.CIBA.approve(Attesto.CIBAStore.ETS, arid, %{subject: "user-1", scope: ["openid"]})

      # A request authenticated as a different client (client_id "client-2").
      other =
        request(config,
          grant_type: "urn:openid:params:grant-type:ciba",
          params: %{"auth_req_id" => arid},
          client: %{id: "client-2", public?: false}
        )

      assert {:error, %OAuthError{error: :invalid_grant}, _} = Token.issue(config, other)
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
      assert aud!(response.access_token) == config.audience
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

      # A normal RFC 8707 subject token carries only resource A. Subject-token
      # verification must recognize that trusted audience before enforcing that
      # an exchange cannot widen it to resource B.
      subject_request = request(config, params: %{"scope" => "read", "resource" => a})

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

      # Omitting resource preserves the subject token's audience instead of
      # silently falling back to the server default.
      inherited =
        request(config,
          grant_type: @grant_token_exchange,
          params: %{
            "subject_token" => subject_response.access_token,
            "subject_token_type" => @subject_token_type_access_token,
            "scope" => "read"
          }
        )

      assert {:ok, inherited_response, _} = Token.issue(config, inherited)
      assert aud!(inherited_response.access_token) == a

      # B is an allow-listed server resource but NOT in the subject token's aud,
      # so exchanging for it would widen authority — refused.
      assert {:error, %OAuthError{error: :invalid_target}, _} = Token.issue(config, exchange.(b))
    end

    test "an inherited subject audience is re-authorized for the exchanger" do
      resource = "https://api.example/client-1-only"
      subject_client = %{id: "client-1", public?: false}
      exchanger = %{id: "client-2", public?: false}

      config =
        config(
          load_client: fn
            "client-1" -> {:ok, subject_client}
            "client-2" -> {:ok, exchanger}
            _other -> {:error, :not_found}
          end,
          resource_indicators: [
            allowed_resources_for: fn
              %{id: "client-1"} -> [resource]
              _other -> []
            end
          ]
        )

      subject_request =
        request(config,
          client: subject_client,
          request_client_id: "client-1",
          params: %{"scope" => "read", "resource" => resource}
        )

      assert {:ok, subject_response, _events} = Token.issue(config, subject_request)

      exchange_request =
        request(config,
          client: exchanger,
          request_client_id: "client-2",
          grant_type: @grant_token_exchange,
          params: %{
            "subject_token" => subject_response.access_token,
            "subject_token_type" => @subject_token_type_access_token,
            "scope" => "read"
          }
        )

      assert {:error, %OAuthError{error: :invalid_target}, _events} = Token.issue(config, exchange_request)
    end

    test "omitting resource preserves a subject token's complete audience array" do
      a = "https://api.example/a"
      b = "https://api.example/b"
      config = config(resource_indicators: [allowed_resources: [a, b]])

      subject_request = request(config, params: %{"scope" => "read", "resource" => [a, b]})
      assert {:ok, subject_response, _events} = Token.issue(config, subject_request)

      exchange_request =
        request(config,
          grant_type: @grant_token_exchange,
          params: %{
            "subject_token" => subject_response.access_token,
            "subject_token_type" => @subject_token_type_access_token,
            "scope" => "read"
          }
        )

      assert {:ok, response, _events} = Token.issue(config, exchange_request)
      assert aud!(response.access_token) == [a, b]
    end

    test "an exchanged token identifies the authenticated exchanger, not the subject-token client" do
      resource = "https://api.example/exchange"
      subject_client = %{id: "client-1", public?: false}
      exchanger = %{id: "client-2", public?: false}

      config =
        config(
          load_client: fn
            "client-1" -> {:ok, subject_client}
            "client-2" -> {:ok, exchanger}
            _other -> {:error, :not_found}
          end,
          resource_indicators: [allowed_resources_for: fn _client -> [resource] end]
        )

      subject_request =
        request(config,
          client: subject_client,
          request_client_id: "client-1",
          params: %{"scope" => "read", "resource" => resource}
        )

      assert {:ok, subject_response, _events} = Token.issue(config, subject_request)
      assert claim!(subject_response.access_token, "client_id") == "client-1"

      exchange_request =
        request(config,
          client: exchanger,
          request_client_id: "client-2",
          grant_type: @grant_token_exchange,
          params: %{
            "subject_token" => subject_response.access_token,
            "subject_token_type" => @subject_token_type_access_token,
            "scope" => "read",
            "resource" => resource
          }
        )

      assert {:ok, response, _events} = Token.issue(config, exchange_request)
      assert claim!(response.access_token, "client_id") == "client-2"

      assert {:ok, %{"client_id" => "client-2", "aud" => ^resource}} =
               Attesto.Token.verify(Config.to_attesto_config(config), response.access_token,
                 trusted_audiences: AttestoPhoenix.ResourceAudiencePolicy.resolver(config)
               )
    end
  end

  describe "denials (RFC 6749 §5.2)" do
    test "a populated authenticated snapshot is never recomputed for denial audit" do
      test_pid = self()

      config =
        config(
          client_id: fn _client ->
            send(test_pid, :client_id_callback_invoked)
            "relabeled-client"
          end
        )

      request =
        request(config,
          request_client_id: "client-1",
          grant_type: "password",
          params: %{"scope" => "read"}
        )

      assert {:error, %OAuthError{}, [%Event{client_id: "client-1", metadata: %{client_id: "client-1"}}]} =
               Token.issue(config, request)

      refute_received :client_id_callback_invoked
    end

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

    test "the protocol injects the authenticated client_id when the principal builder omits it" do
      authenticated_client_id = "authenticated-client"

      config =
        config(
          client_id: nil,
          build_principal: fn _client, subject, scope ->
            %{kind: "client", sub: ensure_sub(subject), scopes: scope, claims: %{}}
          end
        )

      request =
        request(config,
          params: %{"scope" => "read"},
          request_client_id: authenticated_client_id
        )

      assert {:ok, response, _events} = Token.issue(config, request)
      assert claim!(response.access_token, "client_id") == authenticated_client_id
    end

    test "a principal builder cannot replace the authenticated client_id" do
      config =
        config(
          build_principal: fn _client, subject, scope ->
            %{
              kind: "client",
              sub: ensure_sub(subject),
              scopes: scope,
              claims: %{"client_id" => "different-client"}
            }
          end
        )

      request = request(config, params: %{"scope" => "read"}, request_client_id: "authenticated-client")

      assert {:error, %OAuthError{error: :invalid_request}, _events} = Token.issue(config, request)
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
