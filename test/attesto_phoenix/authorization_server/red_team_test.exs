defmodule AttestoPhoenix.AuthorizationServer.RedTeamTest do
  @moduledoc """
  Adversarial regression suite for token grants, DPoP/mTLS sender-constraint
  downgrades, client authentication (`private_key_jwt`, `attest_jwt_client_auth`),
  CIBA push-mode token-endpoint redemption, and dynamic client registration
  privilege escalation and URI validation.
  """
  use ExUnit.Case, async: false

  alias Attesto.CIBAStore.ETS
  alias Attesto.CodeStore.ETS, as: CodeETS
  alias Attesto.RefreshStore.ETS, as: RefreshETS
  alias AttestoPhoenix.AuthorizationServer.{Registration, Token}
  alias AttestoPhoenix.AuthorizationServer.Token.Request
  alias AttestoPhoenix.{ClientAuthentication, Config, Event, OAuthError}

  @signing_pem JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_pem() |> elem(1)
  @issuer "https://issuer.example"

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

  @client_kind Attesto.PrincipalKind.new("client", "oc_", required_claims: [{"client_id", :non_empty_string}])
  @client %{id: "client-1", public?: false}
  @public_client %{id: "client-1", public?: true}

  setup do
    Application.put_env(:attesto_phoenix, __MODULE__.Keystore, signing_pem: @signing_pem)
    on_exit(fn -> Application.delete_env(:attesto_phoenix, __MODULE__.Keystore) end)
    :ok
  end

  defp config(overrides) do
    [
      issuer: @issuer,
      audience: @issuer,
      keystore: __MODULE__.Keystore,
      repo: StubRepo,
      load_client: fn
        "client-1" -> {:ok, @client}
        _ -> {:error, :not_found}
      end,
      verify_client_secret: fn _client, given -> given == "secret-1" end,
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

  defp start_stores do
    for store <- [CodeETS, RefreshETS] do
      case start_supervised(store) do
        {:ok, _pid} -> :ok
        {:error, {:already_started, _pid}} -> :ok
      end

      store.reset()
    end

    :ok
  end

  defp dpop_proof_and_jkt(htu \\ "https://issuer.example/oauth/token") do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, public_map} = JOSE.JWK.to_public_map(jwk)

    payload = %{
      "htm" => "POST",
      "htu" => htu,
      "iat" => System.system_time(:second),
      "jti" => 16 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
    }

    header = %{"alg" => "ES256", "typ" => "dpop+jwt", "jwk" => public_map}
    {_, compact} = jwk |> JOSE.JWT.sign(header, payload) |> JOSE.JWS.compact()
    {compact, Attesto.DPoP.compute_jkt(public_map)}
  end

  defp self_signed_cert_der do
    %{cert: der} = :public_key.pkix_test_root_cert(~c"CN=attesto-redteam", [])
    der
  end

  defp request(config, overrides) do
    fields =
      [
        config: config,
        client: @client,
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
        request_client_id: "client-1"
      ]
      |> Keyword.merge(overrides)

    struct!(Request, fields)
  end

  describe "token grant reuse and rotation grace-window binding attacks" do
    test "retrying a consumed refresh token within the grace window with a modified scope, resource, or DPoP key triggers reuse revocation" do
      start_stores()
      resource_a = "https://api.example/a"
      resource_b = "https://api.example/b"
      {proof_1, jkt_1} = dpop_proof_and_jkt()
      {proof_2, _jkt_2} = dpop_proof_and_jkt()

      {:ok, initial} =
        Attesto.RefreshToken.issue(RefreshETS, %{
          subject: "oc_user-1",
          scope: ["read", "write"],
          resource: [resource_a, resource_b],
          client_id: "client-1",
          issuer: @issuer,
          dpop_jkt: jkt_1
        })

      config =
        config(
          refresh_store: RefreshETS,
          refresh_token_rotation_grace_seconds: 30,
          dpop_enabled: true,
          replay_check: fn _key, _ttl -> :ok end,
          resource_indicators: [allowed_resources: [resource_a, resource_b]]
        )

      first_req =
        request(config,
          client: @public_client,
          client_auth_method: :none,
          grant_type: "refresh_token",
          params: %{
            "refresh_token" => initial.token,
            "scope" => "read",
            "resource" => resource_a
          },
          sender_constraint_input: %{
            dpop_proof: proof_1,
            mtls_cert_der: nil,
            http_uri: "https://issuer.example/oauth/token",
            http_method: "POST"
          }
        )

      assert {:ok, rotated, [%Event{name: :refresh_rotated}]} = Token.issue(config, first_req)

      # Modified scope during the grace window must NOT replay the cached successor;
      # it must trigger reuse detection and revoke the successor family.
      scope_mismatch_req =
        %{first_req | params: Map.put(first_req.params, "scope", "write")}

      assert {:error, %OAuthError{error: :invalid_grant},
              [%Event{name: :refresh_reuse_detected}, %Event{name: :token_denied}]} =
               Token.issue(config, scope_mismatch_req)

      assert :error = RefreshETS.get(Attesto.Secret.hash(rotated.refresh_token))

      # Issue a second family and verify a different DPoP key during the grace window also revokes.
      {:ok, second} =
        Attesto.RefreshToken.issue(RefreshETS, %{
          subject: "oc_user-1",
          scope: ["read"],
          resource: [resource_a],
          client_id: "client-1",
          issuer: @issuer,
          dpop_jkt: jkt_1
        })

      second_req =
        request(config,
          client: @public_client,
          client_auth_method: :none,
          grant_type: "refresh_token",
          params: %{"refresh_token" => second.token, "scope" => "read", "resource" => resource_a},
          sender_constraint_input: %{
            dpop_proof: proof_1,
            mtls_cert_der: nil,
            http_uri: "https://issuer.example/oauth/token",
            http_method: "POST"
          }
        )

      assert {:ok, rotated_2, _} = Token.issue(config, second_req)

      wrong_dpop_req =
        %{
          second_req
          | sender_constraint_input: %{second_req.sender_constraint_input | dpop_proof: proof_2}
        }

      assert {:error, %OAuthError{error: :invalid_grant}, _} = Token.issue(config, wrong_dpop_req)
      assert :error = RefreshETS.get(Attesto.Secret.hash(rotated_2.refresh_token))
    end
  end

  describe "DPoP + mTLS dual-binding downgrade and malformed htu port attempts" do
    test "a refresh token bound to a DPoP key refuses an mTLS-only or unbound refresh" do
      start_stores()
      {_proof, jkt} = dpop_proof_and_jkt()
      cert_der = self_signed_cert_der()

      {:ok, initial} =
        Attesto.RefreshToken.issue(RefreshETS, %{
          subject: "oc_user-1",
          scope: ["read"],
          client_id: "client-1",
          issuer: @issuer,
          dpop_jkt: jkt
        })

      config =
        config(
          refresh_store: RefreshETS,
          dpop_enabled: true,
          mtls_enabled: true,
          replay_check: fn _key, _ttl -> :ok end
        )

      mtls_only_req =
        request(config,
          client: @public_client,
          client_auth_method: :none,
          grant_type: "refresh_token",
          params: %{"refresh_token" => initial.token},
          sender_constraint_input: %{
            dpop_proof: nil,
            mtls_cert_der: cert_der,
            http_uri: "https://issuer.example/oauth/token",
            http_method: "POST"
          }
        )

      assert {:error, %OAuthError{error: :invalid_grant}, _} = Token.issue(config, mtls_only_req)
    end

    test "rejects DPoP proofs whose htu contains a non-numeric, empty, or out-of-range port" do
      config =
        config(
          dpop_enabled: true,
          replay_check: fn _key, _ttl -> :ok end
        )

      for bad_htu <- [
            "https://issuer.example:443xyz/oauth/token",
            "https://issuer.example:99999/oauth/token",
            "https://issuer.example:/oauth/token"
          ] do
        {proof, _jkt} = dpop_proof_and_jkt(bad_htu)

        req =
          request(config,
            params: %{"scope" => "read"},
            sender_constraint_input: %{
              dpop_proof: proof,
              mtls_cert_der: nil,
              http_uri: "https://issuer.example/oauth/token",
              http_method: "POST"
            }
          )

        assert {:error, %OAuthError{error: :invalid_dpop_proof}, _} = Token.issue(config, req)
      end
    end
  end

  describe "wallet attestation instance key substitution and multi-auth confusion" do
    test "refreshing an attestation-bound refresh token with a different wallet instance key is refused" do
      start_stores()
      {_proof_1, att_jkt_1} = dpop_proof_and_jkt()
      {_proof_2, att_jkt_2} = dpop_proof_and_jkt()

      {:ok, initial} =
        Attesto.RefreshToken.issue(RefreshETS, %{
          subject: "oc_user-1",
          scope: ["read"],
          client_id: "client-1",
          issuer: @issuer,
          attestation_jkt: att_jkt_1
        })

      config = config(refresh_store: RefreshETS)

      substituted_req =
        request(config,
          client: @public_client,
          client_auth_method: :attest_jwt_client_auth,
          attestation_jkt: att_jkt_2,
          grant_type: "refresh_token",
          params: %{"refresh_token" => initial.token}
        )

      assert {:error, %OAuthError{error: :invalid_grant}, _} = Token.issue(config, substituted_req)
    end

    test "supplying both HTTP Basic credentials and client_assertion is refused as multiple auth methods" do
      config = config(replay_check: fn _key, _ttl -> :ok end)
      basic = "Basic " <> Base.encode64("client-1:secret-1")

      conn =
        Plug.Test.conn(:post, "/oauth/token", %{
          "grant_type" => "client_credentials",
          "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          "client_assertion" => "eyJhbGciOiJFUzI1NiJ9.e30.e30"
        })
        |> Plug.Conn.put_req_header("authorization", basic)
        |> Plug.Conn.put_private(:attesto_phoenix_config, config)

      assert {:error, %OAuthError{error: :invalid_request, error_description: "multiple client authentication methods"}} =
               ClientAuthentication.authenticate_request(conn, conn.params, config, :token)
    end
  end

  describe "CIBA push-mode token endpoint redemption attempt" do
    test "an approved push-mode CIBA request cannot be redeemed at the token endpoint" do
      case start_supervised(ETS) do
        {:ok, _pid} -> :ok
        {:error, {:already_started, _pid}} -> :ok
      end

      ETS.reset()

      config =
        config(
          ciba_store: ETS,
          ciba: [enabled: true, interval_seconds: 0],
          authenticate_ciba_user: fn _req -> {:ok, "user-1"} end,
          replay_check: fn _key, _ttl -> :ok end
        )

      push_req = %Attesto.CIBA.Request{
        client_id: "client-1",
        delivery_mode: :push,
        client_notification_token: "notif-token-123",
        hint: {:login_hint, "alice@example.test"},
        scope: ["openid"]
      }

      {:ok, %{auth_req_id: auth_req_id}} =
        Attesto.CIBA.issue(ETS, push_req, %{subject: "user-1"}, [])

      {:ok, _} = Attesto.CIBA.approve(ETS, auth_req_id, %{subject: "user-1"})

      token_req =
        request(config,
          grant_type: "urn:openid:params:grant-type:ciba",
          params: %{"auth_req_id" => auth_req_id}
        )

      assert {:error, %OAuthError{error: :unauthorized_client}, _} = Token.issue(config, token_req)
    end
  end

  describe "Dynamic Client Registration privilege escalation and URI validation" do
    defp reg_config do
      config(
        registration_enabled: true,
        register_client: fn attrs -> {:ok, attrs} end
      )
    end

    test "refuses unauthenticated registration of privileged grant types (token-exchange, jwt-bearer, ciba)" do
      for privileged_grant <- [
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "urn:openid:params:grant-type:ciba"
          ] do
        raw = %{
          "redirect_uris" => ["https://client.example/cb"],
          "grant_types" => ["authorization_code", privileged_grant]
        }

        {:ok, req} = Registration.Request.from_params(raw)

        assert {:error, %OAuthError{error: :invalid_client_metadata}} =
                 Registration.register(reg_config(), req)
      end
    end

    test "refuses redirect_uris carrying reserved OAuth response query parameters, fragments, empty ports, or parser-ambiguous authorities" do
      for bad_uri <- [
            "https://client.example/cb?code=injected",
            "https://client.example/cb?state=fixed",
            "https://client.example/cb?error=access_denied",
            "https://client.example/cb?iss=https://evil.example",
            "https://client.example/cb?response=jarm",
            "https://client.example/cb#fragment",
            "https://client.example:/cb",
            "https://client.example:99999/cb",
            "https://evil.example\\@client.example/cb"
          ] do
        raw = %{"redirect_uris" => [bad_uri]}
        {:ok, req} = Registration.Request.from_params(raw)

        assert {:error, %OAuthError{error: :invalid_redirect_uri}} =
                 Registration.register(reg_config(), req),
               "expected #{inspect(bad_uri)} to be rejected"
      end
    end

    test "refuses empty or out-of-range ports in jwks_uri, backchannel_logout_uri, and post_logout_redirect_uris" do
      for bad_uri <- [
            "https://client.example:/jwks.json",
            "https://client.example:99999/jwks.json",
            "https://client.example:443xyz/jwks.json"
          ] do
        for field <- ["jwks_uri", "backchannel_logout_uri"] do
          raw = %{
            "redirect_uris" => ["https://client.example/cb"],
            "token_endpoint_auth_method" => "private_key_jwt",
            field => bad_uri
          }

          {:ok, req} = Registration.Request.from_params(raw)

          assert {:error, %OAuthError{error: :invalid_client_metadata}} =
                   Registration.register(reg_config(), req),
                 "expected #{field}=#{inspect(bad_uri)} to be rejected"
        end
      end

      raw = %{
        "redirect_uris" => ["https://client.example/cb"],
        "post_logout_redirect_uris" => ["https://client.example:/logout"]
      }

      {:ok, req} = Registration.Request.from_params(raw)

      assert {:error, %OAuthError{error: :invalid_client_metadata}} =
               Registration.register(reg_config(), req)
    end
  end
end
