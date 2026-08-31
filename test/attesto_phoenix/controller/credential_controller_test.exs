defmodule AttestoPhoenix.Controller.CredentialControllerTest do
  @moduledoc false
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog
  import Plug.Conn
  import Plug.Test

  alias Attesto.CNonceStore.ETS, as: CNonceStore
  alias Attesto.{Mdoc, SdJwtVc, Token}
  alias Attesto.PreAuthorizedCodeStore.ETS
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Controller.CredentialController
  alias AttestoPhoenix.Plug.PutConfig

  @endpoint_path "/oauth/credential"
  @issuer "https://issuer.example"
  @default_client_id "test-client"
  @subject "ou_user-123"
  @configuration_id "UniversityDegreeCredential"
  @vct "https://credentials.example/UniversityDegreeCredential"
  @jwt_vc_configuration_id "UniversityDegreeCredentialJwtVc"
  @jwt_vc_credential_type "UniversityDegreeCredential"
  @mdoc_configuration_id "org.iso.18013.5.1.mDL"
  @mdoc_doc_type "org.iso.18013.5.1.mDL"
  @mdoc_namespace "org.iso.18013.5.1"
  @signing_pem JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_pem() |> elem(1)
  @rsa_signing_pem JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_pem() |> elem(1)
  @vc_signing_pem JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_pem() |> elem(1)
  @holder_key JOSE.JWK.generate_key({:ec, "P-256"})

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

  defmodule VcKeystore do
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

  defmodule InvalidCNonceStore do
    @moduledoc false

    def valid?(_nonce), do: return(Process.get({__MODULE__, :valid_result}, Process.get({__MODULE__, :result})))
    def consume(_nonce), do: return(Process.get({__MODULE__, :consume_result}))

    defp return({:raise, reason}), do: raise(RuntimeError, reason)
    defp return({:throw, reason}), do: throw(reason)
    defp return({:exit, reason}), do: exit(reason)
    defp return(result), do: result
  end

  defmodule CredentialRouter do
    @moduledoc false
    use Phoenix.Router
    use AttestoPhoenix.Router

    pipeline :attesto_phoenix_config do
      plug PutConfig, otp_app: :attesto_phoenix
    end

    scope "/" do
      attesto_routes(pipeline: :attesto_phoenix_config, credential_issuance: true)
    end
  end

  @user_kind Attesto.PrincipalKind.new("user", "ou_", required_claims: [{"client_id", :non_empty_string}])

  setup do
    Application.put_env(:attesto_phoenix, __MODULE__.Keystore, signing_pem: @signing_pem)
    Application.put_env(:attesto_phoenix, __MODULE__.VcKeystore, signing_pem: @vc_signing_pem)

    on_exit(fn ->
      Application.delete_env(:attesto_phoenix, __MODULE__.Keystore)
      Application.delete_env(:attesto_phoenix, __MODULE__.VcKeystore)
    end)

    start_supervised!(CNonceStore)
    CNonceStore.reset()
    start_supervised!(ETS)

    put_config(
      issuer: @issuer,
      audience: @issuer,
      keystore: __MODULE__.Keystore,
      repo: __MODULE__.Repo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      principal_kinds: [@user_kind],
      require_https: false,
      pre_authorized_code_store: ETS,
      c_nonce_store: CNonceStore,
      credential_configurations_supported: %{
        @configuration_id => %{format: "vc+sd-jwt", vct: @vct}
      },
      build_credential: fn subject, credential_configuration_id, holder_jwk ->
        send(self(), {:credential_requested, subject, credential_configuration_id, holder_jwk})

        {:ok,
         %{
           vct: @vct,
           claims: %{"degree" => "Bachelor", "student_id" => "student-123"},
           valid_from: System.system_time(:second) - 1,
           valid_until: System.system_time(:second) + 3600
         }}
      end
    )

    on_exit(fn ->
      Application.delete_env(:attesto_phoenix, Config)
      Application.delete_env(:attesto_phoenix, :otp_app)
    end)

    :ok
  end

  describe "POST /credential" do
    test "authenticates, verifies the proof, and issues a holder-bound SD-JWT VC" do
      nonce = CNonceStore.issue(60)
      response = post_credential(mint_token(), credential_request(nonce))

      assert response.status == 200
      assert get_resp_header(response, "cache-control") == ["no-store"]
      assert get_resp_header(response, "pragma") == ["no-cache"]

      assert %{"credentials" => [%{"credential" => credential}]} = body(response)
      assert is_binary(credential)

      # The JOSE `typ` header follows the credential configuration's `format`.
      issuer_jwt = credential |> String.split("~") |> hd()
      assert {:ok, %{"typ" => "vc+sd-jwt"}} = Attesto.JWS.peek_json(issuer_jwt, :protected)

      issuer_jwk = @signing_pem |> Attesto.Key.jwk() |> JOSE.JWK.to_public_map() |> elem(1)
      assert Config.resolve!() |> Config.vc_keystore() == Keystore
      assert {:ok, verified} = SdJwtVc.verify(credential, issuer_jwk, accepted_algs: ["ES256"])
      assert verified.vct == @vct
      assert verified.claims["degree"] == "Bachelor"
      assert verified.claims["student_id"] == "student-123"
      assert verified.cnf == %{"jwk" => public_map(@holder_key)}

      assert_receive {:credential_requested, @subject, @configuration_id, holder_jwk}
      assert holder_jwk == public_map(@holder_key)
    end

    test "stamps the JOSE typ from a dc+sd-jwt credential configuration format" do
      # OID4VCI/HAIP moved the SD-JWT VC media type from `vc+sd-jwt` to
      # `dc+sd-jwt`; the issued credential's `typ` MUST follow the configured
      # format, or a conformance verifier rejects the resolved configuration.
      config = Application.fetch_env!(:attesto_phoenix, Config)

      put_config(
        Keyword.put(config, :credential_configurations_supported, %{
          @configuration_id => %{format: "dc+sd-jwt", vct: @vct}
        })
      )

      nonce = CNonceStore.issue(60)
      response = post_credential(mint_token(), credential_request(nonce))

      assert response.status == 200
      assert %{"credentials" => [%{"credential" => credential}]} = body(response)

      issuer_jwt = credential |> String.split("~") |> hd()
      assert {:ok, %{"typ" => "dc+sd-jwt"}} = Attesto.JWS.peek_json(issuer_jwt, :protected)

      issuer_jwk = @signing_pem |> Attesto.Key.jwk() |> JOSE.JWK.to_public_map() |> elem(1)
      assert {:ok, verified} = SdJwtVc.verify(credential, issuer_jwk, accepted_algs: ["ES256"])
      assert verified.vct == @vct
    end

    test "defaults SD-JWT VC signing to RS256 with an RSA main keystore and no vc_keystore" do
      Application.put_env(:attesto_phoenix, __MODULE__.Keystore, signing_pem: @rsa_signing_pem)

      nonce = CNonceStore.issue(60)
      response = post_credential(mint_token(), credential_request(nonce))

      assert response.status == 200
      assert %{"credentials" => [%{"credential" => credential}]} = body(response)

      issuer_jwt = credential |> String.split("~") |> hd()
      assert {:ok, %{"alg" => "RS256"}} = Attesto.JWS.peek_json(issuer_jwt, :protected)

      rsa_jwk = @rsa_signing_pem |> Attesto.Key.jwk() |> JOSE.JWK.to_public_map() |> elem(1)
      assert Config.resolve!() |> Config.vc_keystore() == Keystore
      assert {:ok, verified} = SdJwtVc.verify(credential, rsa_jwk, accepted_algs: ["RS256"])
      assert verified.vct == @vct
      assert verified.cnf == %{"jwk" => public_map(@holder_key)}
    end

    test "signs an SD-JWT VC with a separate ES256 vc_keystore" do
      Application.put_env(:attesto_phoenix, __MODULE__.Keystore, signing_pem: @rsa_signing_pem)

      config = Application.fetch_env!(:attesto_phoenix, Config)
      put_config(Keyword.put(config, :vc_keystore, __MODULE__.VcKeystore))

      nonce = CNonceStore.issue(60)
      response = post_credential(mint_token(), credential_request(nonce))

      assert response.status == 200
      assert %{"credentials" => [%{"credential" => credential}]} = body(response)

      vc_jwk = @vc_signing_pem |> Attesto.Key.jwk() |> JOSE.JWK.to_public_map() |> elem(1)
      main_jwk = @rsa_signing_pem |> Attesto.Key.jwk() |> JOSE.JWK.to_public_map() |> elem(1)

      assert {:ok, verified} = SdJwtVc.verify(credential, vc_jwk, accepted_algs: ["ES256"])
      assert verified.vct == @vct
      assert {:error, _reason} = SdJwtVc.verify(credential, main_jwk, accepted_algs: ["ES256"])
    end

    test "issues a holder-bound jwt_vc_json credential" do
      claims = %{"degree" => "Bachelor", "student_id" => "student-123"}
      config = Application.fetch_env!(:attesto_phoenix, Config)

      config
      |> Keyword.put(:credential_configurations_supported, %{
        @jwt_vc_configuration_id => %{format: "jwt_vc_json"}
      })
      |> Keyword.put(:build_credential, fn subject, credential_configuration_id, holder_jwk ->
        send(self(), {:credential_requested, subject, credential_configuration_id, holder_jwk})

        {:ok,
         %{
           credential_type: @jwt_vc_credential_type,
           claims: claims,
           valid_from: System.system_time(:second) - 1,
           valid_until: System.system_time(:second) + 3600
         }}
      end)
      |> put_config()

      nonce = CNonceStore.issue(60)

      response =
        post_credential(
          mint_token(credential_configuration_ids: [@jwt_vc_configuration_id]),
          credential_request(nonce, credential_configuration_id: @jwt_vc_configuration_id)
        )

      assert response.status == 200
      assert %{"credentials" => [%{"credential" => credential}]} = body(response)

      issuer_jwk =
        @signing_pem
        |> Attesto.Key.jwk()
        |> JOSE.JWK.to_public_map()
        |> elem(1)
        |> Map.merge(%{"alg" => "ES256", "kid" => Attesto.Key.kid(@signing_pem), "use" => "sig"})

      assert {:ok, verified} = Attesto.JwtVc.verify(credential, issuer_jwk)
      assert verified.iss == @issuer
      assert verified.sub == @subject
      assert verified.vc["type"] == ["VerifiableCredential", @jwt_vc_credential_type]
      assert verified.claims == claims
      assert verified.cnf == %{"jwk" => public_map(@holder_key)}

      assert_receive {:credential_requested, @subject, @jwt_vc_configuration_id, holder_jwk}
      assert holder_jwk == public_map(@holder_key)
    end

    test "issues a holder-bound mso_mdoc credential" do
      namespaces = %{
        @mdoc_namespace => %{
          "family_name" => "Doe",
          "given_name" => "Jane"
        }
      }

      config = Application.fetch_env!(:attesto_phoenix, Config)

      config
      |> Keyword.put(:credential_configurations_supported, %{
        @mdoc_configuration_id => %{format: "mso_mdoc", doctype: @mdoc_doc_type}
      })
      |> Keyword.put(:build_credential, fn subject, credential_configuration_id, holder_jwk ->
        send(self(), {:credential_requested, subject, credential_configuration_id, holder_jwk})
        {:ok, %{doc_type: @mdoc_doc_type, namespaces: namespaces}}
      end)
      |> put_config()

      nonce = CNonceStore.issue(60)

      response =
        post_credential(
          mint_token(credential_configuration_ids: [@mdoc_configuration_id]),
          credential_request(nonce, credential_configuration_id: @mdoc_configuration_id)
        )

      assert response.status == 200
      assert %{"credentials" => [%{"credential" => credential}]} = body(response)

      issuer_jwk = @signing_pem |> Attesto.Key.jwk() |> JOSE.JWK.to_public_map() |> elem(1)
      assert {:ok, verified} = Mdoc.verify(credential, issuer_jwk)
      assert verified.doc_type == @mdoc_doc_type
      assert verified.namespaces == namespaces
      assert verified.device_key == public_map(@holder_key)

      assert_receive {:credential_requested, @subject, @mdoc_configuration_id, holder_jwk}
      assert holder_jwk == public_map(@holder_key)
    end

    test "returns a clean invalid_credential_request when mso_mdoc signing is not EC P-256" do
      Application.put_env(:attesto_phoenix, __MODULE__.Keystore, signing_pem: @rsa_signing_pem)

      config = Application.fetch_env!(:attesto_phoenix, Config)

      config
      |> Keyword.put(:credential_configurations_supported, %{
        @mdoc_configuration_id => %{format: "mso_mdoc", doctype: @mdoc_doc_type}
      })
      |> Keyword.put(:build_credential, fn _subject, _credential_configuration_id, _holder_jwk ->
        {:ok,
         %{
           doc_type: @mdoc_doc_type,
           namespaces: %{@mdoc_namespace => %{"family_name" => "Doe"}}
         }}
      end)
      |> put_config()

      nonce = CNonceStore.issue(60)

      response =
        post_credential(
          mint_token(credential_configuration_ids: [@mdoc_configuration_id]),
          credential_request(nonce, credential_configuration_id: @mdoc_configuration_id)
        )

      assert response.status == 400

      assert body(response) == %{
               "error" => "invalid_credential_request",
               "error_description" => "mso_mdoc issuance requires an EC P-256 (ES256) VC signing key."
             }
    end

    test "returns the plug's 401 challenge without an access token" do
      response = post_credential(nil, credential_request("unused"))

      assert response.status == 401
      assert body(response)["error"] == "invalid_token"
      assert ["Bearer" <> _] = get_resp_header(response, "www-authenticate")
    end

    test "returns 401 for a bad access token" do
      response = post_credential("not-a-token", credential_request("unused"))

      assert response.status == 401
      assert body(response)["error"] == "invalid_token"
    end

    test "rejects a credential configuration the access token does not authorize" do
      token = mint_token(credential_configuration_ids: ["OtherCredential"])
      response = post_credential(token, %{"credential_configuration_id" => @configuration_id})

      # OID4VCI §8.3.1: the token is a valid credential token but names a
      # credential_configuration_id it was not granted.
      assert response.status == 400
      assert body(response)["error"] == "unknown_credential_configuration"
    end

    test "rejects a missing proof" do
      response = post_credential(mint_token(), %{"credential_configuration_id" => @configuration_id})

      assert response.status == 400
      assert body(response)["error"] == "invalid_proof"
    end

    test "rejects a c_nonce not issued by the configured store" do
      response = post_credential(mint_token(), credential_request("never-issued"))

      # OID4VCI §8.3: an invalid/expired proof nonce is `invalid_nonce`.
      assert response.status == 400
      assert body(response)["error"] == "invalid_nonce"
    end

    test "fails loudly when the c_nonce store violates its boolean contract" do
      config = Application.fetch_env!(:attesto_phoenix, Config)
      put_config(Keyword.put(config, :c_nonce_store, InvalidCNonceStore))

      for invalid <- [
            :error,
            {:error, :backend_unavailable},
            "sensitive-result-sentinel",
            {:raise, "sensitive-result-sentinel"},
            {:throw, "sensitive-result-sentinel"},
            {:exit, "sensitive-result-sentinel"}
          ] do
        Process.put({InvalidCNonceStore, :result}, invalid)

        error =
          assert_raise RuntimeError, "c_nonce_store valid?/1 must return true or false", fn ->
            post_credential(mint_token(), credential_request("candidate-nonce"))
          end

        refute Exception.message(error) =~ "sensitive-result-sentinel"
        refute_received {:credential_requested, _, _, _}
      end
    end

    test "treats every declared c_nonce consume error as a spent or invalid nonce" do
      config = Application.fetch_env!(:attesto_phoenix, Config)
      put_config(Keyword.put(config, :c_nonce_store, InvalidCNonceStore))
      Process.put({InvalidCNonceStore, :valid_result}, true)

      for {store_error, index} <-
            Enum.with_index([{:error, :used}, {:error, :expired}, {:error, :unknown}, {:error, :offline}]) do
        Process.put({InvalidCNonceStore, :consume_result}, store_error)
        nonce = "candidate-nonce-#{index}"
        response = post_credential(mint_token(), credential_request(nonce))

        assert response.status == 400
        assert body(response)["error"] == "invalid_nonce"
        refute_received {:credential_requested, _, _, _}
      end
    end

    test "fails loudly without values when c_nonce consume violates its contract or fails" do
      config = Application.fetch_env!(:attesto_phoenix, Config)
      put_config(Keyword.put(config, :c_nonce_store, InvalidCNonceStore))
      Process.put({InvalidCNonceStore, :valid_result}, true)

      for {invalid, index} <-
            Enum.with_index([
              :error,
              false,
              "sensitive-result-sentinel",
              {:raise, "sensitive-result-sentinel"},
              {:throw, "sensitive-result-sentinel"},
              {:exit, "sensitive-result-sentinel"}
            ]) do
        Process.put({InvalidCNonceStore, :consume_result}, invalid)
        nonce = "candidate-nonce-#{index}"

        error =
          assert_raise RuntimeError, "c_nonce_store consume/1 must return :ok or {:error, reason}", fn ->
            post_credential(mint_token(), credential_request(nonce))
          end

        refute Exception.message(error) =~ "sensitive-result-sentinel"
        refute_received {:credential_requested, _, _, _}
      end
    end

    test "c_nonce is single-use: replaying a proof with a spent nonce is rejected" do
      nonce = CNonceStore.issue(60)

      first = post_credential(mint_token(), credential_request(nonce))
      assert first.status == 200

      # The nonce was consumed by the first request; the same proof replayed to
      # mint a second credential must fail (not silently issue a duplicate).
      replay = post_credential(mint_token(), credential_request(nonce))
      assert replay.status == 400
      assert body(replay)["error"] == "invalid_nonce"
    end

    test "binds a proof's iss to the authenticated client, rejecting a cross-client or absent iss" do
      # The access token was minted for "client-A"; RFC 9068 guarantees its
      # "client_id" claim carries that. A proof whose `iss` names a different
      # client (or omits `iss` entirely) must be rejected - otherwise a proof
      # captured/forged under one client could be replayed against another
      # client's authenticated token.
      token = mint_token(client_id: "client-A")

      wrong_client_nonce = CNonceStore.issue(60)

      wrong_client_response =
        post_credential(
          token,
          credential_request(wrong_client_nonce, proof: proof_jwt(wrong_client_nonce, iss: "client-B"))
        )

      assert wrong_client_response.status == 400
      assert body(wrong_client_response)["error"] == "invalid_proof"

      absent_iss_nonce = CNonceStore.issue(60)

      absent_iss_response =
        post_credential(
          token,
          credential_request(absent_iss_nonce, proof: proof_jwt(absent_iss_nonce, iss: nil))
        )

      assert absent_iss_response.status == 400
      assert body(absent_iss_response)["error"] == "invalid_proof"

      matching_nonce = CNonceStore.issue(60)

      matching_response =
        post_credential(
          token,
          credential_request(matching_nonce, proof: proof_jwt(matching_nonce, iss: "client-A"))
        )

      assert matching_response.status == 200
    end

    test "rejects a proof with the wrong audience" do
      nonce = CNonceStore.issue(60)
      proof = proof_jwt(nonce, aud: "https://other-issuer.example")

      response =
        post_credential(
          mint_token(),
          credential_request(nonce, proof: proof)
        )

      assert response.status == 400
      assert body(response)["error"] == "invalid_proof"
    end

    test "issues a batch of holder-bound SD-JWT VCs from the proofs form" do
      other_holder_key = JOSE.JWK.generate_key({:ec, "P-256"})
      nonce = CNonceStore.issue(60)

      request = %{
        "credential_configuration_id" => @configuration_id,
        "proofs" => %{"jwt" => [proof_jwt(nonce), proof_jwt(nonce, key: other_holder_key)]}
      }

      response = post_credential(mint_token(), request)

      assert response.status == 200
      assert %{"credentials" => [%{"credential" => credential1}, %{"credential" => credential2}]} = body(response)

      issuer_jwk = @signing_pem |> Attesto.Key.jwk() |> JOSE.JWK.to_public_map() |> elem(1)

      assert {:ok, verified1} = SdJwtVc.verify(credential1, issuer_jwk)
      assert verified1.cnf == %{"jwk" => public_map(@holder_key)}

      assert {:ok, verified2} = SdJwtVc.verify(credential2, issuer_jwk)
      assert verified2.cnf == %{"jwk" => public_map(other_holder_key)}

      assert_receive {:credential_requested, @subject, @configuration_id, holder_jwk1}
      assert_receive {:credential_requested, @subject, @configuration_id, holder_jwk2}

      assert Enum.sort([holder_jwk1, holder_jwk2]) ==
               Enum.sort([public_map(@holder_key), public_map(other_holder_key)])
    end

    test "rejects a batch where one proof has a stale c_nonce" do
      nonce = CNonceStore.issue(60)

      request = %{
        "credential_configuration_id" => @configuration_id,
        "proofs" => %{"jwt" => [proof_jwt(nonce), proof_jwt("never-issued")]}
      }

      response = post_credential(mint_token(), request)

      # A stale nonce on any proof in the batch is `invalid_nonce`.
      assert response.status == 400
      assert body(response)["error"] == "invalid_nonce"
    end

    test "issues for a credential_identifier the access token was granted" do
      # OID4VCI §6.2/§8.2: the token response returns credential_identifiers 1:1
      # with the granted credential_configuration_id, and the wallet presents one
      # as `credential_identifier`. It resolves to the same configuration.
      nonce = CNonceStore.issue(60)

      request = %{
        "credential_identifier" => @configuration_id,
        "proof" => %{"proof_type" => "jwt", "jwt" => proof_jwt(nonce)}
      }

      response = post_credential(mint_token(), request)

      assert response.status == 200
      assert %{"credentials" => [%{"credential" => credential}]} = body(response)
      assert is_binary(credential)
      assert_receive {:credential_requested, @subject, @configuration_id, _holder_jwk}
    end

    test "rejects a credential_identifier the access token was not granted" do
      nonce = CNonceStore.issue(60)

      request = %{
        "credential_identifier" => "credential-not-granted",
        "proof" => %{"proof_type" => "jwt", "jwt" => proof_jwt(nonce)}
      }

      response = post_credential(mint_token(), request)

      assert response.status == 400
      assert body(response)["error"] == "unknown_credential_identifier"
    end

    test "maps a host credential-builder error to invalid_credential_request" do
      config = Application.fetch_env!(:attesto_phoenix, Config)
      put_config(Keyword.put(config, :build_credential, fn _, _, _ -> {:error, "sensitive-domain-error"} end))

      nonce = CNonceStore.issue(60)

      log =
        capture_log(fn ->
          response = post_credential(mint_token(), credential_request(nonce))

          assert response.status == 400

          assert body(response) == %{
                   "error" => "invalid_credential_request",
                   "error_description" => "credential unavailable"
                 }
        end)

      refute log =~ "sensitive-domain-error"
      refute log =~ "credential builder returned an invalid result"
    end

    test "reports a malformed credential-builder result without logging its value" do
      config = Application.fetch_env!(:attesto_phoenix, Config)

      put_config(
        Keyword.put(config, :build_credential, fn _, _, _ ->
          "sensitive-result-sentinel"
        end)
      )

      nonce = CNonceStore.issue(60)

      log =
        capture_log(fn ->
          response = post_credential(mint_token(), credential_request(nonce))

          assert response.status == 400
          assert body(response)["error"] == "invalid_credential_request"
        end)

      assert log =~ "AttestoPhoenix credential builder returned an invalid result; credential issuance denied"
      refute log =~ "sensitive-result-sentinel"
    end

    test "sanitizes a credential-builder failure while leaving it loud" do
      config = Application.fetch_env!(:attesto_phoenix, Config)

      for failure <- [:raise, :throw, :exit] do
        put_config(
          Keyword.put(config, :build_credential, fn _, _, _ ->
            fail_builder(failure)
          end)
        )

        nonce = CNonceStore.issue(60)

        error =
          assert_raise RuntimeError, "AttestoPhoenix credential builder callback failed", fn ->
            post_credential(mint_token(), credential_request(nonce))
          end

        refute Exception.message(error) =~ "sensitive-builder-failure"
      end
    end

    test "honors an atom-key nil credential format without falling back to the string key" do
      config = Application.fetch_env!(:attesto_phoenix, Config)

      configurations = %{
        @configuration_id => %{"format" => "vc+sd-jwt", format: nil, vct: @vct}
      }

      put_config(Keyword.put(config, :credential_configurations_supported, configurations))

      nonce = CNonceStore.issue(60)
      response = post_credential(mint_token(), credential_request(nonce))

      assert response.status == 400

      assert body(response) == %{
               "error" => "invalid_credential_request",
               "error_description" => "credential unavailable"
             }

      refute_received {:credential_requested, _, _, _}
    end

    test "rejects a request that requires credential_response_encryption instead of silently returning plaintext" do
      # This issuer does not implement Credential Response encryption and never
      # advertises it in its metadata. Silently issuing a plaintext credential
      # when the wallet required an encrypted response would be a silent
      # confidentiality downgrade, so the request must fail closed instead.
      nonce = CNonceStore.issue(60)

      request =
        credential_request(nonce)
        |> Map.put("credential_response_encryption", %{
          "jwk" => public_map(@holder_key),
          "alg" => "ECDH-ES",
          "enc" => "A128GCM"
        })

      response = post_credential(mint_token(), request)

      assert response.status == 400
      assert body(response)["error"] == "invalid_encryption_parameters"
      refute_received {:credential_requested, _, _, _}
    end

    test "the opt-in router mounts POST /credential" do
      response = CredentialRouter.call(conn(:post, @endpoint_path), [])

      assert response.status == 401
      assert body(response)["error"] == "invalid_token"
    end
  end

  defp credential_request(nonce, opts \\ []) do
    proof = Keyword.get(opts, :proof, proof_jwt(nonce))
    credential_configuration_id = Keyword.get(opts, :credential_configuration_id, @configuration_id)

    %{
      "credential_configuration_id" => credential_configuration_id,
      "proof" => %{"proof_type" => "jwt", "jwt" => proof}
    }
  end

  defp proof_jwt(nonce, opts \\ []) do
    key = Keyword.get(opts, :key, @holder_key)

    header = %{
      "alg" => "ES256",
      "jwk" => public_map(key),
      "typ" => "openid4vci-proof+jwt"
    }

    claims =
      %{
        "aud" => Keyword.get(opts, :aud, @issuer),
        "iat" => System.system_time(:second),
        "nonce" => nonce
      }
      |> maybe_put_iss(opts)

    key
    |> JOSE.JWT.sign(header, claims)
    |> JOSE.JWS.compact()
    |> elem(1)
  end

  # Every existing proof-related test fixture predates the iss-binding fix and
  # relies on the token's default client_id ("test-client"); default the proof's
  # `iss` to that so the fix doesn't require touching every call site. Pass
  # `iss: nil` explicitly to omit `iss` (testing the absent-iss rejection), or
  # a different value to test a mismatched client.
  defp maybe_put_iss(claims, opts) do
    case Keyword.get(opts, :iss, @default_client_id) do
      nil -> claims
      iss -> Map.put(claims, "iss", iss)
    end
  end

  defp fail_builder(:raise), do: raise("sensitive-builder-failure")
  defp fail_builder(:throw), do: throw("sensitive-builder-failure")
  defp fail_builder(:exit), do: exit("sensitive-builder-failure")

  defp mint_token(opts \\ []) do
    config =
      Attesto.Config.new(
        issuer: @issuer,
        audience: @issuer,
        keystore: __MODULE__.Keystore,
        principal_kinds: [@user_kind]
      )

    credential_configuration_ids = Keyword.get(opts, :credential_configuration_ids, [@configuration_id])
    client_id = Keyword.get(opts, :client_id, @default_client_id)

    principal = %{
      kind: "user",
      sub: @subject,
      scopes: ["credential"],
      claims: %{
        "client_id" => client_id,
        "credential_configuration_ids" => credential_configuration_ids
      }
    }

    {:ok, %{access_token: token}} = Token.mint(config, principal)
    token
  end

  defp post_credential(nil, request), do: post_credential_with_token(nil, request)

  defp post_credential(token, request), do: post_credential_with_token(token, request)

  defp post_credential_with_token(token, request) do
    conn =
      :post
      |> conn(@endpoint_path)
      |> put_private(:attesto_phoenix_config, Config.new(Application.fetch_env!(:attesto_phoenix, Config)))
      |> maybe_authorization(token)

    CredentialController.create(%{conn | body_params: request}, request)
  end

  defp maybe_authorization(conn, nil), do: conn
  defp maybe_authorization(conn, token), do: put_req_header(conn, "authorization", "Bearer " <> token)

  defp public_map(key) do
    {_kty, jwk_map} = JOSE.JWK.to_public_map(key)
    jwk_map
  end

  defp put_config(opts) do
    Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)
    Application.put_env(:attesto_phoenix, Config, opts)
  end

  defp body(conn), do: JSON.decode!(conn.resp_body)
end
