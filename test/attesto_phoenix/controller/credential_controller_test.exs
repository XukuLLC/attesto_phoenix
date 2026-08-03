defmodule AttestoPhoenix.Controller.CredentialControllerTest do
  @moduledoc false
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias Attesto.CNonceStore.ETS, as: CNonceStore
  alias Attesto.{Mdoc, SdJwtVc, Token}
  alias Attesto.PreAuthorizedCodeStore.ETS
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Controller.CredentialController

  @endpoint_path "/oauth/credential"
  @issuer "https://issuer.example"
  @subject "ou_user-123"
  @configuration_id "UniversityDegreeCredential"
  @vct "https://credentials.example/UniversityDegreeCredential"
  @jwt_vc_configuration_id "UniversityDegreeCredentialJwtVc"
  @jwt_vc_credential_type "UniversityDegreeCredential"
  @mdoc_configuration_id "org.iso.18013.5.1.mDL"
  @mdoc_doc_type "org.iso.18013.5.1.mDL"
  @mdoc_namespace "org.iso.18013.5.1"
  @signing_pem JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_pem() |> elem(1)
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

  defmodule CredentialRouter do
    @moduledoc false
    use Phoenix.Router
    use AttestoPhoenix.Router

    scope "/" do
      attesto_routes(credential_issuance: true)
    end
  end

  @user_kind Attesto.PrincipalKind.new("user", "ou_", required_claims: [{"client_id", :non_empty_string}])

  setup do
    Application.put_env(:attesto_phoenix, __MODULE__.Keystore, signing_pem: @signing_pem)
    on_exit(fn -> Application.delete_env(:attesto_phoenix, __MODULE__.Keystore) end)

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

      issuer_jwk = @signing_pem |> Attesto.Key.jwk() |> JOSE.JWK.to_public_map() |> elem(1)
      assert {:ok, verified} = SdJwtVc.verify(credential, issuer_jwk)
      assert verified.vct == @vct
      assert verified.claims["degree"] == "Bachelor"
      assert verified.claims["student_id"] == "student-123"
      assert verified.cnf == %{"jwk" => public_map(@holder_key)}

      assert_receive {:credential_requested, @subject, @configuration_id, holder_jwk}
      assert holder_jwk == public_map(@holder_key)
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

      assert response.status == 403
      assert body(response)["error"] in ["insufficient_scope", "invalid_credential_request"]
    end

    test "rejects a missing proof" do
      response = post_credential(mint_token(), %{"credential_configuration_id" => @configuration_id})

      assert response.status == 400
      assert body(response)["error"] == "invalid_proof"
    end

    test "rejects a c_nonce not issued by the configured store" do
      response = post_credential(mint_token(), credential_request("never-issued"))

      assert response.status == 400
      assert body(response)["error"] == "invalid_proof"
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

      assert response.status == 400
      assert body(response)["error"] == "invalid_proof"
    end

    test "rejects credential_identifier selectors in this slice" do
      response =
        post_credential(mint_token(), %{"credential_identifier" => "credential-123"})

      assert response.status == 400

      assert body(response) == %{
               "error" => "invalid_credential_request",
               "error_description" => "credential_identifier not supported"
             }
    end

    test "maps a host credential-builder error to invalid_credential_request" do
      config = Application.fetch_env!(:attesto_phoenix, Config)
      put_config(Keyword.put(config, :build_credential, fn _, _, _ -> {:error, :not_found} end))

      nonce = CNonceStore.issue(60)
      response = post_credential(mint_token(), credential_request(nonce))

      assert response.status == 400

      assert body(response) == %{
               "error" => "invalid_credential_request",
               "error_description" => "credential unavailable"
             }
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

    claims = %{
      "aud" => Keyword.get(opts, :aud, @issuer),
      "iat" => System.system_time(:second),
      "nonce" => nonce
    }

    key
    |> JOSE.JWT.sign(header, claims)
    |> JOSE.JWS.compact()
    |> elem(1)
  end

  defp mint_token(opts \\ []) do
    config =
      Attesto.Config.new(
        issuer: @issuer,
        audience: @issuer,
        keystore: __MODULE__.Keystore,
        principal_kinds: [@user_kind]
      )

    credential_configuration_ids = Keyword.get(opts, :credential_configuration_ids, [@configuration_id])

    principal = %{
      kind: "user",
      sub: @subject,
      scopes: ["credential"],
      claims: %{
        "client_id" => "test-client",
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
