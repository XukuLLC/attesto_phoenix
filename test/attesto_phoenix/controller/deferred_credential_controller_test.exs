defmodule AttestoPhoenix.Controller.DeferredCredentialControllerTest do
  @moduledoc false
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog
  import Plug.Conn
  import Plug.Test

  alias Attesto.{JwtVc, Mdoc, SdJwtVc, Token}
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Controller.DeferredCredentialController
  alias AttestoPhoenix.Plug.PutConfig

  @endpoint_path "/oauth/deferred_credential"
  @issuer "https://issuer.example"
  @subject "ou_user-123"
  @vct "https://credentials.example/UniversityDegreeCredential"
  @configuration_id "UniversityDegreeCredential"
  @jwt_vc_configuration_id "UniversityDegreeJwtVc"
  @mdoc_configuration_id "org.iso.18013.5.1.mDL"
  @mdoc_doc_type "org.iso.18013.5.1.mDL"
  @mdoc_namespace "org.iso.18013.5.1"
  @holder_key JOSE.JWK.generate_key({:ec, "P-256"})
  @holder_jwk @holder_key |> JOSE.JWK.to_public_map() |> elem(1)
  @signing_pem JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_pem() |> elem(1)
  @vc_signing_pem JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_pem() |> elem(1)

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
      credential_configurations_supported: %{
        @configuration_id => %{format: "dc+sd-jwt", vct: @vct},
        @jwt_vc_configuration_id => %{format: "jwt_vc_json"},
        @mdoc_configuration_id => %{format: "mso_mdoc", doctype: @mdoc_doc_type}
      },
      build_deferred_credential: fn subject, transaction_id ->
        send(self(), {:deferred_credential_requested, subject, transaction_id})

        {:ok,
         deferred_result(
           @configuration_id,
           %{vct: @vct, claims: %{"degree" => "Bachelor", "student_id" => "student-123"}}
         )}
      end
    )

    on_exit(fn ->
      Application.delete_env(:attesto_phoenix, Config)
      Application.delete_env(:attesto_phoenix, :otp_app)
    end)

    :ok
  end

  describe "POST /deferred_credential" do
    test "issues the completed SD-JWT VC once the host reports it is ready" do
      response = post_deferred(mint_token(), %{"transaction_id" => "txn-123"})

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
      assert verified.cnf == %{"jwk" => @holder_jwk}

      [issuer_jwt | _disclosures] = String.split(credential, "~", trim: true)
      assert {:ok, %{"typ" => "dc+sd-jwt"}} = Attesto.JWS.peek_json(issuer_jwt, :protected)

      assert_receive {:deferred_credential_requested, @subject, "txn-123"}
    end

    test "signs the completed SD-JWT VC with a separate ES256 vc_keystore" do
      config = Application.fetch_env!(:attesto_phoenix, Config)
      put_config(Keyword.put(config, :vc_keystore, __MODULE__.VcKeystore))

      response = post_deferred(mint_token(), %{"transaction_id" => "txn-123"})

      assert response.status == 200
      assert %{"credentials" => [%{"credential" => credential}]} = body(response)

      vc_jwk = @vc_signing_pem |> Attesto.Key.jwk() |> JOSE.JWK.to_public_map() |> elem(1)
      main_jwk = @signing_pem |> Attesto.Key.jwk() |> JOSE.JWK.to_public_map() |> elem(1)

      assert {:ok, verified} = SdJwtVc.verify(credential, vc_jwk, accepted_algs: ["ES256"])
      assert verified.vct == @vct
      assert {:error, _reason} = SdJwtVc.verify(credential, main_jwk, accepted_algs: ["ES256"])
    end

    test "returns the OID4VCI issuance_pending error while the host is still working" do
      config = Application.fetch_env!(:attesto_phoenix, Config)
      put_config(Keyword.put(config, :build_deferred_credential, fn _subject, _txn -> {:error, :issuance_pending} end))

      response = post_deferred(mint_token(), %{"transaction_id" => "txn-123"})

      assert response.status == 400

      assert body(response) == %{
               "error" => "issuance_pending",
               "error_description" => "The credential is not yet ready."
             }
    end

    test "maps a host credential-builder error to invalid_credential_request" do
      config = Application.fetch_env!(:attesto_phoenix, Config)

      put_config(
        Keyword.put(config, :build_deferred_credential, fn _subject, _txn ->
          {:error, "sensitive-domain-error"}
        end)
      )

      log =
        capture_log(fn ->
          response = post_deferred(mint_token(), %{"transaction_id" => "txn-123"})

          assert response.status == 400

          assert body(response) == %{
                   "error" => "invalid_credential_request",
                   "error_description" => "credential unavailable"
                 }
        end)

      refute log =~ "sensitive-domain-error"
      refute log =~ "deferred credential builder returned an invalid result"
    end

    test "rejects a legacy result that omits the persisted holder binding" do
      config = Application.fetch_env!(:attesto_phoenix, Config)

      callback = fn _subject, _txn ->
        {:ok, %{credential_type: "UniversityDegreeCredential", claims: %{"degree" => "Bachelor"}}}
      end

      put_config(Keyword.put(config, :build_deferred_credential, callback))

      response = post_deferred(mint_token(), %{"transaction_id" => "txn-123"})

      assert response.status == 400

      assert body(response) == %{
               "error" => "invalid_credential_request",
               "error_description" => "credential unavailable"
             }
    end

    test "issues a holder-bound JWT VC through the shared issuance path" do
      config = Application.fetch_env!(:attesto_phoenix, Config)

      callback = fn _subject, _txn ->
        {:ok,
         deferred_result(
           @jwt_vc_configuration_id,
           %{
             credential_type: "UniversityDegreeCredential",
             claims: %{"degree" => "Bachelor"},
             valid_until: System.system_time(:second) + 3600
           }
         )}
      end

      put_config(Keyword.put(config, :build_deferred_credential, callback))

      response = post_deferred(mint_token(), %{"transaction_id" => "txn-jwt"})
      assert response.status == 200
      assert %{"credentials" => [%{"credential" => credential}]} = body(response)

      issuer_jwk =
        @signing_pem
        |> Attesto.Key.jwk()
        |> JOSE.JWK.to_public_map()
        |> elem(1)
        |> Map.merge(%{"alg" => "ES256", "kid" => Attesto.Key.kid(@signing_pem), "use" => "sig"})

      assert {:ok, verified} = JwtVc.verify(credential, issuer_jwk)
      assert verified.cnf == %{"jwk" => @holder_jwk}
      assert verified.claims["degree"] == "Bachelor"
    end

    test "issues a holder-bound mdoc and rejects a missing validity period" do
      config = Application.fetch_env!(:attesto_phoenix, Config)
      now = System.system_time(:second)

      credential = %{
        namespaces: %{@mdoc_namespace => %{"family_name" => "Doe"}},
        valid_until: now + 3600
      }

      callback = fn _subject, _txn ->
        {:ok, deferred_result(@mdoc_configuration_id, credential)}
      end

      put_config(Keyword.put(config, :build_deferred_credential, callback))

      response = post_deferred(mint_token(), %{"transaction_id" => "txn-mdoc"})
      assert response.status == 200
      assert %{"credentials" => [%{"credential" => encoded}]} = body(response)

      issuer_jwk = @signing_pem |> Attesto.Key.jwk() |> JOSE.JWK.to_public_map() |> elem(1)
      assert {:ok, verified} = Mdoc.verify(encoded, issuer_jwk)
      assert verified.device_key == @holder_jwk
      assert verified.doc_type == @mdoc_doc_type

      missing_validity = fn _subject, _txn ->
        {:ok, deferred_result(@mdoc_configuration_id, Map.delete(credential, :valid_until))}
      end

      put_config(Keyword.put(config, :build_deferred_credential, missing_validity))
      invalid = post_deferred(mint_token(), %{"transaction_id" => "txn-mdoc-invalid"})
      assert invalid.status == 400
      assert body(invalid)["error"] == "invalid_credential_request"
    end

    test "rejects a deferred credential configuration outside the access-token entitlement" do
      config = Application.fetch_env!(:attesto_phoenix, Config)

      callback = fn _subject, _txn ->
        {:ok,
         deferred_result(
           @jwt_vc_configuration_id,
           %{credential_type: "UniversityDegreeCredential", claims: %{}}
         )}
      end

      put_config(Keyword.put(config, :build_deferred_credential, callback))

      response =
        post_deferred(mint_token([@configuration_id]), %{"transaction_id" => "txn-not-entitled"})

      assert response.status == 400
      assert body(response)["error"] == "invalid_credential_request"
    end

    test "rejects malformed and private persisted holder keys" do
      config = Application.fetch_env!(:attesto_phoenix, Config)

      for holder_jwk <- [%{"kty" => "EC", "crv" => "P-256"}, private_map(@holder_key)] do
        callback = fn _subject, _txn ->
          {:ok,
           %{
             credential_configuration_id: @configuration_id,
             holder_jwk: holder_jwk,
             credential: %{vct: @vct, claims: %{"degree" => "Bachelor"}}
           }}
        end

        put_config(Keyword.put(config, :build_deferred_credential, callback))

        response = post_deferred(mint_token(), %{"transaction_id" => "txn-invalid-holder"})
        assert response.status == 400
        assert body(response)["error"] == "invalid_credential_request"
      end
    end

    test "reports a malformed deferred-builder result without logging its value" do
      config = Application.fetch_env!(:attesto_phoenix, Config)

      put_config(
        Keyword.put(config, :build_deferred_credential, fn _subject, _txn ->
          "sensitive-result-sentinel"
        end)
      )

      log =
        capture_log(fn ->
          response = post_deferred(mint_token(), %{"transaction_id" => "txn-123"})

          assert response.status == 400
          assert body(response)["error"] == "invalid_credential_request"
        end)

      assert log =~
               "AttestoPhoenix deferred credential builder returned an invalid result; credential issuance denied"

      refute log =~ "sensitive-result-sentinel"
    end

    test "sanitizes a deferred-builder failure while leaving it loud" do
      config = Application.fetch_env!(:attesto_phoenix, Config)

      for failure <- [:raise, :throw, :exit] do
        put_config(
          Keyword.put(config, :build_deferred_credential, fn _subject, _txn ->
            fail_builder(failure)
          end)
        )

        error =
          assert_raise RuntimeError, "AttestoPhoenix deferred credential builder callback failed", fn ->
            post_deferred(mint_token(), %{"transaction_id" => "txn-123"})
          end

        refute Exception.message(error) =~ "sensitive-builder-failure"
      end
    end

    test "rejects a missing transaction_id" do
      response = post_deferred(mint_token(), %{})

      assert response.status == 400
      assert body(response)["error"] == "invalid_credential_request"
    end

    test "returns the plug's 401 challenge without an access token" do
      response = post_deferred(nil, %{"transaction_id" => "txn-123"})

      assert response.status == 401
      assert body(response)["error"] == "invalid_token"
      assert ["Bearer" <> _] = get_resp_header(response, "www-authenticate")
    end

    test "returns 401 for a bad access token" do
      response = post_deferred("not-a-token", %{"transaction_id" => "txn-123"})

      assert response.status == 401
      assert body(response)["error"] == "invalid_token"
    end

    test "the opt-in router mounts POST /deferred_credential" do
      response = CredentialRouter.call(conn(:post, @endpoint_path), [])

      assert response.status == 401
      assert body(response)["error"] == "invalid_token"
    end
  end

  defp mint_token(credential_configuration_ids \\ [@configuration_id, @jwt_vc_configuration_id, @mdoc_configuration_id]) do
    config =
      Attesto.Config.new(
        issuer: @issuer,
        audience: @issuer,
        keystore: __MODULE__.Keystore,
        principal_kinds: [@user_kind]
      )

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

  defp post_deferred(token, request) do
    conn =
      :post
      |> conn(@endpoint_path)
      |> put_private(:attesto_phoenix_config, Config.new(Application.fetch_env!(:attesto_phoenix, Config)))
      |> maybe_authorization(token)

    DeferredCredentialController.create(%{conn | body_params: request}, request)
  end

  defp maybe_authorization(conn, nil), do: conn
  defp maybe_authorization(conn, token), do: put_req_header(conn, "authorization", "Bearer " <> token)

  defp fail_builder(:raise), do: raise("sensitive-builder-failure")
  defp fail_builder(:throw), do: throw("sensitive-builder-failure")
  defp fail_builder(:exit), do: exit("sensitive-builder-failure")

  defp deferred_result(credential_configuration_id, credential) do
    %{
      credential_configuration_id: credential_configuration_id,
      holder_jwk: @holder_jwk,
      credential: credential
    }
  end

  defp private_map(jwk), do: jwk |> JOSE.JWK.to_map() |> elem(1)

  defp put_config(opts) do
    Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)
    Application.put_env(:attesto_phoenix, Config, opts)
  end

  defp body(conn), do: JSON.decode!(conn.resp_body)
end
