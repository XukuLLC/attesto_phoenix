defmodule AttestoPhoenix.Controller.DeferredCredentialControllerTest do
  @moduledoc false
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias Attesto.{SdJwtVc, Token}
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Controller.DeferredCredentialController

  @endpoint_path "/oauth/deferred_credential"
  @issuer "https://issuer.example"
  @subject "ou_user-123"
  @vct "https://credentials.example/UniversityDegreeCredential"
  @signing_pem JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_pem() |> elem(1)

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
      build_deferred_credential: fn subject, transaction_id ->
        send(self(), {:deferred_credential_requested, subject, transaction_id})

        {:ok, %{vct: @vct, claims: %{"degree" => "Bachelor", "student_id" => "student-123"}}}
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

      assert_receive {:deferred_credential_requested, @subject, "txn-123"}
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
      put_config(Keyword.put(config, :build_deferred_credential, fn _subject, _txn -> {:error, :not_found} end))

      response = post_deferred(mint_token(), %{"transaction_id" => "txn-123"})

      assert response.status == 400

      assert body(response) == %{
               "error" => "invalid_credential_request",
               "error_description" => "credential unavailable"
             }
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

  defp mint_token do
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
      claims: %{"client_id" => "test-client"}
    }

    {:ok, %{access_token: token}} = Token.mint(config, principal)
    token
  end

  defp post_deferred(token, request) do
    conn =
      :post
      |> conn(@endpoint_path)
      |> maybe_authorization(token)

    DeferredCredentialController.create(%{conn | body_params: request}, request)
  end

  defp maybe_authorization(conn, nil), do: conn
  defp maybe_authorization(conn, token), do: put_req_header(conn, "authorization", "Bearer " <> token)

  defp put_config(opts) do
    Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)
    Application.put_env(:attesto_phoenix, Config, opts)
  end

  defp body(conn), do: JSON.decode!(conn.resp_body)
end
