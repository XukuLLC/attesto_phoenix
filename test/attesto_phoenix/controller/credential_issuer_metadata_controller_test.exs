defmodule AttestoPhoenix.Controller.CredentialIssuerMetadataControllerTest do
  @moduledoc false
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Controller.CredentialIssuerMetadataController
  alias AttestoPhoenix.Plug.PutConfig

  @issuer "https://issuer.example"
  @metadata_path "/.well-known/openid-credential-issuer"
  @oauth_prefix "/oauth"
  @credential_configurations %{
    "UniversityDegreeCredential" => %{
      format: "vc+sd-jwt",
      vct: "https://credentials.example/UniversityDegreeCredential"
    }
  }

  defmodule StubKeystore do
    @moduledoc false

    def signing_pem, do: "test-only"
    def verification_pems, do: ["test-only"]
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

  setup do
    put_config(
      issuer: @issuer,
      audience: @issuer,
      keystore: StubKeystore,
      repo: __MODULE__.Repo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      principal_kinds: [Attesto.PrincipalKind.new("user", "usr_")],
      credential_configurations_supported: @credential_configurations
    )

    on_exit(fn ->
      Application.delete_env(:attesto_phoenix, Config)
      Application.delete_env(:attesto_phoenix, :otp_app)
    end)

    :ok
  end

  test "serves metadata at the root well-known path with absolute endpoints" do
    response = CredentialRouter.call(conn(:get, @metadata_path), [])
    body = JSON.decode!(response.resp_body)
    credential_tail = Config.credential_tail()
    nonce_tail = Config.nonce_tail()

    assert response.status == 200
    assert body["credential_issuer"] == @issuer
    assert body["credential_endpoint"] == @issuer <> @oauth_prefix <> credential_tail
    assert body["nonce_endpoint"] == @issuer <> @oauth_prefix <> nonce_tail

    assert body["credential_configurations_supported"] == %{
             "UniversityDegreeCredential" => %{
               "format" => "vc+sd-jwt",
               "vct" => "https://credentials.example/UniversityDegreeCredential"
             }
           }

    assert get_resp_header(response, "cache-control") == ["public, max-age=3600"]
  end

  test "derives wallet endpoint URLs from a custom OAuth path prefix" do
    config = Application.fetch_env!(:attesto_phoenix, Config)

    config =
      config
      |> Keyword.put(:oauth_path_prefix, "/wallet/oauth")
      |> Keyword.put(:build_deferred_credential, fn _subject, _transaction_id -> {:error, :issuance_pending} end)

    put_config(config)

    response =
      conn(:get, @metadata_path)
      |> put_private(:attesto_phoenix_config, Config.new(Application.fetch_env!(:attesto_phoenix, Config)))
      |> CredentialIssuerMetadataController.show(%{})

    body = JSON.decode!(response.resp_body)

    assert body["credential_endpoint"] == @issuer <> "/wallet/oauth/credential"
    assert body["nonce_endpoint"] == @issuer <> "/wallet/oauth/nonce"
    assert body["deferred_credential_endpoint"] == @issuer <> "/wallet/oauth/deferred_credential"
  end

  defp put_config(opts) do
    Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)
    Application.put_env(:attesto_phoenix, Config, opts)
  end
end
