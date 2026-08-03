defmodule AttestoPhoenix.Controller.CredentialIssuerMetadataControllerTest do
  @moduledoc false
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias AttestoPhoenix.Config

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
  end

  defmodule CredentialRouter do
    @moduledoc false
    use Phoenix.Router
    use AttestoPhoenix.Router

    scope "/" do
      attesto_routes(credential_issuance: true)
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

  defp put_config(opts) do
    Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)
    Application.put_env(:attesto_phoenix, Config, opts)
  end
end
