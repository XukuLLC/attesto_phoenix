defmodule AttestoPhoenix.JwtVcIssuerMetadataTestRouter do
  @moduledoc false
  use Phoenix.Router
  use AttestoPhoenix.Router

  scope "/" do
    attesto_routes(prefix: "/wallet", credential_issuance: true)
  end
end

defmodule AttestoPhoenix.Controller.JwtVcIssuerMetadataControllerTest do
  @moduledoc false

  use AttestoPhoenix.ConnCase, endpoint: AttestoPhoenix.JwtVcIssuerMetadataTestRouter

  alias Attesto.{Key, SdJwtVc}
  alias AttestoPhoenix.Config

  @issuer "https://issuer.example"
  @metadata_path "/.well-known/jwt-vc-issuer"
  @vct "https://credentials.example/UniversityDegreeCredential"

  defmodule Keystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @signing_pem JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_pem() |> elem(1)

    @impl true
    def signing_pem, do: @signing_pem

    @impl true
    def verification_pems, do: [@signing_pem]
  end

  defmodule VcKeystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @signing_pem JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_pem() |> elem(1)

    @impl true
    def signing_pem, do: @signing_pem

    @impl true
    def verification_pems, do: [@signing_pem]
  end

  setup do
    Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)

    Application.put_env(:attesto_phoenix, Config,
      issuer: @issuer,
      audience: @issuer,
      keystore: Keystore,
      vc_keystore: VcKeystore,
      repo: __MODULE__.Repo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end
    )

    on_exit(fn ->
      Application.delete_env(:attesto_phoenix, Config)
      Application.delete_env(:attesto_phoenix, :otp_app)
    end)

    :ok
  end

  test "GET publishes the VC signing key at the root well-known path", %{conn: conn} do
    response = get(conn, @metadata_path)
    body = JSON.decode!(response.resp_body)

    assert response.status == 200
    assert body["issuer"] == @issuer
    assert get_resp_header(response, "cache-control") == ["public, max-age=3600"]
    assert [content_type] = get_resp_header(response, "content-type")
    assert content_type =~ "application/json"

    assert %{"jwks" => %{"keys" => keys}} = body

    vc_kid = Key.kid(VcKeystore.signing_pem())
    main_kid = Key.kid(Keystore.signing_pem())

    assert %{"alg" => "ES256", "crv" => "P-256", "kid" => ^vc_kid, "kty" => "EC"} =
             vc_jwk = Enum.find(keys, &(&1["kid"] == vc_kid))

    refute Map.has_key?(vc_jwk, "d")
    refute Enum.any?(keys, &(&1["kid"] == main_kid))

    credential =
      SdJwtVc.issue(
        iss: @issuer,
        vct: @vct,
        pem: Config.resolve!() |> Config.vc_signing_pem(),
        claims: %{"degree" => "Bachelor"}
      )

    assert {:ok, verified} = SdJwtVc.verify(credential, vc_jwk, accepted_algs: ["ES256"])
    assert verified.iss == @issuer
    assert verified.vct == @vct
    assert verified.claims["degree"] == "Bachelor"
  end
end
