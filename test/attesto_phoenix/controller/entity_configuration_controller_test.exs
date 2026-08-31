defmodule AttestoPhoenix.EntityConfigurationTestRouter do
  @moduledoc false
  use Phoenix.Router
  use AttestoPhoenix.Router

  alias AttestoPhoenix.Plug.PutConfig

  pipeline :attesto_phoenix_config do
    plug PutConfig, otp_app: :attesto_phoenix
  end

  scope "/" do
    attesto_routes(pipeline: :attesto_phoenix_config, prefix: "/auth", federation: true)
  end
end

defmodule AttestoPhoenix.Controller.EntityConfigurationControllerTest do
  @moduledoc false

  use AttestoPhoenix.ConnCase, endpoint: AttestoPhoenix.EntityConfigurationTestRouter

  alias Attesto.Federation.EntityStatement
  alias AttestoPhoenix.Config

  @issuer "https://issuer.example"
  @federation_path "/.well-known/openid-federation"
  @authority_hints ["https://federation.example"]
  @entity_metadata %{
    "openid_credential_issuer" => %{
      "credential_issuer" => @issuer
    }
  }

  defmodule Keystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @pem JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_pem() |> elem(1)

    @impl true
    def signing_pem, do: @pem

    @impl true
    def verification_pems, do: [@pem]
  end

  setup do
    Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)

    Application.put_env(:attesto_phoenix, Config,
      issuer: @issuer,
      audience: @issuer,
      keystore: Keystore,
      repo: __MODULE__.Repo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      principal_kinds: [Attesto.PrincipalKind.new("user", "usr_")],
      federation_authority_hints: @authority_hints,
      federation_entity_metadata: @entity_metadata
    )

    on_exit(fn ->
      Application.delete_env(:attesto_phoenix, Config)
      Application.delete_env(:attesto_phoenix, :otp_app)
    end)

    :ok
  end

  test "GET serves a verifiable self-signed Entity Configuration from the root well-known path", %{conn: conn} do
    response = get(conn, @federation_path)

    assert response.status == 200
    assert get_resp_header(response, "content-type") == ["application/entity-statement+jwt"]

    assert {:ok, claims} = EntityStatement.verify_self_signed(response.resp_body)
    assert claims["iss"] == @issuer
    assert claims["sub"] == @issuer
    assert claims["authority_hints"] == @authority_hints
    assert claims["metadata"] == @entity_metadata
  end
end
