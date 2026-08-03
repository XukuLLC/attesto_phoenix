defmodule AttestoPhoenix.Controller.CredentialOfferControllerTest do
  @moduledoc false
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias Attesto.CredentialOfferStore.ETS, as: CredentialOfferStore
  alias AttestoPhoenix.Config

  @issuer "https://issuer.example"
  @oauth_prefix "/oauth"
  @credential_offer_path @oauth_prefix <> Config.credential_offer_tail()

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
    start_supervised!(CredentialOfferStore)
    CredentialOfferStore.reset()

    put_config(
      issuer: @issuer,
      audience: @issuer,
      keystore: StubKeystore,
      repo: __MODULE__.Repo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      require_https: false,
      credential_offer_store: CredentialOfferStore
    )

    on_exit(fn ->
      Application.delete_env(:attesto_phoenix, Config)
      Application.delete_env(:attesto_phoenix, :otp_app)
    end)

    :ok
  end

  describe "GET /credential_offer/:id" do
    test "serves a stored offer by reference and matches the put value" do
      offer = %{
        "credential_issuer" => @issuer,
        "credential_configuration_ids" => ["UniversityDegreeCredential"]
      }

      :ok =
        CredentialOfferStore.put(%{
          id: "offer-123",
          offer: offer,
          expires_at: System.system_time(:second) + 60
        })

      response = CredentialRouter.call(conn(:get, @credential_offer_path <> "/offer-123"), [])

      assert response.status == 200
      assert get_resp_header(response, "cache-control") == ["no-store"]
      assert get_resp_header(response, "pragma") == ["no-cache"]
      assert body(response) == offer
    end

    test "returns 404 for an unknown offer id" do
      response = CredentialRouter.call(conn(:get, @credential_offer_path <> "/never-stored"), [])

      assert response.status == 404
    end

    test "returns 404 for an expired offer" do
      offer = %{
        "credential_issuer" => @issuer,
        "credential_configuration_ids" => ["UniversityDegreeCredential"]
      }

      :ok =
        CredentialOfferStore.put(%{
          id: "offer-expired",
          offer: offer,
          expires_at: System.system_time(:second) - 1
        })

      response = CredentialRouter.call(conn(:get, @credential_offer_path <> "/offer-expired"), [])

      assert response.status == 404
    end
  end

  defp put_config(opts) do
    Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)
    Application.put_env(:attesto_phoenix, Config, opts)
  end

  defp body(conn), do: JSON.decode!(conn.resp_body)
end
