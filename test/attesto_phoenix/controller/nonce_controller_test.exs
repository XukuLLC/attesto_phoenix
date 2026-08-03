defmodule AttestoPhoenix.Controller.NonceControllerTest do
  @moduledoc false
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias Attesto.CNonceStore.ETS, as: CNonceStore
  alias AttestoPhoenix.Config

  @issuer "https://issuer.example"
  @oauth_prefix "/oauth"
  @nonce_path @oauth_prefix <> Config.nonce_tail()

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
    start_supervised!(CNonceStore)
    CNonceStore.reset()

    put_config(
      issuer: @issuer,
      audience: @issuer,
      keystore: StubKeystore,
      repo: __MODULE__.Repo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      require_https: false,
      c_nonce_store: CNonceStore
    )

    on_exit(fn ->
      Application.delete_env(:attesto_phoenix, Config)
      Application.delete_env(:attesto_phoenix, :otp_app)
    end)

    :ok
  end

  test "POSTs to the convention-derived nonce path and issues a valid nonce" do
    response = CredentialRouter.call(conn(:post, @nonce_path), [])

    assert response.status == 200
    assert %{"c_nonce" => nonce} = JSON.decode!(response.resp_body)
    assert is_binary(nonce)
    assert CNonceStore.valid?(nonce)
    assert get_resp_header(response, "cache-control") == ["no-store"]
    assert get_resp_header(response, "pragma") == ["no-cache"]
  end

  defp put_config(opts) do
    Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)
    Application.put_env(:attesto_phoenix, Config, opts)
  end
end
