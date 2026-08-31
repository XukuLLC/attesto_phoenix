defmodule AttestoPhoenix.Controller.NonceControllerTest do
  @moduledoc false
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias Attesto.CNonceStore.ETS, as: CNonceStore
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Controller.NonceController
  alias AttestoPhoenix.Plug.PutConfig

  @issuer "https://issuer.example"
  @oauth_prefix "/oauth"
  @nonce_path @oauth_prefix <> Config.nonce_tail()

  defmodule StubKeystore do
    @moduledoc false

    def signing_pem, do: "test-only"
    def verification_pems, do: ["test-only"]
  end

  defmodule InvalidIssueStore do
    @moduledoc false

    def issue, do: return(Process.get({__MODULE__, :result}))

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
      principal_kinds: [Attesto.PrincipalKind.new("user", "usr_")],
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

  test "fails loudly when the c_nonce store returns an invalid nonce" do
    config = Application.fetch_env!(:attesto_phoenix, Config)
    put_config(Keyword.put(config, :c_nonce_store, InvalidIssueStore))

    for invalid <- [nil, "", :error, {:error, "sensitive-result-sentinel"}] do
      Process.put({InvalidIssueStore, :result}, invalid)

      error =
        assert_raise RuntimeError, "c_nonce_store issue callback must return a non-empty binary", fn ->
          NonceController.create(
            put_private(
              conn(:post, @nonce_path),
              :attesto_phoenix_config,
              Config.new(Application.fetch_env!(:attesto_phoenix, Config))
            ),
            %{}
          )
        end

      refute Exception.message(error) =~ "sensitive-result-sentinel"
    end
  end

  test "sanitizes c_nonce issue callback failures while leaving them loud" do
    config = Application.fetch_env!(:attesto_phoenix, Config)
    put_config(Keyword.put(config, :c_nonce_store, InvalidIssueStore))

    for failure <- [
          {:raise, "sensitive-result-sentinel"},
          {:throw, "sensitive-result-sentinel"},
          {:exit, "sensitive-result-sentinel"}
        ] do
      Process.put({InvalidIssueStore, :result}, failure)

      error =
        assert_raise RuntimeError, "c_nonce_store issue callback failed", fn ->
          NonceController.create(
            put_private(
              conn(:post, @nonce_path),
              :attesto_phoenix_config,
              Config.new(Application.fetch_env!(:attesto_phoenix, Config))
            ),
            %{}
          )
        end

      refute Exception.message(error) =~ "sensitive-result-sentinel"
    end
  end

  defp put_config(opts) do
    Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)
    Application.put_env(:attesto_phoenix, Config, opts)
  end
end
