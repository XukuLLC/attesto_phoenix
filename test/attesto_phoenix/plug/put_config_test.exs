defmodule AttestoPhoenix.Plug.PutConfigTest do
  use ExUnit.Case, async: false

  import Plug.Conn, only: [put_private: 3]
  import Plug.Test, only: [conn: 2]

  alias Attesto.PrincipalKind
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Plug.PutConfig

  @otp_app :attesto_phoenix_put_config_test

  defmodule Keystore do
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem, do: "test-only"

    @impl true
    def verification_pems, do: ["test-only"]
  end

  defmodule Repo do
  end

  setup do
    previous_host_config = Application.get_env(@otp_app, Config, :missing)
    previous_otp_app = Application.get_env(:attesto_phoenix, :otp_app, :missing)

    Application.put_env(@otp_app, Config, host_options())

    on_exit(fn ->
      restore_env(@otp_app, Config, previous_host_config)
      restore_env(:attesto_phoenix, :otp_app, previous_otp_app)
    end)

    :ok
  end

  test "loads and installs the host and derived protocol configs" do
    result = PutConfig.call(conn(:get, "/oauth/authorize"), PutConfig.init(otp_app: @otp_app))

    assert %Config{issuer: "https://issuer.example", repo: Repo} =
             result.private[:attesto_phoenix_config]

    assert %Attesto.Config{
             issuer: "https://issuer.example",
             audience: "https://resource.example",
             keystore: Keystore
           } = result.private[:attesto_protocol_config]
  end

  test "uses the globally configured otp_app when the plug option is omitted" do
    Application.put_env(:attesto_phoenix, :otp_app, @otp_app)

    result = PutConfig.call(conn(:get, "/"), PutConfig.init([]))

    assert %Config{} = result.private[:attesto_phoenix_config]
    assert %Attesto.Config{} = result.private[:attesto_protocol_config]
  end

  test "preserves correctly typed request-specific configs" do
    Application.delete_env(:attesto_phoenix, :otp_app)
    host_config = Config.new(host_options())
    protocol_config = Config.to_attesto_config(host_config)

    result =
      conn(:get, "/")
      |> put_private(:attesto_phoenix_config, host_config)
      |> put_private(:attesto_protocol_config, protocol_config)
      |> PutConfig.call(PutConfig.init([]))

    assert result.private[:attesto_phoenix_config] === host_config
    assert result.private[:attesto_protocol_config] === protocol_config
  end

  test "fails closed when a reserved private key contains the wrong type" do
    input = put_private(conn(:get, "/"), :attesto_phoenix_config, :wrong)

    assert_raise ArgumentError, ~r/expected conn\.private\[:attesto_phoenix_config\]/, fn ->
      PutConfig.call(input, PutConfig.init(otp_app: @otp_app))
    end
  end

  test "requires an otp_app source" do
    Application.delete_env(:attesto_phoenix, :otp_app)

    assert_raise ArgumentError, ~r/requires the :otp_app plug option/, fn ->
      PutConfig.call(conn(:get, "/"), PutConfig.init([]))
    end
  end

  defp host_options do
    [
      issuer: "https://issuer.example",
      audience: "https://resource.example",
      keystore: Keystore,
      repo: Repo,
      load_client: fn _client_id -> :error end,
      verify_client_secret: fn _client, _secret -> false end,
      load_principal: fn _subject -> {:error, :not_found} end,
      principal_kinds: [PrincipalKind.new("user", "usr_")]
    ]
  end

  defp restore_env(app, key, :missing), do: Application.delete_env(app, key)
  defp restore_env(app, key, value), do: Application.put_env(app, key, value)
end
