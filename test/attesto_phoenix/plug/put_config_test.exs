defmodule AttestoPhoenix.Plug.PutConfigTest do
  use ExUnit.Case, async: false

  import Plug.Conn, only: [put_private: 3]
  import Plug.Test, only: [conn: 2]

  alias Attesto.PrincipalKind
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Plug.PutConfig
  alias Plug.Conn.WrapperError

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

  defmodule ScopedController do
    use AttestoPhoenix.Controller, formats: [:json]

    def success(conn, _params) do
      send(self(), {:scoped_config, Config.request_config()})
      conn
    end

    def halt(conn, _params) do
      send(self(), {:scoped_config, Config.request_config()})
      Plug.Conn.halt(conn)
    end

    def raise_error(_conn, _params) do
      send(self(), {:scoped_config, Config.request_config()})
      raise "scoped action failed"
    end

    def throw_error(_conn, _params) do
      send(self(), {:scoped_config, Config.request_config()})
      throw(:scoped_action_throw)
    end

    def exit_error(_conn, _params) do
      send(self(), {:scoped_config, Config.request_config()})
      exit(:scoped_action_exit)
    end
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

    refute Config.request_config()

    assert Config.request_config() == nil
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

    error =
      assert_raise ArgumentError, ~r/expected conn\.private\[:attesto_phoenix_config\]/, fn ->
        PutConfig.call(input, PutConfig.init(otp_app: @otp_app))
      end

    refute error.message =~ "wrong"
  end

  test "fails closed without exposing a malformed protocol config" do
    input = put_private(conn(:get, "/"), :attesto_protocol_config, %{secret: "sensitive-value"})

    error =
      assert_raise ArgumentError, ~r/expected conn\.private\[:attesto_protocol_config\]/, fn ->
        PutConfig.call(input, PutConfig.init(otp_app: @otp_app))
      end

    refute error.message =~ "sensitive-value"
  end

  test "installs the request prefix from a correctly typed private config" do
    host_config = Config.new(host_options(schema_prefix: "request_prefix"))

    _result =
      conn(:get, "/")
      |> put_private(:attesto_phoenix_config, host_config)
      |> PutConfig.call(PutConfig.init(otp_app: @otp_app))

    refute Config.request_config()

    assert Config.request_config() == nil
  end

  test "requires an otp_app source" do
    Application.delete_env(:attesto_phoenix, :otp_app)

    assert_raise ArgumentError, ~r/requires the :otp_app plug option/, fn ->
      PutConfig.call(conn(:get, "/"), PutConfig.init([]))
    end
  end

  test "controller actions bind private config only for bounded success and halt work" do
    config = Config.new(host_options(schema_prefix: "request_prefix"))

    for action <- [:success, :halt] do
      input = put_private(conn(:get, "/"), :attesto_phoenix_config, config)
      result = ScopedController.call(input, action)

      assert_receive {:scoped_config, ^config}
      assert result.halted == (action == :halt)
      assert Config.request_config() == nil
    end
  end

  test "controller actions restore request config after raise, throw, and exit" do
    config = Config.new(host_options(schema_prefix: "request_prefix"))

    input = put_private(conn(:get, "/"), :attesto_phoenix_config, config)

    assert_raise WrapperError, ~r/scoped action failed/, fn ->
      ScopedController.call(input, :raise_error)
    end

    assert_receive {:scoped_config, ^config}
    assert Config.request_config() == nil

    assert catch_throw(ScopedController.call(input, :throw_error)) == :scoped_action_throw
    assert_receive {:scoped_config, ^config}
    assert Config.request_config() == nil

    assert catch_exit(ScopedController.call(input, :exit_error)) == :scoped_action_exit
    assert_receive {:scoped_config, ^config}
    assert Config.request_config() == nil
  end

  defp host_options(overrides \\ []) do
    Keyword.merge(
      [
        issuer: "https://issuer.example",
        audience: "https://resource.example",
        keystore: Keystore,
        repo: Repo,
        schema_prefix: "put_config_prefix",
        load_client: fn _client_id -> :error end,
        verify_client_secret: fn _client, _secret -> false end,
        load_principal: fn _subject -> {:error, :not_found} end,
        principal_kinds: [PrincipalKind.new("user", "usr_")]
      ],
      overrides
    )
  end

  defp restore_env(app, key, :missing), do: Application.delete_env(app, key)
  defp restore_env(app, key, value), do: Application.put_env(app, key, value)
end
