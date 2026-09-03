defmodule Mix.Tasks.AttestoPhoenix.InstallTest do
  @moduledoc """
  Smoke test for the `mix attesto_phoenix.install` Igniter installer.

  The installer's contract is that it is idempotent and re-runnable (see the
  task moduledoc): the first run scaffolds the config, the routes, and the host
  callback modules; a second run on the already-installed project changes
  nothing. These tests drive the task through `Igniter.Test` against a synthetic
  project seeded with a minimal Phoenix-style router, so the suite is
  deterministic and does NOT depend on the `phx_new` Hex archive (which
  `phx_test_project/1` requires). File-level effects are asserted with
  `assert_creates/2`; config/router content is read straight off the rewritten
  source so the test does not depend on the exact unified-diff rendering.
  """

  use ExUnit.Case, async: false

  import Igniter.Test

  alias Attesto.PrincipalKind
  alias AttestoPhoenix.AppEnvSnapshot
  alias AttestoPhoenix.Config, as: PhoenixConfig
  alias AttestoPhoenix.Store.Sweeper
  alias Test.AuthZ.PrincipalStore

  @task "attesto_phoenix.install"

  # The applications configured by test fixtures and the installer task.
  @isolated_apps [:attesto_phoenix, :test]

  # The synthetic project's app is `:test` with module prefix `Test`, so the
  # scaffolded callbacks land under `Test.AuthZ.*` and the router (seeded below)
  # is `TestWeb.Router` at `lib/test_web/router.ex`.
  @client_store_path "lib/test/auth_z/client_store.ex"
  @principal_store_path "lib/test/auth_z/principal_store.ex"
  @scope_policy_path "lib/test/auth_z/scope_policy.ex"
  @consent_policy_path "lib/test/auth_z/consent_policy.ex"
  @registration_store_path "lib/test/auth_z/registration_store.ex"
  @event_sink_path "lib/test/auth_z/event_sink.ex"
  @router_path "lib/test_web/router.ex"
  @application_path "lib/test/application.ex"
  @config_path "config/config.exs"
  @runtime_config_path "config/runtime.exs"

  @mix_fixture """
  defmodule Test.MixProject do
    use Mix.Project

    def project do
      [app: :test, version: "0.1.0", elixir: "~> 1.17", deps: []]
    end

    def application do
      [extra_applications: [:logger], mod: {Test.Application, []}]
    end
  end
  """

  # A minimal `Phoenix.Router` the installer can find and mount into. Seeded as a
  # fixture so the test never shells out to the phx_new generator.
  @router_fixture """
  defmodule TestWeb.Router do
    use Phoenix.Router

    scope "/", TestWeb do
      get "/", PageController, :home
    end
  end
  """

  @application_fixture """
  defmodule Test.Application do
    use Application

    @impl true
    def start(_type, _args) do
      children = [Test.Repo]
      Supervisor.start_link(children, strategy: :one_for_one, name: Test.Supervisor)
    end
  end
  """

  defmodule Keystore do
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem, do: "test-only"

    @impl true
    def verification_pems, do: ["test-only"]
  end

  defmodule GeneratedRepo do
    @moduledoc false
    use GenServer

    def start_link(_opts), do: GenServer.start_link(__MODULE__, :ok)

    @impl true
    def init(:ok), do: {:ok, :ok}
  end

  @old_installer_router_fixture """
  defmodule TestWeb.Router do
    use Phoenix.Router
    use AttestoPhoenix.Router

    scope "/" do
      attesto_routes()
    end
  end
  """

  @prefixed_router_fixture """
  defmodule TestWeb.Router do
    use Phoenix.Router
    use AttestoPhoenix.Router

    scope "/" do
      attesto_routes(prefix: "/mcp")
    end
  end
  """

  @scoped_router_fixture """
  defmodule TestWeb.Router do
    use Phoenix.Router
    use AttestoPhoenix.Router

    scope "/mcp" do
      attesto_routes()
    end
  end
  """

  @scoped_mismatch_router_fixture """
  defmodule TestWeb.Router do
    use Phoenix.Router
    use AttestoPhoenix.Router

    scope "/legacy" do
      attesto_routes(prefix: "/mcp")
    end
  end
  """

  @nested_scoped_router_fixture """
  defmodule TestWeb.Router do
    use Phoenix.Router
    use AttestoPhoenix.Router

    scope "/outer" do
      scope "/inner" do
        attesto_routes()
      end
    end
  end
  """

  @dynamic_scope_router_fixture """
  defmodule TestWeb.Router do
    use Phoenix.Router
    use AttestoPhoenix.Router

    @mount_prefix "/mcp"

    scope @mount_prefix do
      attesto_routes()
    end
  end
  """

  @host_only_scope_router_fixture """
  defmodule TestWeb.Router do
    use Phoenix.Router
    use AttestoPhoenix.Router

    scope host: "auth.example.com" do
      attesto_routes()
    end
  end
  """

  @root_route_prefix_router_fixture """
  defmodule TestWeb.Router do
    use Phoenix.Router
    use AttestoPhoenix.Router

    scope "/" do
      attesto_routes(prefix: "/")
    end
  end
  """

  @old_installer_config_fixture """
  import Config

  config :test, AttestoPhoenix.Config,
    issuer: "https://issuer.example",
    keystore: Test.AuthZ.Keystore,
    repo: Test.Repo,
    load_client: {Test.AuthZ.ClientStore, :load_client},
    verify_client_secret: {Test.AuthZ.ClientStore, :verify_client_secret},
    load_principal: {Test.AuthZ.PrincipalStore, :load_principal}
  """

  @legacy_table_prefix_config_fixture """
  import Config

  config :test, AttestoPhoenix.Config,
    issuer: "https://issuer.example",
    keystore: Test.AuthZ.Keystore,
    repo: Test.Repo,
    table_prefix: "oauth"
  """

  @existing_schema_prefix_config_fixture """
  import Config

  config :test, AttestoPhoenix.Config,
    schema_prefix: "tenant_auth"
  """

  @existing_oauth_path_prefix_config_fixture """
  import Config

  config :test, AttestoPhoenix.Config,
    oauth_path_prefix: "/tenant/oauth"
  """

  @unsupported_configured_oauth_path_prefix_fixture """
  import Config

  config :test, AttestoPhoenix.Config,
    oauth_path_prefix: "/authorization"
  """

  @dynamic_oauth_path_prefix_config_fixture """
  import Config

  config :test, AttestoPhoenix.Config,
    oauth_path_prefix: System.get_env("ATTESTO_OAUTH_PATH", "/tenant/oauth")
  """

  @multiple_oauth_path_prefix_config_fixture """
  import Config

  config :test, AttestoPhoenix.Config,
    oauth_path_prefix: "/tenant/oauth"
  """

  @omitted_oauth_path_prefix_config_fixture """
  import Config

  config :test, AttestoPhoenix.Config,
    issuer: "https://issuer.example"
  """

  @default_schema_prefix_config_fixture """
  import Config

  config :test, AttestoPhoenix.Config,
    schema_prefix: nil
  """

  @production_schema_prefix_config_fixture """
  import Config

  config :test, AttestoPhoenix.Config,
    schema_prefix: "tenant_prod"
  """

  @same_file_schema_prefix_config_fixture """
  import Config

  config :test, AttestoPhoenix.Config,
    schema_prefix: nil

  config :test, AttestoPhoenix.Config,
    schema_prefix: "tenant_prod"
  """

  @duplicate_keyword_schema_prefix_config_fixture """
  import Config

  config :test, AttestoPhoenix.Config,
    schema_prefix: nil,
    schema_prefix: "tenant_prod"
  """

  @split_schema_prefix_config_fixture """
  import Config

  config :test, AttestoPhoenix.Config,
    schema_prefix: "tenant_auth"

  config :test, AttestoPhoenix.Config,
    issuer: "https://issuer.example"
  """

  @reverse_split_schema_prefix_config_fixture """
  import Config

  config :test, AttestoPhoenix.Config,
    issuer: "https://issuer.example"

  config :test, AttestoPhoenix.Config,
    schema_prefix: "tenant_auth"
  """

  @partial_only_schema_config_fixture """
  import Config

  config :test, AttestoPhoenix.Config,
    issuer: "https://issuer.example"

  config :test, AttestoPhoenix.Config,
    audience: "https://api.example"
  """

  @invalid_schema_prefix_config_fixture """
  import Config

  config :test, AttestoPhoenix.Config,
    schema_prefix: 42
  """

  @string_schema_prefix_map_config_fixture ~S"""
  import Config

  config :test, AttestoPhoenix.Config, %{"schema_prefix" => "tenant_auth"}
  """

  @dynamic_schema_prefix_config_fixture """
  import Config

  config :test, AttestoPhoenix.Config,
    Keyword.merge([schema_prefix: "tenant_auth"], Application.get_env(:test, :schema_options, []))
  """

  @aliased_schema_prefix_config_fixture """
  import Config

  alias AttestoPhoenix.Config, as: PhoenixConfig

  config :test, PhoenixConfig,
    schema_prefix: "tenant_auth"
  """

  @elixir_qualified_config_fixture """
  import Config

  config :test, Elixir.AttestoPhoenix.Config,
    schema_prefix: "tenant_auth",
    oauth_path_prefix: "/tenant/oauth"
  """

  @elixir_qualified_alias_config_fixture """
  import Config

  alias Elixir.AttestoPhoenix.Config, as: APC

  config :test, APC,
    schema_prefix: "tenant_auth",
    oauth_path_prefix: "/tenant/oauth"
  """

  @remote_config_fixture """
  import Config

  Config.config(:test, AttestoPhoenix.Config,
    schema_prefix: "tenant_auth",
    oauth_path_prefix: "/tenant/oauth"
  )
  """

  @elixir_remote_config_fixture """
  import Config

  Elixir.Config.config(:test, AttestoPhoenix.Config,
    schema_prefix: "tenant_auth",
    oauth_path_prefix: "/tenant/oauth"
  )
  """

  @aliased_remote_config_fixture """
  import Config

  alias Config, as: AppConfig

  AppConfig.config(:test, AttestoPhoenix.Config,
    schema_prefix: "tenant_auth",
    oauth_path_prefix: "/tenant/oauth"
  )
  """

  @chained_namespace_alias_config_fixture """
  import Config

  alias AttestoPhoenix, as: AP
  alias AP.Config, as: APC

  Config.config(:test, APC,
    schema_prefix: "tenant_auth",
    oauth_path_prefix: "/tenant/oauth"
  )
  """

  @unrelated_fully_qualified_config_fixture """
  import Config

  config :test, OtherApp.Config,
    schema_prefix: "other_schema",
    oauth_path_prefix: "/other/oauth"
  """

  @conditional_if_schema_prefix_config_fixture """
  import Config

  config :test, AttestoPhoenix.Config,
    issuer: "https://issuer.example"

  if config_env() == :prod do
    config :test, AttestoPhoenix.Config,
      schema_prefix: "tenant_auth"
  end
  """

  @conditional_if_oauth_path_prefix_config_fixture """
  import Config

  config :test, AttestoPhoenix.Config,
    issuer: "https://issuer.example"

  if config_env() == :prod do
    config :test, AttestoPhoenix.Config,
      oauth_path_prefix: "/tenant/oauth"
  end
  """

  @conditional_case_schema_prefix_config_fixture """
  import Config

  config :test, AttestoPhoenix.Config,
    issuer: "https://issuer.example"

  case config_env() do
    :prod ->
      config :test, AttestoPhoenix.Config,
        schema_prefix: "tenant_auth"

    _other ->
      config :test, AttestoPhoenix.Config,
        schema_prefix: nil
  end
  """

  @conditional_case_oauth_path_prefix_config_fixture """
  import Config

  config :test, AttestoPhoenix.Config,
    issuer: "https://issuer.example"

  case config_env() do
    :prod ->
      config :test, AttestoPhoenix.Config,
        oauth_path_prefix: "/tenant/oauth"

    _other ->
      config :test, AttestoPhoenix.Config,
        oauth_path_prefix: "/oauth"
  end
  """

  @conditional_runtime_schema_prefix_config_fixture """
  import Config

  config :test, AttestoPhoenix.Config,
    issuer: "https://issuer.example"

  if config_env() == :prod do
    config :test, AttestoPhoenix.Config,
      schema_prefix: "tenant_auth"
  end
  """

  @conditional_runtime_oauth_path_prefix_config_fixture """
  import Config

  config :test, AttestoPhoenix.Config,
    issuer: "https://issuer.example"

  if config_env() == :prod do
    config :test, AttestoPhoenix.Config,
      oauth_path_prefix: "/tenant/oauth"
  end
  """

  @conditional_nested_namespace_alias_schema_fixture """
  import Config

  if config_env() == :prod do
    alias AttestoPhoenix, as: AP
    config :test, AP.Config,
      schema_prefix: "tenant_auth"
  end
  """

  @conditional_nested_namespace_alias_oauth_fixture """
  import Config

  case config_env() do
    :prod ->
      alias AttestoPhoenix, as: AP
      config :test, AP.Config,
        oauth_path_prefix: "/tenant/oauth"

    _other ->
      :ok
  end
  """

  @nested_function_schema_prefix_config_fixture """
  import Config

  defmodule Helper do
    def apply do
      config :test, AttestoPhoenix.Config,
        schema_prefix: "tenant_auth"
    end
  end
  """

  @nested_function_oauth_path_prefix_config_fixture """
  import Config

  defmodule Helper do
    def apply do
      config :test, AttestoPhoenix.Config,
        oauth_path_prefix: "/tenant/oauth"
    end
  end
  """

  @nested_quote_schema_prefix_config_fixture """
  import Config

  quote do
    config :test, AttestoPhoenix.Config,
      schema_prefix: "tenant_auth"
  end
  """

  @nested_quote_oauth_path_prefix_config_fixture """
  import Config

  quote do
    config :test, AttestoPhoenix.Config,
      oauth_path_prefix: "/tenant/oauth"
  end
  """

  @alias_after_config_prefixes_fixture """
  import Config

  config :test, APC,
    schema_prefix: "tenant_auth",
    oauth_path_prefix: "/tenant/oauth"

  alias AttestoPhoenix.Config, as: APC
  """

  @nested_alias_schema_prefix_fixture """
  import Config

  defmodule AliasHolder do
    alias AttestoPhoenix.Config, as: APC
    def config_module, do: APC
  end

  config :test, APC,
    schema_prefix: "tenant_auth"
  """

  @nested_alias_oauth_path_prefix_fixture """
  import Config

  defmodule AliasHolder do
    alias AttestoPhoenix.Config, as: APC
    def config_module, do: APC
  end

  config :test, APC,
    oauth_path_prefix: "/tenant/oauth"
  """

  @quoted_alias_schema_prefix_fixture """
  import Config

  quote do
    alias AttestoPhoenix.Config, as: APC
  end

  config :test, APC,
    schema_prefix: "tenant_auth"
  """

  @quoted_alias_oauth_path_prefix_fixture """
  import Config

  quote do
    alias AttestoPhoenix.Config, as: APC
  end

  config :test, APC,
    oauth_path_prefix: "/tenant/oauth"
  """

  @ambiguous_schema_prefix_module_fixture """
  import Config

  config :test, PhoenixConfig,
    schema_prefix: "tenant_auth"
  """

  @dynamic_schema_prefix_module_fixture """
  import Config

  config :test, Module.concat([AttestoPhoenix, :Config]),
    schema_prefix: "tenant_auth"
  """

  @dynamic_schema_prefix_app_fixture """
  import Config

  config Application.get_env(:test, :otp_app, :test), AttestoPhoenix.Config,
    schema_prefix: "tenant_auth"
  """

  @two_argument_config_fixture """
  import Config

  config :test,
    [{AttestoPhoenix.Config,
      [schema_prefix: "tenant_auth", oauth_path_prefix: "/tenant/oauth"]}]
  """

  @package_legacy_keyword_config_fixture """
  import Config

  config :attesto_phoenix, table_prefix: "oauth_"
  """

  @package_legacy_key_config_fixture """
  import Config

  config :attesto_phoenix, :table_prefix, "oauth_"
  """

  @existing_runtime_secret_fixture """
  import Config

  config :attesto_phoenix, refresh_successor_secret: "host-supplied-development-value"
  """

  @existing_config_secret_fixture """
  import Config

  config :attesto_phoenix, refresh_successor_secret: "host-supplied-config-value"
  """

  @existing_prod_secret_fixture """
  import Config

  config :attesto_phoenix, refresh_successor_secret: "host-supplied-prod-value"
  """

  @existing_imported_config_fixture """
  import Config

  import_config "nested/attesto.exs"
  """

  @existing_nested_secret_fixture """
  import Config

  config :attesto_phoenix, refresh_successor_secret: "host-supplied-imported-value"
  """

  @old_principal_store_fixture """
  defmodule Test.AuthZ.PrincipalStore do
    @behaviour AttestoPhoenix.PrincipalStore

    @impl true
    def load_principal(_subject_id), do: {:error, :not_found}

    @impl true
    def build_principal(_subject, _client, _scopes), do: %{}
  end
  """

  defp project do
    test_project(
      files: %{
        "mix.exs" => @mix_fixture,
        @router_path => @router_fixture,
        @application_path => @application_fixture
      }
    )
  end

  setup do
    AppEnvSnapshot.ensure_unset!([
      {:attesto_phoenix, AttestoPhoenix.Config},
      {:attesto_phoenix, :otp_app},
      {:attesto_phoenix, :table_prefix},
      {:test, AttestoPhoenix.Config}
    ])

    snapshot = AppEnvSnapshot.snapshot(@isolated_apps)
    on_exit(fn -> AppEnvSnapshot.restore(snapshot) end)

    :ok
  end

  describe "first run" do
    test "scaffolds the config, the callback modules, and mounts the routes" do
      igniter = Igniter.compose_task(project(), @task, [])

      # One scaffolded host module per recommended behaviour.
      igniter
      |> assert_creates(@client_store_path)
      |> assert_creates(@principal_store_path)
      |> assert_creates(@scope_policy_path)
      |> assert_creates(@consent_policy_path)
      |> assert_creates(@registration_store_path)
      |> assert_creates(@event_sink_path)

      applied = apply_igniter!(igniter)

      # The AttestoPhoenix.Config skeleton is written under the host's otp_app.
      config = source_content(applied, @config_path)
      assert config =~ "config :test, AttestoPhoenix.Config"
      assert config =~ "config :attesto_phoenix"
      assert config =~ "otp_app: :test"
      assert config =~ "repo: Test.Repo"
      assert config =~ "audience:"
      assert config =~ "principal_kinds: {Test.AuthZ.PrincipalStore, :principal_kinds}"
      assert config =~ "oauth_path_prefix: \"/oauth\""
      assert config =~ "schema_prefix:"
      assert config =~ "code_store: AttestoPhoenix.Store.EctoCodeStore"
      assert config =~ "load_client: {Test.AuthZ.ClientStore, :load_client}"

      runtime_config = source_content(applied, @runtime_config_path)
      assert runtime_config =~ "ATTESTO_REFRESH_SUCCESSOR_SECRET"
      assert runtime_config =~ "config_env() in [:dev, :test]"
      refute runtime_config =~ "development-only"

      application = source_content(applied, @application_path)
      assert application =~ "AttestoPhoenix.Store.Sweeper"
      assert application =~ "AttestoPhoenix.Config.from_otp_app(:test)"
      assert application =~ "if_configured: true"

      {repo_position, _} = :binary.match(application, "Test.Repo")
      {sweeper_position, _} = :binary.match(application, "AttestoPhoenix.Store.Sweeper")
      assert repo_position < sweeper_position

      # The router gains the server scope mounting attesto_routes/1 and the use.
      router = source_content(applied, @router_path)
      assert router =~ "use AttestoPhoenix.Router"
      assert router =~ "pipeline :attesto_phoenix_config do"
      assert router =~ "plug(AttestoPhoenix.Plug.PutConfig, otp_app: :test)"
      assert router =~ "attesto_routes(pipeline: :attesto_phoenix_config)"

      # A scaffolded module tags the behaviour and stubs each callback.
      client_store = source_content(applied, @client_store_path)
      assert client_store =~ "@behaviour AttestoPhoenix.ClientStore"
      assert client_store =~ "def load_client(_arg1) do"
      assert client_store =~ "def verify_client_secret(_arg1, _arg2) do"

      principal_store = source_content(applied, @principal_store_path)
      assert principal_store =~ "def principal_kinds() do"
    end

    test "generated config contains every value needed to build both configs" do
      applied =
        project()
        |> Igniter.compose_task(@task, [])
        |> apply_igniter!()

      evaluated = Config.Reader.eval!(@config_path, source_content(applied, @config_path))
      host_options = evaluated |> Keyword.fetch!(:test) |> Keyword.fetch!(PhoenixConfig)
      library_options = Keyword.fetch!(evaluated, :attesto_phoenix)

      # The installer writes callback modules and config in one source rewrite;
      # the modules are not loaded until the host's normal compilation step.
      # Config.new/1 intentionally rejects unloadable MFAs, so compile the
      # generated callback sources here before exercising the post-install
      # validation path.
      compile_generated_callbacks(applied)

      assert library_options[:otp_app] == :test
      assert library_options[:repo] == Test.Repo

      host_config =
        PhoenixConfig.new(
          Keyword.merge(host_options,
            keystore: Keystore,
            principal_kinds: [PrincipalKind.new("user", "usr_")],
            load_client: fn _client_id -> {:error, :not_found} end,
            verify_client_secret: fn _client, _secret -> false end,
            load_principal: fn _subject -> {:error, :not_found} end
          )
        )

      assert %PhoenixConfig{repo: Test.Repo} = host_config
      assert %Attesto.Config{keystore: Keystore} = PhoenixConfig.to_attesto_config(host_config)
    end

    test "generated runtime config defers the conditional secret requirement to Config" do
      original = System.get_env("ATTESTO_REFRESH_SUCCESSOR_SECRET")
      System.delete_env("ATTESTO_REFRESH_SUCCESSOR_SECRET")

      on_exit(fn ->
        if is_nil(original) do
          System.delete_env("ATTESTO_REFRESH_SUCCESSOR_SECRET")
        else
          System.put_env("ATTESTO_REFRESH_SUCCESSOR_SECRET", original)
        end
      end)

      applied =
        project()
        |> Igniter.compose_task(@task, [])
        |> apply_igniter!()

      runtime = source_content(applied, @runtime_config_path)
      refute runtime =~ "System.fetch_env!(\"ATTESTO_REFRESH_SUCCESSOR_SECRET\")"

      test_config = Config.Reader.eval!(@runtime_config_path, runtime, env: :test)

      test_secret = test_config[:attesto_phoenix][:refresh_successor_secret]
      assert is_binary(test_secret)
      assert {:ok, decoded_secret} = Base.url_decode64(test_secret, padding: false)
      assert byte_size(decoded_secret) >= 32

      prod_config = Config.Reader.eval!(@runtime_config_path, runtime, env: :prod)
      assert is_nil(prod_config[:attesto_phoenix][:refresh_successor_secret])

      staging_config = Config.Reader.eval!(@runtime_config_path, runtime, env: :staging)
      assert is_nil(staging_config[:attesto_phoenix][:refresh_successor_secret])

      System.put_env("ATTESTO_REFRESH_SUCCESSOR_SECRET", "short")

      short_config = Config.Reader.eval!(@runtime_config_path, runtime, env: :prod)
      assert short_config[:attesto_phoenix][:refresh_successor_secret] == "short"

      secret = String.duplicate("production-secret-", 2)
      System.put_env("ATTESTO_REFRESH_SUCCESSOR_SECRET", secret)

      prod_config = Config.Reader.eval!(@runtime_config_path, runtime, env: :prod)
      assert prod_config[:attesto_phoenix][:refresh_successor_secret] == secret
    end

    test "honors a relocated --oauth-path-prefix" do
      applied =
        project()
        |> Igniter.compose_task(@task, ["--oauth-path-prefix", "/mcp/oauth"])
        |> apply_igniter!()

      assert source_content(applied, @config_path) =~ "oauth_path_prefix: \"/mcp/oauth\""

      assert source_content(applied, @router_path) =~
               "attesto_routes(prefix: \"/mcp\", pipeline: :attesto_phoenix_config)"
    end

    test "requires an explicit oauth path to match existing host config" do
      igniter =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @existing_oauth_path_prefix_config_fixture
          }
        )

      router_before = source_content(igniter, @router_path)

      assert_raise Mix.Error, ~r/--oauth-path-prefix.*does not match.*tenant\/oauth/, fn ->
        Igniter.compose_task(igniter, @task, ["--oauth-path-prefix", "/mcp/oauth"])
      end

      assert source_content(igniter, @router_path) == router_before
      refute Igniter.exists?(igniter, @client_store_path)
    end

    test "allows an explicit oauth path that matches existing host config" do
      applied =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @existing_oauth_path_prefix_config_fixture
          }
        )
        |> Igniter.compose_task(@task, ["--oauth-path-prefix", "/tenant/oauth"])
        |> apply_igniter!()

      assert source_content(applied, @router_path) =~
               "attesto_routes(prefix: \"/tenant\", pipeline: :attesto_phoenix_config)"
    end

    test "does not let an explicit oauth path bypass dynamic host config" do
      igniter =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @dynamic_oauth_path_prefix_config_fixture
          }
        )

      assert_raise Mix.Error, ~r/could not determine configured :oauth_path_prefix expression/, fn ->
        Igniter.compose_task(igniter, @task, ["--oauth-path-prefix", "/mcp/oauth"])
      end

      refute Igniter.exists?(igniter, @client_store_path)
    end

    test "does not let an explicit oauth path bypass multiple host config values" do
      igniter =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @multiple_oauth_path_prefix_config_fixture,
            "config/prod.exs" =>
              String.replace(@multiple_oauth_path_prefix_config_fixture, "/tenant/oauth", "/mcp/oauth")
          }
        )

      assert_raise Mix.Error, ~r/multiple literal values.*compiled route/, fn ->
        Igniter.compose_task(igniter, @task, ["--oauth-path-prefix", "/mcp/oauth"])
      end

      refute Igniter.exists?(igniter, @client_store_path)
    end

    test "treats an omitted oauth path as the default when comparing config sources" do
      files = %{
        "mix.exs" => @mix_fixture,
        @router_path => @router_fixture,
        @application_path => @application_fixture,
        @config_path => @omitted_oauth_path_prefix_config_fixture,
        "config/prod.exs" => @existing_oauth_path_prefix_config_fixture
      }

      assert_raise Mix.Error, ~r/multiple literal values.*oauth/, fn ->
        Igniter.compose_task(test_project(files: files), @task, [])
      end
    end

    test "rejects an explicit oauth path when omitted and explicit config sources disagree" do
      files = %{
        "mix.exs" => @mix_fixture,
        @router_path => @router_fixture,
        @application_path => @application_fixture,
        @config_path => @omitted_oauth_path_prefix_config_fixture,
        "config/prod.exs" => @existing_oauth_path_prefix_config_fixture
      }

      igniter = test_project(files: files)
      router_before = source_content(igniter, @router_path)

      assert_raise Mix.Error, ~r/multiple literal values.*compiled route/, fn ->
        Igniter.compose_task(igniter, @task, ["--oauth-path-prefix", "/tenant/oauth"])
      end

      assert source_content(igniter, @router_path) == router_before
      refute Igniter.exists?(igniter, @client_store_path)
    end

    test "flagless rerun preserves a relocated oauth path prefix" do
      first =
        project()
        |> Igniter.compose_task(@task, ["--oauth-path-prefix", "/mcp/oauth"])
        |> apply_igniter!()

      first
      |> Igniter.compose_task(@task, [])
      |> assert_unchanged()
    end

    test "rejects a prefix with endpoint tails the bundled router does not mount" do
      igniter = project()
      router_before = source_content(igniter, @router_path)

      assert_raise Mix.Error, ~r/unsupported --oauth-path-prefix.*manual/, fn ->
        Igniter.compose_task(igniter, @task, ["--oauth-path-prefix", "/auth"])
      end

      assert source_content(igniter, @router_path) == router_before
      refute Igniter.exists?(igniter, @client_store_path)
    end

    test "rejects unsafe oauth prefixes before mutating the project" do
      for invalid_prefix <- [
            "/mcp/quote\"/oauth",
            "/mcp/new\nline/oauth",
            "/mcp/./oauth",
            "/mcp/../oauth",
            "/mcp/oauth?tenant=one",
            "/mcp/oauth#fragment",
            "/mcp/back\\slash/oauth",
            "/mcp/space /oauth",
            "/mcp//oauth"
          ] do
        igniter = project()
        router_before = source_content(igniter, @router_path)

        assert_raise Mix.Error, ~r/unsupported --oauth-path-prefix.*manual/, fn ->
          Igniter.compose_task(igniter, @task, ["--oauth-path-prefix", invalid_prefix])
        end

        assert source_content(igniter, @router_path) == router_before
        refute Igniter.exists?(igniter, @client_store_path)
      end
    end

    test "refuses an unsupported configured :oauth_path_prefix without naming a flag" do
      igniter =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @unsupported_configured_oauth_path_prefix_fixture
          }
        )

      config_before = source_content(igniter, @config_path)

      error =
        assert_raise Mix.Error, fn ->
          Igniter.compose_task(igniter, @task, [])
        end

      assert error.message =~ "configured :oauth_path_prefix"
      assert error.message =~ "/authorization"
      refute error.message =~ ~s|--oauth-path-prefix "/authorization"|
      assert source_content(igniter, @config_path) == config_before
      refute Igniter.exists?(igniter, @client_store_path)
    end

    test "normalizes one trailing slash on a supported oauth prefix" do
      applied =
        project()
        |> Igniter.compose_task(@task, ["--oauth-path-prefix", "/mcp/oauth/"])
        |> apply_igniter!()

      assert source_content(applied, @config_path) =~ "oauth_path_prefix: \"/mcp/oauth\""

      assert source_content(applied, @router_path) =~
               "attesto_routes(prefix: \"/mcp\", pipeline: :attesto_phoenix_config)"
    end

    test "refuses a custom prefix that disagrees with an existing route mount" do
      igniter =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @old_installer_router_fixture,
            @application_path => @application_fixture
          }
        )

      router_before = source_content(igniter, @router_path)

      assert_raise Mix.Error, ~r/existing attesto_routes.*expects.*manual/, fn ->
        Igniter.compose_task(igniter, @task, ["--oauth-path-prefix", "/mcp/oauth"])
      end

      assert source_content(igniter, @router_path) == router_before
      refute Igniter.exists?(igniter, @client_store_path)
    end

    test "keeps a supported custom prefix aligned with an existing route mount" do
      applied =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @prefixed_router_fixture,
            @application_path => @application_fixture
          }
        )
        |> Igniter.compose_task(@task, ["--oauth-path-prefix", "/mcp/oauth"])
        |> apply_igniter!()

      assert source_content(applied, @config_path) =~ "oauth_path_prefix: \"/mcp/oauth\""
      assert source_content(applied, @router_path) =~ "attesto_routes(prefix: \"/mcp\""
    end

    test "accounts for a non-root enclosing scope when validating an existing route" do
      applied =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @scoped_router_fixture,
            @application_path => @application_fixture
          }
        )
        |> Igniter.compose_task(@task, ["--oauth-path-prefix", "/mcp/oauth"])
        |> apply_igniter!()

      assert source_content(applied, @config_path) =~ "oauth_path_prefix: \"/mcp/oauth\""
    end

    test "rejects a non-root scope and macro prefix combination that disagrees" do
      igniter =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @scoped_mismatch_router_fixture,
            @application_path => @application_fixture
          }
        )

      router_before = source_content(igniter, @router_path)

      assert_raise Mix.Error, ~r/existing attesto_routes.*expects.*manual/, fn ->
        Igniter.compose_task(igniter, @task, ["--oauth-path-prefix", "/mcp/oauth"])
      end

      assert source_content(igniter, @router_path) == router_before
      refute Igniter.exists?(igniter, @client_store_path)
    end

    test "accounts for nested literal enclosing scopes in declaration order" do
      applied =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @nested_scoped_router_fixture,
            @application_path => @application_fixture
          }
        )
        |> Igniter.compose_task(@task, ["--oauth-path-prefix", "/outer/inner/oauth"])
        |> apply_igniter!()

      assert source_content(applied, @config_path) =~
               "oauth_path_prefix: \"/outer/inner/oauth\""
    end

    test "rejects a reversed nested scope prefix before mutating the project" do
      igniter =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @nested_scoped_router_fixture,
            @application_path => @application_fixture
          }
        )

      router_before = source_content(igniter, @router_path)

      assert_raise Mix.Error, ~r/existing attesto_routes.*expects.*manual/, fn ->
        Igniter.compose_task(igniter, @task, ["--oauth-path-prefix", "/inner/outer/oauth"])
      end

      assert source_content(igniter, @router_path) == router_before
      refute Igniter.exists?(igniter, @client_store_path)
    end

    test "rejects a dynamic enclosing scope before mutating the project" do
      igniter =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @dynamic_scope_router_fixture,
            @application_path => @application_fixture
          }
        )

      router_before = source_content(igniter, @router_path)

      assert_raise Mix.Error, ~r/could not prove the enclosing Phoenix scope/, fn ->
        Igniter.compose_task(igniter, @task, ["--oauth-path-prefix", "/mcp/oauth"])
      end

      assert source_content(igniter, @router_path) == router_before
      refute Igniter.exists?(igniter, @client_store_path)
    end

    test "accepts a host-only enclosing scope as a root path" do
      applied =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @host_only_scope_router_fixture,
            @application_path => @application_fixture
          }
        )
        |> Igniter.compose_task(@task, [])
        |> apply_igniter!()

      assert source_content(applied, @router_path) =~
               "attesto_routes(pipeline: :attesto_phoenix_config)"
    end

    test "accepts a slash-only route prefix as the root path" do
      applied =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @root_route_prefix_router_fixture,
            @application_path => @application_fixture
          }
        )
        |> Igniter.compose_task(@task, [])
        |> apply_igniter!()

      assert source_content(applied, @router_path) =~
               "attesto_routes(prefix: \"/\", pipeline: :attesto_phoenix_config)"
    end

    test "writes an explicit PostgreSQL schema prefix" do
      composed =
        project()
        |> Igniter.compose_task(@task, ["--schema-prefix", "tenant_auth"])

      assert Enum.any?(composed.notices, fn notice ->
               notice =~ "--schema-prefix tenant_auth" and
                 notice =~ "gen.migration --upgrade 3.0 --repo Test.Repo" and
                 notice =~ "gen.migration --upgrade 3.1 --repo Test.Repo" and
                 notice =~ "PostgreSQL schema `tenant_auth`" and
                 notice =~ "{repo, schema_prefix}" and
                 notice =~ "attesto_authorization_codes_code_hash_index" and
                 notice =~ "subscriber" and
                 notice =~ "publisher second"
             end)

      applied =
        composed
        |> apply_igniter!()

      assert source_content(applied, @config_path) =~ "schema_prefix: \"tenant_auth\""
    end

    test "rerun reads an existing configured schema when the flag is omitted" do
      composed =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @existing_schema_prefix_config_fixture
          }
        )
        |> Igniter.compose_task(@task, [])

      assert Enum.any?(composed.notices, fn notice ->
               notice =~ "--schema-prefix tenant_auth" and
                 notice =~ "PostgreSQL schema `tenant_auth`"
             end)

      applied = apply_igniter!(composed)
      assert source_content(applied, @config_path) =~ "schema_prefix: \"tenant_auth\""
    end

    test "rerun accepts an explicit schema prefix only when existing config already matches" do
      composed =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @existing_schema_prefix_config_fixture
          }
        )
        |> Igniter.compose_task(@task, ["--schema-prefix", "tenant_auth"])

      assert Enum.any?(composed.notices, fn notice ->
               notice =~ "--schema-prefix tenant_auth" and
                 notice =~ "PostgreSQL schema \`tenant_auth\`"
             end)

      applied = apply_igniter!(composed)
      assert source_content(applied, @config_path) =~ "schema_prefix: \"tenant_auth\""
    end

    test "partial config calls in the same source do not erase an explicit schema prefix" do
      for config <- [@split_schema_prefix_config_fixture, @reverse_split_schema_prefix_config_fixture] do
        composed =
          test_project(
            files: %{
              "mix.exs" => @mix_fixture,
              @router_path => @router_fixture,
              @application_path => @application_fixture,
              @config_path => config
            }
          )
          |> Igniter.compose_task(@task, [])

        assert Enum.any?(composed.notices, &String.contains?(&1, "--schema-prefix tenant_auth"))
      end
    end

    test "multiple partial config calls in one source retain the omitted/default selection" do
      composed =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @partial_only_schema_config_fixture
          }
        )
        |> Igniter.compose_task(@task, [])

      assert Enum.any?(composed.notices, fn notice ->
               notice =~ "gen.migration --repo Test.Repo" and
                 notice =~ "connection's default search path"
             end)
    end

    test "rerun refuses an explicit schema prefix that differs from existing config" do
      igniter =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @existing_schema_prefix_config_fixture
          }
        )

      config_before = source_content(igniter, @config_path)

      assert_raise Mix.Error, ~r/does not match the existing host configuration.*will not overwrite/s, fn ->
        Igniter.compose_task(igniter, @task, ["--schema-prefix", "other_schema"])
      end

      assert source_content(igniter, @config_path) == config_before
      refute Igniter.exists?(igniter, @client_store_path)
    end

    test "rerun distinguishes an explicit schema from an existing explicit nil" do
      igniter =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @default_schema_prefix_config_fixture
          }
        )

      assert_raise Mix.Error, ~r/does not match the existing host configuration nil/, fn ->
        Igniter.compose_task(igniter, @task, ["--schema-prefix", "tenant_auth"])
      end
    end

    test "rerun refuses a non-public prefix when the existing config omitted the key" do
      igniter =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @old_installer_config_fixture
          }
        )

      assert_raise Mix.Error, ~r/does not match the existing host configuration nil/, fn ->
        Igniter.compose_task(igniter, @task, ["--schema-prefix", "tenant_auth"])
      end

      refute Igniter.exists?(igniter, @client_store_path)
      refute source_content(igniter, @config_path) =~ "schema_prefix:"
    end

    test "reads schema and OAuth prefixes from valid two-argument Config syntax" do
      composed =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @two_argument_config_fixture
          }
        )
        |> Igniter.compose_task(@task, [])

      assert Enum.any?(composed.notices, &String.contains?(&1, "--schema-prefix tenant_auth"))
      assert Enum.any?(composed.notices, &String.contains?(&1, "/tenant/oauth"))

      applied = apply_igniter!(composed)
      config = source_content(applied, @config_path)
      assert config =~ "schema_prefix: \"tenant_auth\""
      assert config =~ "oauth_path_prefix: \"/tenant/oauth\""
    end

    test "resolves a direct AttestoPhoenix.Config alias when reading schema" do
      composed =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @aliased_schema_prefix_config_fixture
          }
        )
        |> Igniter.compose_task(@task, [])

      assert Enum.any?(composed.notices, fn notice ->
               notice =~ "--schema-prefix tenant_auth" and
                 notice =~ "PostgreSQL schema `tenant_auth`"
             end)
    end

    test "recognizes Elixir-qualified Config while preserving routes and notices" do
      composed =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @elixir_qualified_config_fixture
          }
        )
        |> Igniter.compose_task(@task, [])

      assert Enum.any?(composed.notices, fn notice ->
               notice =~ "--schema-prefix tenant_auth" and notice =~ "/tenant/oauth"
             end)

      applied = apply_igniter!(composed)
      config = source_content(applied, @config_path)
      router = source_content(applied, @router_path)

      assert config =~ "schema_prefix: \"tenant_auth\""
      assert config =~ "oauth_path_prefix: \"/tenant/oauth\""
      assert router =~ "attesto_routes(prefix: \"/tenant\", pipeline: :attesto_phoenix_config)"
    end

    test "recognizes an Elixir-qualified Config alias while preserving routes and notices" do
      composed =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @elixir_qualified_alias_config_fixture
          }
        )
        |> Igniter.compose_task(@task, [])

      assert Enum.any?(composed.notices, fn notice ->
               notice =~ "--schema-prefix tenant_auth" and notice =~ "/tenant/oauth"
             end)

      applied = apply_igniter!(composed)
      config = source_content(applied, @config_path)
      router = source_content(applied, @router_path)

      assert config =~ "schema_prefix: \"tenant_auth\""
      assert config =~ "oauth_path_prefix: \"/tenant/oauth\""
      assert router =~ "attesto_routes(prefix: \"/tenant\", pipeline: :attesto_phoenix_config)"
    end

    test "recognizes qualified Config.config calls for both supported module names" do
      for fixture <- [@remote_config_fixture, @elixir_remote_config_fixture, @aliased_remote_config_fixture] do
        composed =
          test_project(
            files: %{
              "mix.exs" => @mix_fixture,
              @router_path => @router_fixture,
              @application_path => @application_fixture,
              @config_path => fixture
            }
          )
          |> Igniter.compose_task(@task, [])

        assert Enum.any?(composed.notices, fn notice ->
                 notice =~ "--schema-prefix tenant_auth" and notice =~ "/tenant/oauth"
               end)
      end
    end

    test "expands chained namespace aliases before reading qualified Config.config" do
      composed =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @chained_namespace_alias_config_fixture
          }
        )
        |> Igniter.compose_task(@task, [])

      assert Enum.any?(composed.notices, fn notice ->
               notice =~ "--schema-prefix tenant_auth" and notice =~ "/tenant/oauth"
             end)
    end

    test "ignores unrelated fully-qualified config modules" do
      composed =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @unrelated_fully_qualified_config_fixture
          }
        )
        |> Igniter.compose_task(@task, [])

      assert Enum.any?(composed.notices, &String.contains?(&1, "connection's default search path"))
      refute Enum.any?(composed.notices, &String.contains?(&1, "other_schema"))

      applied = apply_igniter!(composed)
      assert source_content(applied, @config_path) =~ "schema_prefix: nil"
    end

    test "refuses dynamic schema options before mutating the project" do
      igniter =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @dynamic_schema_prefix_config_fixture
          }
        )

      router_before = source_content(igniter, @router_path)

      assert_raise Mix.Error, ~r/could not determine configured :schema_prefix expression/, fn ->
        Igniter.compose_task(igniter, @task, [])
      end

      assert source_content(igniter, @router_path) == router_before
      refute Igniter.exists?(igniter, @client_store_path)
    end

    test "an explicit prefix cannot bypass dynamic host schema configuration" do
      igniter =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @dynamic_schema_prefix_config_fixture
          }
        )

      assert_raise Mix.Error, ~r/could not determine configured :schema_prefix expression/, fn ->
        Igniter.compose_task(igniter, @task, ["--schema-prefix", "tenant_auth"])
      end

      refute Igniter.exists?(igniter, @client_store_path)
    end

    test "refuses an ambiguous config module alias before mutating the project" do
      igniter =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @ambiguous_schema_prefix_module_fixture
          }
        )

      router_before = source_content(igniter, @router_path)

      assert_raise Mix.Error, ~r/ambiguous config module PhoenixConfig/, fn ->
        Igniter.compose_task(igniter, @task, [])
      end

      assert source_content(igniter, @router_path) == router_before
      refute Igniter.exists?(igniter, @client_store_path)
    end

    test "refuses a dynamic config module before mutating the project" do
      igniter =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @dynamic_schema_prefix_module_fixture
          }
        )

      router_before = source_content(igniter, @router_path)

      assert_raise Mix.Error, ~r/could not determine configured :schema_prefix expression/, fn ->
        Igniter.compose_task(igniter, @task, [])
      end

      assert source_content(igniter, @router_path) == router_before
      refute Igniter.exists?(igniter, @client_store_path)
    end

    test "refuses a dynamic config app before mutating the project" do
      igniter =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @dynamic_schema_prefix_app_fixture
          }
        )

      router_before = source_content(igniter, @router_path)

      assert_raise Mix.Error, ~r/could not determine configured :schema_prefix expression/, fn ->
        Igniter.compose_task(igniter, @task, [])
      end

      assert source_content(igniter, @router_path) == router_before
      refute Igniter.exists?(igniter, @client_store_path)
    end

    test "fails closed for conditional schema config in every config source" do
      fixtures = [
        {@conditional_if_schema_prefix_config_fixture, @config_path},
        {@conditional_case_schema_prefix_config_fixture, @config_path},
        {@conditional_runtime_schema_prefix_config_fixture, @runtime_config_path},
        {@nested_function_schema_prefix_config_fixture, @config_path},
        {@nested_quote_schema_prefix_config_fixture, @config_path}
      ]

      for {fixture, path} <- fixtures, options <- [[], ["--schema-prefix", "tenant_auth"]] do
        igniter =
          test_project(
            files: %{
              "mix.exs" => @mix_fixture,
              @router_path => @router_fixture,
              @application_path => @application_fixture,
              path => fixture
            }
          )

        router_before = source_content(igniter, @router_path)
        source_before = source_content(igniter, path)

        assert_raise Mix.Error,
                     ~r/could not determine configured :schema_prefix expression.*nested config expression/,
                     fn ->
                       Igniter.compose_task(igniter, @task, options)
                     end

        assert source_content(igniter, path) == source_before
        assert source_content(igniter, @router_path) == router_before
        refute Igniter.exists?(igniter, @client_store_path)
      end
    end

    test "fails closed for conditional OAuth config in every config source" do
      fixtures = [
        {@conditional_if_oauth_path_prefix_config_fixture, @config_path},
        {@conditional_case_oauth_path_prefix_config_fixture, @config_path},
        {@conditional_runtime_oauth_path_prefix_config_fixture, @runtime_config_path},
        {@nested_function_oauth_path_prefix_config_fixture, @config_path},
        {@nested_quote_oauth_path_prefix_config_fixture, @config_path}
      ]

      for {fixture, path} <- fixtures, options <- [[], ["--oauth-path-prefix", "/tenant/oauth"]] do
        igniter =
          test_project(
            files: %{
              "mix.exs" => @mix_fixture,
              @router_path => @router_fixture,
              @application_path => @application_fixture,
              path => fixture
            }
          )

        router_before = source_content(igniter, @router_path)
        source_before = source_content(igniter, path)

        assert_raise Mix.Error,
                     ~r/could not determine configured :oauth_path_prefix expression.*nested config expression/,
                     fn ->
                       Igniter.compose_task(igniter, @task, options)
                     end

        assert source_content(igniter, path) == source_before
        assert source_content(igniter, @router_path) == router_before
        refute Igniter.exists?(igniter, @client_store_path)
      end
    end

    test "fails closed for conditional config using a nested namespace alias" do
      fixtures = [
        {@conditional_nested_namespace_alias_schema_fixture, :schema_prefix},
        {@conditional_nested_namespace_alias_oauth_fixture, :oauth_path_prefix}
      ]

      for {fixture, setting} <- fixtures do
        igniter =
          test_project(
            files: %{
              "mix.exs" => @mix_fixture,
              @router_path => @router_fixture,
              @application_path => @application_fixture,
              @config_path => fixture
            }
          )

        assert_raise Mix.Error,
                     ~r/could not determine configured :#{setting} expression.*nested config expression/,
                     fn -> Igniter.compose_task(igniter, @task, []) end

        refute Igniter.exists?(igniter, @client_store_path)
      end
    end

    test "fails closed for aliases declared after or inside nested config code" do
      fixtures = [
        @alias_after_config_prefixes_fixture,
        @nested_alias_schema_prefix_fixture,
        @nested_alias_oauth_path_prefix_fixture,
        @quoted_alias_schema_prefix_fixture,
        @quoted_alias_oauth_path_prefix_fixture
      ]

      for fixture <- fixtures do
        igniter =
          test_project(
            files: %{
              "mix.exs" => @mix_fixture,
              @router_path => @router_fixture,
              @application_path => @application_fixture,
              @config_path => fixture
            }
          )

        router_before = source_content(igniter, @router_path)

        assert_raise Mix.Error,
                     ~r/could not determine configured :(?:schema_prefix|oauth_path_prefix) expression.*ambiguous config module APC/,
                     fn -> Igniter.compose_task(igniter, @task, []) end

        assert source_content(igniter, @router_path) == router_before
        refute Igniter.exists?(igniter, @client_store_path)
      end
    end

    test "refuses ambiguous literal schema prefixes without an explicit environment selection" do
      assert_raise Mix.Error, ~r/multiple literal values.*Pass --schema-prefix/s, fn ->
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @default_schema_prefix_config_fixture,
            "config/prod.exs" => @production_schema_prefix_config_fixture
          }
        )
        |> Igniter.compose_task(@task, [])
      end
    end

    test "refuses an omitted base prefix plus an environment-specific prefix without an explicit selection" do
      assert_raise Mix.Error, ~r/multiple literal values.*Pass --schema-prefix/s, fn ->
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @old_installer_config_fixture,
            "config/prod.exs" => @production_schema_prefix_config_fixture
          }
        )
        |> Igniter.compose_task(@task, [])
      end
    end

    test "accepts an explicit prefix selected by environment-specific host config" do
      composed =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @old_installer_config_fixture,
            "config/prod.exs" => @production_schema_prefix_config_fixture
          }
        )
        |> Igniter.compose_task(@task, ["--schema-prefix", "tenant_prod"])

      assert Enum.any?(composed.notices, fn notice ->
               notice =~
                 "gen.migration --upgrade 3.0 --repo Test.Repo --schema-prefix tenant_prod" and
                 notice =~
                   "gen.migration --upgrade 3.1 --repo Test.Repo --schema-prefix tenant_prod"
             end)

      applied = apply_igniter!(composed)

      application = source_content(applied, @application_path)
      assert application =~ "AttestoPhoenix.Store.Sweeper"
      refute source_content(applied, @config_path) =~ "schema_prefix:"
      assert source_content(applied, "config/prod.exs") == @production_schema_prefix_config_fixture
    end

    test "rejects an explicit prefix absent from environment-specific host config" do
      assert_raise Mix.Error, ~r/does not match any literal schema selected/, fn ->
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @default_schema_prefix_config_fixture,
            "config/prod.exs" => @production_schema_prefix_config_fixture
          }
        )
        |> Igniter.compose_task(@task, ["--schema-prefix", "different"])
      end
    end

    test "requires an explicit schema prefix when one config source disagrees internally" do
      igniter =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @same_file_schema_prefix_config_fixture
          }
        )

      assert_raise Mix.Error, ~r/conflicting literal :schema_prefix values.*one config source/s, fn ->
        Igniter.compose_task(igniter, @task, [])
      end

      assert_raise Mix.Error, ~r/conflicting literal :schema_prefix values.*explicit flag cannot/s, fn ->
        Igniter.compose_task(igniter, @task, ["--schema-prefix", "tenant_prod"])
      end
    end

    test "requires an explicit schema prefix when one config call repeats the key" do
      igniter =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @duplicate_keyword_schema_prefix_config_fixture
          }
        )

      assert_raise Mix.Error, ~r/conflicting literal :schema_prefix values.*one config source/s, fn ->
        Igniter.compose_task(igniter, @task, [])
      end

      assert_raise Mix.Error, ~r/conflicting literal :schema_prefix values.*explicit flag cannot/s, fn ->
        Igniter.compose_task(igniter, @task, ["--schema-prefix", "tenant_prod"])
      end
    end

    test "rejects PostgreSQL system schemas" do
      for prefix <- ["pg_catalog", "information_schema"] do
        assert_raise Mix.Error, ~r/reserved PostgreSQL system schema/, fn ->
          Igniter.compose_task(project(), @task, ["--schema-prefix", prefix])
        end
      end
    end

    test "rejects a malformed existing schema prefix instead of announcing public" do
      assert_raise Mix.Error, ~r/invalid configured :schema_prefix/, fn ->
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @invalid_schema_prefix_config_fixture
          }
        )
        |> Igniter.compose_task(@task, [])
      end
    end

    test "rejects a string-key schema prefix map instead of announcing public" do
      assert_raise Mix.Error, ~r/string key "schema_prefix"/, fn ->
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @string_schema_prefix_map_config_fixture
          }
        )
        |> Igniter.compose_task(@task, [])
      end
    end

    test "rejects the removed 2.x table-prefix option" do
      assert_raise Mix.Error, ~r/--table-prefix was removed.*--schema-prefix/, fn ->
        Igniter.compose_task(project(), @task, ["--table-prefix", "tenant_auth"])
      end
    end

    test "refuses a legacy table-prefix config on rerun before mutating the project" do
      igniter =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @legacy_table_prefix_config_fixture
          }
        )

      assert_raise Mix.Error, ~r/legacy :table_prefix configuration detected.*made no changes/s, fn ->
        Igniter.compose_task(igniter, @task, [])
      end

      assert_raise Mix.Error, ~r/legacy :table_prefix configuration detected.*made no changes/s, fn ->
        Igniter.compose_task(igniter, @task, ["--schema-prefix", "oauth"])
      end

      assert source_content(igniter, @config_path) =~ "table_prefix: \"oauth\""
      refute Igniter.exists?(igniter, @client_store_path)
    end

    test "evaluated fixture config does not leak into the application environment" do
      before_snapshot = AppEnvSnapshot.snapshot(@isolated_apps)

      AppEnvSnapshot.isolate(@isolated_apps, fn ->
        legacy_igniter =
          test_project(
            files: %{
              "mix.exs" => @mix_fixture,
              @router_path => @router_fixture,
              @application_path => @application_fixture,
              @config_path => @legacy_table_prefix_config_fixture
            }
          )

        assert_raise Mix.Error, ~r/legacy :table_prefix configuration detected.*made no changes/s, fn ->
          Igniter.compose_task(legacy_igniter, @task, [])
        end

        schema_igniter =
          test_project(
            files: %{
              "mix.exs" => @mix_fixture,
              @router_path => @router_fixture,
              @application_path => @application_fixture,
              @config_path => @existing_schema_prefix_config_fixture
            }
          )

        _composed = Igniter.compose_task(schema_igniter, @task, [])

        # Igniter evaluates the project config into the application environment
        # while it formats files. Whether or not the installed Igniter version
        # removes those keys afterwards, the isolation must leave no trace, so
        # a leak is also forced explicitly here.
        Application.put_env(:test, AttestoPhoenix.Config, table_prefix: "oauth")
        Application.put_env(:attesto_phoenix, :otp_app, :test)
      end)

      assert AppEnvSnapshot.snapshot(@isolated_apps) == before_snapshot
      assert Application.fetch_env(:attesto_phoenix, AttestoPhoenix.Config) == :error
      assert Application.fetch_env(:attesto_phoenix, :otp_app) == :error
      assert Application.fetch_env(:test, AttestoPhoenix.Config) == :error
    end

    test "refuses both package-level legacy table-prefix config syntaxes" do
      previous = Application.get_env(:attesto_phoenix, :table_prefix, :missing)

      on_exit(fn ->
        case previous do
          :missing -> Application.delete_env(:attesto_phoenix, :table_prefix)
          value -> Application.put_env(:attesto_phoenix, :table_prefix, value)
        end
      end)

      for config <- [@package_legacy_keyword_config_fixture, @package_legacy_key_config_fixture] do
        Application.delete_env(:attesto_phoenix, :table_prefix)

        igniter =
          test_project(
            files: %{
              "mix.exs" => @mix_fixture,
              @router_path => @router_fixture,
              @application_path => @application_fixture,
              @config_path => config
            }
          )

        assert_raise Mix.Error, ~r/legacy :table_prefix configuration detected.*made no changes/s, fn ->
          Igniter.compose_task(igniter, @task, [])
        end

        refute Igniter.exists?(igniter, @client_store_path)
        assert source_content(igniter, @config_path) == config
      end

      Application.delete_env(:attesto_phoenix, :table_prefix)
    end

    test "repairs router output from installers that predate the config pipeline" do
      applied =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @old_installer_router_fixture,
            @application_path => @application_fixture
          }
        )
        |> Igniter.compose_task(@task, [])
        |> apply_igniter!()

      router = source_content(applied, @router_path)
      assert router =~ "pipeline :attesto_phoenix_config do"
      assert router =~ "plug(AttestoPhoenix.Plug.PutConfig, otp_app: :test)"
      assert router =~ "attesto_routes(pipeline: :attesto_phoenix_config)"
    end

    test "repairs required config omitted by older installer output" do
      applied =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @old_installer_router_fixture,
            @application_path => @application_fixture,
            @config_path => @old_installer_config_fixture,
            @principal_store_path => @old_principal_store_fixture
          }
        )
        |> Igniter.compose_task(@task, [])
        |> apply_igniter!()

      evaluated = Config.Reader.eval!(@config_path, source_content(applied, @config_path))
      host_options = evaluated |> Keyword.fetch!(:test) |> Keyword.fetch!(PhoenixConfig)

      assert Keyword.fetch!(host_options, :audience)

      assert Keyword.fetch!(host_options, :principal_kinds) ==
               {PrincipalStore, :principal_kinds}

      assert evaluated[:attesto_phoenix][:otp_app] == :test
      assert evaluated[:attesto_phoenix][:repo] == Test.Repo

      runtime = source_content(applied, @runtime_config_path)
      assert runtime =~ "refresh_successor_secret:"

      principal_store = source_content(applied, @principal_store_path)
      assert principal_store =~ "def principal_kinds do"
      assert principal_store =~ "def load_principal(_subject_id)"

      assert_generated_upgrade_application_starts(applied)

      applied
      |> Igniter.compose_task(@task, [])
      |> assert_unchanged()
    end
  end

  describe "re-run idempotency" do
    test "a second run on the installed project changes nothing" do
      first =
        project()
        |> Igniter.compose_task(@task, [])
        |> apply_igniter!()

      # Running the installer again against the already-installed project must be
      # a no-op: no duplicated config key, no second router scope, no clobbered
      # (host-edited) callback modules.
      first
      |> Igniter.compose_task(@task, [])
      |> assert_unchanged()
    end

    test "preserves an existing project refresh secret" do
      applied =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @runtime_config_path => @existing_runtime_secret_fixture
          }
        )
        |> Igniter.compose_task(@task, [])
        |> apply_igniter!()

      runtime = source_content(applied, @runtime_config_path)
      evaluated = Config.Reader.eval!(@runtime_config_path, runtime, env: :dev)

      assert evaluated[:attesto_phoenix][:refresh_successor_secret] ==
               "host-supplied-development-value"

      applied
      |> Igniter.compose_task(@task, [])
      |> assert_unchanged()
    end

    test "preserves a secret configured in config.exs" do
      applied =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @existing_config_secret_fixture
          }
        )
        |> Igniter.compose_task(@task, [])
        |> apply_igniter!()

      config = Config.Reader.eval!(@config_path, source_content(applied, @config_path))

      assert config[:attesto_phoenix][:refresh_successor_secret] ==
               "host-supplied-config-value"

      refute Igniter.exists?(applied, @runtime_config_path)
    end

    test "preserves a secret configured in prod.exs" do
      applied =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            "config/prod.exs" => @existing_prod_secret_fixture
          }
        )
        |> Igniter.compose_task(@task, [])
        |> apply_igniter!()

      prod = Config.Reader.eval!("config/prod.exs", source_content(applied, "config/prod.exs"))

      assert prod[:attesto_phoenix][:refresh_successor_secret] ==
               "host-supplied-prod-value"

      refute Igniter.exists?(applied, @runtime_config_path)
    end

    test "preserves a secret configured in an imported config file" do
      applied =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @existing_imported_config_fixture,
            "config/nested/attesto.exs" => @existing_nested_secret_fixture
          }
        )
        |> Igniter.compose_task(@task, [])
        |> apply_igniter!()

      imported =
        Config.Reader.eval!(
          "config/nested/attesto.exs",
          source_content(applied, "config/nested/attesto.exs")
        )

      assert imported[:attesto_phoenix][:refresh_successor_secret] ==
               "host-supplied-imported-value"

      refute Igniter.exists?(applied, @runtime_config_path)
    end
  end

  defp source_content(igniter, path) do
    igniter.rewrite
    |> Rewrite.source!(path)
    |> Rewrite.Source.get(:content)
  end

  defp compile_generated_callbacks(applied) do
    for path <- [
          @client_store_path,
          @principal_store_path,
          @scope_policy_path,
          @consent_policy_path,
          @registration_store_path,
          @event_sink_path
        ] do
      Code.compile_string(source_content(applied, path), path)
    end
  end

  defp assert_generated_upgrade_application_starts(applied) do
    application_module = Module.concat(__MODULE__, GeneratedApplication)
    supervisor_name = Module.concat(__MODULE__, GeneratedSupervisor)

    source =
      applied
      |> source_content(@application_path)
      |> String.replace("Test.Application", inspect(application_module))
      |> String.replace("Test.Repo", inspect(GeneratedRepo))
      |> String.replace("Test.Supervisor", inspect(supervisor_name))

    previous = Application.get_env(:test, PhoenixConfig)

    Application.put_env(:test, PhoenixConfig,
      issuer: "https://issuer.example",
      audience: "https://api.example",
      keystore: Keystore,
      repo: GeneratedRepo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end
    )

    on_exit(fn ->
      if is_nil(previous) do
        Application.delete_env(:test, PhoenixConfig)
      else
        Application.put_env(:test, PhoenixConfig, previous)
      end

      :code.purge(application_module)
      :code.delete(application_module)
    end)

    assert [{^application_module, _bytecode}] = Code.compile_string(source, @application_path)
    # The generated application module is known only at runtime in this reusable
    # installer fixture, so a direct module call is not available here.
    # credo:disable-for-next-line Credo.Check.Refactor.Apply
    assert {:ok, supervisor} = apply(application_module, :start, [:normal, []])
    Process.unlink(supervisor)

    on_exit(fn ->
      try do
        if Process.alive?(supervisor) do
          Supervisor.stop(supervisor)
        end
      catch
        :exit, {:noproc, _} -> :ok
      end
    end)

    children = Supervisor.which_children(supervisor)

    assert {GeneratedRepo, repo_pid, :worker, [GeneratedRepo]} =
             List.keyfind(children, GeneratedRepo, 0)

    assert {sweeper_id, :undefined, :worker, [Sweeper]} =
             Enum.find(children, fn {_id, _pid, _type, modules} -> modules == [Sweeper] end)

    assert sweeper_id == {Sweeper, GeneratedRepo, nil}

    assert Process.alive?(repo_pid)
  end
end
