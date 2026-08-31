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
  alias AttestoPhoenix.Config, as: PhoenixConfig
  alias AttestoPhoenix.Store.Sweeper
  alias Test.AuthZ.PrincipalStore

  @task "attesto_phoenix.install"

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
                 notice =~ "PostgreSQL schema `tenant_auth`" and
                 notice =~ "{repo, schema_prefix}" and
                 notice =~ "attesto_refresh_tokens_family_id_generation_index"
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

    test "requires an explicit schema prefix when config sources disagree" do
      assert_raise Mix.Error, ~r/multiple literal values.*--schema-prefix explicitly/, fn ->
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

    test "requires an explicit schema prefix when one config source disagrees internally" do
      assert_raise Mix.Error, ~r/multiple literal values.*--schema-prefix explicitly/, fn ->
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @same_file_schema_prefix_config_fixture
          }
        )
        |> Igniter.compose_task(@task, [])
      end
    end

    test "requires an explicit schema prefix when one config call repeats the key" do
      assert_raise Mix.Error, ~r/multiple literal values.*--schema-prefix explicitly/, fn ->
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @duplicate_keyword_schema_prefix_config_fixture
          }
        )
        |> Igniter.compose_task(@task, [])
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

    test "notices and preserves a legacy table-prefix config on rerun" do
      composed =
        test_project(
          files: %{
            "mix.exs" => @mix_fixture,
            @router_path => @router_fixture,
            @application_path => @application_fixture,
            @config_path => @legacy_table_prefix_config_fixture
          }
        )
        |> Igniter.compose_task(@task, [])

      assert Enum.any?(composed.notices, fn notice ->
               notice =~ "Legacy `:table_prefix` configuration was found" and
                 notice =~ "not identify one runtime layout" and
                 notice =~ "will fail closed"
             end)

      applied =
        composed
        |> apply_igniter!()

      assert source_content(applied, @config_path) =~ "table_prefix: \"oauth\""
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
