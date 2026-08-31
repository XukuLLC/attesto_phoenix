defmodule Mix.Tasks.AttestoPhoenix.Install.Docs do
  @moduledoc false

  @spec short_doc() :: String.t()
  def short_doc, do: "Installs the attesto_phoenix authorization-server layer into a Phoenix app"

  @spec example() :: String.t()
  def example, do: "mix attesto_phoenix.install"

  @spec long_doc() :: String.t()
  def long_doc do
    """
    #{short_doc()}

    Wires the OAuth 2.0 / OpenID Connect authorization-server layer this library
    provides into the host Phoenix application:

      * adds an `AttestoPhoenix.Config` config skeleton (issuer, audience,
        keystore, repo, principal kinds, the Ecto-backed token stores, a chosen
        `:oauth_path_prefix`, optional `:schema_prefix`, and neutral defaults)
        to the host config, and
        points the library's global resolver and stores at that OTP app/repo,
      * adds runtime refresh-successor encryption configuration: production
        reads `ATTESTO_REFRESH_SUCCESSOR_SECRET`; the bundled Ecto store fails
        config validation when positive retry grace needs it but custom stores
        and strict zero-grace deployments do not; development and test use a
        per-project fallback generated when this task runs,
      * supervises `AttestoPhoenix.Store.Sweeper` after the host repo so expired
        Ecto rows are reclaimed and refresh-successor ciphertext is redacted
        promptly after its short retry window,
      * mounts the server routes (`attesto_routes/1`) at the chosen prefix into
        the host router behind a generated config-loading pipeline,
      * scaffolds host callback modules implementing the recommended production
        behaviours (`AttestoPhoenix.ClientStore`, `PrincipalStore`,
        `ScopePolicy`, `ConsentPolicy`, `RegistrationStore`, `EventSink`) with
        documented stub callbacks the host fills in,
      * points the host at `mix attesto_phoenix.gen.migration` for the Ecto
        tables the bundled stores read, including the durable refresh-family
        revocation tombstones. Existing installations upgrading to a release
        that adds this table must apply its forward migration before boot.

    Every step is idempotent: re-running the task does not duplicate the config,
    the route, or the scaffolded modules. The task never decides authorization
    policy; it scaffolds the contract the host owns (RFC 6749 §2/§3.3/§4.1.1,
    RFC 7591 §3, OpenID Connect Core §3.1.2/§5.3) and emits notices telling the
    host exactly what to fill in.

    ## Example

    ```sh
    #{example()}
    ```

    ## Options

      * `--oauth-path-prefix` - the full client-visible mount prefix for the
        bundled OAuth endpoints (RFC 8414 §3 advertises the absolute URLs). It
        must be `/oauth` or end in `/oauth`, because the bundled router has
        fixed `/oauth/*` endpoint tails; for example,
        `--oauth-path-prefix /mcp/oauth` generates
        `attesto_routes(prefix: "/mcp")` and advertises `/mcp/oauth/*`.
        Unsupported values such as `/auth` are rejected before any files are
        changed. If a host needs a different endpoint suffix or an explicit
        per-endpoint route override, wire the routes manually and set matching
        advertised paths instead of relying on the generated mount. The
        well-known documents (RFC 8615) and the JWKS document stay anchored at
        the host root and are NOT relocated by this prefix.
      * `--schema-prefix` - the PostgreSQL schema selected by Ecto's `prefix:`
        option for every generated table and index. The migration generator
        uses the same value. The legacy 2.x `--table-prefix` option is rejected
        because it controlled literal names in generated migrations, not one
        coherent runtime layout: most stores queried canonical public tables,
        while only the CIBA store and sweeper treated it as an Ecto schema
        prefix.
      * `--callbacks-module` - the base module the scaffolded callback modules
        are generated under. Defaults to `<App>.AuthZ`, yielding
        `<App>.AuthZ.ClientStore` and friends.
    """
  end
end

if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AttestoPhoenix.Install do
    # `@shortdoc` is a compile-time module attribute evaluated before any `alias`
    # below takes effect, so it cannot reference the sibling `...Install.Docs`
    # module by an alias; the literal is inlined here (kept in sync with
    # `Docs.short_doc/0`) rather than fully qualifying the nested module.
    @shortdoc "Installs the attesto_phoenix authorization-server layer into a Phoenix app"

    @moduledoc Mix.Tasks.AttestoPhoenix.Install.Docs.long_doc()

    use Igniter.Mix.Task

    alias AttestoPhoenix.Plug.PutConfig
    # `AttestoPhoenix.Config` is referenced only as a config-path module name (a
    # plain atom Igniter writes into the host config), never as a struct, so it
    # is NOT aliased: aliasing it would make this Mix task a compile-time
    # dependency of the library's own `AttestoPhoenix.Config` and the Ecto stores
    # that pattern-match `%AttestoPhoenix.Config{}`, forming a module cycle in the
    # single compile pass.
    alias AttestoPhoenix.Store.Sweeper
    alias Igniter.Code.Common
    alias Igniter.Code.Function
    alias Igniter.Code.Keyword, as: CodeKeyword
    alias Igniter.Libs.Phoenix
    alias Igniter.Mix.Task.Info
    alias Igniter.Project.Application, as: ProjectApplication
    alias Igniter.Project.Config, as: ProjectConfig
    alias Igniter.Project.Module, as: ProjectModule
    alias Mix.Tasks.AttestoPhoenix.Install.Docs
    alias Sourceror.Zipper

    # The default OAuth mount prefix reproduces the historic `/oauth/*` surface
    # (`AttestoPhoenix.Config`'s `:oauth_path_prefix` default). A host may
    # relocate it with `--oauth-path-prefix`.
    @default_oauth_path_prefix "/oauth"
    @config_pipeline :attesto_phoenix_config
    @refresh_successor_secret_bytes 32

    # The recommended production behaviours and the callbacks each scaffolded
    # module implements. Each tuple is `{submodule, behaviour, [{function,
    # arity}]}`. The behaviours document the full contract (with the governing
    # RFC per callback); the function names match the loose
    # `AttestoPhoenix.Config` keys the config skeleton wires.
    @scaffolds [
      {ClientStore, AttestoPhoenix.ClientStore, [{:load_client, 1}, {:verify_client_secret, 2}]},
      {PrincipalStore, AttestoPhoenix.PrincipalStore,
       [{:load_principal, 1}, {:principal_kinds, 0}, {:build_principal, 3}]},
      {ScopePolicy, AttestoPhoenix.ScopePolicy, [{:authorize_scope, 2}]},
      {ConsentPolicy, AttestoPhoenix.ConsentPolicy, [{:authenticate_resource_owner, 3}, {:consent, 3}]},
      {RegistrationStore, AttestoPhoenix.RegistrationStore,
       [
         {:register_client, 1},
         {:unregister_client, 1},
         {:client_registration_access_token_hash, 1}
       ]},
      {EventSink, AttestoPhoenix.EventSink, [{:on_event, 1}]}
    ]

    @impl Igniter.Mix.Task
    def info(_argv, _composing_task_name) do
      %Info{
        group: :attesto_phoenix,
        example: Docs.example(),
        schema: [
          oauth_path_prefix: :string,
          schema_prefix: :string,
          callbacks_module: :string
        ]
      }
    end

    @impl Igniter.Mix.Task
    def igniter(igniter) do
      reject_legacy_table_prefix_args!(igniter.args.argv)
      igniter = notice_legacy_table_prefix_config(igniter)

      app = Igniter.Project.Application.app_name(igniter)
      app_module = ProjectModule.module_name_prefix(igniter)
      repo = Module.concat(app_module, Repo)
      options = igniter.args.options

      oauth_path_prefix =
        validate_oauth_path_prefix!(options[:oauth_path_prefix] || @default_oauth_path_prefix)

      schema_prefix = schema_prefix(options, igniter, app)
      callbacks_module = callbacks_module(options, app_module)
      refresh_successor_secret = generate_refresh_successor_secret()

      igniter
      |> scaffold_callback_modules(callbacks_module)
      |> configure_attesto_phoenix(
        app,
        oauth_path_prefix,
        schema_prefix,
        callbacks_module,
        repo,
        refresh_successor_secret
      )
      |> supervise_store_sweeper(app, repo)
      |> mount_routes(app, oauth_path_prefix)
      |> add_next_step_notices(app, oauth_path_prefix, schema_prefix, callbacks_module, repo)
    end

    defp supervise_store_sweeper(igniter, app, repo) do
      options =
        quote do
          [config: AttestoPhoenix.Config.from_otp_app(unquote(app)), if_configured: true]
        end

      ProjectApplication.add_new_child(
        igniter,
        {Sweeper, {:code, options}},
        after: [repo]
      )
    end

    # The base module the scaffolded callbacks live under. `--callbacks-module`
    # wins; otherwise `<App>.AuthZ`, the name the `AttestoPhoenix.Config`
    # required-key hints suggest (e.g. `&MyApp.AuthZ.load_client/1`).
    defp callbacks_module(options, app_module) do
      case options[:callbacks_module] do
        nil -> Module.concat(app_module, AuthZ)
        explicit -> ProjectModule.parse(explicit)
      end
    end

    # ------------------------------------------------------------------
    # Config skeleton
    # ------------------------------------------------------------------

    # `configure_new/6` writes the value only when the config path is unset, so
    # re-running the installer never clobbers a host that has already filled the
    # skeleton in. The skeleton sets the required keys (issuer, keystore, repo),
    # wires every required and recommended callback at the scaffolded module, and
    # installs the Ecto-backed stores with neutral defaults. The actual
    # authorization policy stays in the scaffolded host modules; this is only the
    # wiring `AttestoPhoenix.Config.from_otp_app/2` reads at boot.
    defp configure_attesto_phoenix(
           igniter,
           app,
           oauth_path_prefix,
           schema_prefix,
           callbacks_module,
           repo,
           refresh_successor_secret
         ) do
      config = config_skeleton(oauth_path_prefix, schema_prefix, callbacks_module, repo)
      principal_store = Module.concat(callbacks_module, PrincipalStore)

      igniter
      |> ProjectConfig.configure_new(
        "config.exs",
        app,
        [AttestoPhoenix.Config],
        {:code, config}
      )
      |> ProjectConfig.configure_new(
        "config.exs",
        app,
        [AttestoPhoenix.Config, :audience],
        {:code, audience_default()}
      )
      |> ProjectConfig.configure_new(
        "config.exs",
        app,
        [AttestoPhoenix.Config, :principal_kinds],
        {:code, quote(do: {unquote(principal_store), :principal_kinds})}
      )
      |> ProjectConfig.configure_new("config.exs", :attesto_phoenix, [:otp_app], app)
      |> ProjectConfig.configure_new(
        "config.exs",
        :attesto_phoenix,
        [:repo],
        {:code, quote(do: unquote(repo))}
      )
      |> configure_refresh_successor_secret(refresh_successor_secret)
    end

    # Runtime configuration is evaluated after the regular config files, so an
    # unconditional runtime entry would silently override a host value from
    # config.exs, dev.exs, prod.exs, or another imported config file. Include
    # every config source before checking the key and add the generated fallback
    # only when the project has not configured the secret anywhere.
    defp configure_refresh_successor_secret(igniter, refresh_successor_secret) do
      if refresh_successor_secret_configured?(igniter) do
        igniter
      else
        ProjectConfig.configure_new(
          igniter,
          "runtime.exs",
          :attesto_phoenix,
          [:refresh_successor_secret],
          {:code, refresh_successor_secret_runtime_default(refresh_successor_secret)}
        )
      end
    end

    defp refresh_successor_secret_configured?(igniter) do
      config_path = ProjectApplication.config_path(igniter)
      config_dir = config_path |> Path.dirname() |> Path.expand()
      config_glob = Path.join(config_dir, "**/*.exs")
      igniter = Igniter.include_glob(igniter, config_glob)
      config_dir_parts = Path.split(config_dir)

      igniter.rewrite
      |> Rewrite.sources()
      |> Enum.any?(&refresh_successor_secret_configured_in?(&1, igniter, config_dir, config_dir_parts))
    end

    defp refresh_successor_secret_configured_in?(source, igniter, config_dir, config_dir_parts) do
      source_path = Path.expand(source.path)

      cond do
        Path.extname(source.path) != ".exs" ->
          false

        Enum.take(Path.split(source_path), length(config_dir_parts)) != config_dir_parts ->
          false

        true ->
          relative_path = Path.relative_to(source_path, config_dir)

          ProjectConfig.configures_key?(
            igniter,
            relative_path,
            :attesto_phoenix,
            :refresh_successor_secret
          )
      end
    end

    defp config_skeleton(oauth_path_prefix, schema_prefix, callbacks_module, repo) do
      keystore = Module.concat(callbacks_module, Keystore)
      client_store = Module.concat(callbacks_module, ClientStore)
      principal_store = Module.concat(callbacks_module, PrincipalStore)
      scope_policy = Module.concat(callbacks_module, ScopePolicy)
      consent_policy = Module.concat(callbacks_module, ConsentPolicy)
      event_sink = Module.concat(callbacks_module, EventSink)

      quote do
        [
          # Required (AttestoPhoenix.Config @enforce_keys). Set :issuer to the
          # https issuer URL (RFC 8414 §2); it is the base for every advertised
          # endpoint URL. Prefer overriding it in config/runtime.exs per
          # deployment.
          issuer: System.get_env("ATTESTO_ISSUER") || "https://localhost",
          # The protected resource identifier carried in access-token `aud`.
          # A co-located single-resource development server may use its issuer;
          # deployments serving another resource must set ATTESTO_AUDIENCE (or
          # replace this value) with that resource's absolute https URL.
          audience: unquote(audience_default()),
          # A module implementing the Attesto.Keystore behaviour (the signing key
          # and the JWKS verification keys). Scaffold or wire your own.
          keystore: unquote(keystore),
          repo: unquote(repo),
          # PostgreSQL schema selected by Ecto for every generated table and
          # index. Leave nil for the public schema.
          schema_prefix: unquote(schema_prefix),
          # Required host callbacks, wired at the scaffolded modules. Fill in the
          # stub callbacks the installer generated.
          load_client: {unquote(client_store), :load_client},
          verify_client_secret: {unquote(client_store), :verify_client_secret},
          load_principal: {unquote(principal_store), :load_principal},
          principal_kinds: {unquote(principal_store), :principal_kinds},
          # Recommended host callbacks (RFC 6749 §3.3/§4.1.1, OIDC Core §3.1.2).
          build_principal: {unquote(principal_store), :build_principal},
          authorize_scope: {unquote(scope_policy), :authorize_scope},
          authenticate_resource_owner: {unquote(consent_policy), :authenticate_resource_owner},
          consent: {unquote(consent_policy), :consent},
          on_event: {unquote(event_sink), :on_event},
          # The client-visible OAuth mount prefix. The mounted routes and the
          # discovery metadata derive from this same value so they cannot drift.
          oauth_path_prefix: unquote(oauth_path_prefix),
          # Supported scopes advertised in discovery and used as the default
          # scope catalog. `openid` is added automatically for an OpenID
          # Provider; the rest are examples to replace.
          scopes_supported: ["profile", "email", "offline_access"],
          # Ecto-backed stores. Run `mix attesto_phoenix.gen.migration` to create
          # the backing tables, including durable refresh-family revocation
          # tombstones.
          code_store: AttestoPhoenix.Store.EctoCodeStore,
          refresh_store: AttestoPhoenix.Store.EctoRefreshStore,
          nonce_store: AttestoPhoenix.Store.EctoNonceStore,
          replay_check: {AttestoPhoenix.Store.EctoReplayCheck, :check_and_record},
          # PAR reference store (RFC 9126). Ecto-backed so a request_uri pushed to
          # one node resolves on every node; FAPI 2.0 requires PAR.
          par_store: AttestoPhoenix.Store.EctoPARStore,
          # Single-use, request-bound consent grants (RFC 6749 §4.1.1). The host
          # consent screen mints a grant when the user authorizes; the host's
          # :consent callback consumes it before a code is issued, so one consent
          # click cannot approve a different client/redirect/scope/challenge. The
          # backing table is created by `mix attesto_phoenix.gen.migration`.
          consent_grant_store: AttestoPhoenix.Store.EctoConsentGrantStore,
          # Periodic expiry sweep of the Ecto stores (AttestoPhoenix.Store.Sweeper).
          sweep_interval_ms: 60_000,
          # Sender-constraint and transport defaults (additive; reproduce the
          # library defaults). Dynamic client registration is off until the host
          # opts in and wires the registration callbacks.
          dpop_enabled: true,
          dpop_nonce_required: false,
          require_https: true,
          registration_enabled: false
        ]
      end
    end

    defp schema_prefix(options, igniter, app) do
      case options[:schema_prefix] do
        nil ->
          configured_schema_prefix(igniter, app)
          |> validate_schema_prefix!()

        prefix when is_binary(prefix) ->
          validate_schema_prefix!(prefix)

        other ->
          raise Mix.Error,
            message: "invalid --schema-prefix: expected a PostgreSQL schema identifier, got #{inspect(other)}"
      end
    end

    # An installer rerun must keep notices and generated migration commands
    # aligned with an already-configured host schema. Read literal values from
    # the host config AST without evaluating arbitrary config code. Dynamic or
    # ambiguous expressions fail closed: guessing `public` would make generated
    # migration instructions disagree with the runtime database layout.
    defp configured_schema_prefix(igniter, app) do
      config_path = ProjectApplication.config_path(igniter)
      config_dir = config_path |> Path.dirname() |> Path.expand()
      config_glob = Path.join(config_dir, "**/*.exs")
      igniter = Igniter.include_glob(igniter, config_glob)
      config_dir_parts = Path.split(config_dir)

      results =
        igniter.rewrite
        |> Rewrite.sources()
        |> Enum.flat_map(&configured_schema_prefix_source(&1, app, config_dir_parts))

      configured_schema_prefix_results(results)
    end

    defp configured_schema_prefix_source(source, app, config_dir_parts) do
      case config_source?(source.path, config_dir_parts) do
        true ->
          source.content
          |> configured_schema_prefix_in_source(app)
          |> Enum.map(&configured_schema_prefix_source_result/1)

        false ->
          []
      end
    end

    defp configured_schema_prefix_source_result({:ok, prefix}), do: {:found, prefix}
    defp configured_schema_prefix_source_result({:invalid, value}), do: {:invalid, value}
    defp configured_schema_prefix_source_result({:dynamic, expression}), do: {:dynamic, expression}

    defp config_source?(path, config_dir_parts) do
      source_path = Path.expand(path)

      Path.extname(path) == ".exs" and
        Enum.take(Path.split(source_path), length(config_dir_parts)) == config_dir_parts
    end

    defp configured_schema_prefix_results(results) do
      case Enum.find(results, &schema_prefix_error_result?/1) do
        {:invalid, value} -> raise_invalid_schema_prefix(value)
        {:dynamic, expression} -> raise_dynamic_schema_prefix(expression)
        nil -> configured_schema_prefix_literals(results)
      end
    end

    defp configured_schema_prefix_literals(results) do
      prefixes = for {:found, prefix} <- results, do: prefix

      case Enum.uniq(prefixes) do
        [] -> nil
        [prefix] -> prefix
        prefixes -> raise_ambiguous_schema_prefix(prefixes)
      end
    end

    defp schema_prefix_error_result?({:invalid, _value}), do: true
    defp schema_prefix_error_result?({:dynamic, _expression}), do: true
    defp schema_prefix_error_result?(_result), do: false

    defp raise_invalid_schema_prefix(value) do
      raise Mix.Error,
        message:
          "invalid configured :schema_prefix in the host config: expected nil or a " <>
            "lowercase PostgreSQL schema identifier, got #{value}"
    end

    defp raise_dynamic_schema_prefix(expression) do
      raise Mix.Error,
        message:
          "could not determine configured :schema_prefix expression #{expression}; " <>
            "pass --schema-prefix explicitly so the migration and installer cannot " <>
            "silently target public"
    end

    defp raise_ambiguous_schema_prefix(prefixes) do
      raise Mix.Error,
        message:
          "could not determine a single configured :schema_prefix in the host config; " <>
            "found multiple literal values #{inspect(prefixes)}; pass --schema-prefix " <>
            "explicitly so the migration and installer cannot silently target public"
    end

    defp configured_schema_prefix_in_source(content, app) when is_binary(content) do
      case Code.string_to_quoted(content, emit_warnings: false) do
        {:ok, ast} ->
          ast
          |> configured_schema_prefix_ast_results(app)
          |> Enum.map(&format_configured_schema_prefix_result/1)

        {:error, error} ->
          [{:dynamic, "unparseable config source (#{inspect(error)})"}]
      end
    end

    defp configured_schema_prefix_ast_results(ast, app) do
      aliases = config_aliases(ast)

      {_ast, results} =
        Macro.prewalk(ast, [], &configured_schema_prefix_ast_node(&1, &2, app, aliases))

      Enum.reverse(results)
    end

    defp configured_schema_prefix_ast_node(node, results, app, aliases) do
      node_result = configured_schema_prefix_node(node, app, aliases)

      case node_result do
        {^node, :not_found} -> {node, results}
        {^node, node_results} -> {node, node_results ++ results}
      end
    end

    defp configured_schema_prefix_node(
           {:config, _meta, [configured_app, config_module, config_opts]} = node,
           app,
           aliases
         ) do
      case configured_app do
        ^app ->
          configured_schema_prefix_node_for_app(node, config_module, config_opts, aliases)

        configured_app when is_atom(configured_app) ->
          {node, :not_found}

        _dynamic_app ->
          configured_schema_prefix_node_for_dynamic_app(
            node,
            configured_app,
            config_module,
            config_opts,
            aliases
          )
      end
    end

    defp configured_schema_prefix_node(node, _app, _aliases), do: {node, :not_found}

    defp configured_schema_prefix_node_for_app(node, config_module, config_opts, aliases) do
      if attesto_config_module_ast?(config_module, aliases) do
        configured_schema_prefix_config(node, config_opts)
      else
        configured_schema_prefix_node_for_ambiguous_module(node, config_module, config_opts, aliases)
      end
    end

    defp configured_schema_prefix_node_for_dynamic_app(node, configured_app, config_module, config_opts, aliases) do
      if attesto_config_module_ast?(config_module, aliases) and
           ambiguous_schema_prefix_options?(config_opts) do
        {node, [{:dynamic, "ambiguous config app #{Macro.to_string(configured_app)}"}]}
      else
        {node, :not_found}
      end
    end

    defp configured_schema_prefix_node_for_ambiguous_module(node, config_module, config_opts, aliases) do
      if ambiguous_config_module_ast?(config_module, aliases) and
           ambiguous_schema_prefix_options?(config_opts) do
        {node, [{:dynamic, "ambiguous config module #{Macro.to_string(config_module)}"}]}
      else
        {node, :not_found}
      end
    end

    defp configured_schema_prefix_config(node, opts) when is_list(opts) do
      configured_schema_prefix_option(node, opts)
    end

    defp configured_schema_prefix_config(node, {:%{}, _meta, pairs}) when is_list(pairs) do
      configured_schema_prefix_map_option(node, pairs)
    end

    defp configured_schema_prefix_config(node, opts), do: {node, [{:dynamic, Macro.to_string(opts)}]}

    defp configured_schema_prefix_map_option(node, pairs) do
      results = Enum.flat_map(pairs, &schema_prefix_map_option_result/1)

      cond do
        results != [] ->
          {node, results}

        Enum.any?(pairs, &dynamic_config_map_pair?/1) ->
          {node, [{:dynamic, Macro.to_string({:%{}, [], pairs})}]}

        true ->
          {node, :not_found}
      end
    end

    defp schema_prefix_map_option_result({key, value}) do
      case static_config_key(key) do
        :schema_prefix ->
          [{:found, configured_schema_prefix_value(value)}]

        key when key in ["schema_prefix", :table_prefix, "table_prefix"] ->
          [{:found, {:string_key, key, value}}]

        _other ->
          []
      end
    end

    defp schema_prefix_map_option_result(_other), do: []

    defp dynamic_config_map_pair?({key, _value}), do: is_nil(static_config_key(key))
    defp dynamic_config_map_pair?(_other), do: true

    defp format_configured_schema_prefix_result(result) do
      case result do
        {:dynamic, expression} ->
          {:dynamic, expression}

        {:found, {:dynamic, expression}} ->
          {:dynamic, expression}

        {:found, {:string_key, key, value}} ->
          {:invalid, "string key #{inspect(key)} (value #{Macro.to_string(value)})"}

        {:found, prefix} when is_binary(prefix) or is_nil(prefix) ->
          {:ok, prefix}

        {:found, invalid} ->
          {:invalid, Macro.to_string(invalid)}

        :not_found ->
          :not_found
      end
    end

    defp configured_schema_prefix_option(node, opts) do
      results = Enum.flat_map(opts, &schema_prefix_option_result/1)

      cond do
        results != [] ->
          {node, results}

        Enum.any?(opts, &dynamic_config_option?/1) ->
          {node, [{:dynamic, Macro.to_string(opts)}]}

        true ->
          {node, :not_found}
      end
    end

    defp dynamic_config_option?({key, _value}), do: is_nil(static_config_key(key))
    defp dynamic_config_option?(_other), do: true

    defp schema_prefix_option_result({key, value}) do
      case static_config_key(key) do
        :schema_prefix -> [{:found, configured_schema_prefix_value(value)}]
        "schema_prefix" -> [{:found, {:string_key, "schema_prefix", value}}]
        "table_prefix" -> [{:found, {:string_key, "table_prefix", value}}]
        _other -> []
      end
    end

    defp schema_prefix_option_result(_other), do: []

    defp static_config_key({:__block__, _meta, [key]}) when is_atom(key) or is_binary(key), do: key
    defp static_config_key(key) when is_atom(key) or is_binary(key), do: key
    defp static_config_key(_dynamic), do: nil

    defp configured_schema_prefix_value(value) when is_binary(value) or is_nil(value), do: value

    defp configured_schema_prefix_value(value) when is_atom(value) or is_number(value) or is_list(value), do: value

    defp configured_schema_prefix_value(value), do: {:dynamic, Macro.to_string(value)}

    defp config_aliases(ast) do
      {_ast, aliases} =
        Macro.prewalk(ast, %{}, fn
          {:alias, _meta, [target]} = node, aliases ->
            {node, put_config_alias(aliases, target, nil)}

          {:alias, _meta, [target, opts]} = node, aliases when is_list(opts) ->
            {node, put_config_alias(aliases, target, Keyword.get(opts, :as))}

          node, aliases ->
            {node, aliases}
        end)

      aliases
    end

    defp put_config_alias(aliases, {:__aliases__, _meta, target_parts}, as) when is_list(target_parts) do
      alias_name = alias_name(target_parts, as)

      if is_atom(alias_name) do
        case Map.get(aliases, alias_name) do
          nil -> Map.put(aliases, alias_name, target_parts)
          ^target_parts -> aliases
          _other -> Map.put(aliases, alias_name, :ambiguous)
        end
      else
        aliases
      end
    end

    defp put_config_alias(aliases, _target, _as), do: aliases

    defp alias_name(target_parts, nil), do: List.last(target_parts)

    defp alias_name(_target_parts, {:__aliases__, _meta, [alias_name]}), do: alias_name
    defp alias_name(_target_parts, _invalid), do: nil

    defp attesto_config_module_ast?(module, aliases) do
      case module_alias_parts(module, aliases) do
        [:AttestoPhoenix, :Config] -> true
        _other -> false
      end
    end

    defp module_alias_parts({:__aliases__, _meta, [:AttestoPhoenix, :Config]}, _aliases), do: [:AttestoPhoenix, :Config]

    defp module_alias_parts({:__aliases__, _meta, [first | rest]}, aliases) do
      case Map.get(aliases, first) do
        nil -> nil
        :ambiguous -> nil
        target -> target ++ rest
      end
    end

    defp module_alias_parts(_module, _aliases), do: nil

    defp ambiguous_config_module_ast?(module, aliases), do: is_nil(module_alias_parts(module, aliases))

    defp ambiguous_schema_prefix_options?(opts) when is_list(opts) do
      Enum.any?(opts, fn
        {key, _value} when key in [:schema_prefix, "schema_prefix", :table_prefix, "table_prefix"] ->
          true

        {_key, _value} ->
          false

        _dynamic ->
          true
      end)
    end

    defp ambiguous_schema_prefix_options?({:%{}, _meta, pairs}) when is_list(pairs) do
      Enum.any?(pairs, fn
        {key, _value} when key in [:schema_prefix, "schema_prefix", :table_prefix, "table_prefix"] ->
          true

        _other ->
          false
      end)
    end

    defp ambiguous_schema_prefix_options?(_dynamic), do: true

    defp validate_oauth_path_prefix!(prefix) when is_binary(prefix) do
      trimmed = String.trim_trailing(prefix, "/")

      cond do
        trimmed == "" or not String.starts_with?(trimmed, "/") ->
          raise_invalid_oauth_path_prefix(prefix)

        String.contains?(prefix, "//") or
            not Regex.match?(~r/\A\/(?:[A-Za-z0-9_-]+\/)*oauth\z/, trimmed) ->
          raise_invalid_oauth_path_prefix(prefix)

        true ->
          trimmed
      end
    end

    defp validate_oauth_path_prefix!(prefix), do: raise_invalid_oauth_path_prefix(prefix)

    defp raise_invalid_oauth_path_prefix(prefix) do
      raise Mix.Error,
        message:
          "unsupported --oauth-path-prefix #{inspect(prefix)}: the bundled router mounts " <>
            "fixed /oauth/* endpoint tails. Use /oauth or slash-separated literal " <>
            "segments containing only letters, digits, `_`, or `-`, ending in /oauth " <>
            "(for example /mcp/oauth, which generates attesto_routes(prefix: \"/mcp\")). " <>
            "For a different suffix or explicit endpoint paths, mount the routes manually " <>
            "and configure matching advertised paths; the installer made no changes."
    end

    defp validate_schema_prefix!(prefix) do
      cond do
        is_nil(prefix) ->
          nil

        prefix == "" ->
          raise Mix.Error,
            message: "invalid --schema-prefix: expected a non-empty lowercase PostgreSQL schema identifier"

        byte_size(prefix) > 63 ->
          raise Mix.Error,
            message: "invalid --schema-prefix: expected at most 63 bytes"

        prefix == "information_schema" or String.starts_with?(prefix, "pg_") ->
          raise Mix.Error,
            message:
              "invalid --schema-prefix: #{inspect(prefix)} is a reserved PostgreSQL system schema; choose an application-owned schema"

        Regex.match?(~r/\A[a-z_][a-z0-9_]*\z/, prefix) ->
          prefix

        true ->
          raise Mix.Error,
            message: "invalid --schema-prefix: expected a lowercase PostgreSQL schema identifier"
      end
    end

    defp reject_legacy_table_prefix_args!(argv) do
      if Enum.any?(argv, &legacy_table_prefix_arg?/1) do
        raise Mix.Error,
          message:
            "--table-prefix was removed in 3.0. In 2.x it controlled literal names in generated migrations but did not identify one runtime layout: most stores queried canonical public tables, while only the CIBA store and sweeper used it as an Ecto schema prefix. Use --schema-prefix for a fresh migration; inventory and migrate verified existing sources before deploying."
      end
    end

    # The installer can repair its own generated AST, but it cannot safely
    # infer which physical relations a host-owned `:table_prefix` deployment
    # actually used. Leave the source untouched and emit a fail-closed notice:
    # Config rejects the key at boot, so a rerun cannot silently route an
    # existing database to `public`.
    defp notice_legacy_table_prefix_config(igniter) do
      config_path = ProjectApplication.config_path(igniter)
      config_dir = config_path |> Path.dirname() |> Path.expand()
      config_glob = Path.join(config_dir, "**/*.exs")
      igniter = Igniter.include_glob(igniter, config_glob)

      if Rewrite.sources(igniter.rewrite)
         |> Enum.any?(&legacy_table_prefix_config_source?/1) do
        Igniter.add_notice(igniter, """
        Legacy `:table_prefix` configuration was found in the host config. The
        installer leaves that host-owned AST untouched because the setting does
        not identify one runtime layout. In v2.14.2 the migration generator
        could create literal-prefixed tables in `public`, most stores queried
        canonical public tables, and only the CIBA store and sweeper used the
        value as an Ecto schema prefix. Inventory actual sources from counts,
        observed behavior, and backups; stop if a logical table has split
        non-empty candidates; move only verified sources. Then remove every
        legacy `:table_prefix` entry, set `:schema_prefix` to the PostgreSQL
        schema containing the migrated canonical tables, and complete the
        stopped 2.x -> 3.0 cutover before boot. `AttestoPhoenix.Config` will fail closed while the legacy key
        remains; it will not reinterpret it as a schema. See
        `guides/upgrade_3_0_schema_prefix.md` for inventory and migration
        checks.
        """)
      else
        igniter
      end
    end

    defp legacy_table_prefix_config_source?(%{path: path, content: content})
         when is_binary(path) and is_binary(content) do
      Path.extname(path) == ".exs" and
        (String.contains?(content, "table_prefix:") or
           String.contains?(content, ":table_prefix") or
           String.contains?(content, "\"table_prefix\""))
    end

    defp legacy_table_prefix_config_source?(_source), do: false

    defp legacy_table_prefix_arg?("--table-prefix"), do: true
    defp legacy_table_prefix_arg?(arg) when is_binary(arg), do: String.starts_with?(arg, "--table-prefix=")
    defp legacy_table_prefix_arg?(_arg), do: false

    defp audience_default do
      quote do
        System.get_env("ATTESTO_AUDIENCE") || System.get_env("ATTESTO_ISSUER") ||
          "https://localhost"
      end
    end

    # Generate the development/test fallback once per installer invocation. The
    # value is persisted in the generated host's runtime config by
    # `configure_new/5`, which leaves an existing project value untouched on a
    # later run. URL-safe Base64 keeps the literal easy to paste into an
    # environment variable while retaining all 256 bits from the CSPRNG.
    defp generate_refresh_successor_secret do
      @refresh_successor_secret_bytes
      |> :crypto.strong_rand_bytes()
      |> Base.url_encode64(padding: false)
    end

    defp refresh_successor_secret_runtime_default(secret) do
      quote do
        case System.get_env("ATTESTO_REFRESH_SUCCESSOR_SECRET") do
          nil ->
            if config_env() in [:dev, :test] do
              unquote(secret)
            end

          secret ->
            secret
        end
      end
    end

    # ------------------------------------------------------------------
    # Router
    # ------------------------------------------------------------------

    # Mounts `attesto_routes/1` into the host router under the chosen prefix. The
    # whole router edit is guarded by a source-content check for an existing
    # `attesto_routes` call, so re-running the installer neither duplicates the
    # `use AttestoPhoenix.Router` nor adds a second server scope. When no router
    # is found (a non-Phoenix host), a notice tells the host how to mount the
    # routes by hand.
    defp mount_routes(igniter, app, oauth_path_prefix) do
      case Phoenix.list_routers(igniter) do
        {igniter, [router | _]} ->
          igniter
          |> ensure_config_pipeline(router, app)
          |> mount_routes_into(router, oauth_path_prefix)

        {igniter, []} ->
          Igniter.add_notice(igniter, """
          No Phoenix router was found, so the attesto_phoenix routes were not
          mounted. Add them to your router manually:

              use AttestoPhoenix.Router

              pipeline #{inspect(@config_pipeline)} do
                plug AttestoPhoenix.Plug.PutConfig, otp_app: #{inspect(app)}
              end

              scope "/" do
                #{router_scope_body(oauth_path_prefix)}
              end
          """)
      end
    end

    # Installs the pipeline that resolves both immutable configs and puts them in
    # conn.private. An old installer output may already contain the pipeline
    # name, so add only the missing plug rather than replacing host edits.
    defp ensure_config_pipeline(igniter, router, app) do
      plug_code = "plug AttestoPhoenix.Plug.PutConfig, otp_app: #{inspect(app)}"
      pipeline_code = "pipeline #{inspect(@config_pipeline)} do\n  #{plug_code}\nend"

      ProjectModule.find_and_update_module!(igniter, router, fn zipper ->
        case move_to_config_pipeline(zipper) do
          {:ok, pipeline_zipper} ->
            ensure_config_plug(zipper, pipeline_zipper, plug_code)

          :error ->
            {:ok, Common.add_code(zipper, pipeline_code)}
        end
      end)
    end

    defp ensure_config_plug(module_zipper, pipeline_zipper, plug_code) do
      case Common.move_to_do_block(pipeline_zipper) do
        {:ok, block_zipper} -> maybe_add_config_plug(module_zipper, block_zipper, plug_code)
        :error -> {:ok, module_zipper}
      end
    end

    defp maybe_add_config_plug(module_zipper, block_zipper, plug_code) do
      if config_plug_present?(block_zipper) do
        {:ok, module_zipper}
      else
        {:ok, Common.add_code(block_zipper, plug_code)}
      end
    end

    defp move_to_config_pipeline(zipper) do
      Function.move_to_function_call_in_current_scope(
        zipper,
        :pipeline,
        2,
        &Function.argument_equals?(&1, 0, @config_pipeline)
      )
    end

    defp config_plug_present?(zipper) do
      case Function.move_to_function_call_in_current_scope(
             zipper,
             :plug,
             [1, 2],
             &Function.argument_equals?(&1, 0, PutConfig)
           ) do
        {:ok, _plug} -> true
        :error -> false
      end
    end

    # The router edit repairs old installer output as well as creating a fresh
    # mount. An existing literal attesto_routes call with no host pipeline gets
    # the generated config pipeline; a host-managed pipeline declaration remains
    # authoritative.
    defp mount_routes_into(igniter, router, oauth_path_prefix) do
      scope_code = """
      scope "/" do
        #{router_scope_body(oauth_path_prefix)}
      end
      """

      ProjectModule.find_and_update_module!(igniter, router, fn zipper ->
        zipper = add_router_use(zipper)

        case move_to_attesto_routes(zipper) do
          {:ok, routes_zipper} -> ensure_route_pipeline(routes_zipper, oauth_path_prefix)
          :error -> {:ok, Common.add_code(zipper, scope_code)}
        end
      end)
    end

    defp move_to_attesto_routes(zipper), do: Function.move_to_function_call(zipper, :attesto_routes, [0, 1])

    defp ensure_route_pipeline(routes_zipper, oauth_path_prefix) do
      validate_existing_route_prefix!(routes_zipper, oauth_path_prefix)

      case routes_zipper.node do
        {:attesto_routes, _meta, []} ->
          Function.append_argument(routes_zipper, pipeline: @config_pipeline)

        {:attesto_routes, _meta, [_opts]} ->
          Function.update_nth_argument(routes_zipper, 0, &put_config_pipeline/1)

        _other ->
          {:ok, routes_zipper}
      end
    end

    defp validate_existing_route_prefix!(%{node: {:attesto_routes, _meta, args}} = routes_zipper, expected_oauth_prefix) do
      with macro_prefix when is_binary(macro_prefix) <- existing_route_prefix(args),
           {:ok, scope_prefix} <- enclosing_scope_prefix(routes_zipper) do
        actual_oauth_prefix = join_route_prefixes([scope_prefix, macro_prefix]) <> "/oauth"

        if actual_oauth_prefix == expected_oauth_prefix do
          :ok
        else
          raise_existing_route_prefix_error(actual_oauth_prefix, expected_oauth_prefix)
        end
      else
        :dynamic -> raise_existing_route_prefix_error(:dynamic, expected_oauth_prefix)
        {:error, reason} -> raise_existing_route_scope_error(reason, expected_oauth_prefix)
      end
    end

    defp existing_route_prefix([]), do: ""

    defp existing_route_prefix([opts]) when is_list(opts) do
      case Enum.find(opts, fn
             {key, _value} -> keyword_ast_key(key) == :prefix
             _other -> false
           end) do
        nil -> ""
        {_key, value} -> literal_route_prefix(value)
      end
    end

    defp existing_route_prefix(_dynamic), do: :dynamic

    defp enclosing_scope_prefix(routes_zipper), do: collect_scope_prefix(Zipper.up(routes_zipper), [])

    defp collect_scope_prefix(nil, prefixes), do: {:ok, join_route_prefixes(prefixes)}

    defp collect_scope_prefix(%{node: {:scope, _meta, args}} = scope_zipper, prefixes) do
      case literal_scope_prefix(args) do
        prefix when is_binary(prefix) ->
          collect_scope_prefix(Zipper.up(scope_zipper), [prefix | prefixes])

        :dynamic ->
          {:error, :dynamic_or_ambiguous_scope}
      end
    end

    defp collect_scope_prefix(zipper, prefixes), do: collect_scope_prefix(Zipper.up(zipper), prefixes)

    defp literal_scope_prefix([path | _rest]), do: literal_scope_prefix(path)
    defp literal_scope_prefix([]), do: :dynamic

    defp literal_scope_prefix({:__block__, _meta, [prefix]}), do: literal_scope_prefix(prefix)

    defp literal_scope_prefix(prefix) when prefix in ["", "/"], do: ""

    defp literal_scope_prefix(prefix) when is_binary(prefix) do
      if Regex.match?(~r/\A\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]+\z/, prefix), do: prefix, else: :dynamic
    end

    defp literal_scope_prefix(_dynamic), do: :dynamic

    defp join_route_prefixes(prefixes) do
      segments =
        prefixes
        |> Enum.map(&String.trim(&1, "/"))
        |> Enum.reject(&(&1 == ""))

      case segments do
        [] -> ""
        segments -> "/" <> Enum.join(segments, "/")
      end
    end

    defp raise_existing_route_prefix_error(actual_prefix, expected_oauth_prefix) do
      actual = if is_binary(actual_prefix), do: actual_prefix <> "/*", else: "<dynamic>"

      raise Mix.Error,
        message:
          "existing attesto_routes/1 mounts #{inspect(actual)}, but " <>
            "--oauth-path-prefix expects #{inspect(expected_oauth_prefix <> "/*")} for the " <>
            "bundled fixed /oauth/* tails. Update the enclosing scope, route prefix, and " <>
            "advertised :oauth_path_prefix together, or mount the routes manually; the " <>
            "installer made no changes."
    end

    defp raise_existing_route_scope_error(reason, expected_oauth_prefix) do
      raise Mix.Error,
        message:
          "could not prove the enclosing Phoenix scope for existing attesto_routes/1 " <>
            "(#{inspect(reason)}); --oauth-path-prefix #{inspect(expected_oauth_prefix)} " <>
            "requires a statically matching route mount. Update the scope and advertised " <>
            ":oauth_path_prefix together, or mount the routes manually; the installer made " <>
            "no changes."
    end

    defp keyword_ast_key({:__block__, _meta, [key]}) when is_atom(key), do: key
    defp keyword_ast_key(key) when is_atom(key), do: key
    defp keyword_ast_key(_key), do: nil

    defp literal_route_prefix({:__block__, _meta, [prefix]}), do: literal_route_prefix(prefix)

    defp literal_route_prefix(""), do: ""

    defp literal_route_prefix(prefix) when is_binary(prefix) do
      if Regex.match?(~r/\A\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]+\z/, prefix), do: prefix, else: :dynamic
    end

    defp literal_route_prefix(_dynamic), do: :dynamic

    defp put_config_pipeline(opts_zipper) do
      if CodeKeyword.keyword_has_path?(opts_zipper, [:pipeline]) or
           CodeKeyword.keyword_has_path?(opts_zipper, [:route_pipelines]) do
        {:ok, opts_zipper}
      else
        add_config_pipeline_option(opts_zipper)
      end
    end

    defp add_config_pipeline_option(opts_zipper) do
      case CodeKeyword.put_in_keyword(opts_zipper, [:pipeline], @config_pipeline) do
        {:ok, updated} -> {:ok, updated}
        :error -> {:ok, opts_zipper}
      end
    end

    # Adds `use AttestoPhoenix.Router` unless the module already uses it. Operates
    # on (and returns) the zipper positioned at the router module.
    defp add_router_use(zipper) do
      case Function.move_to_function_call_in_current_scope(
             zipper,
             :use,
             [1, 2],
             &Function.argument_equals?(&1, 0, AttestoPhoenix.Router)
           ) do
        {:ok, _present} -> zipper
        :error -> Common.add_code(zipper, "use AttestoPhoenix.Router")
      end
    end

    # The `attesto_routes/1` macro takes a `:prefix` that is prepended to the
    # `/oauth/*` tails. The historic default (`/oauth`) needs no `:prefix`; a
    # relocated prefix is passed through. The router's well-known documents stay
    # at the host root regardless (RFC 8615).
    defp router_scope_body(oauth_path_prefix) do
      case router_prefix(oauth_path_prefix) do
        "" -> "attesto_routes(pipeline: #{inspect(@config_pipeline)})"
        prefix -> ~s|attesto_routes(prefix: "#{prefix}", pipeline: #{inspect(@config_pipeline)})|
      end
    end

    # The macro's `/oauth/*` tails already carry the `/oauth` segment, so the
    # macro `:prefix` is the part of `:oauth_path_prefix` BEYOND that default.
    # `/oauth` -> "" (no prefix needed); `/mcp/oauth` -> "/mcp".
    defp router_prefix(oauth_path_prefix) do
      trimmed = String.trim_trailing(oauth_path_prefix, "/")

      case trimmed do
        "/oauth" -> ""
        other -> String.replace_suffix(other, "/oauth", "")
      end
    end

    # ------------------------------------------------------------------
    # Callback module scaffolds
    # ------------------------------------------------------------------

    # Creates one host module per recommended behaviour, each `@behaviour`-tagged
    # with documented stub callbacks the host fills in. Each scaffold is guarded
    # by a file-existence check at the module's resolved location, so re-running
    # the installer leaves an already-scaffolded (and host-edited) module
    # untouched. The check is on the target file rather than on
    # `module_exists?/2` (deprecated) so the task compiles under
    # `--warnings-as-errors`.
    defp scaffold_callback_modules(igniter, callbacks_module) do
      igniter =
        Enum.reduce(@scaffolds, igniter, fn {submodule, behaviour, callbacks}, igniter ->
          module = Module.concat(callbacks_module, submodule)
          path = ProjectModule.proper_location(igniter, module)

          if Igniter.exists?(igniter, path) do
            igniter
          else
            ProjectModule.create_module(
              igniter,
              module,
              scaffold_contents(behaviour, callbacks)
            )
          end
        end)

      ensure_principal_kinds_callback(igniter, callbacks_module)
    end

    # Older installer output already has a host-owned PrincipalStore module but
    # predates the principal-kind catalog callback. Add only that missing
    # function, leaving every existing definition untouched.
    defp ensure_principal_kinds_callback(igniter, callbacks_module) do
      principal_store = Module.concat(callbacks_module, PrincipalStore)

      ProjectModule.find_and_update_module!(igniter, principal_store, fn zipper ->
        case Function.move_to_def(zipper, :principal_kinds, 0, target: :at) do
          {:ok, _definition} ->
            {:ok, zipper}

          :error ->
            {:ok,
             Common.add_code(zipper, """
             def principal_kinds do
               raise "implement principal_kinds/0 (generated by mix attesto_phoenix.install)"
             end
             """)}
        end
      end)
    end

    defp scaffold_contents(behaviour, callbacks) do
      stubs = Enum.map_join(callbacks, "\n\n", &stub_callback/1)

      """
      @moduledoc \"\"\"
      Host implementation of `#{inspect(behaviour)}`.

      Generated by `mix attesto_phoenix.install`. Each callback below is a stub
      that raises until you implement it. See `#{inspect(behaviour)}` for the
      full contract (with the governing RFC per callback) and wire these
      functions in `config/config.exs` under `config :your_app,
      AttestoPhoenix.Config` (the installer wired the default function names for
      you).
      \"\"\"

      @behaviour #{inspect(behaviour)}

      #{stubs}
      """
    end

    # A single stub callback: the `@impl` annotation, the head with `_`-prefixed
    # arguments, and a `raise` so an unimplemented callback fails loudly rather
    # than silently returning a wrong default on the request path.
    defp stub_callback({function, arity}) do
      args =
        case arity do
          0 -> ""
          n -> Enum.map_join(1..n, ", ", &"_arg#{&1}")
        end

      """
      @impl true
      def #{function}(#{args}) do
        raise "implement #{function}/#{arity} (generated by mix attesto_phoenix.install)"
      end\
      """
    end

    # ------------------------------------------------------------------
    # Notices
    # ------------------------------------------------------------------

    defp add_next_step_notices(igniter, app, oauth_path_prefix, schema_prefix, callbacks_module, repo) do
      migration_command =
        case schema_prefix do
          nil -> "mix attesto_phoenix.gen.migration --repo #{inspect(repo)}"
          prefix -> "mix attesto_phoenix.gen.migration --repo #{inspect(repo)} --schema-prefix #{prefix}"
        end

      selected_schema = schema_prefix || "public (Ecto default)"

      Igniter.add_notice(igniter, """
      attesto_phoenix is installed. Remaining app-owned steps:

        1. Implement the scaffolded callback modules under
           #{inspect(callbacks_module)}.* (each stub callback currently raises).
           Each module documents its contract; the governing RFC is cited per
           callback in the corresponding behaviour module.

           In particular, `#{inspect(callbacks_module)}.PrincipalStore` must
           return the deployment's non-empty `Attesto.PrincipalKind` catalog
           from `principal_kinds/0`.

        2. Provide a keystore: set :keystore in `config :#{app},
           AttestoPhoenix.Config` to a module implementing Attesto.Keystore (the
           signing key plus the JWKS verification keys), set :issuer to your
           https issuer URL, and set :audience to the protected resource URL
           (prefer config/runtime.exs per deployment).

           When the bundled Ecto refresh store uses positive rotation grace,
           provision `ATTESTO_REFRESH_SUCCESSOR_SECRET` as one stable secret of
           at least 32 bytes in production. Every node and deployment serving
           the same refresh-token families must use the same value. Config
           validation refuses startup when that combination lacks a valid
           secret; custom stores and strict zero-grace deployments do not need
           this Ecto-specific key.

        3. Create the Ecto tables the bundled stores read (including the
           durable refresh-family revocation tombstone table):

               #{migration_command}

           then `mix ecto.migrate`.

           The generated stores and sweeper use PostgreSQL schema `#{selected_schema}`.
           Keep one `AttestoPhoenix.Store.Sweeper` instance per independent
           `{repo, schema_prefix}` pair; do not run multiple sweepers against
           one pair or share one sweeper across independent profiles.

           If this is an upgrade of an existing database, add the tombstone
           table with a forward migration and backfill it from revoked rows
           before deploying the new code. Also add the unique
           `(family_id, generation)` index named
           `attesto_refresh_tokens_family_id_generation_index` to
           `attesto_refresh_tokens`; stop and reconcile if duplicate rows make
           that index fail. Do not rerun the create-table migration against
           tables that already exist.

           Stop and drain every 2.x token writer before this migration and
           before starting 3.0, including deployments using the public schema.
           Mixed 2.x/3.0 writers are unsupported because 2.x does not read or
           write durable refresh-family revocation tombstones.

        4. The OAuth endpoints are mounted under "#{oauth_path_prefix}". The
           well-known discovery and JWKS documents stay at the host root
           (RFC 8615). To enable dynamic client registration (RFC 7591), set
           `registration_enabled: true`, wire :register_client, and pass
           `registration: true` to `attesto_routes/1` in your router.

        5. For local development, attesto needs an https issuer. Serve a
           locally-trusted mkcert cert with `mix attesto_phoenix.gen.dev_https`,
           then set `https: AttestoPhoenix.DevTLS.https_opts(port: 4443)` on your
           dev endpoint (see the Local HTTPS guide).
      """)
    end
  end
else
  defmodule Mix.Tasks.AttestoPhoenix.Install do
    @shortdoc "#{Mix.Tasks.AttestoPhoenix.Install.Docs.short_doc()} | Install `igniter` to use"

    @moduledoc Mix.Tasks.AttestoPhoenix.Install.Docs.long_doc()

    use Mix.Task

    @impl Mix.Task
    def run(_argv) do
      Mix.shell().error("""
      The task 'attesto_phoenix.install' requires igniter. Install `igniter` and run it with:

          mix igniter.install attesto_phoenix

      or add `{:igniter, "~> 0.5"}` to your deps and run `mix attesto_phoenix.install` again.
      """)

      exit({:shutdown, 1})
    end
  end
end
