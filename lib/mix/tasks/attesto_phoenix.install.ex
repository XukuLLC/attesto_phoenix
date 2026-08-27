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
        `:oauth_path_prefix`, and neutral defaults) to the host config, and
        points the library's global resolver and stores at that OTP app/repo,
      * mounts the server routes (`attesto_routes/1`) at the chosen prefix into
        the host router behind a generated config-loading pipeline,
      * scaffolds host callback modules implementing the recommended production
        behaviours (`AttestoPhoenix.ClientStore`, `PrincipalStore`,
        `ScopePolicy`, `ConsentPolicy`, `RegistrationStore`, `EventSink`) with
        documented stub callbacks the host fills in,
      * points the host at `mix attesto_phoenix.gen.migration` for the Ecto
        tables the bundled stores read.

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

      * `--oauth-path-prefix` - the client-visible mount prefix for the OAuth
        endpoints (RFC 8414 §3 advertises the absolute URLs; the mounted routes
        and the advertised metadata derive from the same prefix so they cannot
        drift). Defaults to `/oauth`, reproducing the historic surface. A host
        avoiding a collision with a legacy provider may pass, for example,
        `--oauth-path-prefix /mcp/oauth`. The well-known documents (RFC 8615)
        and the JWKS document stay anchored at the host root and are NOT
        relocated by this prefix.
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
    alias Igniter.Code.Common
    alias Igniter.Code.Function
    alias Igniter.Code.Keyword, as: CodeKeyword
    alias Igniter.Libs.Phoenix
    alias Igniter.Mix.Task.Info
    alias Igniter.Project.Config, as: ProjectConfig
    alias Igniter.Project.Module, as: ProjectModule
    alias Mix.Tasks.AttestoPhoenix.Install.Docs

    # The default OAuth mount prefix reproduces the historic `/oauth/*` surface
    # (`AttestoPhoenix.Config`'s `:oauth_path_prefix` default). A host may
    # relocate it with `--oauth-path-prefix`.
    @default_oauth_path_prefix "/oauth"
    @config_pipeline :attesto_phoenix_config

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
          callbacks_module: :string
        ]
      }
    end

    @impl Igniter.Mix.Task
    def igniter(igniter) do
      app = Igniter.Project.Application.app_name(igniter)
      app_module = ProjectModule.module_name_prefix(igniter)
      repo = Module.concat(app_module, Repo)
      options = igniter.args.options

      oauth_path_prefix = options[:oauth_path_prefix] || @default_oauth_path_prefix
      callbacks_module = callbacks_module(options, app_module)

      igniter
      |> scaffold_callback_modules(callbacks_module)
      |> configure_attesto_phoenix(app, oauth_path_prefix, callbacks_module, repo)
      |> mount_routes(app, oauth_path_prefix)
      |> add_next_step_notices(app, oauth_path_prefix, callbacks_module, repo)
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
    defp configure_attesto_phoenix(igniter, app, oauth_path_prefix, callbacks_module, repo) do
      config = config_skeleton(oauth_path_prefix, callbacks_module, repo)
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
    end

    defp config_skeleton(oauth_path_prefix, callbacks_module, repo) do
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
          # the backing tables.
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

    defp audience_default do
      quote do
        System.get_env("ATTESTO_AUDIENCE") || System.get_env("ATTESTO_ISSUER") ||
          "https://localhost"
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
          {:ok, routes_zipper} -> ensure_route_pipeline(routes_zipper)
          :error -> {:ok, Common.add_code(zipper, scope_code)}
        end
      end)
    end

    defp move_to_attesto_routes(zipper), do: Function.move_to_function_call(zipper, :attesto_routes, [0, 1])

    defp ensure_route_pipeline(routes_zipper) do
      case routes_zipper.node do
        {:attesto_routes, _meta, []} ->
          Function.append_argument(routes_zipper, pipeline: @config_pipeline)

        {:attesto_routes, _meta, [_opts]} ->
          Function.update_nth_argument(routes_zipper, 0, &put_config_pipeline/1)

        _other ->
          {:ok, routes_zipper}
      end
    end

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

    defp add_next_step_notices(igniter, app, oauth_path_prefix, callbacks_module, repo) do
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

        3. Create the Ecto tables the bundled stores read:

               mix attesto_phoenix.gen.migration --repo #{inspect(repo)}

           then `mix ecto.migrate`.

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
