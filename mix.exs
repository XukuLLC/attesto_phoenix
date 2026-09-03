defmodule AttestoPhoenix.MixProject do
  @moduledoc false
  use Mix.Project

  alias AttestoPhoenix.Controller.DiscoveryController
  alias AttestoPhoenix.Controller.JWKSController
  alias AttestoPhoenix.Controller.PARController
  alias AttestoPhoenix.Controller.RegistrationController
  alias AttestoPhoenix.Controller.RevocationController
  alias AttestoPhoenix.Controller.TokenController
  alias AttestoPhoenix.Controller.UserinfoController
  alias AttestoPhoenix.OpenAPI.TokenEndpoint
  alias AttestoPhoenix.Plug.PutConfig
  alias AttestoPhoenix.Schema.Authorization
  alias AttestoPhoenix.Schema.DPoPNonce
  alias AttestoPhoenix.Schema.DPoPReplay
  alias AttestoPhoenix.Schema.RefreshToken
  alias AttestoPhoenix.Store.EctoCodeStore
  alias AttestoPhoenix.Store.EctoNonceStore
  alias AttestoPhoenix.Store.EctoRefreshStore
  alias AttestoPhoenix.Store.EctoReplayCheck
  alias AttestoPhoenix.Store.PAR.ETS
  alias AttestoPhoenix.Store.Sweeper

  @version "3.2.0"
  @url "https://github.com/XukuLLC/attesto_phoenix"
  @maintainers ["Neil Berkman"]
  @attesto_requirement ">= 2.0.0 and < 3.0.0"
  @hex_package_tasks ["hex.build", "hex.publish"]

  def project do
    [
      name: "AttestoPhoenix",
      app: :attesto_phoenix,
      version: @version,
      elixir: "~> 1.18",
      package: package(),
      source_url: @url,
      homepage_url: @url,
      maintainers: @maintainers,
      description:
        "Phoenix/Ecto OAuth 2.0 / OIDC authorization server layer over attesto: " <>
          "authorization, token, PAR, revocation, discovery, JWKS, UserInfo, " <>
          "protected-resource plugs, and Ecto-backed token stores.",
      deps: deps(),
      elixirc_paths: elixirc_paths(Mix.env()),
      docs: docs(),
      aliases: aliases(),
      dialyzer: [
        ignore_warnings: ".dialyzer_ignore.exs",
        plt_add_apps: [:mix, :ex_unit],
        plt_core_path: "priv/plts",
        plt_file: {:no_warn, "priv/plts/attesto_phoenix.plt"}
      ]
    ]
  end

  def cli do
    [preferred_envs: [precommit: :test]]
  end

  def application do
    [extra_applications: [:logger], mod: {AttestoPhoenix.Application, []}]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Co-develop against an Attesto source checkout only when explicitly opted in.
  # `ATTESTO_SOURCE_PATH` is the CI-friendly form; ATTESTO_PATH=1 retains the
  # local sibling-checkout shorthand. Both are validated before becoming path
  # dependencies, so a typo cannot silently exercise a released core instead.
  #
  # `mix hex.build` / `mix hex.publish` run in :dev, and a path dep cannot be
  # packaged ("only Hex packages can be dependencies"). Keep those tasks on the
  # Hex requirement even when a developer's shell exports a path opt-in. This
  # also makes the generated package metadata the release contract every time.
  #
  # The 2.0 floor is load-bearing: this package implements the atomic refresh
  # rotation transaction and device-code decision contracts introduced by that
  # major. Resolving an older core would leave the Ecto adapters and grant
  # orchestration on incompatible public callbacks.
  defp attesto_dep do
    source_path = System.get_env("ATTESTO_SOURCE_PATH")

    cond do
      hex_package_task?() -> {:attesto, @attesto_requirement}
      is_binary(source_path) and source_path != "" -> attesto_source_dep!(source_path)
      System.get_env("ATTESTO_PATH") in ~w(1 true) -> attesto_source_dep!("../attesto")
      true -> {:attesto, @attesto_requirement}
    end
  end

  defp hex_package_task? do
    Enum.any?(System.argv(), &(&1 in @hex_package_tasks))
  end

  defp attesto_source_dep!(path) do
    expanded_path = Path.expand(path)

    if File.dir?(expanded_path) and
         File.regular?(Path.join(expanded_path, "mix.exs")) and
         (File.dir?(Path.join(expanded_path, ".git")) or
            File.regular?(Path.join(expanded_path, ".git"))) do
      {:attesto, path: expanded_path}
    else
      Mix.raise(
        "Attesto source dependency path #{inspect(path)} must point to a Git checkout " <>
          "containing mix.exs (resolved to #{inspect(expanded_path)})"
      )
    end
  end

  defp deps do
    [
      # Core OAuth2/OIDC primitives: Token, IDToken, DPoP, MTLS, Scope,
      # AuthorizationCode, AuthorizationRequest, RefreshToken, Discovery,
      # OpenIDDiscovery, the store behaviours, and the base plugs.
      attesto_dep(),
      # ISO 18013-5 mdoc encoding for the mso_mdoc credential issuance path.
      {:cbor, "~> 1.0", optional: true},
      # Ecto-backed CodeStore/RefreshStore/NonceStore/ReplayCheck + the migration
      # generator.
      {:ecto_sql, "~> 3.10"},
      # Runtime events emitted by the sweeper-liveness monitor.
      {:telemetry, "~> 1.0"},
      # Controllers + the attesto_routes/1 router macro.
      {:phoenix, "~> 1.7.24 or >= 1.8.9 and < 2.0.0"},
      # Optional OpenAPI structs for hosts that publish an OpenApiSpex spec.
      {:open_api_spex, "~> 3.0", optional: true},
      # Plug behaviours for the protected-resource plugs (also a Phoenix
      # transitive dependency).
      {:plug, "~> 1.16.6 or ~> 1.17.4 or ~> 1.18.5 or ~> 1.19.5 or >= 1.20.3 and < 2.0.0"},
      # `mix attesto_phoenix.install` (Mix.Tasks.AttestoPhoenix.Install) is an
      # upgrade-aware Igniter installer: it inspects the host's config and router
      # and applies idempotent patches. Declared `optional: true` so the runtime
      # hex package never forces igniter onto a consumer that only depends on the
      # library at runtime. The dependency is present for the install task to
      # compile against and for a host that opts into running the installer, but
      # it is not a transitive runtime requirement. Igniter 0.6 is the oldest
      # line that compiles on this package's supported Elixir/OTP floor.
      {:igniter, "~> 0.6", optional: true},

      # HTTP client for the bundled Client ID Metadata/JWT JWKS fetcher, CIBA
      # ping deliverer, and Back-Channel Logout client. Req -> Finch -> Mint
      # gives redirect control, connect/receive timeouts, and the connect-by-IP
      # pinning the SSRF guard needs (Mint's `:hostname` connect option keeps TLS
      # SNI + certificate verification on the original host while the socket
      # targets a validated IP). Declared `optional: true` so a host that never
      # enables those outbound paths - or supplies its own adapters - pays
      # nothing for it.
      {:req, ">= 0.6.1 and < 1.0.0", optional: true},

      # test - the bundled Ecto stores run against a real Postgres repo.
      {:postgrex, ">= 0.22.4", only: [:dev, :test]},
      # test-only client interop: prove the protected-resource plug accepts
      # DPoP requests generated by an external Req client package.
      {:req_dpop, "~> 0.5", only: :test, runtime: false},
      # test-only HTTP origin server for outbound delivery/fetch tests. Bandit
      # avoids pulling the advisory-affected Cowboy/Cowlib stack into the lock.
      {:bandit, "~> 1.12.1", only: :test},

      # dev / quality
      {:ex_doc, "~> 0.40", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev], runtime: false},
      {:mix_test_watch, "~> 1.4", only: :dev, runtime: false},
      {:quokka, "~> 2.12", only: [:dev, :test], runtime: false}
    ]
  end

  defp aliases do
    [
      setup: ["deps.get"],
      precommit: [
        "format --check-formatted",
        "compile --warnings-as-errors",
        "credo --strict",
        "test"
      ]
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      source_url: @url,
      extras: [
        "README.md",
        "guides/upgrade_3_0_schema_prefix.md",
        "guides/examples.md",
        "guides/local_https.md",
        "guides/consumer_migration.md",
        "guides/proxy_canonical_host.md",
        "guides/replay_nonce_production.md",
        "guides/error_envelope.md",
        "guides/identity_assertion_grant.md",
        "notebooks/attesto_phoenix_demo.livemd",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "LICENSE"
      ],
      groups_for_extras: [
        Guides: ~r/guides\/.*/,
        Notebooks: ~r/notebooks\/.*/,
        Changelog: ~r/CHANGELOG\.md/,
        Contributing: ~r/CONTRIBUTING\.md/,
        License: ~r/LICENSE/
      ],
      groups_for_modules: [
        Setup: [
          AttestoPhoenix,
          AttestoPhoenix.Config,
          PutConfig,
          AttestoPhoenix.Router
        ],
        "Host contracts (behaviours)": [
          AttestoPhoenix.ClientStore,
          AttestoPhoenix.PrincipalStore,
          AttestoPhoenix.ScopePolicy,
          AttestoPhoenix.ConsentPolicy,
          AttestoPhoenix.RegistrationStore,
          AttestoPhoenix.EventSink
        ],
        Controllers: [
          TokenController,
          RevocationController,
          DiscoveryController,
          JWKSController,
          PARController,
          RegistrationController,
          UserinfoController
        ],
        OpenAPI: [
          TokenEndpoint
        ],
        Stores: [
          EctoCodeStore,
          EctoRefreshStore,
          EctoReplayCheck,
          EctoNonceStore,
          ETS,
          Sweeper
        ],
        Schemas: [
          Authorization,
          RefreshToken,
          DPoPReplay,
          DPoPNonce
        ],
        Shared: [
          AttestoPhoenix.AuthorizationCodePrivateContext,
          AttestoPhoenix.OAuthError,
          AttestoPhoenix.Event,
          AttestoPhoenix.PARStore,
          AttestoPhoenix.ResourceAudiencePolicy,
          AttestoPhoenix.RequestContext
        ]
      ]
    ]
  end

  defp package do
    [
      maintainers: @maintainers,
      licenses: ["MIT"],
      links: %{
        "Changelog" => "https://hexdocs.pm/attesto_phoenix/changelog.html",
        "GitHub" => @url
      },
      files: ~w(lib guides notebooks LICENSE mix.exs README.md CHANGELOG.md CONTRIBUTING.md)
    ]
  end
end
