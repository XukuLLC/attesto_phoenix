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

  @version "2.13.0"
  @url "https://github.com/XukuLLC/attesto_phoenix"
  @maintainers ["Neil Berkman"]

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
    [extra_applications: [:logger]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Co-develop against the sibling attesto checkout, but ONLY when explicitly
  # opted in via ATTESTO_PATH=1 (and the checkout exists). This is deliberately
  # NOT keyed on Mix.env alone: `mix hex.build` / `mix hex.publish` run in :dev,
  # and a path dep cannot be packaged ("only Hex packages can be dependencies"),
  # so a Mix.env-based switch would break publishing from a dev checkout. The
  # default - including every publish - resolves the published version
  # constraint; local development sets ATTESTO_PATH=1 to use the sibling.
  #
  # The 1.11.0 floor is load-bearing, not housekeeping. 1.9.0 carried
  # `Attesto.RedirectURI`'s
  # `:exact_allow_loopback_port_including_localhost` mode, which the native-app
  # policy selects when the host enables `:loopback_include_localhost`. An
  # older core would compile this package but raise when that mode reaches
  # `Attesto.RedirectURI.registered?/3`. It also carries
  # `Attesto.DPoP.verify_proof/2`'s `replay_ttl`, which this package's deferred
  # token-endpoint replay claim reads to size the entry it records - against an
  # older core that key is absent and `commit_replay_claim/2` cannot make the
  # claim the endpoint owes RFC 9449 §11.1. It also carries `Attesto.Telemetry`,
  # emitted from the same path, and `Attesto.RedirectURI.unambiguous?/1` with
  # the CIMD document validation that rejects a parser-ambiguous redirect URI -
  # without which this package's origin-phrased same-origin check would compile
  # and then approve a redirect URI a browser resolves to a different host. An
  # older core would additionally omit the key-bound FAPI algorithm enforcement
  # and RFC 9864 Edwards identifiers that client authentication, request
  # objects, and CIBA rely on. 1.10.0 raised the floor for the OID4VC security
  # hardening this package's HTTP surface documents and relies on: the
  # library-generated credential-offer id
  # (`Attesto.CredentialOffer.store_by_reference/3`), the single-use
  # presentation result (`AttestoPhoenix.Verifier.presentation_result/2`
  # consuming through the store's now-required `take/1`), and the bounded
  # Credential Request `proofs`. 1.11.0 adds the required `Attesto.CNonceStore`
  # `consume/1` callback, which the credential endpoint now calls to single-use
  # the c_nonce - an older core lacks it and the endpoint fails closed.
  # 1.13.0 supplies the ID-JAG assertion-claim validation the token endpoint's
  # JWT-bearer enforcement builds on. Most of it is defence in depth (this
  # package re-validates the signed `resource` and matches `cnf.jkt` itself),
  # but the `authorization_details` rejection lives ONLY in core: on an older
  # release an assertion carrying RFC 9396 constraints is accepted and treated
  # as broader scope-only authority, which is exactly the widening 2.12.0
  # closes. 1.15.0 supplies the RFC 8705 §2 certificate-identity matcher and
  # non-extractable `Attesto.Signer` path now invoked by this package; resolving
  # an older core would leave advertised mTLS authentication and JWS credential
  # issuance pointing at missing runtime functions. The floor is therefore
  # load-bearing, not cosmetic.
  defp attesto_dep do
    if System.get_env("ATTESTO_PATH") in ~w(1 true) and File.dir?("../attesto") do
      {:attesto, path: "../attesto"}
    else
      {:attesto, ">= 1.15.0 and < 2.0.0"}
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
      # it is not a transitive runtime requirement. The `~> 0.5` requirement
      # admits the current 0.6 line.
      {:igniter, "~> 0.5", optional: true},

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
        "guides/examples.md",
        "guides/local_https.md",
        "guides/consumer_migration.md",
        "guides/proxy_canonical_host.md",
        "guides/replay_nonce_production.md",
        "guides/error_envelope.md",
        "guides/identity_assertion_grant.md",
        "notebooks/attesto_phoenix_demo.livemd",
        "CHANGELOG.md",
        "LICENSE"
      ],
      groups_for_extras: [
        Guides: ~r/guides\/.*/,
        Notebooks: ~r/notebooks\/.*/,
        Changelog: ~r/CHANGELOG\.md/,
        License: ~r/LICENSE/
      ],
      groups_for_modules: [
        Setup: [AttestoPhoenix, AttestoPhoenix.Config, AttestoPhoenix.Router],
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
      files: ~w(lib guides notebooks LICENSE mix.exs README.md CHANGELOG.md)
    ]
  end
end
