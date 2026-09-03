defmodule AttestoPhoenix.ConfigTest do
  use ExUnit.Case, async: false

  import Plug.Conn, only: [put_private: 3]
  import Plug.Test, only: [conn: 2]

  alias Attesto.DPoP.NonceStore.ETS
  alias Attesto.RequestObject.Policy
  alias AttestoPhoenix.ClientIdMetadata.Fetcher.Req
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Store.EctoRefreshStore

  defmodule Keystore do
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem, do: "main-pem"

    @impl true
    def verification_pems, do: [signing_pem()]
  end

  defmodule VcKeystore do
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem, do: "vc-pem"

    @impl true
    def verification_pems, do: [signing_pem()]
  end

  defmodule VerifierEncryptionKeystore do
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem, do: "verifier-encryption-pem"

    @impl true
    def verification_pems, do: [signing_pem()]
  end

  # A behaviour module that implements every ClientStore callback the resolver
  # routes through `:client_store`, plus the principal/scope/event/consent/
  # registration callbacks the other behaviour-module keys route through. Each
  # callback returns a sentinel so a test can assert the resolved `{module,
  # function}` was actually invoked (not just the flat key).
  defmodule FullStore do
    @behaviour AttestoPhoenix.ClientStore
    @behaviour AttestoPhoenix.ConsentPolicy
    @behaviour AttestoPhoenix.EventSink
    @behaviour AttestoPhoenix.PrincipalStore
    @behaviour AttestoPhoenix.RegistrationStore
    @behaviour AttestoPhoenix.ScopePolicy

    # ClaimsProvider's build_principal/3 collides with PrincipalStore's, so this
    # module satisfies ClaimsProvider by exporting the functions without the
    # `@behaviour` annotation (the resolver checks `function_exported?`, not the
    # declared behaviours).

    @impl AttestoPhoenix.ClientStore
    def load_client(_client_id), do: {:ok, :store_client}
    @impl AttestoPhoenix.ClientStore
    def verify_client_secret(_client, _secret), do: true
    @impl AttestoPhoenix.ClientStore
    def client_id(_client), do: "store-client-id"
    @impl AttestoPhoenix.ClientStore
    def client_jwks(_client), do: %{"keys" => []}
    @impl AttestoPhoenix.ClientStore
    def client_redirect_uris(_client), do: ["https://store.example/cb"]
    @impl AttestoPhoenix.ClientStore
    def client_public?(_client), do: true
    @impl AttestoPhoenix.ClientStore
    def client_requires_mtls?(_client), do: true
    @impl AttestoPhoenix.ClientStore
    def client_requires_dpop?(_client), do: true
    @impl AttestoPhoenix.ClientStore
    def client_grant_types(_client), do: ["authorization_code"]

    @impl AttestoPhoenix.PrincipalStore
    def load_principal(_subject_id), do: {:ok, :store_principal}
    @impl AttestoPhoenix.PrincipalStore
    def build_principal(_client, subject, _scope), do: %{subject: subject}

    @impl AttestoPhoenix.ScopePolicy
    def authorize_scope(_client, scope), do: {:ok, scope}

    @impl AttestoPhoenix.ConsentPolicy
    def authenticate_resource_owner(_conn, _request, _opts), do: {:none}
    @impl AttestoPhoenix.ConsentPolicy
    def consent(_conn, _request, subject), do: {:consented, subject}

    @impl AttestoPhoenix.EventSink
    def on_event(_event), do: :store_emitted

    @impl AttestoPhoenix.RegistrationStore
    def register_client(_attrs), do: {:ok, :registered}
    @impl AttestoPhoenix.RegistrationStore
    def unregister_client(_client), do: :ok
    @impl AttestoPhoenix.RegistrationStore
    def client_registration_access_token_hash(_client), do: "store-hash"

    # Satisfies AttestoPhoenix.ClaimsProvider.build_userinfo_claims/3.
    def build_userinfo_claims(_subject, _scopes, _requested), do: %{"from" => "store"}
  end

  # A module that exports none of the callbacks the resolver wants. Installed
  # under a behaviour-module key it makes the resolver fall through to `nil`
  # (for optional callbacks); used to drive the boot-validation failure path
  # for required callbacks.
  defmodule EmptyModule do
  end

  # A ClientStore exporting only the two required callbacks; its optional
  # callbacks are absent so the resolver falls through to nil for them.
  defmodule RequiredOnlyStore do
    @behaviour AttestoPhoenix.ClientStore

    @impl true
    def load_client(_client_id), do: {:error, :not_found}
    @impl true
    def verify_client_secret(_client, _secret), do: false
  end

  # A module installed as :client_store that omits the required
  # verify_client_secret/2, driving the boot-validation failure path.
  defmodule LoadOnlyStore do
    def load_client(_client_id), do: {:error, :not_found}
  end

  defmodule ResourceMetadataResolver do
    @moduledoc false

    def resolve(conn), do: "https://api.example/.well-known/oauth-protected-resource" <> conn.request_path
    def resolve_with_base(conn, base), do: base <> conn.request_path
    def wrong_arity, do: nil
  end

  defmodule FlatCallbackModule do
    @moduledoc false

    def client_id(client, suffix), do: client <> suffix
  end

  defmodule ReplayCallbacks do
    @moduledoc false

    def check(_key, _ttl), do: :ok
    def check_with_partition(_key, _ttl, _partition), do: :ok
    def wrong_arity(_key), do: :ok
  end

  defmodule ConfigAwareNonceStore do
    def issue(_config, _ttl_seconds), do: "nonce"
    def valid?(_config, _nonce), do: true
  end

  defmodule IncompleteNonceStore do
    def issue(_ttl_seconds), do: "nonce"
  end

  defmodule FetchOnlyPARStore do
    @behaviour AttestoPhoenix.PARStore

    @impl true
    def put(_request_uri, _params, _ttl_seconds), do: :ok

    @impl true
    def fetch(_request_uri), do: :error
  end

  # The minimal required-key set. Required callbacks stay flat (this phase keeps
  # the flat keys as the required surface); overrides layer behaviour-module
  # keys or competing flat callbacks on top.
  defp config(overrides \\ []) do
    base = [
      issuer: "https://issuer.example",
      keystore: __MODULE__.Keystore,
      repo: __MODULE__.Repo,
      audience: "https://api.example.com",
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end
    ]

    Config.new(Keyword.merge(base, overrides))
  end

  # Like `config/1` but supplies NONE of the flat required callbacks, so the
  # required capabilities (load_client, verify_client_secret, load_principal)
  # must be satisfied by installed behaviour modules. Exercises the real
  # `Config.new/1` boot surface, not `struct/2`.
  defp behaviour_only_config(overrides) do
    base = [
      issuer: "https://issuer.example",
      keystore: __MODULE__.Keystore,
      repo: __MODULE__.Repo,
      audience: "https://api.example.com"
    ]

    Config.new(Keyword.merge(base, overrides))
  end

  describe "credential-signing keystore" do
    test "falls back to the main keystore when vc_keystore is unset" do
      cfg = config()

      assert Config.keystore(cfg) == Keystore
      assert Config.vc_keystore(cfg) == Keystore
      assert Config.vc_signing_pem(cfg) == "main-pem"
    end

    test "uses a separately configured vc_keystore" do
      cfg = config(vc_keystore: VcKeystore)

      assert Config.keystore(cfg) == Keystore
      assert Config.vc_keystore(cfg) == VcKeystore
      assert Config.vc_signing_pem(cfg) == "vc-pem"
    end
  end

  describe "refresh rotation configuration" do
    setup do
      original = Application.get_env(:attesto_phoenix, :refresh_successor_secret)

      on_exit(fn ->
        if is_nil(original) do
          Application.delete_env(:attesto_phoenix, :refresh_successor_secret)
        else
          Application.put_env(:attesto_phoenix, :refresh_successor_secret, original)
        end
      end)

      :ok
    end

    test "rejects invalid grace values" do
      for value <- [-1, 1.5, "60", nil] do
        assert_raise ArgumentError, ~r/:refresh_token_rotation_grace_seconds.*non-negative integer/, fn ->
          config(refresh_token_rotation_grace_seconds: value)
        end
      end
    end

    test "requires a positive refresh lifetime and bounds grace by it" do
      for value <- [0, -1, 1.5, "1200", nil] do
        assert_raise ArgumentError, ~r/:refresh_token_ttl must be a positive integer/, fn ->
          config(refresh_token_ttl: value)
        end
      end

      assert_raise ArgumentError, ~r/:refresh_token_ttl must not exceed 2147483647 seconds/, fn ->
        config(refresh_token_ttl: 2_147_483_648)
      end

      assert_raise ArgumentError, ~r/grace_seconds must not exceed.*refresh_token_ttl/s, fn ->
        config(refresh_token_ttl: 59, refresh_token_rotation_grace_seconds: 60)
      end

      assert %Config{} = config(refresh_token_ttl: 60, refresh_token_rotation_grace_seconds: 60)
    end

    test "validates the sweep interval and requires it for Ecto retry-state cleanup" do
      for value <- [0, -1, 1.5, "60000", false] do
        assert_raise ArgumentError, ~r/:sweep_interval_ms must be a positive integer or nil/, fn ->
          config(sweep_interval_ms: value)
        end
      end

      Application.put_env(
        :attesto_phoenix,
        :refresh_successor_secret,
        String.duplicate("stable-secret-", 3)
      )

      assert_raise ArgumentError, ~r/requires a positive :sweep_interval_ms/, fn ->
        config(refresh_store: EctoRefreshStore, sweep_interval_ms: nil)
      end

      assert %Config{} = config(refresh_store: EctoRefreshStore, sweep_interval_ms: 60_000)
    end

    test "requires a valid stable secret for Ecto retry recovery" do
      Application.delete_env(:attesto_phoenix, :refresh_successor_secret)

      assert_raise ArgumentError, ~r/:refresh_successor_secret.*at least 32 bytes/, fn ->
        config(refresh_store: EctoRefreshStore)
      end

      Application.put_env(:attesto_phoenix, :refresh_successor_secret, "too-short")

      assert_raise ArgumentError, ~r/:refresh_successor_secret.*at least 32 bytes/, fn ->
        config(refresh_store: EctoRefreshStore)
      end

      Application.put_env(
        :attesto_phoenix,
        :refresh_successor_secret,
        String.duplicate("stable-secret-", 3)
      )

      assert %Config{} = config(refresh_store: EctoRefreshStore, sweep_interval_ms: 60_000)
    end

    test "revalidates prebuilt configs loaded from application environment" do
      previous = Application.get_env(:attesto_phoenix, Config, :missing)
      secret = String.duplicate("stable-secret-", 3)
      Application.put_env(:attesto_phoenix, :refresh_successor_secret, secret)

      valid = config(refresh_store: EctoRefreshStore, sweep_interval_ms: 60_000)
      Application.put_env(:attesto_phoenix, Config, valid)

      on_exit(fn ->
        case previous do
          :missing -> Application.delete_env(:attesto_phoenix, Config)
          value -> Application.put_env(:attesto_phoenix, Config, value)
        end
      end)

      assert Config.from_otp_app(:attesto_phoenix) === valid

      Application.delete_env(:attesto_phoenix, :refresh_successor_secret)

      assert_raise ArgumentError, ~r/:refresh_successor_secret.*at least 32 bytes/, fn ->
        Config.from_otp_app(:attesto_phoenix)
      end
    end

    test "strict zero grace and custom stores do not depend on a usable Ecto cipher secret" do
      Application.delete_env(:attesto_phoenix, :refresh_successor_secret)

      assert %Config{} =
               config(
                 refresh_store: EctoRefreshStore,
                 refresh_token_rotation_grace_seconds: 0
               )

      assert %Config{} =
               config(
                 refresh_store: EmptyModule,
                 refresh_token_rotation_grace_seconds: 60
               )

      Application.put_env(:attesto_phoenix, :refresh_successor_secret, "short")

      assert %Config{} =
               config(
                 refresh_store: EctoRefreshStore,
                 refresh_token_rotation_grace_seconds: 0
               )

      assert %Config{} =
               config(
                 refresh_store: EmptyModule,
                 refresh_token_rotation_grace_seconds: 60
               )
    end
  end

  describe "DPoP nonce configuration" do
    test "required nonce enforcement needs DPoP and a capable store" do
      assert_raise ArgumentError, ~r/:nonce_store must select a capable module/, fn ->
        config(dpop_nonce_required: true, nonce_store: nil)
      end

      assert_raise ArgumentError, ~r/is not a loadable nonce store/, fn ->
        config(dpop_nonce_required: true, nonce_store: IncompleteNonceStore)
      end

      assert_raise ArgumentError, ~r/cannot be true when :dpop_enabled is false/, fn ->
        config(dpop_enabled: false, dpop_nonce_required: true, nonce_store: ConfigAwareNonceStore)
      end
    end

    test "accepts behaviour and config-aware nonce stores" do
      assert %Config{} =
               config(dpop_nonce_required: true, nonce_store: ETS)

      assert %Config{} =
               config(dpop_nonce_required: true, nonce_store: ConfigAwareNonceStore)
    end
  end

  describe "top-level boolean policy configuration" do
    test "rejects non-booleans for every direct boolean field" do
      keys = [
        :claims_parameter_supported,
        :require_nonce,
        :require_pkce,
        :require_pushed_authorization_requests,
        :authorization_response_iss,
        :require_https,
        :dpop_enabled,
        :dpop_nonce_required,
        :mtls_enabled,
        :registration_enabled
      ]

      for key <- keys, value <- ["true", 1, nil] do
        assert_raise ArgumentError, ~r/#{key} must be true or false/, fn ->
          config([{key, value}])
        end
      end
    end
  end

  describe "required PAR configuration" do
    test "requires an atomic take callback only when PAR is required" do
      assert %Config{par_store: FetchOnlyPARStore} = config(par_store: FetchOnlyPARStore)

      assert_raise ArgumentError, ~r/:par_store must be.*atomic take\/1/, fn ->
        config(
          require_pushed_authorization_requests: true,
          par_store: FetchOnlyPARStore
        )
      end
    end

    test "the default store remains valid and is unchanged when PAR is required" do
      assert %Config{par_store: nil, require_pushed_authorization_requests: false} = config()

      assert %Config{par_store: nil, require_pushed_authorization_requests: true} =
               config(require_pushed_authorization_requests: true)
    end
  end

  describe "nested boolean policy configuration" do
    test "rejects malformed feature flags instead of silently changing security policy" do
      cases = [
        {:client_id_metadata, :enabled},
        {:client_id_metadata, :allow_loopback},
        {:client_id_metadata, :require_same_origin_redirect_uri},
        {:jwt_bearer, :enabled},
        {:device_authorization, :enabled},
        {:ciba, :enabled},
        {:ciba, :require_signed_request},
        {:ciba, :require_binding_message},
        {:ciba, :user_code_parameter_supported},
        {:ciba, :enforce_fapi_alg_policy},
        {:logout, :enabled},
        {:session_management, :enabled}
      ]

      for {group, key} <- cases, value <- ["false", 0, nil] do
        assert_raise ArgumentError, ~r/#{group}.*#{key}.*must be true or false/, fn ->
          config([{group, [{key, value}]}])
        end
      end
    end
  end

  describe "advertised and enforced protocol catalogs" do
    test "an explicit empty catalog stays empty instead of widening to defaults" do
      cfg =
        config(
          grant_types_supported: [],
          token_endpoint_auth_methods_supported: []
        )

      assert Config.grant_types_supported(cfg) == []
      assert Config.token_endpoint_auth_methods_supported(cfg) == []
    end

    test "explicit grant catalogs stay authoritative when optional grants are enabled" do
      feature_configs = [
        device_code: [
          device_authorization: [enabled: true],
          device_code_store: EmptyModule
        ],
        ciba: [
          ciba: [enabled: true, require_signed_request: false],
          ciba_store: EmptyModule,
          authenticate_ciba_user: fn _request -> {:error, :not_found} end
        ],
        jwt_bearer: [
          jwt_bearer: [
            enabled: true,
            issuers: %{"https://assertions.example" => [jwks: %{"keys" => []}]}
          ],
          resolve_jwt_bearer_subject: fn _claims -> {:error, :not_found} end
        ],
        pre_authorized_code: [pre_authorized_code_store: EmptyModule]
      ]

      for {feature, feature_opts} <- feature_configs do
        empty = config(Keyword.put(feature_opts, :grant_types_supported, []))
        narrowed = config(Keyword.put(feature_opts, :grant_types_supported, ["authorization_code"]))

        assert Config.grant_types_supported(empty) == [],
               "#{feature} widened an explicit empty grant catalog"

        assert Config.grant_types_supported(narrowed) == ["authorization_code"],
               "#{feature} widened an explicit narrowed grant catalog"
      end
    end

    test "token authentication defaults match discovery and endpoint enforcement" do
      cfg = config([])

      assert Config.token_endpoint_auth_methods_supported(cfg) == [
               "client_secret_basic",
               "client_secret_post",
               "private_key_jwt",
               "none"
             ]

      with_wallet_keys =
        config(trusted_wallet_provider_jwks: %{"keys" => [%{"kty" => "EC"}]})

      assert Config.token_endpoint_auth_methods_supported(with_wallet_keys) == [
               "client_secret_basic",
               "client_secret_post",
               "private_key_jwt",
               "none",
               "attest_jwt_client_auth"
             ]
    end

    test "rejects malformed catalog values during configuration construction" do
      for {key, value} <- [
            {:grant_types_supported, "authorization_code"},
            {:grant_types_supported, ["authorization_code", ""]},
            {:grant_types_supported, ["authorization_code", :refresh_token]},
            {:token_endpoint_auth_methods_supported, "client_secret_basic"},
            {:token_endpoint_auth_methods_supported, ["client_secret_basic", ""]},
            {:token_endpoint_auth_methods_supported, ["client_secret_basic", :none]}
          ] do
        assert_raise ArgumentError, ~r/#{key}.*nil or a list of non-empty strings/, fn ->
          config([{key, value}])
        end
      end
    end
  end

  describe "OID4VCI key-attestation configuration" do
    test "required key attestation needs at least one usable trusted key" do
      for jwks <- [nil, [], %{"keys" => []}, %{"keys" => [%{"kty" => "EC"}]}, "invalid"] do
        assert_raise ArgumentError, ~r/:key_attestation_trusted_jwks.*usable trusted public key/, fn ->
          config(require_key_attestation: true, key_attestation_trusted_jwks: jwks)
        end
      end
    end

    test "accepts a usable trusted key when key attestation is required" do
      key = JOSE.JWK.generate_key({:ec, "P-256"})
      {_meta, public_jwk} = JOSE.JWK.to_public_map(key)

      assert %Config{} =
               config(
                 require_key_attestation: true,
                 key_attestation_trusted_jwks: %{"keys" => [public_jwk]}
               )
    end

    test "rejects a non-boolean requirement instead of silently disabling it" do
      assert_raise ArgumentError, ~r/:require_key_attestation must be true, false, or nil/, fn ->
        config(require_key_attestation: "true")
      end
    end
  end

  describe "RFC 8705 client authentication configuration" do
    test "requires client registration metadata for either mTLS auth method" do
      assert_raise ArgumentError, ~r/requires :client_mtls_metadata/, fn ->
        config(token_endpoint_auth_methods_supported: ["tls_client_auth"])
      end
    end

    test "self-signed authentication additionally requires resolved client JWKS" do
      assert_raise ArgumentError, ~r/requires :client_jwks/, fn ->
        config(
          token_endpoint_auth_methods_supported: ["self_signed_tls_client_auth"],
          client_mtls_metadata: fn _client -> %{} end
        )
      end

      assert %Config{} =
               config(
                 token_endpoint_auth_methods_supported: ["self_signed_tls_client_auth"],
                 client_mtls_metadata: fn _client -> %{} end,
                 client_jwks: fn _client -> %{"keys" => []} end
               )
    end

    test "normalizes and validates RFC 8705 endpoint aliases" do
      config =
        config(
          mtls_endpoint_aliases: [
            token_endpoint: "https://mtls.issuer.example/oauth/token",
            introspection_endpoint: "https://mtls.issuer.example/oauth/introspect"
          ]
        )

      assert config.mtls_endpoint_aliases == %{
               "token_endpoint" => "https://mtls.issuer.example/oauth/token",
               "introspection_endpoint" => "https://mtls.issuer.example/oauth/introspect"
             }

      for invalid <- [
            %{},
            %{"unknown_endpoint" => "https://mtls.issuer.example/unknown"},
            %{"token_endpoint" => "http://insecure.example/token"}
          ] do
        assert_raise ArgumentError, ~r/:mtls_endpoint_aliases/, fn ->
          config(mtls_endpoint_aliases: invalid)
        end
      end
    end
  end

  describe "ecto_repo!/0" do
    setup do
      previous = Application.get_env(:attesto_phoenix, :repo)
      previous_otp_app = Application.fetch_env(:attesto_phoenix, :otp_app)

      # This describe exercises the package-level compatibility lookup. Keep a
      # host application's otp_app pointer from redirecting it to unrelated
      # request configuration left by an earlier case.
      Application.delete_env(:attesto_phoenix, :otp_app)

      on_exit(fn ->
        case previous_otp_app do
          {:ok, otp_app} -> Application.put_env(:attesto_phoenix, :otp_app, otp_app)
          :error -> Application.delete_env(:attesto_phoenix, :otp_app)
        end

        case previous do
          nil -> Application.delete_env(:attesto_phoenix, :repo)
          repo -> Application.put_env(:attesto_phoenix, :repo, repo)
        end
      end)

      :ok
    end

    test "returns the configured repository" do
      Application.put_env(:attesto_phoenix, :repo, __MODULE__.Repo)

      assert Config.ecto_repo!() == __MODULE__.Repo
    end

    test "raises when the repository is unset" do
      Application.delete_env(:attesto_phoenix, :repo)

      assert_raise ArgumentError,
                   "AttestoPhoenix: no :repo configured. Set :repo on the request/host " <>
                     "AttestoPhoenix.Config; legacy deployments without :otp_app may set " <>
                     "config :attesto_phoenix, repo: MyApp.Repo",
                   &Config.ecto_repo!/0
    end
  end

  describe "resolve_callback/2 precedence" do
    test "an explicit flat key wins over an installed behaviour module" do
      flat = fn _ -> :flat end
      cfg = config(client_store: FullStore, client_id: flat)

      assert Config.resolve_callback(cfg, :client_id) == flat
      assert Config.client_id_fun(cfg) == flat
    end

    test "falls back to {module, function} when the module exports the callback" do
      cfg = config(client_store: FullStore)

      assert Config.resolve_callback(cfg, :client_id) == {FullStore, :client_id}
      assert Config.client_id_fun(cfg) == {FullStore, :client_id}
    end

    test "resolves nil when neither a flat key nor an exporting module is set" do
      cfg = config()

      assert Config.resolve_callback(cfg, :client_id) == nil
      assert Config.client_id_fun(cfg) == nil
    end

    test "resolves nil when an installed module does not export the optional callback" do
      # RequiredOnlyStore exports only the required ClientStore callbacks. An
      # optional callback it omits (`client_jwks/1`) must resolve to nil. The
      # required flat keys are unset here (built via `struct/2`, bypassing the
      # @enforce_keys surface) to isolate the module-resolution path.
      cfg =
        struct(Config, %{
          issuer: "https://issuer.example",
          keystore: __MODULE__.Keystore,
          repo: __MODULE__.Repo,
          client_store: RequiredOnlyStore
        })

      assert Config.load_client_fun(cfg) == {RequiredOnlyStore, :load_client}
      assert Config.client_jwks_fun(cfg) == nil
    end

    test "every named resolver fun strips a trailing ? from its key" do
      cfg = config(client_store: FullStore)

      assert Config.client_public_fun(cfg) == {FullStore, :client_public?}
      assert Config.client_requires_mtls_fun(cfg) == {FullStore, :client_requires_mtls?}
      assert Config.client_requires_dpop_fun(cfg) == {FullStore, :client_requires_dpop?}
    end

    test "principal/scope/consent/event/registration/claims keys resolve to their module" do
      cfg =
        config(
          principal_store: FullStore,
          scope_policy: FullStore,
          consent_policy: FullStore,
          event_sink: FullStore,
          registration: FullStore,
          claims_provider: FullStore
        )

      assert Config.build_principal_fun(cfg) == {FullStore, :build_principal}
      assert Config.authorize_scope_fun(cfg) == {FullStore, :authorize_scope}
      assert Config.consent_fun(cfg) == {FullStore, :consent}

      assert Config.authenticate_resource_owner_fun(cfg) ==
               {FullStore, :authenticate_resource_owner}

      assert Config.on_event_fun(cfg) == {FullStore, :on_event}
      assert Config.unregister_client_fun(cfg) == {FullStore, :unregister_client}

      assert Config.client_registration_access_token_hash_fun(cfg) ==
               {FullStore, :client_registration_access_token_hash}

      assert Config.build_userinfo_claims_fun(cfg) == {FullStore, :build_userinfo_claims}
    end
  end

  describe "client_store_load/2 and client_store_verify_secret/3" do
    test "invoke the resolved flat callback" do
      cfg =
        config(
          load_client: fn id -> {:ok, {:loaded, id}} end,
          verify_client_secret: fn _client, secret -> secret == "good" end
        )

      assert Config.client_store_load(cfg, "abc") == {:ok, {:loaded, "abc"}}
      assert Config.client_store_verify_secret(cfg, :client, "good") == true
      assert Config.client_store_verify_secret(cfg, :client, "bad") == false
    end

    test "invoke the resolved behaviour module when no flat callback is set" do
      # Required flat keys unset (via `struct/2`) so the installed module wins.
      cfg =
        struct(Config, %{
          issuer: "https://issuer.example",
          keystore: __MODULE__.Keystore,
          repo: __MODULE__.Repo,
          client_store: FullStore
        })

      assert Config.client_store_load(cfg, "abc") == {:ok, :store_client}
      assert Config.client_store_verify_secret(cfg, :client, "whatever") == true
    end
  end

  describe "build_userinfo_claims/4" do
    test "raises when no claim source is configured" do
      cfg = config()

      assert_raise ArgumentError, ~r/:build_userinfo_claims is required/, fn ->
        Config.build_userinfo_claims(cfg, "sub", ["openid"], %{})
      end
    end

    test "uses an explicit flat callback (3-arity userinfo contract)" do
      cfg = config(build_userinfo_claims: fn _sub, _scopes, _req -> %{"from" => "flat"} end)

      assert Config.build_userinfo_claims(cfg, "sub", ["openid"], %{}) == %{"from" => "flat"}
    end

    test "uses an installed :claims_provider module" do
      cfg = config(claims_provider: FullStore)

      assert Config.build_userinfo_claims(cfg, "sub", ["openid"], %{}) == %{"from" => "store"}
    end
  end

  describe "new/1 boot-time behaviour-module conformance" do
    test "accepts a module that exports every required behaviour callback" do
      assert %Config{} = config(client_store: FullStore)
    end

    test "rejects a behaviour module missing a required callback" do
      assert_raise ArgumentError, ~r/does not export verify_client_secret\/2/, fn ->
        config(client_store: __MODULE__.LoadOnlyStore)
      end
    end

    test "rejects a behaviour-module key that is not a module" do
      assert_raise ArgumentError, ~r/must be a module implementing/, fn ->
        config(scope_policy: "not a module")
      end
    end

    test "rejects a module that cannot be loaded" do
      assert_raise ArgumentError, ~r/cannot be loaded/, fn ->
        config(event_sink: Definitely.Not.A.Real.Module)
      end
    end

    test "does not require optional behaviour callbacks" do
      # consent_policy callbacks are both optional, so a module exporting none
      # of them is accepted; the resolver simply returns nil for each.
      assert %Config{} = cfg = config(consent_policy: EmptyModule)
      assert Config.consent_fun(cfg) == nil
    end

    test "accepts required capabilities supplied entirely by behaviour modules (no flat callbacks)" do
      # The advertised feature: install :client_store and :principal_store and
      # the required callbacks resolve from them, with NO flat load_client /
      # verify_client_secret / load_principal keys present.
      cfg = behaviour_only_config(client_store: FullStore, principal_store: FullStore)

      assert %Config{} = cfg
      assert Config.load_client_fun(cfg) == {FullStore, :load_client}
      assert Config.verify_client_secret_fun(cfg) == {FullStore, :verify_client_secret}
      assert Config.load_principal_fun(cfg) == {FullStore, :load_principal}
    end

    test "accepts a behaviour module for one capability and a flat callback for another" do
      cfg =
        behaviour_only_config(
          client_store: FullStore,
          load_principal: fn _ -> {:ok, :flat_principal} end
        )

      assert %Config{} = cfg
      assert Config.load_client_fun(cfg) == {FullStore, :load_client}
      assert is_function(Config.load_principal_fun(cfg), 1)
    end

    test "rejects when a required capability resolves to neither a flat key nor a module" do
      # client_store satisfies load_client/verify_client_secret, but nothing
      # provides load_principal: the capability is unresolved and boot fails.
      assert_raise ArgumentError, ~r/:load_principal capability is required but unresolved/, fn ->
        behaviour_only_config(client_store: FullStore)
      end
    end

    test "rejects when no required capability is wired at all" do
      assert_raise ArgumentError, ~r/:load_client capability is required but unresolved/, fn ->
        behaviour_only_config([])
      end
    end
  end

  describe "new/1 flat callback arity validation" do
    test "rejects an anonymous callback with the wrong call arity" do
      assert_raise ArgumentError, ~r/:client_id must be a one-argument callback/, fn ->
        config(client_id: fn -> "client" end)
      end
    end

    test "rejects an unloadable MFA without including its value in the error" do
      missing_module = Module.concat(__MODULE__, "MissingClientCallback")

      error =
        assert_raise ArgumentError, fn ->
          config(client_id: {missing_module, :client_id, ["secret-marker"]})
        end

      assert error.message =~ ":client_id callback module cannot be loaded"
      refute error.message =~ "secret-marker"
    end

    test "accepts an MFA with extra arguments when its effective arity matches" do
      cfg = config(client_id: {FlatCallbackModule, :client_id, ["-suffix"]})

      assert Config.client_identifier(cfg, "client") == "client-suffix"
    end
  end

  describe "registration_enabled boot gate" do
    test "accepts an installed :registration module in place of the flat key" do
      assert %Config{} = config(registration_enabled: true, registration: FullStore)
    end

    test "still accepts the flat :register_client key" do
      assert %Config{} =
               config(registration_enabled: true, register_client: fn _ -> {:ok, :c} end)
    end

    test "rejects when neither the flat key nor a module is wired" do
      assert_raise ArgumentError, ~r/:register_client is required/, fn ->
        config(registration_enabled: true)
      end
    end
  end

  describe ":registration_default_scope (RFC 7591 §2)" do
    test "resolves :scopes_supported to the full catalog" do
      config = config(scopes_supported: ["read", "write"], registration_default_scope: :scopes_supported)
      assert Config.registration_default_scope(config) == ["read", "write"]
    end

    test "resolves an explicit list" do
      config = config(scopes_supported: ["read", "write"], registration_default_scope: ["read"])
      assert Config.registration_default_scope(config) == ["read"]
    end

    test "defaults to nil (no defaulting, fail-closed)" do
      assert Config.registration_default_scope(config(scopes_supported: ["read"])) == nil
    end

    test "rejects an explicit default scope outside :scopes_supported at boot" do
      assert_raise ArgumentError, ~r/:registration_default_scope contains scope/, fn ->
        config(scopes_supported: ["read"], registration_default_scope: ["read", "admin"])
      end
    end
  end

  describe "RFC 8707 resource-indicator policy" do
    test "static resources compose with the default audience and de-duplicate" do
      resource = "https://resource.example/mcp"

      built =
        config(
          resource_indicators: [
            allowed_resources: [resource, resource],
            allowed_resources_for: fn _client -> ["https://resource.example/per-client"] end
          ]
        )

      assert Config.static_allowed_resources(built) == ["https://api.example.com", resource]

      assert Config.allowed_resources(built, :client) == [
               "https://api.example.com",
               resource,
               "https://resource.example/per-client"
             ]
    end

    test "invalid static resources fail at boot" do
      for invalid <- ["", "/relative", "https://resource.example/#fragment", "https://resource.example/%ZZ", 123] do
        assert_raise ArgumentError, ~r/every :resource_indicators :allowed_resources entry/, fn ->
          config(resource_indicators: [allowed_resources: [invalid]])
        end
      end
    end

    test "an invalid per-client callback fails at boot" do
      assert_raise ArgumentError, ~r/:allowed_resources_for must be a one-argument callback/, fn ->
        config(resource_indicators: [allowed_resources_for: fn -> [] end])
      end
    end

    test "invalid dynamic callback entries are ignored without poisoning valid trust" do
      resource = "https://resource.example/per-client"

      built =
        config(
          resource_indicators: [
            allowed_resources_for: fn _client -> [resource, "", 123, "https://bad.example/#fragment"] end
          ]
        )

      assert Config.allowed_resources(built, :client) == ["https://api.example.com", resource]
    end
  end

  describe ":authorization_grant_id_claim" do
    test "is disabled by default and exposes a configured claim name" do
      assert Config.authorization_grant_id_claim(config()) == nil

      claim = "https://api.example.com/claims/oauth_grant_id"
      assert Config.authorization_grant_id_claim(config(authorization_grant_id_claim: claim)) == claim
    end

    test "rejects empty and non-string claim names" do
      for invalid <- ["", :grant_id, 123, %{}] do
        assert_raise ArgumentError, ~r/:authorization_grant_id_claim/, fn ->
          config(authorization_grant_id_claim: invalid)
        end
      end
    end

    test "rejects registered and library-owned access-token claim names" do
      reserved_claims =
        ~w(
          iss sub aud exp nbf iat jti
          auth_time acr amr cnf client_id scope
          name given_name family_name middle_name nickname preferred_username
          profile picture website email email_verified gender birthdate zoneinfo
          locale phone_number phone_number_verified address updated_at
          roles groups entitlements act may_act authorization_details
          typ principal_kind claims credential_configuration_ids sid
        )

      for invalid <- reserved_claims do
        assert_raise ArgumentError, ~r/:authorization_grant_id_claim/, fn ->
          config(authorization_grant_id_claim: invalid)
        end
      end
    end
  end

  describe ":authorization_code_completion" do
    test "is absent by default and accepts a two-argument callback" do
      assert Config.authorization_code_completion_fun(config()) == nil

      callback = fn _context, continuation -> continuation.() end
      built = config(authorization_code_completion: callback)

      assert Config.authorization_code_completion_fun(built) == callback
    end

    test "rejects callbacks with the wrong arity or unsupported forms" do
      for invalid <- [fn _context -> :ok end, :not_a_callback, {__MODULE__, :missing_callback}] do
        assert_raise ArgumentError, ~r/:authorization_code_completion must be a two-argument callback/, fn ->
          config(authorization_code_completion: invalid)
        end
      end
    end

    test "accepts a private-context builder only with the completion callback" do
      completion = fn _context, continuation -> continuation.() end
      builder = fn _context -> %{"security_epoch" => 42} end

      built =
        config(
          authorization_code_completion: completion,
          authorization_code_private_context: builder
        )

      assert Config.authorization_code_private_context_fun(built) == builder
    end

    test "rejects an invalid or unenforced private-context builder" do
      assert_raise ArgumentError, ~r/:authorization_code_private_context must be a one-argument callback/, fn ->
        config(
          authorization_code_completion: fn _context, continuation -> continuation.() end,
          authorization_code_private_context: fn _context, _extra -> %{} end
        )
      end

      # Issuance without enforcement would persist host state nothing reads.
      assert_raise ArgumentError, ~r/:authorization_code_private_context requires :authorization_code_completion/, fn ->
        config(authorization_code_private_context: fn _context -> %{} end)
      end
    end
  end

  describe ":audience boot gate (RFC 9068 §3 aud)" do
    # The required-key/capability checks all pass here; only :audience is
    # missing, so this isolates the audience gate from the other boot checks.
    # (A function, not a module attribute: the opts carry anonymous callbacks,
    # which cannot be escaped into an @attribute.)
    defp audience_required_opts do
      [
        issuer: "https://issuer.example",
        keystore: __MODULE__.Keystore,
        repo: __MODULE__.Repo,
        load_client: fn _ -> {:error, :not_found} end,
        verify_client_secret: fn _, _ -> false end,
        load_principal: fn _ -> {:error, :not_found} end
      ]
    end

    test "raises when :audience is nil even though every other required key is set" do
      assert_raise ArgumentError, ~r/:audience is required/, fn ->
        Config.new(audience_required_opts())
      end
    end

    test "raises when :audience is blank, non-https, non-URL, or non-binary (not just nil)" do
      for bad <- [
            "",
            "api",
            "/relative",
            "http://a.example",
            "https://a.example#frag",
            "https://a.example/%ZZ",
            ["https://a.example"],
            :aud,
            123
          ] do
        assert_raise ArgumentError, ~r/:audience is required and must be an absolute https URL/, fn ->
          Config.new(Keyword.put(audience_required_opts(), :audience, bad))
        end
      end
    end

    test ":resource_metadata, when set, must be an absolute https URL with a host and no fragment" do
      base = Keyword.put(audience_required_opts(), :audience, "https://api.example.com")

      for bad <- ["", "/relative", "not-a-url", "http://api.example", "https://api.example#frag", 123] do
        assert_raise ArgumentError, ~r/:resource_metadata, when set, must be an absolute https URL/, fn ->
          Config.new(Keyword.put(base, :resource_metadata, bad))
        end
      end

      cfg = Config.new(Keyword.put(base, :resource_metadata, "https://api.example/.well-known/x"))
      assert cfg.resource_metadata == "https://api.example/.well-known/x"
    end

    test ":resource_metadata_resolver selects per-request metadata and may deliberately omit it" do
      base = Keyword.put(audience_required_opts(), :audience, "https://api.example.com")
      static = "https://api.example/.well-known/oauth-protected-resource"

      resolver = fn conn ->
        case conn.request_path do
          "/alpha" -> "https://api.example/.well-known/oauth-protected-resource/alpha"
          "/invalid" -> "not-an-absolute-url"
          "/invalid-utf8" -> <<"https://api.example/", 0xFF>>
          _ -> nil
        end
      end

      cfg =
        base
        |> Keyword.put(:resource_metadata, static)
        |> Keyword.put(:resource_metadata_resolver, resolver)
        |> Config.new()

      assert Config.resource_metadata_url(cfg, Plug.Test.conn(:get, "/alpha")) ==
               "https://api.example/.well-known/oauth-protected-resource/alpha"

      assert Config.resource_metadata_url(cfg, Plug.Test.conn(:get, "/unowned")) == nil
      assert Config.resource_metadata_url(cfg, Plug.Test.conn(:get, "/invalid")) == nil
      assert Config.resource_metadata_url(cfg, Plug.Test.conn(:get, "/invalid-utf8")) == nil

      static_cfg = Config.new(Keyword.put(base, :resource_metadata, static))
      assert Config.resource_metadata_url(static_cfg, Plug.Test.conn(:get, "/alpha")) == static
    end

    test "an explicit plug resource_metadata override is validated, wins including nil, and skips the resolver" do
      base = Keyword.put(audience_required_opts(), :audience, "https://api.example.com")

      cfg =
        base
        |> Keyword.put(:resource_metadata_resolver, fn _conn ->
          raise "the configured resolver must not run for an explicit plug override"
        end)
        |> Config.new()

      conn = Plug.Test.conn(:get, "/alpha")
      explicit = "https://plug.example/.well-known/oauth-protected-resource/alpha"

      assert Config.resource_metadata_url(cfg, conn, resource_metadata: explicit) == explicit
      assert Config.resource_metadata_url(cfg, conn, resource_metadata: nil) == nil
      assert Config.resource_metadata_url(cfg, conn, resource_metadata: "http://unsafe.example") == nil
    end

    test ":resource_metadata_resolver validates function and MFA call arity" do
      base = Keyword.put(audience_required_opts(), :audience, "https://api.example.com")
      conn = Plug.Test.conn(:get, "/reports")

      pair = {ResourceMetadataResolver, :resolve}
      triple = {ResourceMetadataResolver, :resolve_with_base, ["https://api.example"]}

      assert %Config{resource_metadata_resolver: ^pair} =
               pair_config =
               Config.new(Keyword.put(base, :resource_metadata_resolver, pair))

      assert Config.resource_metadata_url(pair_config, conn) ==
               "https://api.example/.well-known/oauth-protected-resource/reports"

      assert %Config{resource_metadata_resolver: ^triple} =
               triple_config =
               Config.new(Keyword.put(base, :resource_metadata_resolver, triple))

      # The request is the per-call argument and the configured base is
      # appended after it. Reversing that order would fail inside the callback.
      assert Config.resource_metadata_url(triple_config, conn) == "https://api.example/reports"

      for bad <- [
            123,
            :resolver,
            fn -> nil end,
            {"not-a-module", :resolve},
            {ResourceMetadataResolver, :missing},
            {ResourceMetadataResolver, :wrong_arity},
            {ResourceMetadataResolver, :resolve_with_base, []},
            {ResourceMetadataResolver, :resolve, [:unexpected]}
          ] do
        assert_raise ArgumentError, ~r/:resource_metadata_resolver must be a one-argument callback/, fn ->
          Config.new(Keyword.put(base, :resource_metadata_resolver, bad))
        end
      end
    end

    test ":bearer_methods_supported defaults to header-only and is configurable" do
      base = Keyword.put(audience_required_opts(), :audience, "https://api.example.com")

      assert Config.new(base).bearer_methods_supported == ["header"]

      assert Config.new(Keyword.put(base, :bearer_methods_supported, ["header", "body"])).bearer_methods_supported ==
               ["header", "body"]
    end

    test ":bearer_methods_supported rejects empty, duplicate, query, or unknown methods (RFC 6750 §2)" do
      base = Keyword.put(audience_required_opts(), :audience, "https://api.example.com")

      # "query" (§2.3) is rejected: AttestoPhoenix.Plug.Authenticate never accepts
      # a query-presented token, so advertising it would be inaccurate.
      for bad <- [[], ["query"], ["cookie"], ["header", "cookie"], ["header", "header"], "header", nil] do
        assert_raise ArgumentError, ~r/:bearer_methods_supported must be a non-empty list of distinct/, fn ->
          Config.new(Keyword.put(base, :bearer_methods_supported, bad))
        end
      end
    end

    test "the diagnostic names :invalid_audience so the late failure is explained" do
      message =
        assert_raise(ArgumentError, fn -> Config.new(audience_required_opts()) end).message

      assert message =~ ":invalid_audience"
    end

    test "succeeds with a string :audience and carries it into to_attesto_config/1" do
      cfg = Config.new(Keyword.put(audience_required_opts(), :audience, "https://api.example.com"))

      assert cfg.audience == "https://api.example.com"

      assert Config.to_attesto_config(cfg, principal_kinds: [Attesto.PrincipalKind.new("user", "usr_")]).audience ==
               "https://api.example.com"
    end
  end

  describe ":client_auth_signing_algs" do
    test "defaults to the FAPI 2 set when unset" do
      built = config()

      assert built.client_auth_signing_algs == Attesto.SigningAlg.fapi_algs()
      assert "Ed25519" in built.client_auth_signing_algs
      assert built.client_auth_enforce_fapi_alg_policy == true
    end

    test "an explicit algorithm list is a non-FAPI policy unless enforcement is requested" do
      algs = ["PS256", "ES256", "RS256"]
      explicit = config(client_auth_signing_algs: algs)

      enforced =
        config(
          client_auth_signing_algs: ["PS256", "ES256"],
          client_auth_enforce_fapi_alg_policy: true
        )

      assert explicit.client_auth_signing_algs == algs
      assert explicit.client_auth_enforce_fapi_alg_policy == false
      assert enforced.client_auth_enforce_fapi_alg_policy == true
    end

    test "an explicit false can opt the default allowlist out of the FAPI key gate" do
      assert config(client_auth_enforce_fapi_alg_policy: false).client_auth_enforce_fapi_alg_policy == false
    end

    test "rejects a non-boolean enforcement value at boot" do
      assert_raise ArgumentError, ~r/:client_auth_enforce_fapi_alg_policy must be a boolean/, fn ->
        config(client_auth_enforce_fapi_alg_policy: :yes)
      end
    end

    test "rejects malformed and unsupported algorithm lists at boot" do
      assert_raise ArgumentError, ~r/:client_auth_signing_algs must be a non-empty list/, fn ->
        config(client_auth_signing_algs: false)
      end

      assert_raise ArgumentError, ~r/unsupported signing algorithms \["unknown"\]/, fn ->
        config(client_auth_signing_algs: ["PS256", "unknown"])
      end
    end

    test "an enforced list cannot advertise algorithms outside the FAPI set" do
      assert_raise ArgumentError, ~r/:client_auth_signing_algs contains \["RS256"\].*outside.*FAPI/s, fn ->
        config(
          client_auth_signing_algs: ["PS256", "RS256"],
          client_auth_enforce_fapi_alg_policy: true
        )
      end
    end
  end

  describe ":trusted_wallet_provider_jwks" do
    test "is optional and exposes configured Wallet Provider keys" do
      jwks = %{"keys" => [%{"kty" => "EC", "crv" => "P-256", "x" => "x", "y" => "y"}]}

      assert Config.trusted_wallet_provider_jwks(config()) == nil
      assert Config.trusted_wallet_provider_jwks(config(trusted_wallet_provider_jwks: jwks)) == jwks
    end
  end

  describe "CIBA algorithm policy" do
    test "client registration callback accepts only a map or nil" do
      assert Config.client_ciba_registration(
               config(client_ciba_registration: fn _client -> %{token_delivery_mode: :poll} end),
               %{}
             ) == %{token_delivery_mode: :poll}

      assert Config.client_ciba_registration(
               config(client_ciba_registration: fn _client -> nil end),
               %{}
             ) == %{}

      assert_raise ArgumentError,
                   ~r/:client_ciba_registration callback must return a map or nil/,
                   fn ->
                     Config.client_ciba_registration(
                       config(client_ciba_registration: fn _client -> {:error, :unavailable} end),
                       %{}
                     )
                   end
    end

    test "the default FAPI-CIBA allowlist retains the FAPI key gate" do
      opts = Config.ciba(config())

      assert opts[:request_signing_algs] == ["PS256", "ES256"]
      assert opts[:enforce_fapi_alg_policy] == true
    end

    test "an explicit request allowlist is non-FAPI unless enforcement is requested" do
      explicit = Config.ciba(config(ciba: [request_signing_algs: ["EdDSA"]]))

      enforced =
        Config.ciba(config(ciba: [request_signing_algs: ["PS256"], enforce_fapi_alg_policy: true]))

      assert explicit[:enforce_fapi_alg_policy] == false
      assert enforced[:enforce_fapi_alg_policy] == true
    end

    test "rejects a non-boolean CIBA enforcement value at boot" do
      assert_raise ArgumentError, ~r/:ciba :enforce_fapi_alg_policy must be true or false/, fn ->
        config(ciba: [enforce_fapi_alg_policy: :yes])
      end
    end

    test "rejects a non-boolean signed-request policy at boot" do
      for invalid <- [nil, "true", :yes, 1] do
        assert_raise ArgumentError, ~r/:ciba :require_signed_request must be true or false/, fn ->
          config(ciba: [require_signed_request: invalid])
        end
      end
    end

    test "an enforced CIBA list is limited to the FAPI-CIBA PS256/ES256 set" do
      for alg <- ["EdDSA", "Ed448"] do
        assert_raise ArgumentError, ~r/ciba: \[:request_signing_algs\].*outside.*FAPI-CIBA/s, fn ->
          config(ciba: [request_signing_algs: [alg], enforce_fapi_alg_policy: true])
        end
      end
    end
  end

  describe ":request_object_policy" do
    test "defaults to the generic %Policy{} when unset" do
      assert config().request_object_policy == %Policy{}
    end

    test "accepts an Attesto.RequestObject.Policy" do
      # A policy that requires a signed request object needs :client_jwks; pair
      # them so the config is valid (see the boot-rejection test below).
      policy = Policy.fapi_message_signing()

      built =
        config(request_object_policy: policy, client_jwks: fn _ -> %{"keys" => []} end)

      assert built.request_object_policy == policy
    end

    test "rejects a non-Policy value at boot" do
      for value <- [:fapi, false] do
        assert_raise ArgumentError, ~r/:request_object_policy must be an/, fn ->
          config(request_object_policy: value)
        end
      end
    end

    test "rejects a non-boolean request-object enforcement value at boot" do
      policy = %Policy{enforce_fapi_alg_policy: :yes}

      assert_raise ArgumentError, ~r/request_object_policy.enforce_fapi_alg_policy must be nil or a boolean/, fn ->
        config(request_object_policy: policy)
      end
    end

    test "rejects non-boolean request-object requirement fields at boot" do
      for key <- [:require_request_object, :require_nbf, :require_exp],
          invalid <- [nil, "true", :yes, 1] do
        policy = struct!(Policy, [{key, invalid}])

        assert_raise ArgumentError, ~r/request_object_policy\.#{key} must be a boolean/, fn ->
          config(request_object_policy: policy)
        end
      end
    end

    test "rejects invalid request-object lifetime limits at boot" do
      for key <- [:max_nbf_age_seconds, :max_lifetime_seconds],
          invalid <- [0, -1, 1.5, "60"] do
        policy = struct!(Policy, [{key, invalid}])

        assert_raise ArgumentError, ~r/request_object_policy\.#{key} must be a positive integer or nil/, fn ->
          config(request_object_policy: policy)
        end
      end
    end

    test "an enforced request-object list cannot advertise algorithms outside the FAPI set" do
      policy = %Policy{accepted_algs: ["RS256"], enforce_fapi_alg_policy: true}

      assert_raise ArgumentError, ~r/request_object_policy.accepted_algs.*\["RS256"\].*outside.*FAPI/s, fn ->
        config(request_object_policy: policy)
      end
    end

    test "an explicit non-FAPI request-object policy retains supported compatibility algorithms" do
      policy = %Policy{accepted_algs: ["RS256", "Ed448"], enforce_fapi_alg_policy: false}

      assert config(request_object_policy: policy).request_object_policy == policy
    end

    test "rejects a required-request-object policy without :client_jwks at boot" do
      # An unsatisfiable config: every authorization request would be rejected
      # (one with no request object fails the policy; one with a request object
      # fails verification for want of keys). Fail fast rather than deploy it.
      assert_raise ArgumentError, ~r/needs a way to resolve a client's trusted JWKS/, fn ->
        config(request_object_policy: Policy.fapi_message_signing())
      end
    end

    test "accepts a required-request-object policy when :client_jwks resolves via :client_store" do
      # The capability may come from an installed :client_store, not only a flat
      # :client_jwks callback.
      policy = Policy.fapi_message_signing()
      built = config(request_object_policy: policy, client_store: FullStore)

      assert built.request_object_policy == policy
    end
  end

  describe ":client_id_metadata (CIMD §9)" do
    test "defaults to the feature-off keyword list when unset" do
      cimd = Config.client_id_metadata(config())

      assert cimd[:enabled] == false
      assert cimd[:fetcher] == Req
      assert cimd[:cache] == AttestoPhoenix.ClientIdMetadata.Cache.Ecto
      assert cimd[:allow_loopback] == false
      assert cimd[:max_document_bytes] == 5_120
      assert cimd[:request_timeout_ms] == 5_000
      assert cimd[:cache_ttl_bounds] == {60, 86_400}
      assert cimd[:require_same_origin_redirect_uri] == true
      assert cimd[:allowed_hosts] == nil
      assert cimd[:blocked_hosts] == []
    end

    test "merges host overrides over the defaults, leaving unset members defaulted" do
      cimd =
        config(client_id_metadata: [enabled: true, allow_loopback: true])
        |> Config.client_id_metadata()

      assert cimd[:enabled] == true
      assert cimd[:allow_loopback] == true
      # Unset members keep their defaults.
      assert cimd[:max_document_bytes] == 5_120
      assert cimd[:cache] == AttestoPhoenix.ClientIdMetadata.Cache.Ecto
    end

    test "client_id_metadata_enabled?/1 reflects the :enabled member" do
      refute Config.client_id_metadata_enabled?(config())
      refute Config.client_id_metadata_enabled?(config(client_id_metadata: []))
      assert Config.client_id_metadata_enabled?(config(client_id_metadata: [enabled: true]))
    end
  end

  describe ":native_apps (RFC 8252)" do
    test "defaults the §7.3 exception on and the §8.12 heuristic off" do
      native_apps = Config.native_apps(config())

      # §7.3 is a MUST for native clients, so it is an opt-OUT. What keeps the
      # profile off for an unconfigured deployment is `:client_native?`
      # defaulting to false, not this member.
      assert native_apps[:loopback_redirect] == true
      # §8.12 is a heuristic SHOULD, so it stays a genuine opt-in.
      assert native_apps[:reject_embedded_user_agents] == false
      # Widening §7.3 to the `localhost` name goes past the MUST, so it too is
      # a genuine opt-in.
      assert native_apps[:loopback_include_localhost] == false
    end

    test "merges host overrides over the defaults, leaving unset members defaulted" do
      native_apps = config(native_apps: [reject_embedded_user_agents: true]) |> Config.native_apps()

      assert native_apps[:reject_embedded_user_agents] == true
      assert native_apps[:loopback_redirect] == true
    end

    test "native_app_loopback_redirect?/1 is an opt-out, not a gate" do
      assert Config.native_app_loopback_redirect?(config())
      assert Config.native_app_loopback_redirect?(config(native_apps: []))
      assert Config.native_app_loopback_redirect?(config(native_apps: [loopback_redirect: true]))

      # Only an explicit `false` turns it off.
      refute Config.native_app_loopback_redirect?(config(native_apps: [loopback_redirect: false]))
    end

    test "reject_embedded_user_agents?/1 reflects the :reject_embedded_user_agents member" do
      refute Config.reject_embedded_user_agents?(config())
      refute Config.reject_embedded_user_agents?(config(native_apps: [loopback_redirect: true]))
      assert Config.reject_embedded_user_agents?(config(native_apps: [reject_embedded_user_agents: true]))
    end

    test "native_app_loopback_matching/1 is an opt-in for the localhost name" do
      assert Config.native_app_loopback_matching(config()) == :exact_allow_loopback_port
      assert Config.native_app_loopback_matching(config(native_apps: [])) == :exact_allow_loopback_port

      assert Config.native_app_loopback_matching(config(native_apps: [loopback_include_localhost: false])) ==
               :exact_allow_loopback_port

      assert Config.native_app_loopback_matching(config(native_apps: [loopback_include_localhost: true])) ==
               :exact_allow_loopback_port_including_localhost
    end

    test "rejects a non-boolean :loopback_include_localhost rather than failing open" do
      assert_raise ArgumentError, ~r/:native_apps :loopback_include_localhost must be true or false/, fn ->
        config(native_apps: [loopback_include_localhost: "true"])
      end
    end

    # `:loopback_redirect` is the switch an operator reaches for to FORBID a
    # relaxation, so a value it cannot read must not be mistaken for "enabled".
    # Refused at boot rather than silently ignored.
    test "rejects a non-boolean :loopback_redirect rather than failing open" do
      for value <- ["false", "true", nil, 0, :no, 1] do
        assert_raise ArgumentError, ~r/:native_apps :loopback_redirect must be true or false/, fn ->
          config(native_apps: [loopback_redirect: value])
        end
      end
    end

    test "rejects a non-boolean :reject_embedded_user_agents too" do
      assert_raise ArgumentError, ~r/must be true or false/, fn ->
        config(native_apps: [reject_embedded_user_agents: "yes"])
      end
    end

    # A typo'd member would otherwise sit in the keyword list doing nothing
    # while the operator believed it had disabled the exception.
    test "rejects an unrecognized :native_apps member" do
      assert_raise ArgumentError, ~r/unknown :native_apps option :loopbak_redirect/, fn ->
        config(native_apps: [loopbak_redirect: false])
      end
    end

    test "the loopback opt-out and embedded-user-agent flag are independent" do
      config = config(native_apps: [loopback_redirect: false, reject_embedded_user_agents: true])

      refute Config.native_app_loopback_redirect?(config)
      assert Config.reject_embedded_user_agents?(config)
    end
  end

  describe "outbound adapter boot validation" do
    test "rejects an active adapter configured with a non-module value" do
      assert_raise ArgumentError, ~r/client_id_metadata.*must select a module/s, fn ->
        config(client_id_metadata: [enabled: true, fetcher: {:not, :a_module}])
      end
    end

    test "rejects an active adapter module that cannot be loaded" do
      assert_raise ArgumentError, ~r/client_id_metadata.*cannot be loaded/s, fn ->
        config(
          client_id_metadata: [
            enabled: true,
            fetcher: __MODULE__.MissingOutboundAdapter
          ]
        )
      end
    end

    test "rejects an active CIMD adapter without fetch/2" do
      assert_raise ArgumentError, ~r/client_id_metadata.*does not export fetch\/2/s, fn ->
        config(client_id_metadata: [enabled: true, fetcher: EmptyModule])
      end
    end

    test "rejects an active Back-Channel Logout adapter without post/2" do
      assert_raise ArgumentError, ~r/logout.*does not export post\/2/s, fn ->
        config(
          logout: [enabled: true, http_client: EmptyModule],
          logout_session_store: EmptyModule,
          terminate_session: fn _conn, _params -> :ok end
        )
      end
    end

    test "rejects an active CIBA ping adapter without post/3" do
      assert_raise ArgumentError, ~r/ciba_ping_http_client.*does not export post\/3/s, fn ->
        config(
          ciba: [enabled: true, delivery_modes: [:ping]],
          ciba_store: EmptyModule,
          ciba_ping_http_client: EmptyModule,
          authenticate_ciba_user: fn _request -> {:error, :not_found} end,
          replay_check: fn _key, _ttl -> :ok end
        )
      end
    end

    test "rejects an active JWT remote-JWKS adapter without fetch/2" do
      assert_raise ArgumentError, ~r/jwt_bearer.*does not export fetch\/2/s, fn ->
        config(
          jwt_bearer: [
            enabled: true,
            jwks_fetcher: EmptyModule,
            issuers: %{"https://assertions.example" => [jwks_uri: "https://assertions.example/jwks"]}
          ],
          resolve_jwt_bearer_subject: fn _claims -> {:error, :not_found} end
        )
      end
    end
  end

  describe "CIBA delivery-mode boot validation" do
    test "requires replay protection when signed authentication requests are required" do
      assert_raise ArgumentError,
                   ~r/:replay_check is required when CIBA signed authentication requests are required/,
                   fn ->
                     config(
                       ciba: [enabled: true, require_signed_request: true],
                       ciba_store: EmptyModule,
                       authenticate_ciba_user: fn _request -> {:error, :not_found} end
                     )
                   end

      assert %Config{} =
               config(
                 ciba: [enabled: true, require_signed_request: true],
                 ciba_store: EmptyModule,
                 authenticate_ciba_user: fn _request -> {:error, :not_found} end,
                 replay_check: fn _key, _ttl -> :ok end
               )
    end

    test "allows an explicitly unsigned CIBA profile without replay storage" do
      assert %Config{} =
               config(
                 ciba: [enabled: true, require_signed_request: false],
                 ciba_store: EmptyModule,
                 authenticate_ciba_user: fn _request -> {:error, :not_found} end
               )
    end

    test "validates every configured replay callback before serving requests" do
      invalid_callbacks = [
        false,
        :typo,
        fn _key -> :ok end,
        {ReplayCallbacks, :wrong_arity},
        {EmptyModule, :check},
        {Module.concat(__MODULE__, MissingReplayCallback), :check},
        EmptyModule
      ]

      Enum.each(invalid_callbacks, fn replay_check ->
        assert_raise ArgumentError, ~r/:replay_check must be a two-argument callback/, fn ->
          config(replay_check: replay_check)
        end
      end)

      assert %Config{} = config(replay_check: &ReplayCallbacks.check/2)
      assert %Config{} = config(replay_check: {ReplayCallbacks, :check})

      assert %Config{} =
               config(replay_check: {ReplayCallbacks, :check_with_partition, [:primary]})
    end

    test "rejects :push because no push deliverer is implemented" do
      assert_raise ArgumentError, ~r/CIBA :push delivery is not implemented/, fn ->
        config(
          ciba: [enabled: true, delivery_modes: [:push]],
          ciba_store: EmptyModule,
          authenticate_ciba_user: fn _request -> {:error, :not_found} end
        )
      end
    end
  end

  # Boot-time discovery-document safety guard (the "silent discovery mismatch"
  # class of failure): `new/1` must fail fast rather than build a config that
  # would serve a discovery document missing a required endpoint (RFC 8414 §2 /
  # OpenID Connect Discovery §3) or advertising an endpoint the router does not
  # mount.
  describe "boot-time discovery validation: required endpoints (check #1)" do
    test "a valid config still builds (every required endpoint resolves absolute)" do
      built = config()

      # The four required discovery members the library derives are all absolute.
      assert Config.issuer(built) == "https://issuer.example"
      assert Config.authorize_endpoint_url(built) =~ ~r{^https://issuer\.example/oauth/authorize$}
      assert Config.token_endpoint_url(built) =~ ~r{^https://issuer\.example/oauth/token$}
      assert Config.jwks_uri(built) =~ ~r{^https://issuer\.example/\.well-known/jwks\.json$}
    end

    test "a scheme-less :issuer raises (authorization_endpoint would be host-less)" do
      # `URI.merge/2` on a scheme-less issuer yields a path-only, host-less
      # endpoint URL - the discovery document would advertise an unresolvable
      # `authorization_endpoint`/`token_endpoint`.
      assert_raise ArgumentError, ~r/non-absolute|absolute URL/, fn ->
        config(issuer: "issuer.example")
      end
    end

    test "a path-only :issuer raises" do
      assert_raise ArgumentError, ~r/absolute URL/, fn ->
        config(issuer: "/oauth")
      end
    end

    test ":issuer must use HTTPS and cannot contain a query, fragment, or malformed escape" do
      for bad <- [
            "http://issuer.example",
            "https://issuer.example?tenant=one",
            "https://issuer.example#tenant-one",
            "https://issuer.example/%ZZ",
            <<255>>,
            123
          ] do
        assert_raise ArgumentError, ~r/:issuer must be an absolute URL using the https scheme/, fn ->
          config(issuer: bad)
        end
      end
    end

    test "path-bearing issuers remain valid for host-mounted standards-derived well-known routes" do
      assert Config.issuer(config(issuer: "https://issuer.example/tenant")) ==
               "https://issuer.example/tenant"
    end

    test "OpenID endpoint overrides must be absolute HTTPS URLs without fragments" do
      for key <- [:authorization_endpoint, :userinfo_endpoint],
          bad <- [
            "/relative",
            "http://issuer.example/endpoint",
            "https://issuer.example/endpoint#fragment",
            "https://issuer.example/%ZZ",
            :automatic,
            123
          ] do
        assert_raise ArgumentError, ~r/#{key}.*absolute https URL/, fn ->
          config([{key, bad}])
        end
      end

      assert config(authorization_endpoint: "https://login.example/authorize?audience=api").authorization_endpoint ==
               "https://login.example/authorize?audience=api"

      assert config(userinfo_endpoint: "https://claims.example/userinfo").userinfo_endpoint ==
               "https://claims.example/userinfo"

      assert config(userinfo_endpoint: :derived).userinfo_endpoint == :derived
    end

    test "a derived UserInfo endpoint must resolve to a valid HTTPS URL at boot" do
      for userinfo_path <- [
            "/oauth/%ZZ",
            "/oauth/user info",
            "/oauth/userinfo#claims"
          ] do
        assert_raise ArgumentError, ~r/:userinfo_endpoint resolves to an invalid derived URL/, fn ->
          config(userinfo_endpoint: :derived, userinfo_path: userinfo_path)
        end
      end

      assert_raise ArgumentError, ~r/:derived must remain on the :issuer origin/, fn ->
        config(
          userinfo_endpoint: :derived,
          userinfo_path: "//claims.example/userinfo"
        )
      end

      same_origin =
        config(
          userinfo_endpoint: :derived,
          userinfo_path: "//%69SSUER.EXAMPLE:443/oauth/userinfo"
        )

      assert Config.userinfo_endpoint_url(same_origin) ==
               "https://%69SSUER.EXAMPLE/oauth/userinfo"
    end

    test "the raised message names the offending member and the issuer" do
      message =
        assert_raise(ArgumentError, fn -> config(issuer: "issuer.example") end).message

      # `issuer` is validated first (it is the root cause of every host-less
      # derived endpoint), so it is the member named.
      assert message =~ "issuer"
      assert message =~ "issuer.example"
      assert message =~ "absolute URL"
    end
  end

  describe "boot-time discovery validation: prefix vs override consistency (check #2)" do
    test "the default prefix with no overrides builds" do
      assert %Config{} = config()
    end

    test "a custom :oauth_path_prefix with endpoints derived from it builds" do
      built = config(oauth_path_prefix: "/mcp/oauth")

      assert Config.token_path(built) == "/mcp/oauth/token"
      assert Config.par_path(built) == "/mcp/oauth/par"
      assert Config.credential_path(built) == "/mcp/oauth/credential"
      assert Config.nonce_path(built) == "/mcp/oauth/nonce"
      assert Config.status_list_path(built) == "/mcp/oauth/statuslist"
      assert Config.credential_offer_path(built) == "/mcp/oauth/credential_offer"
      assert Config.deferred_credential_path(built) == "/mcp/oauth/deferred_credential"

      assert Config.credential_endpoint_url(built) == "https://issuer.example/mcp/oauth/credential"
      assert Config.nonce_endpoint_url(built) == "https://issuer.example/mcp/oauth/nonce"
      assert Config.status_list_endpoint_url(built) == "https://issuer.example/mcp/oauth/statuslist"

      assert Config.deferred_credential_endpoint_url(built) ==
               "https://issuer.example/mcp/oauth/deferred_credential"
    end

    test "a custom prefix with an override that stays under the prefix builds" do
      # Renaming a tail but keeping the prefix is still mounted under the same
      # tree, so it is allowed.
      built = config(oauth_path_prefix: "/mcp/oauth", token_path: "/mcp/oauth/token2")

      assert Config.token_path(built) == "/mcp/oauth/token2"
    end

    test "a custom prefix with an override that leaves the prefix raises" do
      assert_raise ArgumentError, ~r/sits outside the configured :oauth_path_prefix/, fn ->
        config(oauth_path_prefix: "/mcp/oauth", token_path: "/oauth/token")
      end
    end

    test "the raised message names both the advertised path and the prefix-derived path" do
      message =
        assert_raise(ArgumentError, fn ->
          config(oauth_path_prefix: "/mcp/oauth", token_path: "/elsewhere/token")
        end).message

      assert message =~ "/elsewhere/token"
      assert message =~ "/mcp/oauth/token"
      assert message =~ ":token_path"
    end

    test "an override on the DEFAULT prefix is allowed (documented per-endpoint override)" do
      # With the default prefix the host has not declared a custom mount tree, so
      # a single per-endpoint override is the documented feature, not a mismatch.
      built = config(token_path: "/custom/token")

      assert Config.token_path(built) == "/custom/token"
    end
  end

  describe "OID4VP verifier configuration" do
    test "exposes verifier identity settings and convention-derived URLs" do
      certificate_der = <<1, 2, 3>>

      built =
        config(
          oauth_path_prefix: "/wallet/oauth",
          presentation_session_store: __MODULE__.PresentationStore,
          verifier_encryption_keystore: VerifierEncryptionKeystore,
          verifier_client_id: "verifier-client-1",
          verifier_client_id_scheme: "x509_san_dns",
          verifier_x5c: [certificate_der],
          verifier_dns: "verifier.example"
        )

      assert Config.presentation_session_store(built) == __MODULE__.PresentationStore
      assert Config.verifier_encryption_keystore(built) == VerifierEncryptionKeystore
      assert Config.verifier_client_id(built) == "verifier-client-1"
      assert Config.verifier_client_id_scheme(built) == "x509_san_dns"
      assert Config.verifier_x5c(built) == [certificate_der]
      assert Config.verifier_dns(built) == "verifier.example"
      assert Config.presentation_response_mode(built) == "direct_post"
      assert Config.presentation_request_path(built) == "/wallet/oauth/presentation_request"
      assert Config.presentation_response_path(built) == "/wallet/oauth/presentation_response"

      assert Config.presentation_request_endpoint_url(built) ==
               "https://issuer.example/wallet/oauth/presentation_request"

      assert Config.presentation_response_endpoint_url(built) ==
               "https://issuer.example/wallet/oauth/presentation_response"
    end

    test "keeps verifier-only settings optional for non-presentation hosts" do
      built = config()

      assert Config.presentation_session_store(built) == nil
      assert Config.verifier_encryption_keystore(built) == nil
      assert Config.verifier_client_id(built) == nil
      assert Config.verifier_client_id_scheme(built) == nil
      assert Config.verifier_x5c(built) == nil
      assert Config.verifier_dns(built) == nil
      assert Config.presentation_response_mode(built) == "direct_post"
    end

    test "rejects a configured verifier client id that is not a non-empty string" do
      for invalid <- ["", :verifier, 123] do
        assert_raise ArgumentError, ~r/:verifier_client_id must be a non-empty string/, fn ->
          config(verifier_client_id: invalid)
        end
      end
    end

    test "accepts only the supported presentation response modes" do
      assert Config.presentation_response_mode(config(presentation_response_mode: "direct_post.jwt")) ==
               "direct_post.jwt"

      for invalid <- ["", "query.jwt", :direct_post, nil] do
        assert_raise ArgumentError, ~r/:presentation_response_mode must be/, fn ->
          config(presentation_response_mode: invalid)
        end
      end
    end

    test "accepts only supported verifier client-id schemes" do
      assert Config.verifier_client_id_scheme(config(verifier_client_id_scheme: "redirect_uri")) ==
               "redirect_uri"

      assert Config.verifier_client_id_scheme(config(verifier_client_id_scheme: "x509_san_dns")) ==
               "x509_san_dns"

      for invalid <- ["", "did", :x509_san_dns] do
        assert_raise ArgumentError, ~r/:verifier_client_id_scheme must be/, fn ->
          config(verifier_client_id_scheme: invalid)
        end
      end
    end

    test "validates configured verifier certificate and DNS value types" do
      assert Config.verifier_x5c(config(verifier_x5c: [])) == []
      assert Config.verifier_dns(config(verifier_dns: "")) == ""

      for invalid <- [:certificate, [""], [123]] do
        assert_raise ArgumentError, ~r/:verifier_x5c must be/, fn ->
          config(verifier_x5c: invalid)
        end
      end

      assert_raise ArgumentError, ~r/:verifier_dns must be/, fn ->
        config(verifier_dns: :verifier)
      end
    end
  end

  describe "front-channel logout client metadata (Front-Channel Logout 1.0 §2)" do
    test "an https frontchannel_logout_uri is returned" do
      built = config(client_frontchannel_logout_uri: fn client -> client.fc end)

      assert Config.client_frontchannel_logout_uri(built, %{fc: "https://rp.example/fc"}) ==
               "https://rp.example/fc"
    end

    test "a non-https or malformed frontchannel_logout_uri is treated as absent (fail closed)" do
      built = config(client_frontchannel_logout_uri: fn client -> client.fc end)

      # http would be blocked as mixed content on the https logout page.
      assert Config.client_frontchannel_logout_uri(built, %{fc: "http://rp.example/fc"}) == nil
      assert Config.client_frontchannel_logout_uri(built, %{fc: "https://user@rp.example/fc"}) == nil
      assert Config.client_frontchannel_logout_uri(built, %{fc: "not a uri"}) == nil
      assert Config.client_frontchannel_logout_uri(built, %{fc: nil}) == nil
    end

    test "no callback wired means no front-channel URI" do
      assert Config.client_frontchannel_logout_uri(config(), %{}) == nil
    end

    test "frontchannel_logout_session_required defaults to false and honors the callback" do
      assert Config.client_frontchannel_logout_session_required(config(), %{}) == false

      built = config(client_frontchannel_logout_session_required: fn _client -> true end)
      assert Config.client_frontchannel_logout_session_required(built, %{}) == true
    end

    test "frontchannel_logout_supported? requires logout enabled AND a session store" do
      refute Config.frontchannel_logout_supported?(config())

      enabled =
        config(
          logout: [enabled: true],
          terminate_session: fn conn, _ctx -> {:ok, conn} end
        )

      refute Config.frontchannel_logout_supported?(enabled)

      with_store =
        config(
          logout: [enabled: true],
          terminate_session: fn conn, _ctx -> {:ok, conn} end,
          logout_session_store: EmptyModule
        )

      assert Config.frontchannel_logout_supported?(with_store)
      assert Config.frontchannel_logout_session_supported?(with_store)
    end
  end

  describe "session management options (Session Management 1.0)" do
    test "off by default, with defaulted (__Host-) cookie name and lifetime" do
      built = config()

      refute Config.session_management_enabled?(built)
      assert Config.browser_state_cookie(built) == "__Host-attesto_op_browser_state"
      assert Config.browser_state_cookie_max_age(built) == 86_400
    end

    test "enabling merges over the defaults" do
      secret = :crypto.strong_rand_bytes(32)

      built =
        config(session_management: [enabled: true, browser_state_cookie: "opbs", browser_state_secret: secret])

      assert Config.session_management_enabled?(built)
      assert Config.browser_state_cookie(built) == "opbs"
      assert Config.browser_state_cookie_max_age(built) == 86_400
      assert Config.browser_state_secret(built) == secret
    end

    test "enabling without a browser_state_secret is rejected" do
      assert_raise ArgumentError, ~r/:browser_state_secret is required/, fn ->
        config(session_management: [enabled: true])
      end
    end

    test "a too-short browser_state_secret is rejected" do
      assert_raise ArgumentError, ~r/at least 32 bytes/, fn ->
        config(session_management: [enabled: true, browser_state_secret: "short"])
      end
    end

    test "the check-session iframe URL derives from the issuer and prefix" do
      assert Config.check_session_iframe_url(config()) ==
               "https://issuer.example/oauth/check_session"
    end
  end

  describe "request-scoped resolution" do
    test "resolves the validated config from conn.private instead of application config" do
      request_config = config(issuer: "https://request.example")
      global_config = config(issuer: "https://global.example")
      previous_otp_app = Application.get_env(:attesto_phoenix, :otp_app, :missing)
      previous_config = Application.get_env(:attesto_phoenix, Config, :missing)

      Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)
      Application.put_env(:attesto_phoenix, Config, global_config)

      on_exit(fn ->
        restore_env(:otp_app, previous_otp_app)
        restore_env(Config, previous_config)
      end)

      assert Config.resolve!(put_private(conn(:get, "/"), :attesto_phoenix_config, request_config)) ===
               request_config
    end

    test "fails closed when conn.private has no validated config" do
      assert_raise ArgumentError, ~r/expected conn\.private\[:attesto_phoenix_config\]/, fn ->
        Config.resolve!(conn(:get, "/"))
      end
    end

    test "fails closed when conn.private has a malformed config" do
      malformed = %{issuer: "https://bad.example", client_secret: "sensitive-value"}
      conn = put_private(conn(:get, "/"), :attesto_phoenix_config, malformed)

      error =
        assert_raise ArgumentError, ~r/expected conn\.private\[:attesto_phoenix_config\]/, fn ->
          Config.resolve!(conn)
        end

      refute error.message =~ "bad.example"
      refute error.message =~ "sensitive-value"
    end
  end

  defp restore_env(key, :missing), do: Application.delete_env(:attesto_phoenix, key)
  defp restore_env(key, value), do: Application.put_env(:attesto_phoenix, key, value)
end
