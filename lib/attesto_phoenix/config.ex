defmodule AttestoPhoenix.Config do
  @moduledoc """
  Configuration for the `attesto_phoenix` authorization-server layer.

  This is the single source of truth consumed by every controller and plug in
  the library. It reads the host's configuration (from a host-chosen
  `otp_app`/config key), validates the required keys, applies neutral defaults,
  and derives the `Attesto.Config` the protocol layer needs.

  Build one with `new/1` (from a keyword list or map) or `from_otp_app/2` (to
  read `Application.get_env/2`). Validation raises `ArgumentError` on a missing
  required key so misconfiguration fails fast at boot.

  ## Keys

  ### Required

    * `:issuer` - issuer URL (string) used as the JWT `iss`, the discovery
      issuer, and the base for endpoint URLs.
    * `:keystore` - module implementing `Attesto.Keystore` providing the
      signing key and the verification keys published via JWKS. Use a static
      keystore or a host KMS/HSM/Vault-backed implementation; per-key `alg`
      metadata is supported by the core keystore behaviour.
    * `:repo` - `Ecto.Repo` module used by the Ecto-backed code, refresh,
      nonce, and replay stores.
    * `:load_client` - `(client_id -> {:ok, client} | {:error, :not_found} |
      {:error, :revoked})`. Resolves an OAuth client. The host owns the client
      registry and revocation policy.
    * `:verify_client_secret` - `(client, presented_secret -> boolean)`.
      Constant-time client-secret verification (e.g. via
      `Attesto.SecureCompare`). The host owns secret hashing.
    * `:load_principal` - `(subject_id -> {:ok, principal} | {:error,
      :not_found})`. Resolves the subject/principal during protected-resource
      authentication.

  ### Optional callbacks

    * `:authorize_scope` - `(client, requested_scope -> {:ok, granted_scope} |
      {:error, :invalid_scope})`. Validates/narrows requested scope using
      `Attesto.Scope` algebra. Defaults to "subset of `:scopes_supported`".
    * `:on_event` - `(%AttestoPhoenix.Event{} -> any)`. Audit/telemetry hook.
      No-op by default; the library never stores events itself.
    * `:send_error` - `(conn, status, body_map -> conn)`. Optional transport
      hook used by `AttestoPhoenix.OAuthError` to serialize OAuth/OIDC errors
      into the host's API envelope while preserving the RFC status, challenge,
      and cache-control semantics.
    * `:no_store` - `(conn -> conn)`. Optional transport hook used by
      `AttestoPhoenix.OAuthError` to apply no-store headers.
    * `:www_authenticate` - `(conn, challenge_string -> conn)`. Optional
      transport hook used by `AttestoPhoenix.OAuthError` to write the
      `WWW-Authenticate` challenge header.
    * `:basic_realm` - realm string for token-endpoint Basic auth challenges.
      Default `"OAuth"`.
    * `:htu` - `(conn -> canonical_url_string)`. Overrides how the DPoP `htu`
      is computed behind proxies. Defaults to derivation from `:trusted_proxies`.
    * `:cert_der` - `(conn -> der_binary | nil)`. Extracts the client mTLS
      certificate DER. Required only when `:mtls_enabled`.
    * `:register_client` - `(metadata -> {:ok, client} | {:error, reason})`.
      Persists a dynamically registered client. Required only when
      `:registration_enabled`.
    * `:unregister_client` - `(client -> :ok | {:ok, client} | {:error, reason})`.
      Deletes a dynamically registered client for registration management
      cleanup (RFC 7592). Optional; when unset, DELETE requests to the
      registration management endpoint fail closed.
    * `:client_registration_access_token_hash` - `(client -> String.t() | nil)`.
      Extracts the stored hash of the registration access token issued with a
      dynamic client (RFC 7592). Optional; when unset, DELETE requests fail
      closed.
    * `:principal_kinds` - non-empty list of `Attesto.PrincipalKind` values
      or a zero-arity callback returning that list, passed into the core token
      configuration.
    * `:build_principal` - `(client, subject, scope -> map)`. Builds the
      principal map passed to `Attesto.Token.mint/3`.
    * `:build_userinfo_claims` - `(subject, granted_scopes, requested_claims ->
      claims_map)`. Produces the claim values the UserInfo endpoint
      (OpenID Connect Core §5.3) returns for the authenticated subject. The
      host owns the claim source (its user store); the library owns only the
      scope-to-claim shaping (OpenID Connect Core §5.4) and the guarantee that
      `sub` is present (OpenID Connect Core §5.3.2). `granted_scopes` is the
      list of scopes on the access token; `requested_claims` is the per-claim
      request map from the OpenID Connect `claims` parameter (`%{}` when none).
      Required only when the UserInfo endpoint is mounted.
    * `:client_id` - `(client -> String.t())`. Extracts the OAuth client
      identifier from the host's client struct.
    * `:client_jwks` - `(client -> jwks)`. Returns the client's trusted public
      JWK Set for `private_key_jwt` client authentication. Required only for
      clients that authenticate with `private_key_jwt`.
    * `:client_redirect_uris` - `(client -> [String.t()])`. Returns the
      client's registered redirect URIs (RFC 6749 §3.1.2.2). The authorization
      endpoint exact-matches the request `redirect_uri` against this set
      (RFC 6749 §3.1.2.3); a client exposing none rejects every authorization
      request (fail closed).
    * `:authenticate_resource_owner` - `(conn, request, auth_opts ->
      {:authenticated, subject} | {:halt, conn} | {:none} | {:error,
      :login_required | :consent_required | :interaction_required})`.
      Establishes the resource owner for an authorization request (RFC 6749
      §3.1, OIDC Core §3.1.2.3). Returns `{:authenticated, subject}` once a
      resource owner is known (a map carrying at least `:subject`, the OIDC
      `sub`, and optionally `:auth_time`, `:acr`, `:amr`), `{:halt, conn}` to
      take over the connection (e.g. redirect to a host login page that
      re-enters the authorization endpoint), `{:none}` when no subject can be
      established without UI, or an `{:error, _}` classifying why interaction is
      required (OIDC Core §3.1.2.6). `auth_opts` is a map carrying the OIDC Core
      §3.1.2.1 `prompt`/`max_age` directives the host must honour: `:prompt`,
      `:force_reauth` (`prompt=login`), `:interactive` (`false` for
      `prompt=none`, forbidding UI), and `:max_age`. The host owns all login
      UI; the library only invokes this hook. Required only when the
      authorization endpoint is mounted.
    * `:consent` - `(conn, request, subject -> {:consented, subject} |
      {:halt, conn} | {:denied, reason})`. Obtains the resource owner's consent
      for an authorization request (RFC 6749 §4.1.1). Returns
      `{:consented, subject}` to proceed (the returned subject may carry
      consent-derived claims), `{:halt, conn}` to take over the connection (e.g.
      render a consent screen that re-enters the authorization endpoint), or
      `{:denied, reason}` to refuse (reported to the client as `access_denied`,
      RFC 6749 §4.1.2.1). When unset, consent is implicitly granted for the
      authenticated subject.
    * `:client_public?` - `(client -> boolean())`. Returns whether a client
      may authenticate without a secret and rely on PKCE.
    * `:client_requires_mtls?` - `(client -> boolean())`. Returns whether a
      client requires mTLS-bound token issuance.
    * `:issue_refresh_token?` - `(client, granted_scope -> boolean())`.
      Returns whether the authorization-code grant should issue an initial
      refresh token (RFC 6749 §6). When unset, the token controller issues one
      iff the granted scope contains `offline_access` (OIDC Core §11) and a
      `:refresh_store` is configured.
    * `:code_store` - module implementing `Attesto.CodeStore`.
    * `:refresh_store` - module implementing `Attesto.RefreshStore`.
    * `:par_store` - module implementing `AttestoPhoenix.PARStore`.
    * `:grant_types_supported` - grant types advertised/accepted by dynamic
      client registration.
    * `:token_endpoint_auth_methods_supported` - client authentication methods
      advertised/accepted by dynamic client registration.

  ### Optional values (with defaults)

    * `:audience` - default access-token audience (string or list).
    * `:scopes_supported` - list of supported scope strings (concrete and
      wildcard) advertised in discovery and used as the default scope catalog.
      For an OpenID Provider the reserved `openid` scope (OpenID Connect Core
      §3.1.2.1) is added to the OpenID Provider Metadata automatically by the
      core builder; it need not be listed here.
    * `:authorization_endpoint` - absolute URL of the host-owned authorization
      endpoint (RFC 6749 §3.1 / OpenID Connect Discovery §3). The authorization
      endpoint runs the host's login/consent UI, so the library does not mount
      it; the host supplies the URL where it serves it. Advertised in the
      OpenID Provider Metadata; omitted when unset.
    * `:userinfo_endpoint` - absolute URL of the host-owned UserInfo endpoint
      (OpenID Connect Core §5.3). The host owns the claim source, so the
      library does not mount it; the host supplies the URL. Advertised in the
      OpenID Provider Metadata; omitted when unset.
    * `:claims_supported` - list of claim names the host's UserInfo endpoint
      and ID Tokens can return (OpenID Connect Discovery §3). Advertised in the
      OpenID Provider Metadata; omitted when unset.
    * `:claims_parameter_supported` - whether the provider accepts the OpenID
      Connect `claims` request parameter (OpenID Connect Discovery §3 /
      OpenID Connect Core §5.5). Default `false`: the authorization endpoint
      does not consume a `claims` parameter unless the host wires it, so the
      provider does not claim support for it. Advertised in the OpenID Provider
      Metadata only when set to `true` (the core builder treats absence as
      `false` per OpenID Connect Discovery §3).
    * `:acr_values_supported` - list of Authentication Context Class Reference
      values the provider can satisfy (OpenID Connect Discovery §3 /
      OpenID Connect Core §2). Advertised only when the host configures a
      non-empty list; omitted otherwise.
    * `:ui_locales_supported` - list of BCP47 (RFC 5646) language tags the
      provider's UI supports (OpenID Connect Discovery §3). Advertised only
      when the host configures a non-empty list; omitted otherwise.
    * `:require_nonce` - require the OpenID Connect `nonce` parameter on
      OpenID Connect Authentication Requests (OpenID Connect Core §3.1.2.1).
      Default `false`. When `true`, the authorization endpoint passes
      `require_nonce: true` to `Attesto.AuthorizationRequest.validate/2` for a
      request whose scope contains `openid`, so a missing `nonce` on an OIDC
      request is rejected with a redirectable `invalid_request` error. A
      non-OpenID OAuth 2.0 request is never affected (RFC 6749 keeps the
      authorization code at SHOULD, never requiring a `nonce`). The host sets
      this per its own OpenID Provider policy.
    * `:require_https` - enforce HTTPS on the endpoints. Default `true`.
    * `:trusted_proxies` - list of trusted proxy CIDRs/IPs controlling whether
      `X-Forwarded-*` headers are honored. Default `[]` (no forwarded trust).
    * `:access_token_ttl` - access-token lifetime, seconds. Default `900`.
    * `:refresh_token_ttl` - refresh-token lifetime, seconds. Default `1_209_600`.
    * `:authorization_code_ttl` - authorization-code lifetime, seconds. Default `60`.
    * `:dpop_enabled` - enable DPoP sender-constraint support. Default `true`.
    * `:dpop_nonce_required` - require server-issued DPoP nonces. Default `false`.
    * `:mtls_enabled` - enable mTLS (RFC 8705) `cnf` binding. Default `false`.
    * `:registration_enabled` - enable `/oauth/register`. Default `false`.
    * `:replay_check` - DPoP `jti` replay check (module or `{module, fun}`).
      Defaults to the single-node ETS replay cache.
    * `:nonce_store` - `Attesto.DPoP.NonceStore` implementation. Defaults to
      the single-node ETS nonce store.
    * `:sweep_interval_ms` - interval for `AttestoPhoenix.Store.Sweeper`. The
      sweeper is not started if unset.
    * `:table_prefix` - optional Ecto schema/table prefix for the generated
      tables.
  """

  @enforce_keys [
    :issuer,
    :keystore,
    :repo,
    :load_client,
    :verify_client_secret,
    :load_principal
  ]
  defstruct [
    :issuer,
    :keystore,
    :repo,
    :load_client,
    :verify_client_secret,
    :load_principal,
    :audience,
    :authorize_scope,
    :on_event,
    :send_error,
    :no_store,
    :www_authenticate,
    :htu,
    :cert_der,
    :register_client,
    :unregister_client,
    :client_registration_access_token_hash,
    :principal_kinds,
    :build_principal,
    :build_userinfo_claims,
    :client_id,
    :client_jwks,
    :client_redirect_uris,
    :authenticate_resource_owner,
    :consent,
    :client_public?,
    :client_requires_mtls?,
    :issue_refresh_token?,
    :code_store,
    :refresh_store,
    :par_store,
    :grant_types_supported,
    :token_endpoint_auth_methods_supported,
    :authorization_endpoint,
    :userinfo_endpoint,
    :replay_check,
    :nonce_store,
    :sweep_interval_ms,
    :table_prefix,
    scopes_supported: [],
    claims_supported: [],
    acr_values_supported: [],
    ui_locales_supported: [],
    claims_parameter_supported: false,
    require_nonce: false,
    require_pkce: true,
    require_https: true,
    trusted_proxies: [],
    access_token_ttl: 900,
    refresh_token_ttl: 1_209_600,
    authorization_code_ttl: 60,
    par_ttl: 90,
    dpop_enabled: true,
    dpop_nonce_required: false,
    mtls_enabled: false,
    registration_enabled: false,
    basic_realm: "OAuth"
  ]

  # A host callback is an anonymous function, a `{module, function}` pair, or a
  # `{module, function, extra_args}` triple. The triple is NOT `mfa()`: its third
  # element is a list of extra arguments appended after the call arguments
  # (`apply(module, function, args ++ extra)`), not an arity. Spelling it `mfa()`
  # would type that element as `arity()` (`0..255`), which contradicts the
  # `is_list/1` dispatch in every `invoke/2` helper that consumes this type.
  @type callback :: function() | {module(), atom()} | {module(), atom(), [any()]}

  @type t :: %__MODULE__{
          issuer: String.t(),
          keystore: module(),
          repo: module(),
          load_client: callback(),
          verify_client_secret: callback(),
          load_principal: callback(),
          audience: String.t() | [String.t()] | nil,
          authorize_scope: callback() | nil,
          on_event: callback() | nil,
          send_error: callback() | nil,
          no_store: callback() | nil,
          www_authenticate: callback() | nil,
          basic_realm: String.t(),
          htu: callback() | nil,
          cert_der: callback() | nil,
          register_client: callback() | nil,
          unregister_client: callback() | nil,
          client_registration_access_token_hash: callback() | nil,
          principal_kinds: [Attesto.PrincipalKind.t()] | callback() | nil,
          build_principal: callback() | nil,
          build_userinfo_claims: callback() | nil,
          client_id: callback() | nil,
          client_jwks: callback() | nil,
          client_redirect_uris: callback() | nil,
          authenticate_resource_owner: callback() | nil,
          consent: callback() | nil,
          client_public?: callback() | nil,
          client_requires_mtls?: callback() | nil,
          issue_refresh_token?: callback() | nil,
          code_store: module() | nil,
          refresh_store: module() | nil,
          par_store: module() | nil,
          grant_types_supported: [String.t()] | nil,
          token_endpoint_auth_methods_supported: [String.t()] | nil,
          authorization_endpoint: String.t() | nil,
          userinfo_endpoint: String.t() | nil,
          replay_check: callback() | module() | nil,
          nonce_store: module() | nil,
          sweep_interval_ms: pos_integer() | nil,
          table_prefix: String.t() | nil,
          scopes_supported: [String.t()],
          claims_supported: [String.t()],
          acr_values_supported: [String.t()],
          ui_locales_supported: [String.t()],
          claims_parameter_supported: boolean(),
          require_nonce: boolean(),
          require_pkce: boolean(),
          require_https: boolean(),
          trusted_proxies: [String.t()],
          access_token_ttl: pos_integer(),
          refresh_token_ttl: pos_integer(),
          authorization_code_ttl: pos_integer(),
          par_ttl: pos_integer(),
          dpop_enabled: boolean(),
          dpop_nonce_required: boolean(),
          mtls_enabled: boolean(),
          registration_enabled: boolean()
        }

  @required @enforce_keys

  @doc """
  Builds and validates a config from a keyword list or map.

  Raises `ArgumentError` if a required key is missing or if a dependent key is
  absent for an enabled feature (e.g. `:register_client` when
  `:registration_enabled`, or `:cert_der` when `:mtls_enabled`).
  """
  @spec new(keyword() | map()) :: t()
  def new(opts) when is_list(opts), do: opts |> Map.new() |> new()

  def new(opts) when is_map(opts) do
    config = struct!(__MODULE__, opts)
    validate!(config)
  end

  @doc """
  Reads the config for `otp_app` under `key` (default `AttestoPhoenix`) from the
  application environment and builds a validated config.
  """
  @spec from_otp_app(atom(), atom()) :: t()
  def from_otp_app(otp_app, key \\ __MODULE__) when is_atom(otp_app) do
    otp_app
    |> Application.get_env(key, [])
    |> new()
  end

  @doc """
  Derives the `Attesto.Config` consumed by the protocol layer from this config.

  The protocol layer owns only the claim-level policy (`:issuer`, `:audience`,
  `:keystore`, the principal kinds, and the default access-token lifetime). The
  refresh/code TTLs and the DPoP/mTLS feature toggles are read directly from
  this struct by the controllers and plugs, so they are not duplicated into the
  `Attesto.Config`.

  Pass `principal_kinds:` (a non-empty list of `Attesto.PrincipalKind`) and any
  other `Attesto.Config.new/1` option as `extra` to complete the protocol
  config; they are merged over the values derived here.
  """
  @spec to_attesto_config(t(), keyword()) :: Attesto.Config.t()
  def to_attesto_config(%__MODULE__{} = config, extra \\ []) do
    [
      issuer: config.issuer,
      audience: config.audience,
      keystore: config.keystore,
      default_lifetime_seconds: config.access_token_ttl
    ]
    |> Keyword.merge(extra)
    |> Attesto.Config.new()
  end

  @doc """
  Invokes the host's `:build_userinfo_claims` callback for the authenticated
  subject and returns the raw claims map it produces.

  The callback is applied with `[subject, granted_scopes, requested_claims]`
  (see the `:build_userinfo_claims` key documentation). It is the claim source
  for the UserInfo endpoint (OpenID Connect Core §5.3); the host owns the claim
  values, the controller owns the scope-to-claim shaping. Raises
  `ArgumentError` when the host has not configured the callback, so a mounted
  UserInfo endpoint cannot silently return an empty document.
  """
  @spec build_userinfo_claims(t(), String.t(), [String.t()], map()) :: map()
  def build_userinfo_claims(
        %__MODULE__{build_userinfo_claims: nil},
        _subject,
        _scopes,
        _requested
      ) do
    raise ArgumentError,
          "AttestoPhoenix.Config: :build_userinfo_claims is required to serve the UserInfo endpoint"
  end

  def build_userinfo_claims(
        %__MODULE__{build_userinfo_claims: callback},
        subject,
        scopes,
        requested
      ) do
    invoke(callback, [subject, scopes, requested])
  end

  defp invoke(fun, args) when is_function(fun), do: apply(fun, args)

  defp invoke({module, fun}, args) when is_atom(module) and is_atom(fun),
    do: apply(module, fun, args)

  defp invoke({module, fun, extra}, args)
       when is_atom(module) and is_atom(fun) and is_list(extra),
       do: apply(module, fun, args ++ extra)

  defp validate!(%__MODULE__{} = config) do
    Enum.each(@required, fn key ->
      if is_nil(Map.fetch!(config, key)) do
        raise ArgumentError,
              "AttestoPhoenix.Config: required key #{inspect(key)} is missing"
      end
    end)

    if config.mtls_enabled and is_nil(config.cert_der) do
      raise ArgumentError,
            "AttestoPhoenix.Config: :cert_der is required when :mtls_enabled is true"
    end

    if config.registration_enabled and is_nil(config.register_client) do
      raise ArgumentError,
            "AttestoPhoenix.Config: :register_client is required when :registration_enabled is true"
    end

    config
  end
end
