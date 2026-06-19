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
    * `:introspection_authorize` - `(caller_client_id, response -> boolean)`.
      Authorizes the authenticated introspection caller against the token being
      introspected (RFC 7662 §4 / RFC 9701 §5). Consulted only for an active
      response; returning anything but `true` (or raising) downgrades the
      response to `%{"active" => false}` so a caller not entitled to the token
      learns nothing about it (FAPI: a regular client querying introspection is
      a leakage risk). `response` is the RFC 7662 member map (carrying `aud`,
      `client_id`, `sub`, `scope`, ...), letting the host match the token's
      audience/scope against the calling protected resource. Optional - when
      unset, every authenticated caller may introspect any token (the
      single-trust-domain default).
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
    * `:build_id_token_claims` - `(client, subject, granted_scopes,
      requested_claims -> claims_map)`. Produces the host claims merged into an
      ID Token (OpenID Connect Core §3.1.3.6 / §5.5 `id_token` member). Distinct
      from `:build_userinfo_claims`: it receives the resolved `client`, draws
      from the `claims` parameter's `id_token` member, and MUST NOT carry `sub`
      (the library sets the verified subject; a host-supplied `sub` is rejected
      by `Attesto.IDToken`). Optional - when unset the ID Token carries only the
      protocol claims.
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
    * `:client_requires_dpop?` - `(client -> boolean())`. Returns whether a
      client requires DPoP-bound token issuance.
    * `:client_grant_types` - `(client -> [String.t()] | nil)`. Returns the
      grant types registered for this client (RFC 7591 §2). When set, the
      token endpoint rejects a requested grant type not in the returned list.
    * `:issue_refresh_token?` - `(client, granted_scope -> boolean())`.
      Returns whether the authorization-code grant should issue an initial
      refresh token (RFC 6749 §6). When unset, the token controller issues one
      iff the granted scope contains `offline_access` (OIDC Core §11) and a
      `:refresh_store` is configured.
    * `:code_store` - module implementing `Attesto.CodeStore`.
    * `:refresh_store` - module implementing `Attesto.RefreshStore`.
    * `:par_store` - module implementing `AttestoPhoenix.PARStore`. Defaults to
      the single-node `AttestoPhoenix.Store.PAR.ETS`; use
      `AttestoPhoenix.Store.EctoPARStore` for a clustered/load-balanced
      deployment so a `request_uri` resolves on every node (FAPI 2.0 requires
      PAR).
    * `:grant_types_supported` - the grant types the server supports. Advertised
      as `grant_types_supported` (RFC 8414 §2), enforced by the token endpoint (a
      `grant_type` outside the set is rejected), and the accepted set for dynamic
      registration. Defaults to every implemented grant; narrow it to disable one
      (e.g. drop token-exchange) everywhere at once. See `grant_types_supported/1`.
    * `:token_endpoint_auth_methods_supported` - client authentication methods
      advertised/accepted by dynamic client registration and by the token/PAR
      endpoints when configured. When unset, all package-supported methods are
      accepted.

  ### Optional values (with defaults)

    * `:audience` - default access-token audience (string or list).
    * `:client_auth_signing_algs` - the JOSE algorithms accepted for
      `private_key_jwt` client-assertion signatures, and the set advertised as
      `token_endpoint_auth_signing_alg_values_supported` in discovery. Defaults
      to `Attesto.SigningAlg.fapi_algs/0` (PS256, ES256, EdDSA). A non-FAPI
      deployment can widen it; verification and the advertised metadata stay in
      lockstep because both read this one value.
    * `:request_object_policy` - an `Attesto.RequestObject.Policy` controlling
      verification of signed authorization request objects (JAR, RFC 9101).
      Defaults to `%Attesto.RequestObject.Policy{}` (generic OpenID Connect §6.1:
      `nbf`/`exp`/`typ` not required). For FAPI 2.0 Message Signing §5.3.1 set
      `Attesto.RequestObject.Policy.fapi_message_signing()`; the policy is then
      enforced both at the PAR endpoint and at `/authorize`.
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
    * `:require_pushed_authorization_requests` - require front-channel
      authorization requests to use a PAR `request_uri` issued by this server
      (RFC 9126). Default `false`.
    * `:authorization_response_iss` - include the RFC 9207 `iss` authorization
      response parameter on success and error redirects. Default `true`
      (authorization-server mix-up defense, mandated by FAPI 2.0); set `false`
      only for a deployment that must omit it.
    * `:require_https` - enforce HTTPS on the endpoints. Default `true`.
    * `:trusted_proxies` - list of trusted proxy CIDRs/IPs controlling whether
      `X-Forwarded-*` headers are honored. Default `[]` (no forwarded trust).
    * `:access_token_ttl` - access-token lifetime, seconds. Default `900`.
    * `:refresh_token_ttl` - refresh-token lifetime, seconds. Default `1_209_600`.
    * `:refresh_token_rotation_grace_seconds` - idempotency window, in
      seconds, during which a just-rotated refresh token can be retried and
      receive the same successor refresh token instead of being treated as a
      reuse attack. Default `60`; set `0` for strict immediate reuse
      revocation. A non-zero window is important for clients that lose the
      first rotation response and retry the previous token (OAuth 2.0 Security
      BCP §4.13; FAPI 2.0 Security Profile §5.3.2.1).
    * `:authorization_code_ttl` - authorization-code lifetime, seconds. Default `60`.
    * `:dpop_enabled` - enable DPoP sender-constraint support. Default `true`.
    * `:dpop_nonce_required` - require server-issued DPoP nonces. Default `false`.
    * `:mtls_enabled` - enable mTLS (RFC 8705) `cnf` binding. Default `false`.
    * `:registration_enabled` - enable `/oauth/register`. Default `false`.
    * `:client_id_metadata` - Client ID Metadata Document support - CIMD
      (`draft-ietf-oauth-client-id-metadata-document-01`, IETF OAuth WG). A
      keyword list configuring whether (and how) the authorization server
      dereferences an HTTPS `client_id` URL to a client metadata document. The
      whole feature is off by default; when `enabled: true`, discovery
      advertises `client_id_metadata_document_supported` and
      `AttestoPhoenix.ClientIdMetadata.Resolver` resolves a CIMD `client_id`
      through the configured fetcher and cache. Read it back with
      `client_id_metadata/1` (the merged, defaulted keyword list) or the
      `client_id_metadata_enabled?/1` predicate. Recognized members, with their
      defaults:

        * `:enabled` - master switch. Default `false`.
        * `:fetcher` - module implementing
          `AttestoPhoenix.ClientIdMetadata.Fetcher` (the SSRF-guarded outbound
          `GET`). Default `AttestoPhoenix.ClientIdMetadata.Fetcher.Req`. A host
          may override with its own HTTP stack or a CIMD proxy service.
        * `:cache` - module implementing
          `AttestoPhoenix.ClientIdMetadata.Cache`. Default
          `AttestoPhoenix.ClientIdMetadata.Cache.Ecto` (cluster-coherent); a
          single-node deployment may select
          `AttestoPhoenix.ClientIdMetadata.Cache.ETS`.
        * `:allow_loopback` - permit loopback addresses (the draft's "AS runs on
          loopback" exception; development only). Default `false`.
        * `:max_document_bytes` - body size cap for the fetched document
          (draft's recommended 5 KB). Default `5_120`.
        * `:request_timeout_ms` - connect and receive timeout for the fetch.
          Default `5_000`.
        * `:cache_ttl_bounds` - `{min_seconds, max_seconds}` the resolver clamps
          the response's `Cache-Control: max-age` / `Expires` freshness to
          (RFC 9111). Default `{60, 86_400}`.
        * `:require_same_origin_redirect_uri` - additionally require the request
          `redirect_uri` to be same-origin with the `client_id` URL, on top of
          the exact-match against the document's `redirect_uris` (draft §2 MAY,
          enforced by default here). Default `true`.
        * `:allowed_hosts` - optional allowlist of hostnames a CIMD `client_id`
          URL may resolve through; `nil` means "any public host" (subject to the
          fetcher's SSRF guard). Default `nil`.
        * `:blocked_hosts` - hostnames a CIMD `client_id` URL must never resolve
          through, checked before any network work. Default `[]`.
    * `:replay_check` - DPoP `jti` replay check (module or `{module, fun}`).
      Defaults to the single-node ETS replay cache.
    * `:nonce_store` - `Attesto.DPoP.NonceStore` implementation. Defaults to
      the single-node ETS nonce store.
    * `:sweep_interval_ms` - interval for `AttestoPhoenix.Store.Sweeper`. The
      sweeper is not started if unset.
    * `:table_prefix` - optional Ecto schema/table prefix for the generated
      tables.

  ### Endpoint paths advertised in metadata

  The discovery documents (RFC 8414 §3, OpenID Connect Discovery §4) and the
  RFC 7591 §3.2.1 registration response advertise absolute endpoint URLs built
  from the `:issuer` and the request path each endpoint is mounted at. By
  default the OAuth endpoints live under `/oauth/*` (the historic surface), but
  a host that mounts them elsewhere (for example under `/mcp/oauth/*` to avoid
  colliding with a legacy provider) MUST advertise the paths it actually serves
  or clients are misdirected. These keys control that, all additive with
  defaults that reproduce the historic `/oauth/*` surface exactly:

    * `:oauth_path_prefix` - path segment prepended to every OAuth endpoint
      tail. Default `"/oauth"`, yielding the historic `/oauth/token`,
      `/oauth/par`, etc. A host mounting under `/mcp/oauth` sets
      `oauth_path_prefix: "/mcp/oauth"` to advertise `/mcp/oauth/token` and so
      on. This is the FULL client-visible mount prefix, since the controllers
      cannot see the surrounding Phoenix `scope`. The well-known documents
      (RFC 8615) and the JWKS document stay anchored at the host root and are
      NOT relocated by this prefix.
    * `:authorize_path`, `:token_path`, `:par_path`, `:revocation_path`,
      `:introspection_path`, `:registration_path`, `:userinfo_path` - explicit per-endpoint path
      overrides. When set, the override wins over `:oauth_path_prefix` for that
      one endpoint (the integrator's "explicit endpoint overrides plus sane
      defaults"). Each defaults to `nil`, meaning "derive from
      `:oauth_path_prefix`". An override is an absolute path reference
      (`"/custom/token"`), advertised verbatim merged onto the issuer.

  Use the resolver helpers (`token_endpoint_url/1`, `par_endpoint_url/1`,
  `revocation_endpoint_url/1`, `registration_endpoint_url/1`,
  `userinfo_endpoint_url/1`, `authorize_endpoint_url/1`, `jwks_uri/1`, and the
  resolved-path helpers `token_path/1` and friends) rather than re-deriving the
  URLs in callers; the router macro derives its mounted-route tails from the
  same source so the mounted routes and the advertised routes cannot drift.

  ## Recommended production callback contracts

  The loose `*_client`, `*_principal`, `authorize_scope`, consent, registration,
  and event callbacks above are grouped into named behaviours that document the
  full contract (with the governing RFC for each callback) and serve as the
  recommended production shape: `AttestoPhoenix.ClientStore`,
  `AttestoPhoenix.PrincipalStore`, `AttestoPhoenix.ScopePolicy`,
  `AttestoPhoenix.ConsentPolicy`, `AttestoPhoenix.RegistrationStore`, and
  `AttestoPhoenix.EventSink`. Wiring stays identical: pass an anonymous
  function, a `{module, function}` pair, or a `{module, function, extra_args}`
  triple per key as documented above. The behaviours are the contract; the
  Config keys are how a host installs an implementation.

  ## Behaviour-module Config keys

  Rather than wiring every host callback as an individual flat key, a host may
  install one behaviour module per concern and let the library resolve each
  callback from it:

    * `:client_store` - a module implementing `AttestoPhoenix.ClientStore`.
    * `:principal_store` - a module implementing `AttestoPhoenix.PrincipalStore`.
    * `:consent_policy` - a module implementing `AttestoPhoenix.ConsentPolicy`.
    * `:scope_policy` - a module implementing `AttestoPhoenix.ScopePolicy`.
    * `:event_sink` - a module implementing `AttestoPhoenix.EventSink`.
    * `:registration` - a module implementing `AttestoPhoenix.RegistrationStore`.
    * `:claims_provider` - a module implementing `AttestoPhoenix.ClaimsProvider`.

  Each per-callback value is resolved through the matching resolver fun on this
  module (`client_id_fun/1`, `load_principal_fun/1`, `consent_fun/1`, and so on)
  with a single precedence: the explicit flat key wins when set; otherwise, when
  a behaviour module is installed and exports the corresponding behaviour
  callback (after `Code.ensure_loaded/1`), the `{module, function}` pair is used;
  otherwise the resolution is `nil` (and the consumer's existing fail-closed
  default applies). Flat keys therefore never break: a host that wires the
  individual callbacks keeps the exact behaviour it had. `new/1` validates at
  boot that any installed behaviour module is loadable and exports the callbacks
  it claims, so a typo'd or partial module fails fast rather than silently
  resolving to `nil` at request time.
  """

  alias Attesto.RequestObject.Policy
  alias AttestoPhoenix.Callback

  # Only the plain required *values* are enforced by `struct!/2`. The required
  # *capabilities* (`:load_client`, `:verify_client_secret`, `:load_principal`)
  # are NOT enforced here, because a host may supply them via an installed
  # behaviour module (`:client_store` / `:principal_store`) instead of a flat
  # callback. They are validated by resolution in `validate!/1` so the
  # behaviour-module install path actually works.
  alias AttestoPhoenix.ClientIdMetadata.Fetcher.Req

  @enforce_keys [
    :issuer,
    :keystore,
    :repo
  ]
  defstruct [
    :issuer,
    :keystore,
    :repo,
    :load_client,
    :verify_client_secret,
    :load_principal,
    :client_store,
    :principal_store,
    :consent_policy,
    :scope_policy,
    :event_sink,
    :registration,
    :claims_provider,
    :client_auth_signing_algs,
    :request_object_policy,
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
    :introspection_authorize,
    :principal_kinds,
    :build_principal,
    :build_userinfo_claims,
    :build_id_token_claims,
    :client_id,
    :client_jwks,
    :client_redirect_uris,
    :authenticate_resource_owner,
    :consent,
    :client_public?,
    :client_requires_mtls?,
    :client_requires_dpop?,
    :client_grant_types,
    :issue_refresh_token?,
    :resolve_jwt_bearer_subject,
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
    :authorize_path,
    :token_path,
    :par_path,
    :revocation_path,
    :introspection_path,
    :registration_path,
    :userinfo_path,
    oauth_path_prefix: "/oauth",
    scopes_supported: [],
    claims_supported: [],
    acr_values_supported: [],
    ui_locales_supported: [],
    claims_parameter_supported: false,
    require_nonce: false,
    require_pkce: true,
    require_pushed_authorization_requests: false,
    authorization_response_iss: true,
    require_https: true,
    trusted_proxies: [],
    access_token_ttl: 900,
    refresh_token_ttl: 1_209_600,
    refresh_token_rotation_grace_seconds: 60,
    authorization_code_ttl: 60,
    par_ttl: 90,
    dpop_enabled: true,
    dpop_nonce_required: false,
    mtls_enabled: false,
    registration_enabled: false,
    client_id_metadata: [],
    jwt_bearer: [],
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
          client_store: module() | nil,
          principal_store: module() | nil,
          consent_policy: module() | nil,
          scope_policy: module() | nil,
          event_sink: module() | nil,
          registration: module() | nil,
          claims_provider: module() | nil,
          client_auth_signing_algs: [String.t()] | nil,
          request_object_policy: Policy.t() | nil,
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
          introspection_authorize: callback() | nil,
          principal_kinds: [Attesto.PrincipalKind.t()] | callback() | nil,
          build_principal: callback() | nil,
          build_userinfo_claims: callback() | nil,
          build_id_token_claims: callback() | nil,
          client_id: callback() | nil,
          client_jwks: callback() | nil,
          client_redirect_uris: callback() | nil,
          authenticate_resource_owner: callback() | nil,
          consent: callback() | nil,
          client_public?: callback() | nil,
          client_requires_mtls?: callback() | nil,
          client_requires_dpop?: callback() | nil,
          client_grant_types: callback() | nil,
          issue_refresh_token?: callback() | nil,
          resolve_jwt_bearer_subject: callback() | nil,
          code_store: module() | nil,
          refresh_store: module() | nil,
          par_store: module() | nil,
          grant_types_supported: [String.t()] | nil,
          token_endpoint_auth_methods_supported: [String.t()] | nil,
          require_pushed_authorization_requests: boolean(),
          authorization_response_iss: boolean(),
          authorization_endpoint: String.t() | nil,
          userinfo_endpoint: String.t() | nil,
          replay_check: callback() | module() | nil,
          nonce_store: module() | nil,
          sweep_interval_ms: pos_integer() | nil,
          table_prefix: String.t() | nil,
          oauth_path_prefix: String.t(),
          authorize_path: String.t() | nil,
          token_path: String.t() | nil,
          par_path: String.t() | nil,
          revocation_path: String.t() | nil,
          introspection_path: String.t() | nil,
          registration_path: String.t() | nil,
          userinfo_path: String.t() | nil,
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
          refresh_token_rotation_grace_seconds: non_neg_integer(),
          authorization_code_ttl: pos_integer(),
          par_ttl: pos_integer(),
          dpop_enabled: boolean(),
          dpop_nonce_required: boolean(),
          mtls_enabled: boolean(),
          registration_enabled: boolean(),
          client_id_metadata: keyword(),
          jwt_bearer: keyword()
        }

  # Required plain values: enforced for presence as struct fields.
  @required @enforce_keys

  # Required capabilities: each must RESOLVE (flat callback or installed
  # behaviour module), validated in `validate!/1` after construction.
  @required_capabilities [:load_client, :verify_client_secret, :load_principal]

  @doc """
  Builds and validates a config from a keyword list or map.

  Raises `ArgumentError` if a required key is missing or if a dependent key is
  absent for an enabled feature (e.g. `:register_client` when
  `:registration_enabled`, or `:cert_der` when `:mtls_enabled`).
  """
  @spec new(keyword() | map()) :: t()
  def new(opts) when is_list(opts), do: opts |> Map.new() |> new()

  def new(opts) when is_map(opts) do
    __MODULE__
    |> struct!(opts)
    |> apply_defaults()
    |> validate!()
  end

  # Defaults that cannot be static struct values (they call a function) or that
  # merge a host-supplied keyword list over the library's defaults.
  defp apply_defaults(%__MODULE__{} = config) do
    %{
      config
      | client_auth_signing_algs: config.client_auth_signing_algs || Attesto.SigningAlg.fapi_algs(),
        request_object_policy: config.request_object_policy || %Policy{},
        client_id_metadata: normalize_client_id_metadata(config.client_id_metadata),
        jwt_bearer: normalize_jwt_bearer(config.jwt_bearer)
    }
  end

  # The CIMD defaults the host's `:client_id_metadata` keyword list is merged
  # over (`draft-ietf-oauth-client-id-metadata-document-01` §9). The whole
  # feature is off by default; a host enables it with `enabled: true` and may
  # override any individual member. The merged list is what `client_id_metadata/1`
  # returns and what the resolver / discovery wiring read.
  @client_id_metadata_defaults [
    enabled: false,
    fetcher: Req,
    cache: AttestoPhoenix.ClientIdMetadata.Cache.Ecto,
    allow_loopback: false,
    max_document_bytes: 5_120,
    request_timeout_ms: 5_000,
    cache_ttl_bounds: {60, 86_400},
    require_same_origin_redirect_uri: true,
    allowed_hosts: nil,
    blocked_hosts: []
  ]

  defp normalize_client_id_metadata(nil), do: @client_id_metadata_defaults

  defp normalize_client_id_metadata(opts) when is_list(opts) do
    Keyword.merge(@client_id_metadata_defaults, opts)
  end

  # The Identity Assertion JWT Authorization Grant (ID-JAG / jwt-bearer)
  # defaults the host's `:jwt_bearer` keyword is merged over
  # (`draft-ietf-oauth-identity-assertion-authz-grant-04`). The whole feature is
  # off by default; a host enables it with `enabled: true` and a non-empty
  # `:issuers` map (or a `:jwks_resolver`). `:jwks_fetcher`/`:jwks_cache` are the
  # SSRF-guarded remote-JWKS seam (reused from CIMD) for any issuer configured by
  # `:jwks_uri`. The merged list is what `jwt_bearer/1` returns and what the
  # grant handler reads.
  @jwt_bearer_defaults [
    enabled: false,
    issuers: %{},
    assertion_max_lifetime_seconds: 300,
    jwks_resolver: nil,
    jwks_fetcher: Req,
    jwks_cache: AttestoPhoenix.ClientIdMetadata.Cache.Ecto,
    jwks_cache_ttl_bounds: {300, 86_400},
    fetch_opts: []
  ]

  defp normalize_jwt_bearer(nil), do: @jwt_bearer_defaults

  defp normalize_jwt_bearer(opts) when is_list(opts) do
    Keyword.merge(@jwt_bearer_defaults, opts)
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
  Returns the merged, defaulted Client ID Metadata Document (CIMD) options.

  This is the host's `:client_id_metadata` keyword list merged over the library
  defaults (`draft-ietf-oauth-client-id-metadata-document-01` §9), so every
  recognized member (`:enabled`, `:fetcher`, `:cache`, `:allow_loopback`,
  `:max_document_bytes`, `:request_timeout_ms`, `:cache_ttl_bounds`,
  `:require_same_origin_redirect_uri`, `:allowed_hosts`, `:blocked_hosts`) is
  always present. `AttestoPhoenix.ClientIdMetadata.Resolver` and the discovery
  wiring read the feature's configuration through this helper rather than
  reaching into the struct field directly.
  """
  @spec client_id_metadata(t()) :: keyword()
  def client_id_metadata(%__MODULE__{client_id_metadata: opts}), do: opts

  @doc """
  Returns `true` iff Client ID Metadata Document support is enabled.

  The feature is off unless the host sets `client_id_metadata: [enabled: true]`.
  Discovery advertises `client_id_metadata_document_supported` and the
  authorization endpoint resolves a CIMD `client_id` URL only when this is
  `true`.
  """
  @spec client_id_metadata_enabled?(t()) :: boolean()
  def client_id_metadata_enabled?(%__MODULE__{} = config) do
    config |> client_id_metadata() |> Keyword.get(:enabled, false) == true
  end

  @doc """
  Returns the merged, defaulted Identity Assertion JWT Authorization Grant
  (ID-JAG / `jwt-bearer`) options.

  This is the host's `:jwt_bearer` keyword merged over the library defaults
  (`draft-ietf-oauth-identity-assertion-authz-grant-04`), so every recognized
  member (`:enabled`, `:issuers`, `:assertion_max_lifetime_seconds`,
  `:jwks_resolver`, `:jwks_fetcher`, `:jwks_cache`, `:jwks_cache_ttl_bounds`,
  `:fetch_opts`) is always present.
  `AttestoPhoenix.AuthorizationServer.JwtBearer` reads the feature's
  configuration through this helper.
  """
  @spec jwt_bearer(t()) :: keyword()
  def jwt_bearer(%__MODULE__{jwt_bearer: opts}), do: opts

  @doc """
  Returns `true` iff the Identity Assertion JWT Authorization Grant (ID-JAG /
  `jwt-bearer`) is enabled.

  The feature is off unless the host sets `jwt_bearer: [enabled: true, ...]`.
  When enabled, `urn:ietf:params:oauth:grant-type:jwt-bearer` is added to
  `grant_types_supported/1` (so both discovery and the token endpoint honour it).
  """
  @spec jwt_bearer_enabled?(t()) :: boolean()
  def jwt_bearer_enabled?(%__MODULE__{} = config) do
    config |> jwt_bearer() |> Keyword.get(:enabled, false) == true
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
    # The resolved token path is passed automatically so the core builder's
    # `token_endpoint` (and the DPoP `htu` it derives) reflect where the host
    # mounted the endpoint, without the consumer hand-passing
    # `token_endpoint_path`. `extra` still wins (it is merged last) so a host
    # can override it explicitly if it must.
    [
      issuer: config.issuer,
      audience: config.audience,
      keystore: config.keystore,
      default_lifetime_seconds: config.access_token_ttl,
      token_endpoint_path: token_path(config)
    ]
    |> Keyword.merge(resolved_principal_kinds(config))
    |> Keyword.merge(extra)
    |> Attesto.Config.new()
  end

  # Resolve the host's `:principal_kinds` (a list or a callback returning one)
  # so to_attesto_config/1 yields a complete Attesto.Config for callers that do
  # not pass principal_kinds explicitly (e.g. the authorization endpoint signing
  # JARM responses). An explicit `extra` still wins. Omitted when unresolved so
  # Attesto.Config.new/1 surfaces the missing required value.
  defp resolved_principal_kinds(%__MODULE__{principal_kinds: principal_kinds}) do
    # Read the field directly: it is declared `[PrincipalKind.t()] | callback() |
    # nil`, so the list branch is reachable. (`config_callback/2` narrows its
    # return to `callback() | nil`, under which the `is_list` guard cannot hold.)
    case principal_kinds do
      kinds when is_list(kinds) and kinds != [] ->
        [principal_kinds: kinds]

      nil ->
        []

      callback ->
        case Callback.invoke(callback, []) do
          kinds when is_list(kinds) and kinds != [] -> [principal_kinds: kinds]
          _ -> []
        end
    end
  end

  # The default OAuth endpoint tails appended to the resolved
  # `:oauth_path_prefix` when no explicit per-endpoint override is set. These
  # reproduce the historic `/oauth/*` surface when the prefix is its default
  # `"/oauth"`.
  @authorize_tail "/authorize"
  @token_tail "/token"
  @par_tail "/par"
  @revocation_tail "/revoke"
  @introspection_tail "/introspect"
  @registration_tail "/register"
  @userinfo_tail "/userinfo"

  @doc false
  @spec authorize_tail() :: String.t()
  def authorize_tail, do: @authorize_tail

  @doc false
  @spec token_tail() :: String.t()
  def token_tail, do: @token_tail

  @doc false
  @spec par_tail() :: String.t()
  def par_tail, do: @par_tail

  @doc false
  @spec revocation_tail() :: String.t()
  def revocation_tail, do: @revocation_tail

  @doc false
  @spec introspection_tail() :: String.t()
  def introspection_tail, do: @introspection_tail

  @doc false
  @spec registration_tail() :: String.t()
  def registration_tail, do: @registration_tail

  @doc false
  @spec userinfo_tail() :: String.t()
  def userinfo_tail, do: @userinfo_tail

  @doc """
  The resolved request path of the authorization endpoint: the explicit
  `:authorize_path` override when set, otherwise `:oauth_path_prefix` joined
  with the conventional `#{@authorize_tail}` tail.
  """
  @spec authorize_path(t()) :: String.t()
  def authorize_path(%__MODULE__{authorize_path: override} = config),
    do: resolve_path(override, config, @authorize_tail)

  @doc """
  The resolved request path of the token endpoint. See `authorize_path/1`.
  """
  @spec token_path(t()) :: String.t()
  def token_path(%__MODULE__{token_path: override} = config), do: resolve_path(override, config, @token_tail)

  @doc """
  The resolved request path of the pushed-authorization-request endpoint
  (RFC 9126). See `authorize_path/1`.
  """
  @spec par_path(t()) :: String.t()
  def par_path(%__MODULE__{par_path: override} = config), do: resolve_path(override, config, @par_tail)

  @doc """
  The resolved request path of the revocation endpoint (RFC 7009). See
  `authorize_path/1`.
  """
  @spec revocation_path(t()) :: String.t()
  def revocation_path(%__MODULE__{revocation_path: override} = config),
    do: resolve_path(override, config, @revocation_tail)

  @doc """
  The resolved request path of the token introspection endpoint (RFC 7662). See
  `authorize_path/1`.
  """
  @spec introspection_path(t()) :: String.t()
  def introspection_path(%__MODULE__{introspection_path: override} = config),
    do: resolve_path(override, config, @introspection_tail)

  @doc """
  The resolved request path of the dynamic client registration endpoint
  (RFC 7591). See `authorize_path/1`.
  """
  @spec registration_path(t()) :: String.t()
  def registration_path(%__MODULE__{registration_path: override} = config),
    do: resolve_path(override, config, @registration_tail)

  @doc """
  The resolved request path of the UserInfo endpoint (OpenID Connect Core
  §5.3). See `authorize_path/1`.
  """
  @spec userinfo_path(t()) :: String.t()
  def userinfo_path(%__MODULE__{userinfo_path: override} = config), do: resolve_path(override, config, @userinfo_tail)

  # An explicit per-endpoint override wins over the prefix; otherwise the
  # endpoint path is the prefix joined with the conventional tail. The prefix
  # default `"/oauth"` reproduces the historic surface.
  defp resolve_path(override, _config, _tail) when is_binary(override) and override != "", do: override

  defp resolve_path(_override, %__MODULE__{oauth_path_prefix: prefix}, tail), do: join_path(prefix, tail)

  # Join a prefix and a tail into a single absolute path, collapsing the seam so
  # neither a trailing slash on the prefix nor the leading slash on the tail
  # doubles up.
  defp join_path(prefix, tail) do
    prefix = String.trim_trailing(to_string(prefix), "/")
    tail = "/" <> String.trim_leading(tail, "/")
    prefix <> tail
  end

  @doc """
  Absolute URL of the authorization endpoint: the issuer merged with
  `authorize_path/1`. Advertised in the OpenID Provider Metadata when the host
  does not supply a separate `:authorization_endpoint`.
  """
  @spec authorize_endpoint_url(t()) :: String.t()
  def authorize_endpoint_url(%__MODULE__{} = config), do: endpoint_url(config, authorize_path(config))

  @doc """
  Absolute URL of the token endpoint: the issuer merged with `token_path/1`.
  Advertised as `token_endpoint` (RFC 8414 §2).
  """
  @spec token_endpoint_url(t()) :: String.t()
  def token_endpoint_url(%__MODULE__{} = config), do: endpoint_url(config, token_path(config))

  @doc """
  Absolute URL of the pushed-authorization-request endpoint: the issuer merged
  with `par_path/1`. Advertised as `pushed_authorization_request_endpoint`
  (RFC 9126 §5).
  """
  @spec par_endpoint_url(t()) :: String.t()
  def par_endpoint_url(%__MODULE__{} = config), do: endpoint_url(config, par_path(config))

  @doc """
  Absolute URL of the revocation endpoint: the issuer merged with
  `revocation_path/1`. Advertised as `revocation_endpoint` (RFC 8414 §2,
  RFC 7009).
  """
  @spec revocation_endpoint_url(t()) :: String.t()
  def revocation_endpoint_url(%__MODULE__{} = config), do: endpoint_url(config, revocation_path(config))

  @doc """
  Absolute URL of the token introspection endpoint (RFC 7662): the issuer merged
  with `introspection_path/1`. Advertised as `introspection_endpoint`.
  """
  @spec introspection_endpoint_url(t()) :: String.t()
  def introspection_endpoint_url(%__MODULE__{} = config), do: endpoint_url(config, introspection_path(config))

  # Every grant type the token endpoint implements: RFC 6749 authorization_code /
  # refresh_token / client_credentials and RFC 8693 token-exchange. This is the
  # default advertised + accepted set; `:grant_types_supported` narrows it.
  @default_grant_types_supported [
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "urn:ietf:params:oauth:grant-type:token-exchange"
  ]

  @doc """
  The grant types the authorization server supports.

  Advertised as `grant_types_supported` (RFC 8414 §2) by both discovery documents
  and enforced by the token endpoint — a `grant_type` outside this set is rejected
  as `unsupported_grant_type` before dispatch. Defaults to every grant the token
  endpoint implements (#{inspect(@default_grant_types_supported)}); configure
  `:grant_types_supported` to narrow it, e.g. drop
  `urn:ietf:params:oauth:grant-type:token-exchange` to disable token exchange
  across discovery, the token endpoint, and dynamic registration at once.
  """
  # RFC 7523 §4 / draft-ietf-oauth-identity-assertion-authz-grant-04: the ID-JAG
  # JWT-bearer authorization grant, advertised + accepted only when the feature
  # is enabled (`jwt_bearer: [enabled: true]`).
  @grant_jwt_bearer "urn:ietf:params:oauth:grant-type:jwt-bearer"

  @spec grant_types_supported(t()) :: [String.t()]
  def grant_types_supported(%__MODULE__{grant_types_supported: list} = config) when is_list(list) and list != [],
    do: maybe_add_jwt_bearer(list, config)

  def grant_types_supported(%__MODULE__{} = config), do: maybe_add_jwt_bearer(@default_grant_types_supported, config)

  defp maybe_add_jwt_bearer(list, %__MODULE__{} = config) do
    if jwt_bearer_enabled?(config) and @grant_jwt_bearer not in list,
      do: list ++ [@grant_jwt_bearer],
      else: list
  end

  @doc """
  Absolute URL of the dynamic client registration endpoint: the issuer merged
  with `registration_path/1`. Advertised as `registration_endpoint` (RFC 7591
  §3) only when registration is enabled.
  """
  @spec registration_endpoint_url(t()) :: String.t()
  def registration_endpoint_url(%__MODULE__{} = config), do: endpoint_url(config, registration_path(config))

  @doc """
  Absolute URL of the UserInfo endpoint: the issuer merged with
  `userinfo_path/1`. Used when the host does not supply a separate
  `:userinfo_endpoint`.
  """
  @spec userinfo_endpoint_url(t()) :: String.t()
  def userinfo_endpoint_url(%__MODULE__{} = config), do: endpoint_url(config, userinfo_path(config))

  @doc """
  Absolute URL of an individual registered client's RFC 7592 management
  endpoint: the registration endpoint URL with the URL-encoded `client_id`
  appended. Returned as `registration_client_uri` in the RFC 7591 §3.2.1
  client information response.
  """
  @spec registration_client_uri(t(), String.t()) :: String.t()
  def registration_client_uri(%__MODULE__{} = config, client_id) when is_binary(client_id) do
    encoded = URI.encode(client_id, &URI.char_unreserved?/1)
    endpoint_url(config, join_path(registration_path(config), encoded))
  end

  @doc """
  Absolute URL of the JWK Set document (RFC 7517 §5; the `jwks_uri` per
  RFC 8414 §2). The JWKS document is anchored at the host root under RFC 8615,
  so it is NOT relocated by `:oauth_path_prefix`.
  """
  @spec jwks_uri(t()) :: String.t()
  def jwks_uri(%__MODULE__{} = config), do: endpoint_url(config, "/.well-known/jwks.json")

  defp endpoint_url(%__MODULE__{issuer: issuer}, path) do
    issuer
    |> URI.parse()
    |> URI.merge(path)
    |> URI.to_string()
  end

  # ── Behaviour-module callback resolution ─────────────────────────────────

  # The resolution table. Each flat callback key maps to the behaviour-module
  # Config key that owns it and the `{function, arity}` that module must export
  # for the `{module, function}` form to win. The precedence is fixed: an
  # explicit flat key wins; else the installed behaviour module if it exports
  # the callback; else `nil`. The arity is the behaviour callback's arity, used
  # only for the `function_exported?` conformance check - the resolved value is
  # the bare `{module, function}` pair, invoked by the caller through
  # `AttestoPhoenix.Callback.invoke/2,3` (which appends the per-call args).
  #
  # `:registration` carries the optional management callbacks too, so a host
  # that installs a single registration module gets RFC 7592 management for
  # free; the required `register_client/1` stays a flat-only required key.
  @resolution %{
    load_client: {:client_store, :load_client, 1},
    verify_client_secret: {:client_store, :verify_client_secret, 2},
    client_id: {:client_store, :client_id, 1},
    client_jwks: {:client_store, :client_jwks, 1},
    client_redirect_uris: {:client_store, :client_redirect_uris, 1},
    client_public?: {:client_store, :client_public?, 1},
    client_requires_mtls?: {:client_store, :client_requires_mtls?, 1},
    client_requires_dpop?: {:client_store, :client_requires_dpop?, 1},
    client_grant_types: {:client_store, :client_grant_types, 1},
    load_principal: {:principal_store, :load_principal, 1},
    build_principal: {:principal_store, :build_principal, 3},
    resolve_jwt_bearer_subject: {:principal_store, :resolve_jwt_bearer_subject, 1},
    authenticate_resource_owner: {:consent_policy, :authenticate_resource_owner, 3},
    consent: {:consent_policy, :consent, 3},
    authorize_scope: {:scope_policy, :authorize_scope, 2},
    on_event: {:event_sink, :on_event, 1},
    register_client: {:registration, :register_client, 1},
    unregister_client: {:registration, :unregister_client, 1},
    client_registration_access_token_hash: {:registration, :client_registration_access_token_hash, 1},
    build_userinfo_claims: {:claims_provider, :build_userinfo_claims, 3},
    build_id_token_claims: {:claims_provider, :build_id_token_claims, 4}
  }

  # The behaviour-module Config keys, each paired with the behaviour module it
  # is expected to implement. Used for boot-time conformance validation.
  @behaviour_modules %{
    client_store: AttestoPhoenix.ClientStore,
    principal_store: AttestoPhoenix.PrincipalStore,
    consent_policy: AttestoPhoenix.ConsentPolicy,
    scope_policy: AttestoPhoenix.ScopePolicy,
    event_sink: AttestoPhoenix.EventSink,
    registration: AttestoPhoenix.RegistrationStore,
    claims_provider: AttestoPhoenix.ClaimsProvider
  }

  @doc """
  Resolve a configured callback by its flat `key`.

  Precedence (see the "Behaviour-module Config keys" section): the explicit
  flat key wins when set; otherwise the installed behaviour module wins when it
  exports the corresponding behaviour callback; otherwise `nil`. The result is a
  value an `AttestoPhoenix.Callback.invoke/2,3` caller can run (an anonymous
  function, a `{module, function}` pair, a `{module, function, extra_args}`
  triple), or `nil`.
  """
  @spec resolve_callback(t(), atom()) :: callback() | nil
  def resolve_callback(%__MODULE__{} = config, key) when is_atom(key) do
    case Map.get(config, key) do
      nil -> resolve_from_store(config, key)
      flat -> flat
    end
  end

  defp resolve_from_store(%__MODULE__{} = config, key) do
    with {store_key, fun, arity} <- Map.get(@resolution, key),
         module when is_atom(module) and not is_nil(module) <- Map.get(config, store_key),
         true <- callback_exported?(module, fun, arity) do
      {module, fun}
    else
      _ -> nil
    end
  end

  defp callback_exported?(module, fun, arity) do
    Code.ensure_loaded?(module) and function_exported?(module, fun, arity)
  end

  # One resolver fun per flat callback key. Each is a thin alias over
  # `resolve_callback/2` so consumers read the callback by name without knowing
  # the resolution table, matching the integrator's "resolver funs on Config"
  # surface. They return the same `callback()`-or-`nil` value.
  for {key, _} <- @resolution do
    name = key |> Atom.to_string() |> String.trim_trailing("?") |> Kernel.<>("_fun")
    name = String.to_atom(name)

    @doc """
    Resolve the `#{key}` callback. See `resolve_callback/2`.
    """
    @spec unquote(name)(t()) :: callback() | nil
    def unquote(name)(%__MODULE__{} = config), do: resolve_callback(config, unquote(key))
  end

  @doc """
  Resolve and load the host's client by `client_id` (RFC 6749 §2.2).

  A required callback (`:load_client` / `AttestoPhoenix.ClientStore`); this
  helper invokes the resolved callback so consumers do not re-derive it.
  """
  @spec client_store_load(t(), String.t()) :: term()
  def client_store_load(%__MODULE__{} = config, client_id), do: Callback.invoke(load_client_fun(config), [client_id])

  @doc """
  Resolve and run the host's constant-time client-secret verification
  (RFC 6749 §2.3.1) for `client`/`presented_secret`.
  """
  @spec client_store_verify_secret(t(), term(), String.t()) :: boolean()
  def client_store_verify_secret(%__MODULE__{} = config, client, presented_secret),
    do: Callback.invoke(verify_client_secret_fun(config), [client, presented_secret]) == true

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
  def build_userinfo_claims(%__MODULE__{} = config, subject, scopes, requested) do
    case build_userinfo_claims_fun(config) do
      nil ->
        raise ArgumentError,
              "AttestoPhoenix.Config: :build_userinfo_claims is required to serve the UserInfo endpoint"

      callback ->
        Callback.invoke(callback, [subject, scopes, requested])
    end
  end

  # draft-ietf-oauth-identity-assertion-authz-grant-04: when the jwt-bearer grant
  # is enabled the host MUST configure both how to TRUST an assertion (a
  # non-empty `:issuers` map, or a custom `:jwks_resolver`) and how to RESOLVE its
  # subject to a local principal (`:resolve_jwt_bearer_subject`). Fail closed at
  # boot rather than reject every assertion at runtime. (`jti` replay reuses the
  # configured `:replay_check`, falling back to the bundled ETS cache like DPoP.)
  defp validate_jwt_bearer!(%__MODULE__{} = config) do
    if jwt_bearer_enabled?(config) do
      opts = jwt_bearer(config)
      issuers = Keyword.get(opts, :issuers, %{})

      if (not is_map(issuers) or map_size(issuers) == 0) and is_nil(Keyword.get(opts, :jwks_resolver)) do
        raise ArgumentError,
              "AttestoPhoenix.Config: jwt_bearer requires a non-empty :issuers map " <>
                "(issuer => [jwks: ... | jwks_uri: ...]) or a :jwks_resolver function " <>
                "when :enabled is true, or set jwt_bearer: [enabled: false]."
      end

      if is_nil(resolve_jwt_bearer_subject_fun(config)) do
        raise ArgumentError,
              "AttestoPhoenix.Config: :resolve_jwt_bearer_subject is required when the " <>
                "jwt_bearer grant is enabled. Add a " <>
                "`resolve_jwt_bearer_subject: &MyApp.AuthZ.resolve_jwt_bearer_subject/1` " <>
                "callback (or a :principal_store module implementing " <>
                "resolve_jwt_bearer_subject/1) so the asserted subject maps to a local " <>
                "principal."
      end
    end

    :ok
  end

  defp validate!(%__MODULE__{} = config) do
    Enum.each(@required, fn key ->
      if is_nil(Map.fetch!(config, key)) do
        raise ArgumentError,
              "AttestoPhoenix.Config: required key #{inspect(key)} is missing. " <>
                required_key_hint(key)
      end
    end)

    # Required capabilities are validated by RESOLUTION, not flat-key presence,
    # so installing a behaviour module (`:client_store`/`:principal_store`)
    # satisfies them just as a flat callback does.
    Enum.each(@required_capabilities, fn capability ->
      if is_nil(resolve_callback(config, capability)) do
        raise ArgumentError, required_capability_hint(capability)
      end
    end)

    if config.mtls_enabled and is_nil(config.cert_der) do
      raise ArgumentError,
            "AttestoPhoenix.Config: :cert_der is required when :mtls_enabled is true. " <>
              "Add a `cert_der: &MyApp.AuthZ.cert_der/1` callback " <>
              "(implements AttestoPhoenix.ClientStore-adjacent mTLS extraction) " <>
              "or set `mtls_enabled: false`."
    end

    if config.registration_enabled and is_nil(register_client_fun(config)) do
      raise ArgumentError,
            "AttestoPhoenix.Config: :register_client is required when " <>
              ":registration_enabled is true. Add a " <>
              "`register_client: &MyApp.AuthZ.register_client/1` callback " <>
              "(or install a `:registration` module implementing " <>
              "AttestoPhoenix.RegistrationStore) or set " <>
              "`registration_enabled: false` so no registration endpoint is mounted."
    end

    validate_jwt_bearer!(config)
    validate_behaviour_modules!(config)
    validate_request_object_policy!(config)

    validate_path!(:oauth_path_prefix, config.oauth_path_prefix)
    validate_optional_path!(:authorize_path, config.authorize_path)
    validate_optional_path!(:token_path, config.token_path)
    validate_optional_path!(:par_path, config.par_path)
    validate_optional_path!(:revocation_path, config.revocation_path)
    validate_optional_path!(:registration_path, config.registration_path)
    validate_optional_path!(:userinfo_path, config.userinfo_path)

    validate_discovery_endpoints!(config)
    validate_advertised_paths_consistent!(config)

    config
  end

  # ── Boot-time discovery-document safety guard ────────────────────────────
  #
  # A discovery document that omits a required endpoint - or advertises an
  # endpoint at a path the router does not mount - is a "silent" failure: the
  # document still serializes and is served 200, but a conformant client reading
  # it (RFC 8414 §2 for the OAuth metadata, OpenID Connect Discovery §3 for the
  # OpenID configuration) is misdirected to a missing or wrong endpoint and the
  # flow breaks with no error on the server. The motivating regression: the
  # RFC 8414 document once omitted `authorization_endpoint` (RFC 8414 §2 REQUIRES
  # it for the authorization-code flow) because the controller never supplied it,
  # so an OAuth client that reads RFC 8414 rather than OpenID Discovery (the
  # ChatGPT MCP connector) got a document missing a required endpoint. The two
  # checks below promote that class of failure from "ships a broken document" to
  # "fails fast at boot", matching how the required-key validation above already
  # fails `new/1` with an `ArgumentError`.

  # The discovery endpoints this library is responsible for deriving and that a
  # conformant authorization-code / OpenID Provider discovery document MUST carry
  # (RFC 8414 §2: `issuer`, `authorization_endpoint`, `token_endpoint`,
  # `jwks_uri`; OpenID Connect Discovery §3 requires the same set). Each entry is
  # `{member_name, resolver}` where the resolver derives the advertised value
  # from this config; the library owns every one of them (they are derived from
  # `:issuer` and the resolved endpoint paths), so every one MUST resolve to a
  # non-nil absolute https/http URL or the document would silently omit or
  # mis-advertise a required member.
  @required_discovery_endpoints [
    {"issuer", &__MODULE__.issuer/1},
    {"authorization_endpoint", &__MODULE__.authorize_endpoint_url/1},
    {"token_endpoint", &__MODULE__.token_endpoint_url/1},
    {"jwks_uri", &__MODULE__.jwks_uri/1}
  ]

  @doc false
  @spec issuer(t()) :: String.t() | nil
  def issuer(%__MODULE__{issuer: issuer}), do: issuer

  # Check #1: every required discovery endpoint must resolve to a non-nil
  # absolute URL. Because all of them are derived from `:issuer` (directly, or
  # via `URI.merge/2` with a resolved path), the realistic failure mode is an
  # `:issuer` that is not an absolute URL with a scheme and host (e.g.
  # `"issuer.example"` or `"/oauth"`): `URI.merge/2` then yields a path-only,
  # host-less endpoint URL, and the discovery document advertises an endpoint a
  # client cannot resolve. Validating the derived URLs (not just `:issuer`) also
  # guards against any future regression where a resolver returns nil/empty.
  defp validate_discovery_endpoints!(%__MODULE__{} = config) do
    Enum.each(@required_discovery_endpoints, fn {member, resolver} ->
      url = resolver.(config)

      if not absolute_url?(url) do
        raise ArgumentError,
              "AttestoPhoenix.Config: the discovery document would advertise a missing " <>
                "or non-absolute #{member} (#{inspect(url)}). RFC 8414 §2 / OpenID Connect " <>
                "Discovery §3 require #{member} to be an absolute URL. This is almost always " <>
                "an :issuer that is not an absolute https URL (got #{inspect(config.issuer)}); " <>
                "set :issuer to the full origin, e.g. \"https://api.example\"."
      end
    end)
  end

  # An absolute URL for discovery purposes has both a scheme and a host. A
  # path-only string (what `URI.merge/2` yields from a scheme-less issuer) has a
  # nil host and is rejected.
  defp absolute_url?(value) when is_binary(value) and value != "" do
    case URI.parse(value) do
      %URI{scheme: scheme, host: host} when is_binary(scheme) and is_binary(host) and host != "" -> true
      _ -> false
    end
  end

  defp absolute_url?(_), do: false

  # The OAuth endpoint members whose advertised path the router mounts, paired
  # with the resolver that yields the advertised path and the canonical tail the
  # router appends under its own `/oauth` mount prefix. The well-known documents
  # and `jwks_uri` are anchored at the host root (RFC 8615) and are NOT relocated
  # by `:oauth_path_prefix`, so they are not in this set. The authorization
  # endpoint is excluded because the host MAY serve it off-server via the
  # `:authorization_endpoint` absolute-URL override (it runs the host login UI),
  # which the router does not mount.
  @mounted_oauth_endpoints [
    {:token_path, &__MODULE__.token_path/1, @token_tail},
    {:par_path, &__MODULE__.par_path/1, @par_tail},
    {:revocation_path, &__MODULE__.revocation_path/1, @revocation_tail},
    {:introspection_path, &__MODULE__.introspection_path/1, @introspection_tail},
    {:registration_path, &__MODULE__.registration_path/1, @registration_tail},
    {:userinfo_path, &__MODULE__.userinfo_path/1, @userinfo_tail}
  ]

  # Check #2: detect an `:oauth_path_prefix` vs explicit-override mismatch that
  # the router provably cannot serve.
  #
  # The router macro (`AttestoPhoenix.Router.attesto_routes/1`) mounts EVERY
  # OAuth endpoint at a single shared prefix - a compile-time `"/oauth" <> tail`
  # joined under the macro's own `:prefix` option - so the mounted routes always
  # share one common mount tree and each ends in its canonical tail. The router's
  # macro `:prefix` is invisible at config-build time, so a full
  # advertised-vs-mounted cross-check is impossible here (the override could be
  # exactly where the host mounted the route by hand). What IS provable is the
  # discovery document's INTERNAL consistency: the host having committed to a
  # non-default `:oauth_path_prefix` (a deliberate "all my OAuth endpoints live
  # under this prefix" statement) AND then advertising one endpoint OUTSIDE that
  # prefix via an explicit per-endpoint override.
  #
  # We deliberately scope the check to a NON-DEFAULT `:oauth_path_prefix`. A
  # per-endpoint override is a documented, legitimate feature (the integrator's
  # "explicit endpoint overrides plus sane defaults"); flagging every override
  # would break that contract and contradict "do not invent constraints". But
  # once a host sets a custom prefix, an override that does not sit under it is
  # the precise silent mismatch a downstream consumer hit: discovery advertises
  # that endpoint under a different prefix than its siblings (and than the prefix
  # the host declared), while the router mounts them all together, so a client is
  # misdirected to a route that is not served. That divergence is provable from
  # the config alone, so we raise.
  @default_oauth_path_prefix "/oauth"

  defp validate_advertised_paths_consistent!(%__MODULE__{oauth_path_prefix: @default_oauth_path_prefix}), do: :ok

  defp validate_advertised_paths_consistent!(%__MODULE__{} = config) do
    prefix = String.trim_trailing(to_string(config.oauth_path_prefix), "/")

    Enum.each(@mounted_oauth_endpoints, fn {key, resolver, tail} ->
      path = resolver.(config)
      derived = join_path(config.oauth_path_prefix, tail)

      # Consistent iff the advertised path is the prefix-derived path, or at
      # least sits under the declared prefix (an override that merely renames the
      # tail but keeps the prefix is still mounted under the same tree). A path
      # that leaves the prefix entirely is the provable divergence.
      under_prefix? = path == derived or String.starts_with?(path, prefix <> "/")

      if not under_prefix? do
        raise ArgumentError,
              "AttestoPhoenix.Config: #{inspect(key)} advertises #{inspect(path)}, which sits " <>
                "outside the configured :oauth_path_prefix #{inspect(config.oauth_path_prefix)} " <>
                "(the prefix-derived path is #{inspect(derived)}). The router mounts every OAuth " <>
                "endpoint under one shared prefix, so an override that leaves that tree is " <>
                "advertised at a path the router does not serve - the exact silent discovery " <>
                "mismatch this guard prevents. Either drop the #{inspect(key)} override so the " <>
                "endpoint derives from :oauth_path_prefix, or set :oauth_path_prefix to the prefix " <>
                "you actually mount the routes under (and mount via `attesto_routes(prefix: ...)`)."
      end
    end)
  end

  # The required (non-optional) behaviour callbacks each installed
  # behaviour-module Config key must export. A module installed under the key
  # must be loadable and export every `{function, arity}` here, so a typo'd or
  # partial module fails fast at boot rather than silently resolving to `nil`
  # at request time. Optional behaviour callbacks are not listed: a module may
  # omit them and the resolver falls through to `nil` (the consumer's
  # fail-closed default), so they are not boot errors.
  @behaviour_required %{
    client_store: [load_client: 1, verify_client_secret: 2],
    principal_store: [load_principal: 1],
    consent_policy: [],
    scope_policy: [authorize_scope: 2],
    event_sink: [on_event: 1],
    registration: [register_client: 1],
    claims_provider: []
  }

  # Boot-time conformance: every installed behaviour module must be loadable and
  # must export the required callbacks of the behaviour it is installed as.
  # `:request_object_policy` is a security knob; reject a wrong value at boot
  # rather than crashing later in `RequestObject.Policy.to_verify_opts/1` when a
  # PAR or /authorize request is verified. `apply_defaults/1` has already
  # replaced a `nil` with `%Attesto.RequestObject.Policy{}`.
  defp validate_request_object_policy!(%__MODULE__{request_object_policy: %Policy{} = policy} = config) do
    # A policy that REQUIRES a signed request object (FAPI 2.0 Message Signing
    # §5.3.1) is unsatisfiable without a way to resolve the client's trusted
    # JWKS: every authorization request would be rejected (one carrying no
    # request object fails the policy; one carrying a request object fails
    # verification for want of keys). Fail fast at boot rather than deploy an OP
    # that rejects every request - and that would otherwise advertise the
    # incoherent pair `request_parameter_supported: false` +
    # `require_signed_request_object: true`.
    if Policy.require_request_object?(policy) and
         is_nil(client_jwks_fun(config)) do
      raise ArgumentError,
            "AttestoPhoenix.Config: a :request_object_policy that requires a signed " <>
              "request object (e.g. Attesto.RequestObject.Policy.fapi_message_signing/0) " <>
              "needs a way to resolve a client's trusted JWKS to verify it. Add a " <>
              "`client_jwks: &MyApp.AuthZ.client_jwks/1` callback (or install a " <>
              ":client_store module implementing AttestoPhoenix.ClientStore.client_jwks/1), " <>
              "or relax the policy (Attesto.RequestObject.Policy.generic/0)."
    end

    :ok
  end

  defp validate_request_object_policy!(%__MODULE__{request_object_policy: other}) do
    raise ArgumentError,
          "AttestoPhoenix.Config: :request_object_policy must be an " <>
            "%Attesto.RequestObject.Policy{} (e.g. " <>
            "Attesto.RequestObject.Policy.fapi_message_signing/0); got #{inspect(other)}."
  end

  defp validate_behaviour_modules!(%__MODULE__{} = config) do
    Enum.each(@behaviour_modules, fn {store_key, behaviour} ->
      case Map.get(config, store_key) do
        nil -> :ok
        module -> validate_behaviour_module!(store_key, behaviour, module, config)
      end
    end)
  end

  defp validate_behaviour_module!(store_key, behaviour, module, _config) when is_atom(module) do
    if !Code.ensure_loaded?(module) do
      raise ArgumentError,
            "AttestoPhoenix.Config: #{inspect(store_key)} is set to #{inspect(module)}, " <>
              "which cannot be loaded. Set it to a module implementing " <>
              "#{inspect(behaviour)}."
    end

    Enum.each(Map.fetch!(@behaviour_required, store_key), fn {fun, arity} ->
      if !function_exported?(module, fun, arity) do
        raise ArgumentError,
              "AttestoPhoenix.Config: #{inspect(store_key)} module #{inspect(module)} " <>
                "does not export #{fun}/#{arity}, required by #{inspect(behaviour)}."
      end
    end)
  end

  defp validate_behaviour_module!(store_key, behaviour, module, _config) do
    raise ArgumentError,
          "AttestoPhoenix.Config: #{inspect(store_key)} must be a module implementing " <>
            "#{inspect(behaviour)}; got #{inspect(module)}."
  end

  # The store/callback each required key installs, so a missing-key error tells
  # the host exactly what to wire rather than just naming the key.
  defp required_key_hint(:issuer), do: "Set it to the https issuer URL (RFC 8414 §2), e.g. \"https://api.example\"."

  defp required_key_hint(:keystore), do: "Set it to a module implementing the Attesto.Keystore behaviour."

  defp required_key_hint(:repo), do: "Set it to your Ecto.Repo module."

  defp required_key_hint(_key), do: ""

  # A required capability is unresolved when neither the flat callback nor an
  # installed behaviour module provides it. Name BOTH install routes so the host
  # knows it can wire a flat callback OR install the owning behaviour module.
  defp required_capability_hint(capability) do
    {store_key, fun, arity} = Map.fetch!(@resolution, capability)
    behaviour = Map.fetch!(@behaviour_modules, store_key)

    "AttestoPhoenix.Config: the #{inspect(capability)} capability is required but " <>
      "unresolved. Provide it either as a flat callback " <>
      "(`#{capability}: &MyApp.AuthZ.#{fun}/#{arity}`) or by installing a " <>
      "`#{inspect(store_key)}` module implementing #{inspect(behaviour)} " <>
      "(which exports #{fun}/#{arity})."
  end

  # `:oauth_path_prefix` is always present (defaulted); it must be an absolute
  # path reference so it merges cleanly onto the issuer.
  defp validate_path!(key, value) do
    if not (is_binary(value) and String.starts_with?(value, "/")) do
      raise ArgumentError,
            "AttestoPhoenix.Config: #{inspect(key)} must be an absolute path " <>
              "beginning with \"/\" (e.g. \"/oauth\" or \"/mcp/oauth\"); got #{inspect(value)}"
    end
  end

  # A per-endpoint override is optional (nil = derive from the prefix); when
  # set it must be an absolute path reference.
  defp validate_optional_path!(_key, nil), do: :ok
  defp validate_optional_path!(key, value), do: validate_path!(key, value)
end
