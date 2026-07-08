# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-07-08

### Added

- **OpenID Connect CIBA (Client-Initiated Backchannel Authentication) — the
  Phoenix layer.** The backchannel authentication endpoint (`/bc-authorize`),
  poll and ping token delivery, the §10.2 ping notification deliverer, and an
  Ecto-backed CIBA request store. Certified **FAPI-CIBA ID1** in both **poll**
  and **ping** delivery modes.
- **Local HTTPS for development.** `AttestoPhoenix.DevTLS.https_opts/1` wires a
  mkcert certificate into a Phoenix dev endpoint in one line, and
  `mix attesto_phoenix.gen.dev_https` generates it — so an app can develop
  against attesto's required `https` issuer with no tunnel and no downgrade. New
  `guides/local_https.md`; the installer points at it.

### Changed

- Discovery advertises `tls_client_certificate_bound_access_tokens` when mTLS is
  enabled (RFC 8705 §3.3).
- The token endpoint and the CIBA backchannel endpoint accept the issuer
  identifier, the token-endpoint URL, **or** the endpoint's own URL as a
  `private_key_jwt` client-assertion audience (RFC 7523 §3).
- The CIBA `client_notification_token` is stored as `:text` (CIBA §7.3 sets no
  length bound); requires a fresh migration via `mix attesto_phoenix.gen.migration`.
- The CIBA ping notification channel offers TLS 1.3 (FAPI transport).

### Fixed

- The UserInfo endpoint now adapts a `{module, function}` `:cert_der` callback to
  the bare function `Attesto.Plug.Authenticate` requires, so mTLS
  certificate-bound tokens are correctly enforced at the resource server (a
  presented certificate that does not match the token's `cnf.x5t#S256` is
  rejected).

## [1.1.0] - 2026-07-07

### Added

- **OpenID Connect Front-Channel Logout 1.0 (OP side).**
  - The end-session endpoint renders every front-channel-capable RP's
    registered `frontchannel_logout_uri` in a hidden iframe on the logout page
    (with `iss`/`sid` whenever the session's `sid` is known), then completes
    the RP-Initiated flow from the page itself: with a validated
    `post_logout_redirect_uri` it continues there once the iframes have loaded
    (JavaScript with a bounded timeout, plus a meta-refresh and a visible link
    as no-JS fallbacks); with no return URI the page is the logged-out page.
    The iframes and the back-channel `logout_token` POSTs are driven by the
    same atomically-taken logout-session rows, so a session is fanned out
    exactly once. A non-browser caller cannot run iframes, so front-channel
    targets are skipped (logged) and the response is unchanged.
  - The token endpoint records a logout session at ID-Token mint for any
    client that registered a `frontchannel_logout_uri` and/or a
    `backchannel_logout_uri` (previously back-channel only).
    `AttestoPhoenix.Schema.LogoutSession` / `EctoLogoutSessionStore` carry the
    new `frontchannel_logout_uri` / `frontchannel_session_required` columns,
    `backchannel_logout_uri` is now nullable, and the migration template
    reflects the new shape.
  - Client registry: new `:client_frontchannel_logout_uri` /
    `:client_frontchannel_logout_session_required` Config callbacks (and
    optional `AttestoPhoenix.ClientStore` callbacks). A non-`https`
    `frontchannel_logout_uri` is treated as absent (browsers block it as
    mixed content on the https logout page), a deliberate tightening of the
    spec's http-for-confidential-clients allowance.
  - Dynamic registration passes `frontchannel_logout_uri` (string) and
    `frontchannel_logout_session_required` (boolean) through to the host
    store (Front-Channel Logout 1.0 §2).
  - Discovery advertises `frontchannel_logout_supported` /
    `frontchannel_logout_session_supported` when logout is enabled and a
    `:logout_session_store` is wired.
- **OpenID Connect Session Management 1.0 (OP side).**
  - `session_management: [enabled: true]` turns the feature on;
    `attesto_routes(session_management: true)` mounts
    `GET /oauth/check_session`, the §3.3 `check_session_iframe` served by the
    new `AttestoPhoenix.Controller.CheckSessionController` (a static page
    whose script recomputes `session_state` with `crypto.subtle` from the
    message's `client_id`, the sender's `MessageEvent.origin`, the OP
    browser-state cookie, and the received salt, replying
    `unchanged`/`changed`/`error`).
  - Successful authorization responses carry the §2 `session_state`
    parameter, computed by `Attesto.SessionState` over the `redirect_uri`'s
    browser origin. (Deliberate deviation: the SHOULD-level `session_state` on
    authorization **error** responses is not emitted.)
  - `AttestoPhoenix.BrowserState` owns the JavaScript-readable OP
    browser-state cookie (`SameSite=None; Secure`, not `HttpOnly`): minted at
    the authorization endpoint when absent (login), expired at the
    end-session endpoint (logout), so a post-logout recomputation yields
    `changed`.
  - Discovery advertises `check_session_iframe` when the feature is enabled.

## [1.0.0] - 2026-07-04

First stable release; the public API is now under semantic versioning. No
functional change from 0.20.0. Requires `attesto ~> 1.0`.

The Phoenix/Ecto authorization-server layer drives an OpenID Provider that
passes the OpenID Foundation conformance suite for OpenID Connect Core (Basic),
FAPI 2.0 Security Profile Final, FAPI 2.0 Message Signing Final, RP-Initiated
Logout, and Back-Channel Logout.

## [0.20.0] - 2026-07-01

### Changed

- **End-session endpoint now content-negotiates its responses.** The
  browser-facing `/oauth/end_session` errors (`invalid post_logout_redirect_uri`,
  `invalid id_token_hint`, ...) and the default logged-out response rendered
  JSON to every caller; a browser (`Accept: text/html`) now gets a minimal
  human-readable HTML page instead, while non-browser callers keep the JSON
  body — matching the authorization endpoint's direct-error handling. A wired
  `:render_logged_out` callback still takes precedence.

## [0.19.1] - 2026-06-26

### Fixed

- **Authorization-endpoint direct-error HTML showed the wrong code.** A
  non-redirectable `/authorize` error rendered to a browser (`Accept:
  text/html`) hardcoded `invalid_request` in the page, while the JSON body
  correctly carried the resolved code. A browser hitting an expired/unknown PAR
  `request_uri` therefore saw `invalid_request` instead of `invalid_request_uri`
  (which a conformance check reading the rendered page rejects). The HTML page
  now renders the same resolved code as the JSON body.

## [0.19.0] - 2026-06-23

### Added

- **Dynamic-registration default scope (RFC 7591 §2).** A new
  `:registration_default_scope` config assigns a scope to a client that
  registers without one — `:scopes_supported` for the full catalog, or an
  explicit list (validated against `:scopes_supported` at boot) — echoed back in
  the §3.2.1 response so the client learns what it got. Default `nil` keeps the
  prior fail-closed behavior (a scopeless registration stays scopeless). This
  lets a scopeless DCR client (e.g. an MCP/agent client) register with a usable
  scope as protocol behavior, rather than each host's `authorize_scope` fallback
  reinventing it.

### Changed

- **Token-endpoint error diagnostics.** `POST /oauth/token` now logs the
  resolved RFC 6749 §5.2 error code + description at `:debug` at the single
  render boundary, so a host operator can tell e.g. `invalid_scope` from
  `invalid_grant` behind an otherwise-opaque 400 without reading the source. The
  level is `:debug` so a 4xx under load is never prod log noise; the structured
  `:token_denied` event still carries the same reason for hosts that want it
  louder.

## [0.18.0] - 2026-06-23

### Added

- **OpenID Connect Logout (RP-Initiated Logout 1.0 + Back-Channel Logout 1.0).**
  A `logout: true` option on `attesto_routes/1` mounts `GET`/`POST
  /oauth/end_session` (`AttestoPhoenix.Controller.EndSessionController`), gated
  by a `logout: [enabled: true]` config block. The endpoint verifies the
  `id_token_hint`, validates `post_logout_redirect_uri` against the client's
  registered set (exact match — no open redirect), and either redirects with
  `state` or hands off to the host's logged-out page.
  - The **host is the session authority**: a REQUIRED `:terminate_session`
    callback clears the browser session and returns the confirmed
    `%{sid, subject}` that scopes the Back-Channel fan-out — so a replayed or
    stolen `id_token_hint` cannot force-log-out an arbitrary session.
    `AttestoPhoenix.Config` raises at boot if logout is enabled without it (no
    fail-open logout). `:render_logged_out` is an optional page renderer.
  - Back-Channel fan-out: a `logout_token` is POSTed to every RP holding the
    terminated session, recorded at ID-Token mint
    (`AttestoPhoenix.Schema.LogoutSession` + `EctoLogoutSessionStore`, a new
    `attesto_logout_sessions` table) and taken atomically
    (`DELETE ... RETURNING`) so concurrent logouts cannot double-deliver.
    Delivery (`AttestoPhoenix.BackChannelLogout` / `.Req`) is best-effort and
    SSRF-guarded: a `backchannel_logout_uri` is honored only when it is `https`
    with no userinfo/fragment and a non-internal host (loopback / RFC 1918 /
    link-local / ULA literals are refused).
  - The authorization endpoint threads the host's `:sid` (from the authenticate
    subject map) into the ID Token, and dynamic registration accepts
    `post_logout_redirect_uris`, `backchannel_logout_uri`, and
    `backchannel_logout_session_required`. Discovery advertises
    `end_session_endpoint` + `backchannel_logout_supported` +
    `backchannel_logout_session_supported` when enabled. The sweeper reaps
    expired logout-session rows.

- Requires `attesto ~> 0.13`.

## [0.17.0] - 2026-06-23

### Added

- **RFC 8628 Device Authorization Grant.** A `device: true` option on
  `attesto_routes/1` mounts `POST /oauth/device_authorization` and the
  `GET`/`POST /oauth/device_verification` page; the token endpoint gains a
  `device_code` grant dispatch (the §3.5 polling errors render with their own
  codes, not collapsed to `invalid_grant`). A PUBLIC (`:none`) client MUST
  present a DPoP proof at the device-authorization endpoint (a device-issued
  bearer token has no PKCE/redirect backstop), and the bound RFC 8707 `resource`
  / RFC 9470 `acr`+`auth_time` thread through to the minted token. New
  `device_authorization` config block + `:device_code_store`, the
  `AttestoPhoenix.Store.EctoDeviceCodeStore` (every transition a single guarded
  atomic UPDATE) + `attesto_device_codes` table, the
  `:authenticate_device_user` / `:render_device_verification` host callbacks,
  and `device_authorization_endpoint` advertised in discovery when enabled.

### Changed

- Requires `attesto ~> 0.12`.

## [0.16.0] - 2026-06-22

### Added

- **RFC 9470 Step-Up Authentication.** The token endpoint mints the
  authentication context (`acr` / `auth_time`) onto access tokens so a resource
  server can enforce a step-up requirement: `authorization_code` mints them from
  the redeemed code's claims, and the refresh family persists and replays the
  ORIGINAL `acr` / `auth_time` (never re-stamped on rotation). A machine grant
  establishes no auth context and so fails closed against any step-up
  requirement. New `acr` / `auth_time` columns on `attesto_refresh_tokens`
  (migration generator + schema).

### Changed

- Requires `attesto ~> 0.11`.

### Fixed

- **Refresh-family revocation race (security).** `AttestoPhoenix.Store.EctoRefreshStore`
  now serializes `insert/1` and `revoke_family/1` for a given family with a
  Postgres advisory transaction lock. Previously, under `READ COMMITTED`, a
  successor insert could interleave with a concurrent family revocation and
  leave a live token in a revoked family (a `FOR UPDATE` on existing rows would
  not catch the just-inserted successor — a phantom). Sticky family revocation
  (RFC 6749 §10.4 / OAuth 2.0 Security BCP) now holds under concurrency.

## [0.15.0] - 2026-06-22

### Added

- **RFC 8707 Resource Indicators across every grant.** `client_credentials`,
  token exchange, and jwt-bearer validate (§2.1) and authorize (§2.2) the
  request-time `resource` and mint the access-token `aud` from it;
  `authorization_code` binds the resource authorized at the authorize endpoint
  and mints `aud` from it (optionally narrowed at redemption, never widened);
  `refresh_token` carries and subset-narrows it. Multiple allow-listed resources
  mint a JWT `aud` array; an unserved resource is `invalid_target`.
- Grant-agnostic `resource_indicators: [allowed_resources, allowed_resources_for]`
  config and `AttestoPhoenix.Config.allowed_resources/2` (server `:audience` +
  static list + optional per-client callback), replacing the jwt-bearer-only
  `jwt_bearer: [allowed_resources]`.
- A `resource` column persisted on the authorization-code and refresh-token
  stores (migration generator + schemas).

### Security

- Token exchange now ceilings a requested `resource` to the subject token's own
  `aud` (RFC 8693 §2.1 / RFC 8707): a token confined to resource A can no longer
  be exchanged for one audienced to a sibling resource B.

### Changed

- Requires `attesto ~> 0.10`.

## [0.14.2] - 2026-06-22

### Fixed

- `AttestoPhoenix.RequestContext` now folds an IPv4-mapped IPv6 peer address
  (`::ffff:a.b.c.d`) back to its IPv4 tuple before testing it against
  `:trusted_proxies`. A dual-stack listener bound on `::` (the common Docker /
  Kamal topology, where a TLS-terminating reverse proxy reaches the app over an
  IPv4 bridge network) surfaces the proxy peer as `::ffff:172.x.y.z`, which an
  IPv4 CIDR allowlist (e.g. `172.16.0.0/12`) never matched — so the proxy was
  treated as untrusted, `X-Forwarded-Proto: https` was ignored, and a
  legitimately TLS-terminated request to the token / protected-resource
  endpoint was misread as plain HTTP and refused with `invalid_request`
  ("TLS required"). The fold makes the forwarded-header trust gate work behind
  such a proxy without widening the allowlist to IPv6.

## [0.14.1] - 2026-06-22

### Fixed

- `AttestoPhoenix.Store.NonceStore` now calls the `Attesto.DPoP.NonceStore`
  behaviour callback `issue/1` (with an explicit TTL) on its config-free
  fallback, instead of an arity-0 `issue/0` that the behaviour does not
  guarantee. A third-party nonce store implementing the behaviour exactly
  (`issue/1` only, without an arity-0 convenience) is now dispatched correctly
  rather than crashing in the fallback. The bundled ETS and Ecto stores are
  unaffected. Doc corrected to stop referring to a non-existent `issue/0`.
- The token endpoint now rejects a request carrying more than one `DPoP` header
  outright with `invalid_dpop_proof` (RFC 9449 §4.3), rather than silently
  selecting one proof — closing a header-smuggling vector where an intermediary
  could inject an attacker's proof.
- An unparseable client certificate at the token endpoint now returns
  `invalid_request` ("invalid client certificate") rather than `invalid_client`:
  non-X.509 bytes are a malformed request parameter (there is nothing to bind a
  token to), not a client-authentication failure.
- The token-endpoint denial path no longer raises when the request body was
  never parsed (e.g. a rejected/unsupported `Content-Type` leaves `body_params`
  an `%Plug.Conn.Unfetched{}` struct). It now falls back to the action params
  instead of treating the struct as parsed params and raising on key access.

## [0.14.0] - 2026-06-22

### Security

- `AttestoPhoenix.AuthorizationServer.SenderConstraint.resolve/3` now resolves a
  client's REQUIRED sender constraint before any opportunistic binding, so a
  required constraint can no longer be satisfied by presenting a DIFFERENT
  valid one. Previously the first opportunistically-present constraint was
  bound before the client's requirement was checked: a DPoP-required client
  that presented a client certificate (and no proof) was issued an
  mTLS-bound token, and symmetrically an mTLS-required client presenting a DPoP
  proof was DPoP-bound — defeating the per-client policy. Now a DPoP-required
  client is bound only by a DPoP proof (a certificate-only request is rejected
  with `DPoP proof required`), an mTLS-required client only by a certificate (a
  proof-only request is rejected with `client certificate required`), and a
  client requiring neither keeps the existing opportunistic precedence
  (DPoP over mTLS, else Bearer).

### Fixed

- The token-endpoint and resource-server DPoP paths now accept a
  `{module, function}` / `{module, function, extra_args}` MFA `:replay_check`.
  The configured callback was passed verbatim to `Attesto.DPoP.verify_proof/2`,
  which requires a bare 2-arity function, so a host configuring an MFA replay
  store (the only form config can hold) crashed with an `ArgumentError` on every
  DPoP request. All four DPoP verify sites — token endpoint, PAR, UserInfo, and
  the `Authenticate` plug — now adapt the callback via
  `AttestoPhoenix.Callback.to_fun2/1`.
- `dpop_nonce_required: true` no longer crashes when `AttestoPhoenix.Config` is
  configured under the host's own otp_app. The DPoP paths now thread the live
  request config into nonce issuance and validation instead of letting the
  nonce store re-resolve config from a hardcoded `:attesto_phoenix` otp_app
  (which raised when the host configured the library elsewhere). A persistent
  nonce store such as `AttestoPhoenix.Store.EctoNonceStore` receives the
  resolved config and never has to guess an otp_app.

### Added

- `AttestoPhoenix.Callback.to_fun2/1` adapts any configured callback form into
  the bare 2-arity function the DPoP verifier requires for `:replay_check`.
- `AttestoPhoenix.Store.NonceStore` dispatches to the configured
  `Attesto.DPoP.NonceStore`, threading the live `%AttestoPhoenix.Config{}` to a
  store's config-aware `issue/2` / `valid?/2` entrypoints when present and
  falling back to the behaviour arities for config-free stores.

## [0.13.5] - 2026-06-21

### Added

- `:token_denied` events now carry richer audit metadata: `:client_id` when
  known, structured `:reason` as the OAuth error atom, and sender-constraint
  fields mirroring issuance events (`:token_type`, `:sender_constraint`, and
  `:cnf`).
- `AttestoPhoenix.AuthorizationServer.SenderConstraint.audit_metadata/2` exposes
  the shared sender-constraint audit classification used by token denial events.

### Changed

- `AttestoPhoenix.Controller.TokenController` now rejects token requests whose
  `Content-Type` is not `application/x-www-form-urlencoded` or
  `application/json` before client authentication. Unsupported media types
  return `400 invalid_request` naming the rejected Content-Type.

### Fixed

- Token endpoint `invalid_client` responses from `Authorization`-header client
  authentication now follow RFC 6749 §5.2: Basic/header failures return `401`
  with a matching `WWW-Authenticate` challenge, while body credentials and
  absent credentials remain `400` without a challenge.

## [0.13.4] - 2026-06-21

### Added

- `AttestoPhoenix.ConsentGrant.binding_from_params/2` builds the same canonical
  consent-grant binding as `binding/2` from raw string-keyed OAuth params, so
  consent-screen mint actions and live `/authorize` consume callbacks no longer
  need duplicate host-side binding reconstruction.

## [0.13.3] - 2026-06-21

### Added

- **Token issuance events now include sender-constraint audit metadata.**
  `:token_issued` events, plus the related `:refresh_issued` and
  `:refresh_rotated` issuance events, now preserve the mint-time sender
  constraint in `event.metadata`: `:token_type` (`"Bearer"` or `"DPoP"`),
  `:sender_constraint` (`:none`, `:dpop`, or `:mtls`), and `:cnf`
  (`%{"jkt" => thumbprint}`, `%{"x5t#S256" => thumbprint}`, or `nil`). Existing
  `:client_ip` metadata is unchanged.

## [0.13.2] - 2026-06-21

### Fixed

- **Consent grants now bind the PKCE `code_challenge_method`.**
  `AttestoPhoenix.ConsentGrant.binding/2` and `binding_hash/1` now include
  `code_challenge_method` alongside `code_challenge`, so a grant consented for
  an `S256` authorization request cannot be reused for an otherwise-identical
  `plain` request with the same challenge value. Missing PKCE fields continue to
  canonicalize as empty strings.

### Compatibility

- The consent-grant hash input changed. Any consent grant minted before this
  upgrade will not match after the upgrade. Consent grants are single-use and
  short-TTL, so the practical effect is limited to an in-flight authorization
  started across the upgrade re-prompting once.

## [0.13.1] - 2026-06-21

### Added

- **Optional OpenApiSpex token endpoint helpers.**
  `AttestoPhoenix.OpenAPI.TokenEndpoint` now exposes reusable OpenAPI values for
  `POST /oauth/token`: `operation/1`, `schemas/0`, `request_body/0`, and
  `responses/0`. The documented surface covers RFC 6749 §4.4
  `client_credentials` form requests, body client authentication,
  `private_key_jwt`, optional DPoP proof headers, Bearer and DPoP token success
  responses, OAuth error responses, and RFC 9449 `invalid_dpop_proof` /
  `use_dpop_nonce` with `DPoP-Nonce`. The `:open_api_spex` dependency is
  optional and the module compiles only when OpenApiSpex is available.

### Changed

- **Token endpoint rejects credential-bearing query strings.**
  `AttestoPhoenix.Controller.TokenController` now rejects `grant_type`,
  `client_id`, `client_secret`, or `scope` when any appears in the query string,
  before TLS validation, client authentication, or grant dispatch. The response
  is the normal RFC 6749 §5.2 `400 invalid_request` JSON envelope. The same
  fields remain accepted in the form body.

### Fixed

- **Optional `Req` dependency remains optional for consumers.**
  `AttestoPhoenix.ClientIdMetadata.Fetcher.Req` is now compile-guarded on `Req`
  being loaded, matching the existing optional dependency declaration and
  allowing a consumer that does not enable CIMD fetching to compile
  `attesto_phoenix` with `--warnings-as-errors` without depending on `:req`.

## [0.13.0] - 2026-06-21

### Changed

- **Protected-resource bearer credentials default to header-only.**
  `:bearer_methods_supported` now defaults to `["header"]`, and
  `AttestoPhoenix.Plug.Authenticate` passes that setting through to the core
  verifier. Resource servers that intentionally accept RFC 6750 §2.2 form-body
  `access_token` credentials can configure `["header", "body"]`; the runtime
  verifier and RFC 9728 metadata now use the same setting. Requires
  `attesto ~> 0.9`.

## [0.12.0] - 2026-06-21

### Added

- **Single-use, request-bound consent grants (RFC 6749 §4.1.1).** A new
  authorization-server correctness primitive that ties one consent decision to
  the *exact* authorization request the resource owner saw, so an Authorize
  click cannot approve a different client, redirect URI, scope set, or PKCE
  challenge than the one displayed. Opt-in and additive — a host that does not
  wire it is unaffected.
  - `AttestoPhoenix.ConsentGrantStore` — the store behaviour (`mint/2`,
    `consume/2`). `consume/2` is a single atomic conditional `UPDATE`, so a grant
    token works exactly once, for exactly the request it was granted for, even
    under concurrent presentation.
  - `AttestoPhoenix.ConsentGrant` — the canonical request binding
    (`subject + client_id + redirect_uri + sorted scope set + code_challenge`).
  - `AttestoPhoenix.Store.EctoConsentGrantStore` +
    `AttestoPhoenix.Schema.ConsentGrant` — the Postgres-backed implementation,
    swept by `AttestoPhoenix.Store.Sweeper`.
  - `AttestoPhoenix.Config` `:consent_grant_store` — the opt-in callback (no
    default). The host's consent UI mints a grant when the user authorizes; the
    `:consent` callback consumes it before a code is issued.
  - `mix attesto_phoenix.gen.migration` emits the `attesto_consent_grants`
    table; `mix attesto_phoenix.install` wires `EctoConsentGrantStore`.

### Fixed

- **Docs:** `AttestoPhoenix.ConsentGrantStore` referred to `consume/3` in two
  places; the callback is `consume/2`.

## [0.11.0] - 2026-06-20

### Added

- **`AttestoPhoenix.Config` `:bearer_methods_supported`** — the RFC 6750
  access-token presentation methods the resource server accepts, advertised as
  `bearer_methods_supported` in the RFC 9728 protected-resource metadata document
  (`/.well-known/oauth-protected-resource`). Previously the
  `ProtectedResourceController` hardcoded `["header", "body"]`, forcing a
  header-only deployment to advertise the form-body method (RFC 6750 §2.2) it
  rejects — a metadata-accuracy/interoperability defect, since a conformant
  client could select a rejected method (RFC 9728 §2 / RFC 6750 §3). The field is
  now configurable (a non-empty list of distinct methods, each `"header"` or
  `"body"` — exactly the surface `AttestoPhoenix.Plug.Authenticate` accepts:
  the `Authorization` header (§2.1) and a POST form-body `access_token` (§2.2);
  validated at config build), mirroring `:scopes_supported`. The §2.3 `"query"`
  method is rejected — the plug never accepts a query-presented token, so
  advertising it would be the same inaccuracy inverted (and RFC 6750 §2.3 says it
  SHOULD NOT be used). Defaults to `["header", "body"]`; a header-only resource
  server sets `["header"]`.

## [0.10.0] - 2026-06-20


### Added

- **`GET /.well-known/oauth-protected-resource` endpoint
  (`AttestoPhoenix.Controller.ProtectedResourceController`).** Serves the RFC 9728
  protected-resource metadata document (`resource`, `authorization_servers`,
  `scopes_supported`, `bearer_methods_supported`), derived from the same issuer,
  audience, and scope configuration the RFC 8414 discovery document uses. Mounted
  by `attesto_routes/1` at the host root (RFC 8615); it is the discovery target of
  the `resource_metadata` `WWW-Authenticate` challenge the protected-resource
  plugs emit, so a resource server is discovery-complete without the caller
  hand-rolling the document.

- **`AttestoPhoenix.Config` `:resource_metadata`.** Absolute URL of this
  resource's RFC 9728 protected-resource metadata document. When set,
  `AttestoPhoenix.Plug.Authenticate` and the UserInfo endpoint advertise it as a
  `resource_metadata` auth-param on every `WWW-Authenticate` challenge they
  render (RFC 9728 §5.1), so a client refused with 401/403 can discover which
  authorization server issues tokens for this resource. Configured once on the
  Config; omitted from the challenge when unset.

- **`AttestoPhoenix.Config.new/1` now validates `:audience` at boot.** It must be a non-empty **absolute https URL** with a host and no fragment, not merely present. It
  is the access-token `aud` (RFC 9068 §3), the audience the protected-resource
  verifier requires (a mismatch is `:invalid_audience`), and the RFC 9728 resource
  identifier served at `/.well-known/oauth-protected-resource` — so a nil, blank,
  or non-URL value would either fail late (every token rejected `:invalid_audience`)
  or 500 the protected-resource metadata endpoint. `new/1` now raises
  `ArgumentError` instead. With RFC 8707 resource handling the minted `aud` may
  differ per request, but `config.audience` remains the required default/fallback
  and RS verification audience.

- **Identity Assertion JWT Authorization Grant (ID-JAG / `jwt-bearer`)** — the
  resource server's half of
  `draft-ietf-oauth-identity-assertion-authz-grant-04`, the grant behind MCP
  Enterprise-Managed Authorization (EMA). A token request with
  `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and an `assertion`
  (an ID-JAG signed by a trusted enterprise IdP) is exchanged for a normal
  access token — no redirect, no consent.
  - **Off by default**, gated by `jwt_bearer: [enabled: true, ...]`. When
    enabled, `urn:ietf:params:oauth:grant-type:jwt-bearer` is advertised in
    `grant_types_supported` (both discovery documents) and accepted at the token
    endpoint; existing deployments are unaffected.
  - **Trusted issuers** (`jwt_bearer: [issuers: %{...}]`): each issuer supplies
    static `:jwks`, a cached `:jwks_uri` (fetched through the SSRF-guarded CIMD
    fetcher + cache), or a custom `:jwks_resolver`; with `:allowed_algs` and an
    optional `:audience` override. Assertions from unconfigured issuers are
    denied.
  - **Validation** via `Attesto.IdentityAssertion`: `typ=oauth-id-jag+jwt`,
    signature against the issuer JWKS, `iss`/`aud`/`exp`/`iat` (with skew), the
    required `client_id` binding to the authenticated client, and `jti` replay
    (reusing the configured `:replay_check`). Every failure is RFC 6749 §5.2
    `invalid_grant`; a missing `assertion` is `invalid_request`.
  - **Subject resolution** via a new `:resolve_jwt_bearer_subject` callback
    (also installable as `resolve_jwt_bearer_subject/1` on
    `AttestoPhoenix.PrincipalStore`): maps the validated claims to a local
    principal subject, or denies. Required at boot when the grant is enabled.
  - The grant requires client authentication (confidential clients only) and
    honours per-client `grant_types`. The assertion's `scope` claim is the
    granted-scope ceiling; `:authorize_scope` narrows from there.
  - **No refresh token is issued** for this grant: access is re-derived from a
    fresh assertion on each request (RFC 7523 §4), so it cannot outlive the
    enterprise IdP's policy/deprovisioning window.
  - **RFC 8707 `resource` indicator → access-token `aud`** (via
    `Attesto.Token.mint/3`'s `:audience` option, requiring `attesto ~> 0.8`): a
    single valid resource becomes the minted `aud` (§2.2); an absent resource
    falls back to `config.audience`. The resource is authorized fail-closed
    (§2.2) — it must be `config.audience` or an explicitly configured
    `jwt_bearer: [allowed_resources: [...]]` entry — so an authenticated client
    cannot mint a token audienced to a resource the server does not serve. An
    invalid (non-absolute-URI / fragment / bad percent-encoding), multiple, or
    unauthorized resource is rejected `invalid_target` (§2.1).
  - See [the ID-JAG guide](guides/identity_assertion_grant.md). Requires
    `attesto ~> 0.8`.

### Changed

- Made OAuth error-code resolution (RFC 6749 §5.2) total by construction. The
  `@error_*` codes in the token core, token controller, introspection
  controller, and sender-constraint module are now compile-time atoms passed
  straight to `OAuthError.new/3`, replacing a private `String.to_existing_atom/1`
  round-trip that could raise `ArgumentError` and turn a clean §5.2 error body
  into a 500 if a code string were ever emitted before its atom existed.

### Documentation

- **Documented and test-proved the DCR → `client_credentials` subject seam.**
  Dynamic Client Registration (RFC 7591 §3.2.1) issues an *unprefixed*
  `client_id`, while a minted principal's `sub` MUST carry its
  `Attesto.PrincipalKind` `sub_prefix` (`:invalid_sub` otherwise). The host's
  `:build_principal` callback is the sole seam that reconciles the two by
  namespacing `:sub`; the `:build_principal` doc on `AttestoPhoenix.Config` and
  the `c:AttestoPhoenix.PrincipalStore.build_principal/3` behaviour doc now state
  this mandate and cite the prefix as mint-time defense-in-depth. A new
  end-to-end test registers a confidential `client_credentials` client through
  the registration endpoint, issues a token with the bare DCR id, and verifies
  `sub == prefix <> client_id` and `client_id == client_id`, with a negative
  control proving a non-prefixing `:build_principal` is rejected as the
  RFC 6749 §5.2 `invalid_request`.


## [0.9.5] - 2026-06-16

### Fixed

- **Holder-of-key (DPoP) failures are now surfaced ahead of the client-auth
  error (FAPI2 `ensure-holder-of-key-required`).** A token request redeeming a
  sender-constrained (DPoP-bound) authorization code WITHOUT a DPoP proof is a
  holder-of-key failure; FAPI2 expects it reported as
  `invalid_request`/`invalid_grant`/`invalid_dpop_proof`. When such a request
  ALSO lacked client authentication, the client-auth check masked it with
  `invalid_client`. The token endpoint now reads the code (via the store's
  non-consuming `c:Attesto.CodeStore.get/1`) and, when it is DPoP-bound and no
  proof is presented, returns `invalid_request "DPoP proof required"` — even
  before the client-auth failure. The code is NOT consumed, so a legitimate
  retry is unaffected. Only DPoP-bound codes are affected; a plain (e.g. OIDC)
  code still surfaces `invalid_client`. Requires attesto 0.7.2.

### Added

- **`AttestoPhoenix.Store.EctoCodeStore.get/1`** — the non-consuming read
  (`c:Attesto.CodeStore.get/1`) for the Ecto-backed code store, a plain SELECT of
  the live (unconsumed) row.

## [0.9.4] - 2026-06-14

### Security

Adversarial-review hardening of the token, authorization, and revocation
endpoints (all found by an internal multi-agent security review).

- **Public clients can no longer run confidential-only grants.** The token
  endpoint gated grants only on the optional per-client `:client_grant_types`
  callback (unset ⇒ all grants allowed), so a public (`none`) client that proved
  possession of no credential could run `client_credentials` (RFC 6749 §4.4) or
  RFC 8693 token-exchange. The resolved client-auth method is now threaded into
  the request, and both grants reject the `:none` path with `invalid_client`,
  independent of any host policy.

- **The revocation endpoint now enforces TLS.** `RevocationController` never
  called `check_https`, so under the default `require_https: true` a plain-HTTP
  `POST /oauth/revoke` carrying the client secret + refresh token was still
  processed — leaking both over cleartext. It now gates on TLS first, like every
  other credential-bearing endpoint.

- **DPoP proofs are replay-protected at the token endpoint (RFC 9449 §11.1).**
  `SenderConstraint.bind_dpop` never wired `:replay_check`, so a captured
  token-endpoint proof's `jti` was never recorded and the proof was replayable
  within its acceptance window. The proof's `jti` is now recorded (via the same
  default `Attesto.DPoP.ReplayCache` the PAR endpoint uses).

- **The direct (non-PAR) authorization endpoint honors a signed `dpop_jkt`.** It
  read `dpop_jkt` from the raw outer query, ignoring the signed request object —
  letting a front-channel attacker strip or substitute the code's DPoP key
  binding. It now reads the value off the verified request
  (`Attesto.AuthorizationRequest.dpop_jkt`, requires attesto 0.7.1), so a signed
  request object's value is authoritative. The PAR-resolved path continues to use
  the PAR-verified thumbprint stored at the top level (a pushed request object is
  re-merged at `/authorize`, which would otherwise drop it).

- **The dynamic client registration endpoint now enforces TLS.**
  `RegistrationController.create/2` returns a freshly minted plaintext
  `client_secret` and `delete/2` reads a registration-access-token bearer
  credential; neither gated on TLS, so under the default `require_https: true`
  they served those credentials over cleartext. Both now refuse plain HTTP first,
  like every other credential-bearing endpoint. (Found by adversarial
  verification of the revocation fix — same class, uncovered sibling.)

- **The revocation endpoint equalizes client-auth timing.** A lookup failure
  skipped `verify_client_secret`, leaving a timing oracle for client-id
  enumeration. It now runs a dummy verify against an `:unknown_client` sentinel
  so the unknown-client and wrong-secret paths match in observable timing,
  matching the shared `AttestoPhoenix.ClientAuthentication` core.

- **CIMD SSRF guard covers Teredo and ORCHIDv2.** Added `2001:0000::/32` (Teredo)
  and `2001:20::/28` (ORCHIDv2) to the RFC 6890 special-use IPv6 table the
  fetcher screens against.

## [0.9.3] - 2026-06-14

### Security

- **Token exchange can no longer broaden scope (RFC 8693 §2.1).** The
  token-exchange grant validated the requested `scope` only against the host's
  `:authorize_scope` policy, which is never handed the subject token — so the
  library could not, and did not, enforce that the issued token's scope stays
  within the subject token's. A client registered for a broad scope set could
  exchange a narrowly-scoped subject token for a broader one. The token endpoint
  now rejects (`invalid_scope`) any requested scope not present in the subject
  token's scope, before delegating to `:authorize_scope` — an exchange can only
  preserve or narrow scope. (`:authorize_scope` may still narrow further.)

- **The token endpoint now enforces `grant_types_supported`.** Previously the
  only grant gate was the optional per-client `:client_grant_types` callback
  (unset ⇒ every grant allowed), while discovery advertised a hardcoded grant
  superset including token-exchange — so a host that didn't lock every client
  down had an advertised, working token-exchange grant it never opted into. The
  token endpoint now rejects (`unsupported_grant_type`) any `grant_type` outside
  the configured set, as a global backstop independent of per-client policy.

### Changed

- **`grant_types_supported` is now driven by host config, not a hardcoded list.**
  Both discovery documents (RFC 8414 and OpenID configuration) and the new token
  endpoint gate read `AttestoPhoenix.Config.grant_types_supported/1`, which
  defaults to every implemented grant (so existing deployments are unchanged) and
  is narrowed by configuring `:grant_types_supported` — dropping a grant (e.g.
  token-exchange) now disables it across discovery, the token endpoint, and
  dynamic registration at once, instead of only registration.

## [0.9.2] - 2026-06-14

### Fixed

- **A CIMD client no longer crashes a host `:authorize_scope` policy.** A Client
  ID Metadata Document need not declare a `scope` member, so the metadata map
  attesto hands the host policy callbacks carried no scope key at all. A scope
  policy written for a registered client (reading `client.scopes`) raised
  `KeyError` on it, 500-ing the token endpoint for an otherwise valid CIMD
  authorization_code exchange (observed end-to-end against the ChatGPT MCP
  connector). `host_client/1` now exposes the document's *declared* scopes — or
  an empty set when the document omits `scope` — under the atom `:scopes` key, so
  the callback reads an empty *declared* set instead of a missing key. The host
  still owns what an empty set grants (typically the resource owner's consent).

### Added

- **`AttestoPhoenix.ClientIdMetadata.scopes/1`** — the public accessor for a CIMD
  document's declared scopes (its space-delimited RFC 7591 §2 `scope` member as a
  list; `[]` when absent), alongside the existing `client_id/1`, `redirect_uris/1`,
  and `jwks/1` accessors.

## [0.9.1] - 2026-06-14

### Added

- **Boot-time discovery-document safety guard.** `AttestoPhoenix.Config.new/1`
  now validates, at config-build time (alongside the existing required-key
  checks), that the discovery documents it will serve are internally consistent —
  so a "silent discovery mismatch" (a document that omits a required endpoint or
  advertises one the router does not mount, served 200 with no error) can no
  longer ship. It raises `ArgumentError` with an actionable message for two
  classes of failure:
  - **A required discovery endpoint that would be missing or non-absolute.** The
    RFC 8414 §2 / OpenID Connect Discovery §3 endpoints the library derives —
    `issuer`, `authorization_endpoint`, `token_endpoint`, and `jwks_uri` — must
    each resolve to an absolute URL (scheme + host). The realistic trigger is an
    `:issuer` that is not an absolute https URL (e.g. `"issuer.example"`), which
    `URI.merge/2` turns into host-less, unresolvable endpoint URLs; this is the
    same class of failure as the 0.9.1 regression where the RFC 8414 document
    silently omitted `authorization_endpoint`.
  - **An `:oauth_path_prefix` vs explicit per-endpoint override mismatch.** When a
    host declares a non-default `:oauth_path_prefix` (committing every OAuth
    endpoint to one mount tree) but then sets a per-endpoint override
    (`:token_path` and friends) that escapes that prefix, discovery would
    advertise that endpoint at a path the router — which mounts every OAuth
    endpoint under one shared prefix — does not serve. That provable divergence
    now fails fast. A per-endpoint override on the default prefix, or one that
    stays under the declared prefix, remains a supported feature.

### Fixed

- **The RFC 8414 `/.well-known/oauth-authorization-server` document now advertises
  `authorization_endpoint`.** It was omitted entirely: `Attesto.Discovery` derives
  only `issuer`/`token_endpoint`, and the controller's host-member list never
  supplied `authorization_endpoint`, so the OAuth metadata silently lacked a field
  RFC 8414 §2 requires for the authorization-code flow. An OAuth client that reads
  this document rather than OpenID Discovery (e.g. the ChatGPT MCP connector)
  therefore concluded the server "does not implement OAuth." It is now derived via
  `authorize_endpoint_url/1` — the same path resolution as `token_endpoint`,
  so the two cannot diverge. (OpenID Discovery's `/.well-known/openid-configuration`
  already advertised it.)

## [0.9.0] - 2026-06-14

Requires `attesto ~> 0.7.0`.

### Added

- **Client ID Metadata Documents (CIMD,
  `draft-ietf-oauth-client-id-metadata-document-01`) — opt-in, default off.** A
  client can identify itself with no prior registration by using an HTTPS URL as
  its `client_id`; the authorization server dereferences that URL to a JSON
  client metadata document and uses it as the client. Enable with
  `client_id_metadata: [enabled: true, ...]` in the config.
  - `AttestoPhoenix.ClientIdMetadata.Fetcher` (+ the default
    `...Fetcher.Req`) — the SSRF-guarded outbound GET. It resolves the host,
    rejects any A/AAAA address that is special-use (RFC 6890: loopback, private,
    link-local, CGNAT, multicast, reserved, and every IPv6 form that embeds an
    IPv4 — IPv4-mapped, NAT64 `64:ff9b::/96` and local-use `64:ff9b:1::/48`,
    6to4, IPv4-compatible — unwrapped and re-checked), pins the connection to a
    validated IP to close the DNS-rebinding window (TLS SNI/cert stay on the
    original hostname), refuses redirects, requires `200` + JSON, and caps the
    body at 5 KB. Requires the optional `:req` dependency, or a host-supplied
    `:fetcher` (e.g. a CIMD proxy service).
  - `AttestoPhoenix.ClientIdMetadata.Cache` (default Ecto, cluster-coherent;
    ETS opt-out) — respects RFC 9111 cache headers clamped to bounds, never
    caches errors/invalid documents, re-checks expiry on read. New table
    `attesto_client_id_metadata` (`mix attesto_phoenix.gen.migration`), swept by
    `AttestoPhoenix.Store.Sweeper`.
  - `AttestoPhoenix.ClientIdMetadata.Resolver` + integration: a CIMD `client_id`
    URL resolves via the document and is wired through the authorization, PAR,
    and token endpoints as a `{:cimd, metadata}` client — PKCE forced, treated
    as a public client (or `private_key_jwt` via the document `jwks`/`jwks_uri`),
    `redirect_uri` exact-matched against the document's `redirect_uris` and (by
    default) required to be same-origin with the `client_id` URL. Opaque
    `client_id`s still resolve through `:load_client` unchanged.
  - Discovery advertises `client_id_metadata_document_supported` when enabled.

- New optional dependency `{:req, "~> 0.5", optional: true}` for the default
  CIMD fetcher (a host that never enables CIMD pays nothing).

## [0.8.0] - 2026-06-14

Requires `attesto ~> 0.6.16`.

### Added

- **`AttestoPhoenix.Store.EctoPARStore` — a Postgres-backed Pushed Authorization
  Request store (RFC 9126), closing the last per-node gap to a fully clusterable
  authorization server.** PAR was the only mutable OAuth store without an Ecto
  implementation: the default `AttestoPhoenix.Store.PAR.ETS` keeps the
  `request_uri` → params mapping in per-node memory, so a reference pushed to one
  node could not be resolved when `/authorize` landed on another — and FAPI 2.0
  *requires* PAR. The new store persists each pushed request so any node resolves
  a `request_uri` issued by any other, matching the code/refresh/nonce/replay
  Ecto stores. `fetch/1` is non-consuming (the authorization endpoint may
  re-enter after a login/consent detour); `take/1` is an atomic single-use
  `DELETE … RETURNING`.
  - New `AttestoPhoenix.Schema.PushedAuthorizationRequest` (table
    `attesto_pushed_authorization_requests`, keyed on the `request_uri` primary
    key, `params` as `jsonb`).
  - `mix attesto_phoenix.gen.migration` now creates the fifth table, and
    `mix attesto_phoenix.install` wires `par_store: …EctoPARStore` by default, so
    a by-the-docs install is cluster-safe out of the box.
  - `AttestoPhoenix.Store.Sweeper` now also reclaims expired PAR references.

- **Atomic single-use of the PAR `request_uri` at completion.** The
  authorization endpoint now claims the pushed reference with the store's atomic
  `take/1` *before* issuing the code (it was previously consumed after issuance,
  with the result ignored), so two concurrent completions — on one node or
  across a cluster — can no longer each mint a code from one pushed request:
  exactly one wins the claim; the loser is redirected `invalid_request_uri` and
  issues nothing. Resolution still uses the non-consuming `fetch/1`, so a host
  may establish login/consent and re-enter `/authorize` with the same reference.

### Changed

- README documents the clustering story end-to-end and the PAR caveat; the
  `:par_store` config doc points at `EctoPARStore` for clustered/FAPI
  deployments. The default `par_store` is unchanged (single-node ETS), so
  existing single-node hosts are unaffected.

## [0.7.7] - 2026-06-13

Requires `attesto ~> 0.6.16`.

### Fixed

- **Token endpoint finalizes the authorization code only after the full
  response is built.** The `authorization_code` grant now calls
  `Attesto.AuthorizationCode.finalize/3` (new in attesto 0.6.16) once the access
  token, optional refresh token, and id_token have all been minted and recorded
  successfully. Previously the reuse marker was set the moment the code
  validated, so any later failure in the same request (a refresh-store write
  error, an id_token mint fault, a host `build_principal` callback returning the
  subject under the wrong key) left the code spent AND flagged as a successful
  redemption — turning a legitimate client retry into a false reuse attack that
  revoked the whole refresh-token family. A redemption that validates but fails
  downstream is now a clean `invalid_grant` on replay.

## [0.7.6] - 2026-06-12

Requires `attesto ~> 0.6.13`.

### Fixed

- The token endpoint no longer short-circuits a missing PKCE `code_verifier` as
  `invalid_request`. PKCE enforcement is challenge-based:
  `Token.fetch_code_verifier/3` passes the verifier through to
  `Attesto.AuthorizationCode.redeem/4`, which requires a matching verifier for a
  challenge-bound code and collapses a missing OR mismatched verifier to a single
  `invalid_grant` (RFC 7636 §4.6). The authorization/PAR endpoint still requires a
  `code_challenge` for clients that must use PKCE (`RequestPolicy.require_pkce?/2`),
  so a challenge-bound code is always issued. Matches the FAPI
  ensure-pkce-code-verifier-required test (it expects `invalid_grant`).

## [0.7.5] - 2026-06-10

Requires `attesto ~> 0.6.13`.

### Security

- **PAR `request_uri` is now single-use (RFC 9126 §2.2 / FAPI 2.0).** The
  reference is consumed once an authorization code is issued (not on the
  non-consuming `fetch` that lets the host establish login/consent and
  re-enter), so a completed flow cannot be replayed within the remaining TTL.
  An already-consumed reference is rejected as `invalid_request_uri`. (Flips the
  conformance `PARAttemptReuseRequestUri` warning to a clean pass.)
- **UserInfo derives the DPoP `htu` via `RequestContext.canonical_url`**, like
  every other endpoint — honouring a configured `:htu` but otherwise gating
  `X-Forwarded-*`/Host on the trusted-proxy allowlist. Previously it fell back
  to the raw request Host when `:htu` was unset (its default), the one endpoint
  that bypassed the host-header trust boundary.

### Fixed

- **Sender-constrained (DPoP/mTLS) clients now require PKCE.** A FAPI 2.0 client
  is sender-constrained, and FAPI 2.0 Security Profile §5.3.1.2 / RFC 9700
  §2.1.1 mandate PKCE for it even though it authenticates confidentially (e.g.
  `private_key_jwt`). `RequestPolicy.require_pkce?/2` now forces PKCE whenever
  `client_requires_dpop?`/`client_requires_mtls?` is true, regardless of the
  global `:require_pkce` flag, and the token endpoint enforces the matching
  `code_verifier` through that same predicate (one source of truth, so the
  authorization and token endpoints cannot drift). A plain confidential
  Basic-profile client still follows the global flag. (Flips the conformance
  `EnsurePKCERequired` test to a pass.)

## [0.7.4] - 2026-06-04

Requires `attesto ~> 0.6.13`.

### Security / FAPI 2.0 conformance

Closes four conformance gaps found by auditing the OpenID FAPI 2.0 test suite
source against the implementation:

- **PAR `request_uri` is bound to the client.** The authorization endpoint now
  rejects a front-channel `client_id` that does not match the client the
  `request_uri` was issued to (RFC 9126 §2.2 / `PAREnsureRequestUriIsBoundToClient`)
  instead of silently using the stored client.
- **Unknown/expired PAR `request_uri` → `invalid_request_uri`.** A
  `urn:ietf:params:oauth:request_uri:` reference not in the store now returns the
  correct `invalid_request_uri` error rather than falling through to
  `request_uri_not_supported`/`invalid_request` (RFC 9126 §2.2 /
  `PARAttemptToUseExpiredRequestUri`). External (non-PAR) references still report
  `request_uri_not_supported`.
- **PAR rejects a `request_uri` parameter.** The PAR endpoint rejects a request
  carrying `request_uri` (RFC 9126 §2.1 step 2), checked on the raw parameters so
  it cannot be masked by a `request` object replacing the set.
- **Client-assertion audience is issuer-only.** `private_key_jwt` assertions at
  the token, PAR, and introspection endpoints must be audienced to the issuer
  identifier (FAPI 2.0 §5.3.2.1); the concrete endpoint URL is no longer accepted
  as `aud`, closing a confused-deputy gap (`PAREndpointAsAudienceFails`).

### Changed

- `:authorization_response_iss` now defaults to **`true`** (RFC 9207
  authorization-server mix-up defense, mandated by FAPI 2.0). Set `false` to opt
  out. Discovery advertises `authorization_response_iss_parameter_supported`
  accordingly.
- Internal: `mix dialyzer` is clean again. `token.ex` resolves `:principal_kinds`
  by reading the struct field directly (its type admits a list, unlike the
  `callback() | nil` reader), and two fail-closed grant-pipeline clauses are
  documented in `.dialyzer_ignore.exs`. No behaviour change.

## [0.7.3] - 2026-06-04

The FAPI 2.0 Message Signing endpoints on the Phoenix layer: signed
authorization responses (JARM), the RFC 7662 / RFC 9701 introspection endpoint,
and PAR/JAR hardening. Requires `attesto ~> 0.6.13`.

### Added

- `POST /oauth/introspect` — OAuth 2.0 Token Introspection (RFC 7662) with the
  RFC 9701 signed-JWT response (FAPI 2.0 Message Signing §5.5). Authenticates
  the caller through the shared `AttestoPhoenix.ClientAuthentication` core
  (`client_secret_basic`/`client_secret_post`/`private_key_jwt`), introspects
  via the conn-free `Attesto.Introspection`, and negotiates by `Accept` between
  the plain JSON response and `application/token-introspection+jwt`.
- `:introspection_authorize` Config callback `(caller_client_id, response ->
  boolean)` — authorizes the authenticated introspection caller against the
  token (RFC 7662 §4 / RFC 9701 §5). Consulted only for an active response;
  a non-`true` return (or a raise) downgrades the response to
  `%{"active" => false}` so a caller not entitled to the token learns nothing
  about it. Optional — when unset, every authenticated caller may introspect
  any token (the single-trust-domain default).
- The authorization endpoint emits JARM (§5.4) responses for the JARM
  `response_mode`s (`jwt`/`query.jwt`/`fragment.jwt`/`form_post.jwt`), and the
  discovery documents advertise the supported `response_modes_supported`,
  `authorization_signing_alg_values_supported`, the introspection endpoint, and
  its signing-algorithm metadata.

### Changed

- The PAR endpoint now validates the pushed request as an authorization request
  at push time (RFC 9126 §2.1 step 3): the request `redirect_uri` must exactly
  match one of the client's registered URIs (RFC 6749 §3.1.2.3), and the
  `response_type`/PKCE/`response_mode` must be valid, so an invalid request is
  refused early rather than only when the `request_uri` is later resolved at
  `/authorize`. The redirect-URI/PKCE/nonce policy is resolved by the new
  conn-free `AttestoPhoenix.AuthorizationServer.RequestPolicy`, shared with the
  authorization endpoint so both validate identically. **A host that mounts the
  PAR endpoint must configure `:client_redirect_uris`** (the authorization
  endpoint already required it).
- `AttestoPhoenix.ClientAuthentication.Result.client_id` falls back to the
  presented credential identifier so the signed-introspection audience (and the
  PAR/token client identity) resolves without a separate `:client_id` callback.
- OpenID Provider Metadata derives `request_parameter_supported` (and only then
  advertises `request_object_signing_alg_values_supported`) from actual
  request-object capability — whether the host can resolve a client's trusted
  JWKS (a `:client_jwks` callback or an installed `:client_store`). An install
  without that capability now advertises `request_parameter_supported: false`
  instead of a JAR support it cannot honour.
- The OAuth 2.0 Authorization Server Metadata document (RFC 8414) now advertises
  the signed-request-object metadata (`require_signed_request_object` and
  `request_object_signing_alg_values_supported`, RFC 9101 §10.5), matching the
  OpenID Provider Metadata document so a FAPI client reading either sees
  identical JAR support. Both documents derive it from the new conn-free
  `AttestoPhoenix.AuthorizationServer.RequestObjectMetadata` (no more split,
  drift-prone assembly).
- `AttestoPhoenix.Config` now rejects at boot a `:request_object_policy` that
  requires a signed request object (e.g. `Policy.fapi_message_signing/0`) when
  no `:client_jwks` capability is configured. Such a config is unsatisfiable
  (every authorization request would be rejected) and would otherwise advertise
  the incoherent pair `request_parameter_supported: false` +
  `require_signed_request_object: true`. Pair the policy with `:client_jwks`
  (or an installed `:client_store`).

## [0.7.2] - 2026-06-03

### Added

- `:request_object_policy` Config key (an `Attesto.RequestObject.Policy`,
  default `%Policy{}` = generic OpenID Connect §6.1). It is enforced at BOTH
  the PAR endpoint and `/authorize`: a signed request object pushed to `/par`
  is verified there (rejected with `invalid_request_object` if it fails the
  policy), and re-verified at `/authorize` (RFC 9101). On success the PAR store
  holds the VERIFIED request-object parameters, never the unsigned body values
  beside them (RFC 9101 §6.3). A non-`%Attesto.RequestObject.Policy{}` value is
  rejected at boot. Set
  `Attesto.RequestObject.Policy.fapi_message_signing()` for the FAPI 2.0
  Message Signing §5.3.1 profile (`nbf`/`exp` required and bounded to 60
  minutes, `typ` = `"oauth-authz-req+jwt"`). Behaviour is unchanged unless a
  host opts in. Requires `attesto ~> 0.6.12`.

## [0.7.1] - 2026-06-03

### Added

- `:client_auth_signing_algs` Config key — the JOSE algorithms accepted for
  `private_key_jwt` client-assertion signatures, threaded into
  `Attesto.ClientAssertion.verify/5` (via its `:accepted_algs` opt) and also
  rendered as `token_endpoint_auth_signing_alg_values_supported` in discovery.
  Defaults to `Attesto.SigningAlg.fapi_algs/0` (PS256, ES256, EdDSA), so
  behaviour is unchanged unless a host overrides it. Verification and the
  advertised metadata now read this one value and cannot drift. Requires
  `attesto ~> 0.6.11`.

## [0.7.0] - 2026-06-03

A structural refactor of the token/PAR controllers into a reusable
authorization-server core, plus a behaviour-module install surface and several
correctness fixes. Pre-1.0 minor bump because it carries breaking changes to
the host-callback contract (see **BREAKING** below).

### Added

- Behaviour-module install for host callbacks. The Config keys `:client_store`,
  `:principal_store`, `:consent_policy`, `:scope_policy`, `:event_sink`,
  `:registration`, and `:claims_provider` each resolve their callbacks from a
  single installed module. Precedence is fixed: an explicit flat callback key
  wins; else the installed behaviour module if it exports the callback; else
  `nil`. The required capabilities (`load_client`, `verify_client_secret`,
  `load_principal`) are validated by *resolution* at boot, so a
  behaviour-module-only install works. Boot-time conformance validation fails
  fast on a typo'd or partial module.
- `AttestoPhoenix.ClaimsProvider` behaviour — the host UserInfo/ID-Token claim
  source (`build_userinfo_claims/3`, `build_id_token_claims/4`).
- `AttestoPhoenix.Callback` — one callback dispatcher (function / `{m,f}` /
  `{m,f,extra}`), replacing ~10 duplicated private `invoke/2` helpers.
- `AttestoPhoenix.ClientAuthentication` and
  `AttestoPhoenix.AuthorizationServer.{SenderConstraint, Token, PAR}` — conn-free
  core modules. The token and PAR controllers are now thin adapters that lift
  conn facts into data, call the core, and render; the core returns data and
  audit events rather than writing the conn or emitting events.

### Changed

- **BREAKING:** the ID-Token extra-claims source is now the separate
  `:build_id_token_claims` callback (`(client, subject, granted_scopes,
  requested_claims -> map)`, and it MUST NOT carry `sub`). Previously the
  4-arity form of `:build_userinfo_claims` doubled as the ID-Token source;
  `:build_userinfo_claims` is now the 3-arity UserInfo source only. Hosts that
  wired a 4-arity `:build_userinfo_claims` must move it to
  `:build_id_token_claims`.
- **BREAKING:** `AttestoPhoenix.ClaimsProvider` no longer declares
  `build_principal/3`; principal building stays solely on
  `AttestoPhoenix.PrincipalStore`. Claim sourcing and principal loading are
  separate concerns.
- Client-assertion `aud` now accepts the issuer **or** the concrete token/PAR
  endpoint URL (RFC 7523 / OIDC Core §9), widened from issuer-only. The endpoint
  URL is derived from trusted Config (issuer + path), never the request Host.
  Still FAPI 2 valid (the issuer remains accepted).
- Client authentication (RFC 6749 §2.3.1): a request-body `client_id` presented
  alongside HTTP Basic is accepted as identification when it matches the Basic
  userid, and rejected as `invalid_request` when it conflicts. Only a second
  *credential* (body `client_secret` or `client_assertion`) is treated as a
  competing authentication method. The token and PAR endpoints now share one
  client-authentication implementation, so they no longer diverge.
- PAR stores the resolved authenticated `client_id`; when no `:client_id`
  callback is configured it leaves the request's presented `client_id` intact
  rather than clobbering it. The opaque-struct `client[:id]`/`client["id"]`
  fallback is removed.

## [0.6.23] - 2026-06-02

### Changed

- Require the client-authentication assertion `aud` to be the issuer identifier
  at both the token and PAR endpoints (FAPI 2). The endpoint URL is no longer
  accepted as an audience. Requires `attesto ~> 0.6.10`.

## [0.6.22] - 2026-06-02

### Changed

- Advertise only the FAPI 2 client-authentication signing algorithms
  (`PS256`, `ES256`, `EdDSA`) in `token_endpoint_auth_signing_alg_values_supported`,
  matching the underlying enforcement in attesto 0.6.9 which rejects RS256
  client assertions. Requires `attesto ~> 0.6.9`.

## [0.6.21] - 2026-06-02

### Fixed

- Return the standard OAuth token endpoint error `invalid_request` when a
  client that requires DPoP omits the proof entirely. Presented-but-invalid
  proofs still return `invalid_dpop_proof`; the omitted-proof case now matches
  FAPI's expected token endpoint error classification.

## [0.6.20] - 2026-06-02

### Added

- Add `:refresh_token_rotation_grace_seconds` to `AttestoPhoenix.Config` and
  pass it through to `Attesto.RefreshToken.rotate/3`. The default is now a
  FAPI retry-compatible 60-second idempotency window for retrying a
  just-rotated refresh token when the client did not receive or persist the
  first rotation response; set `0` for strict immediate reuse revocation.

## [0.6.19] - 2026-06-02

### Fixed

- Bind refresh tokens to the DPoP proof key only for public clients, as
  required by RFC 9449. Confidential clients keep refresh tokens bound to the
  authenticated client, allowing a later refresh request to use a fresh DPoP
  proof key while still minting the returned access token as DPoP-bound to that
  current proof.

## [0.6.18] - 2026-06-02

### Added

- Add `:client_requires_dpop?` as a host callback so deployments can mark a
  client as requiring DPoP-bound token issuance. When such a client calls the
  token endpoint without a DPoP proof, the controller now rejects the request
  with `invalid_dpop_proof` rather than silently issuing an unbound Bearer
  token.

## [0.6.17] - 2026-06-02

### Fixed

- Treat a resolved PAR `request_uri` as the complete authorization request, so
  front-channel parameters outside the pushed request object do not augment the
  request. In particular, a `state` query parameter that was not included in the
  pushed request is no longer echoed in the authorization response.

## [0.6.16] - 2026-06-02

### Fixed

- Allow PAR requests to carry an explicit `dpop_jkt` without also requiring a
  DPoP proof on the PAR request itself. If a PAR DPoP proof is present, an
  explicit `dpop_jkt` must still match that proof; otherwise the stored
  thumbprint is later enforced when the authorization code is redeemed.

## [0.6.15] - 2026-06-02

### Fixed

- Carry the DPoP JWK thumbprint from a pushed authorization request into the
  issued authorization code. A token request that redeems the code with a
  different DPoP proof key is now rejected instead of minting a token bound to
  the later key.

## [0.6.14] - 2026-06-01

### Fixed

- Verify DPoP proofs at the PAR endpoint and bind stored pushed
  authorization requests to the verified proof key. If a PAR request includes
  an explicit `dpop_jkt`, it must match the verified proof JWK thumbprint;
  mismatches now return `invalid_dpop_proof` instead of issuing a
  `request_uri`.

## [0.6.13] - 2026-06-01

### Fixed

- Accept `private_key_jwt` client assertions whose `aud` is the issuer at the
  token endpoint and PAR endpoint, while continuing to accept endpoint-specific
  audiences and reject unrelated audiences. This matches FAPI conformance suite
  client-authentication behavior without relaxing signature, `iss`/`sub`, `jti`,
  or replay checks.

## [0.6.12] - 2026-06-01

### Security

- Reject replayed `private_key_jwt` client assertions at the token endpoint and
  PAR endpoint by recording assertion `jti` values through the configured
  replay check.
- Enforce per-client registered grant types when a host provides
  `:client_grant_types`, preventing a client registered for one grant from
  minting tokens through another.
- Bind PAR `request_uri` authorization requests to the authenticated pushed
  request client and store that authenticated client id, rather than trusting a
  front-channel or body-supplied `client_id`.

### Fixed

- Preserve keystore-provided per-key `alg` metadata in the JWKS endpoint. This
  keeps FAPI deployments that sign ID tokens with `PS256` from advertising the
  same key as `RS256`.
- Add the zero-arity `issue/0` entrypoint to the Ecto DPoP nonce store so
  server-issued DPoP nonces work when the store is configured directly as a
  behaviour module.
- Decode form-encoded client id and secret values in revocation endpoint Basic
  authentication, matching the token endpoint.
- Make the default ETS PAR store tolerate concurrent first-use table creation.

## [0.6.11] - 2026-06-01

### Fixed

- Resolve PAR `request_uri` references non-destructively at the authorization
  endpoint, so host login or consent re-entry can complete without consuming the
  pushed request before authorization-code issuance.

### Changed

- Add a `fetch` callback to `AttestoPhoenix.PARStore` for authorization-endpoint
  resolution. Existing custom stores that only implement `take/1` still work
  through a compatibility fallback, but new stores should implement `fetch/1`.

## [0.6.10] - 2026-06-01

### Fixed

- Treat an explicit `nil` `:par_store` config value as unset when applying the
  default ETS PAR store. This prevents PAR from calling `nil.put/3` when hosts
  enable pushed authorization requests without overriding the development PAR
  store.
- Apply the same nil-aware defaulting to authorization-endpoint PAR resolution.

## [0.6.9] - 2026-06-01

### Added

- Advertise FAPI-required discovery metadata when configured:
  `authorization_response_iss_parameter_supported: true` when RFC 9207
  authorization-response `iss` is enabled, and
  `token_endpoint_auth_signing_alg_values_supported` from Attesto's asymmetric
  signing algorithm set for `private_key_jwt` clients.

## [0.6.8] - 2026-06-01

### Added

- Add host-configurable FAPI-oriented authorization-server controls:
  `:require_pushed_authorization_requests` rejects direct front-channel
  authorization requests unless they arrive through a PAR `request_uri`, and
  `:authorization_response_iss` includes the RFC 9207 `iss` parameter on
  successful and error authorization responses.
- Allow hosts to configure the advertised and accepted token endpoint client
  authentication methods. The token endpoint and PAR endpoint now enforce
  `:token_endpoint_auth_methods_supported` when set, so deployments can expose
  stricter profiles such as `private_key_jwt` only.
- Advertise configured token endpoint authentication methods and PAR-required
  policy in OAuth/OIDC metadata.

## [0.6.7] - 2026-06-01

### Added

- Mount `POST /oauth/authorize` alongside `GET /oauth/authorize`, matching
  OpenID Connect Core's requirement that the Authorization Endpoint support both
  methods.
- Extend the Ecto authorization-code store with successful-consumption markers
  and issued-access-token tracking. When a successfully redeemed authorization
  code is replayed, the token endpoint still returns `invalid_grant` and now
  revokes the access token minted by the original code redemption when the Ecto
  store is configured.

## [0.6.6] - 2026-06-01

### Fixed

- Dynamic client registration now preserves inline `jwks` metadata (RFC 7591
  §2) and hands it to the host `:register_client` callback. Hosts can then
  return those keys through `:client_jwks` for request-object and
  `private_key_jwt` verification.

## [0.6.5] - 2026-06-01

### Fixed

- Return a clean `request_uri_not_supported` authorization response for
  unsupported OIDC `request_uri` references when no PAR store is configured,
  instead of calling a nil PAR store.

## [0.6.4] - 2026-05-31

### Changed

- Replace the direct `jason` dependency with Elixir's built-in `JSON` module.

### Added

- Add a test-only `req_dpop` compatibility check proving that
  `AttestoPhoenix.Plug.Authenticate` accepts RFC 9449 DPoP proofs generated by
  an external Req client plugin. `req_dpop` is not a runtime dependency.
- Document `req_dpop` as an optional Req client companion for tests and
  internal tooling.

## [0.6.3] - 2026-05-31

### Added

- `mix attesto_phoenix.install`, an upgrade-aware Igniter installer. It is
  idempotent and re-runnable: it adds the `AttestoPhoenix.Config` config skeleton
  (issuer, keystore, repo, the Ecto-backed token stores, a chosen
  `:oauth_path_prefix`, and neutral defaults) to the host config, mounts
  `attesto_routes/1` at the chosen prefix into the host router, scaffolds host
  callback modules implementing the recommended behaviours (`ClientStore`,
  `PrincipalStore`, `ScopePolicy`, `ConsentPolicy`, `RegistrationStore`,
  `EventSink`) with documented stub callbacks, and points the host at
  `mix attesto_phoenix.gen.migration` for the Ecto tables. `igniter` is declared
  as an optional dependency, so the runtime package never forces it on consumers;
  the task is available to a host that opts into running it. Options:
  `--oauth-path-prefix` and `--callbacks-module`.

- Configurable OAuth endpoint paths. `AttestoPhoenix.Config` now accepts an
  `:oauth_path_prefix` (default `"/oauth"`, reproducing the historic surface)
  plus explicit per-endpoint overrides (`:authorize_path`, `:token_path`,
  `:par_path`, `:revocation_path`, `:registration_path`, `:userinfo_path`) that
  win when set. Resolver helpers (`token_endpoint_url/1`, `par_endpoint_url/1`,
  `revocation_endpoint_url/1`, `registration_endpoint_url/1`,
  `userinfo_endpoint_url/1`, `authorize_endpoint_url/1`, `jwks_uri/1`,
  `registration_client_uri/2`, and the `*_path/1` helpers) build absolute URLs
  from the issuer and the resolved path. The discovery (RFC 8414),
  OpenID-configuration (OpenID Connect Discovery), and registration (RFC 7591 /
  RFC 7592) controllers read every advertised URL from these resolvers instead
  of hardcoding `/oauth/*`, and `to_attesto_config/2` passes the resolved token
  path to the core builder automatically so the DPoP `htu` follows the mount.
  A host that mounts under `/mcp/oauth` now advertises correct URLs.
- Named host-contract behaviours documenting the full callback contract with
  the governing RFC for each callback, as the recommended production shape:
  `AttestoPhoenix.ClientStore`, `AttestoPhoenix.PrincipalStore`,
  `AttestoPhoenix.ScopePolicy`, `AttestoPhoenix.ConsentPolicy`,
  `AttestoPhoenix.RegistrationStore`, and `AttestoPhoenix.EventSink`. Wiring is
  unchanged: pass an anonymous function, a `{module, function}` pair, or a
  `{module, function, extra_args}` triple per `AttestoPhoenix.Config` key.
- Dynamic registration metadata passthrough (RFC 7591 §2). The registration
  endpoint now validates and carries the known client-identity members
  (`client_name`, `client_uri`, `logo_uri`, `contacts`, `policy_uri`,
  `tos_uri`, and related software/JWKS members) through to `:register_client`
  so consent screens keep the client's identity. Unknown members are dropped
  and never promoted to trusted policy; known members are merged under the
  validated protocol-critical members so they cannot override them.
- Actionable `AttestoPhoenix.Config.new/1` validation errors that name the
  callback/store/path to add for each enabled feature, and absolute-path
  validation for `:oauth_path_prefix` and the per-endpoint overrides.
- Operations guides wired into the published docs: `replay_nonce_production.md`,
  `proxy_canonical_host.md`, `error_envelope.md`, `consumer_migration.md`, and
  `examples.md`.

## [0.6.2]

- Advertise `response_modes_supported: ["query"]` from the RFC 8414 OAuth
  Authorization Server Metadata endpoint, matching the authorization-code
  redirect response mode already used by the Phoenix authorization endpoint.

## [0.6.1]

- Emit `:token_denied` audit/telemetry events for token endpoint failures,
  including OAuth error, status, client/grant/scope context when available, and
  sender-constraint presence.
- Normalize Phoenix callback specs before handing `:cert_der` to core Attesto
  protected-resource verification, so function captures, `{Module, function}`,
  and `{Module, function, extra_args}` all work consistently.

## [0.6.0]

Initial release: a Phoenix/Ecto OAuth 2.0 / OIDC authorization server layer
over [attesto](https://hex.pm/packages/attesto).

### Added

- `AttestoPhoenix.Config`: centralized, validated configuration with neutral
  host callbacks (`:load_client`, `:verify_client_secret`, `:load_principal`,
  `:authorize_scope`, `:on_event`, and others), deriving the `Attesto.Config`
  the protocol layer consumes.
- `AttestoPhoenix.Router`: the `attesto_routes/1` macro mounting the token,
  revocation, discovery, JWKS, and optional dynamic-registration endpoints.
- Controllers for the token endpoint (`authorization_code`, `refresh_token`,
  and `client_credentials` grants), revocation (RFC 7009), discovery
  (RFC 8414), JWKS (RFC 7517), and optional dynamic client registration
  (RFC 7591).
- `AttestoPhoenix.Plug.Authenticate` and `AttestoPhoenix.Plug.RequireScopes`
  protected-resource plugs with DPoP and mTLS sender-constraint enforcement.
- Ecto-backed implementations of the attesto store behaviours: code store,
  refresh store (rotation with reuse detection), DPoP nonce store, and DPoP
  `jti` replay check, plus an optional TTL sweeper.
- `mix attesto_phoenix.gen.migration` to generate the operational tables.
- Pushed Authorization Requests (PAR, RFC 9126), `private_key_jwt` client
  authentication, signed request object validation, token exchange, UserInfo,
  registration management cleanup, and Phoenix resource-server plugs.
