# AttestoPhoenix

[![Hex.pm](https://img.shields.io/hexpm/v/attesto_phoenix)](https://hex.pm/packages/attesto_phoenix)
[![Hexdocs.pm](https://img.shields.io/badge/docs-hexdocs.pm-blue)](https://hexdocs.pm/attesto_phoenix)
[![Elixir CI](https://github.com/XukuLLC/attesto_phoenix/actions/workflows/elixir.yml/badge.svg)](https://github.com/XukuLLC/attesto_phoenix/actions/workflows/elixir.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](https://github.com/XukuLLC/attesto_phoenix/blob/main/LICENSE)
[![Elixir](https://img.shields.io/badge/elixir-%E2%89%A5%201.18-purple)](https://elixir-lang.org)
[![OpenID Certified](https://img.shields.io/badge/OpenID-Certified-F78C40)](https://openid.net/certification/certified-openid-connect-implementations/)

An opinionated Phoenix/Ecto OAuth 2.0 / OIDC authorization server on top of
[attesto](https://hex.pm/packages/attesto).

For a batteries-included authenticated MCP server integration, use
[`attesto_mcp_server`](https://hex.pm/packages/attesto_mcp_server). It reuses
AttestoPhoenix issuer, verification, revocation, principal, DPoP, and mTLS
policy.

<a href="https://openid.net/certification/certified-openid-connect-implementations/"><img src="https://openid.net/wordpress-content/uploads/2016/04/oid-l-certification-mark-l-rgb-150dpi-90mm.png" alt="OpenID Certified" width="180" align="right"></a>

An authorization server built from `attesto` + `attesto_phoenix` is
[OpenID Certified](https://openid.net/certification/certified-openid-connect-implementations/)
to **FAPI 2.0 Security Profile Final — OP**, **FAPI 2.0 Message
Signing Final — OP**, **FAPI-CIBA — OP**, **OpenID Connect Basic — OP** and
**Config — OP**, **RP-Initiated**, **Back-Channel**, and **Front-Channel
Logout — OP**, and **Session Management — OP** — the first Elixir provider with
FAPI 2.0 certification.

[![FAPI 2.0 Certified](https://img.shields.io/badge/FAPI_2.0-Certified-F78C40)](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/)
[![FAPI-CIBA Certified](https://img.shields.io/badge/FAPI--CIBA-Certified-F78C40)](https://openid.net/certification/certified-fapi-ciba-openid-providers-profiles/)
[![OpenID Connect Certified](https://img.shields.io/badge/OpenID_Connect-Certified-F78C40)](https://openid.net/certification/certified-openid-providers-profiles/)
[![Logout Profiles Certified](https://img.shields.io/badge/Logout_Profiles-Certified-F78C40)](https://openid.net/certification/certified-openid-providers-for-logout-profiles/)
[![Session Management Certified](https://img.shields.io/badge/Session_Management-Certified-F78C40)](https://openid.net/certification/certified-openid-providers-for-logout-profiles/)

**attesto brings the protocol, attesto_phoenix brings transport + persistence;
you bring principals, keys, and policy.**

`attesto` is a transport-agnostic library of OAuth/OIDC primitives: JWT access
tokens, JWKS/key handling, DPoP, mTLS, PKCE, scope algebra, private-key client
assertions, signed request objects, JARM response JWTs, token introspection
primitives, and the token-lifecycle building blocks.
`attesto_phoenix` wires those primitives into a running server:

- HTTP endpoints (authorization, token, PAR, revocation, discovery, JWKS,
  UserInfo, protected-resource metadata, optional dynamic registration, plus the
  opt-in CIBA backchannel-authentication, device-authorization, end-session
  (RP-Initiated Logout), and check-session endpoints) mounted into your router
  with one macro. The authorization endpoint supports the default query response
  mode and the JARM JWT response modes; Back-Channel and Front-Channel Logout run
  alongside the end-session flow.
- Protected-resource plugs that verify Bearer JWTs and enforce DPoP / mTLS
  sender-constraint binding.
- Ecto-backed implementations of every mutable store the OAuth/OIDC flows need
  — authorization codes, refresh tokens, DPoP nonces, DPoP proof `jti` replay
  records, and Pushed Authorization Request (PAR) references — so a clustered or
  load-balanced deployment keeps no OAuth state per node.

Attesto owns the standards route catalog and protocol controllers; the host
chooses route mounts and route pipeline classes declaratively. It
deliberately does **not** own your client registry, principal store, secret
hashing, scope catalog, resource-owner authentication, consent, or audit log.
Those are application policy and are supplied through neutral configuration
callbacks.

## What you can build with it

- **An API that AI assistants can connect to.** Assistant connectors — ChatGPT,
  Claude — authorize through OAuth: PKCE, dynamic client registration, pushed
  authorization requests, sender-constrained tokens, and protected-resource
  discovery. `attesto_phoenix` mounts that whole surface with one router macro,
  so your app can expose tools and data to an assistant without hand-rolling an
  OAuth server. Pair it with
  [`attesto_mcp_server`](https://hex.pm/packages/attesto_mcp_server) for the MCP
  server, Phoenix installer, protected-resource metadata, and Attesto-backed
  authorization. Applications with a custom MCP transport can instead use the
  lower-level [`attesto_mcp`](https://hex.pm/packages/attesto_mcp) boundary.
- **Your own authorization server.** Issue short-lived, scoped JWT access tokens
  and OIDC ID tokens for first-party apps and machine clients, instead of
  outsourcing to a hosted identity provider.
- **A resource server that resists stolen tokens.** Verify access tokens locally
  — signature, issuer, audience, and DPoP / mTLS sender-constraint — with no
  token database or introspection call on the hot path, so a leaked bearer token
  alone can't call the API.
- **An EU digital-identity credential issuer and verifier.** Mount the
  OpenID4VCI issuer and OpenID4VP verifier endpoints for SD-JWT VC and ISO mdoc
  credentials — credential offers, the credential/nonce endpoints, DCQL
  presentation requests, `direct_post` responses, and Token Status List
  revocation — targeting the HAIP profile. See
  [OpenID for Verifiable Credentials](#openid-for-verifiable-credentials-oid4vc--eu-wallet).

The standards each use case rests on are catalogued below and in
[the `attesto` core README](https://github.com/XukuLLC/attesto#rfc-coverage);
you don't need to track them to use the library.

## Positioning vs. attesto core

| Concern | `attesto` (core) | `attesto_phoenix` (this package) |
| --- | --- | --- |
| JWT mint/verify, JWKS, DPoP, mTLS, PKCE, scopes | yes | reuses core |
| `private_key_jwt`, signed request objects, JARM, token exchange primitives | yes | wires into endpoints |
| Grant orchestration primitives | yes | reuses core |
| HTTP endpoints + router macro | no | yes |
| Protected-resource plugs | core plug building blocks | Phoenix-friendly wrappers |
| Ecto-backed token stores | store *behaviours* only | Ecto *implementations* |
| Client registry, principals, keys, audit | no | supplied via callbacks |

If you only need the protocol primitives and want to build your own transport,
depend on `attesto` directly. If you want a batteries-included Phoenix
authorization server, use `attesto_phoenix`.

## Contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Mounting the routes](#mounting-the-routes)
  - [OpenID for Verifiable Credentials (OID4VC / EU wallet)](#openid-for-verifiable-credentials-oid4vc--eu-wallet)
- [Protecting resources](#protecting-resources)
- [Database migration](#database-migration)
- [Guides and examples](#guides-and-examples)
- [Development](#development)
- [License](#license)

## Installation

Add `attesto_phoenix` to your dependencies:

```elixir
def deps do
  [
    {:attesto_phoenix, "~> 2.0"}
  ]
end
```

The optional Igniter installer needs `igniter` available while you run it. It is
not a runtime dependency of this package:

```elixir
def deps do
  [
    {:attesto_phoenix, "~> 2.0"},
    {:igniter, "~> 0.5", only: [:dev], runtime: false}
  ]
end
```

## Quick start

For a new Phoenix app, start with the installer. It is idempotent and writes the
host-owned callback modules as stubs rather than guessing your client registry,
principal model, or authorization policy.

```bash
mix deps.get
mix attesto_phoenix.install
mix attesto_phoenix.gen.migration --repo MyApp.Repo
mix ecto.migrate
```

Use `--oauth-path-prefix` when the OAuth endpoints should not live under
`/oauth`:

```bash
mix attesto_phoenix.install --oauth-path-prefix /mcp/oauth
```

After the installer runs, fill in the generated callback modules and configure a
keystore. The rest of this README shows the same pieces explicitly so you can
review what the installer generated or wire them by hand.

## Configuration

All behavior is centralized in `AttestoPhoenix.Config`. Anything that is
inherently application policy is a neutral callback rather than a baked-in
assumption.

```elixir
# Points controllers and Ecto-backed stores at the host application.
config :attesto_phoenix,
  otp_app: :my_app,
  repo: MyApp.Repo

config :my_app, AttestoPhoenix.Config,
  # --- required ---
  issuer: "https://auth.example.com",
  audience: "https://api.example.com",
  keystore: MyApp.Keystore,            # implements Attesto.Keystore
  repo: MyApp.Repo,                    # Ecto.Repo for the token stores
  principal_kinds: {MyApp.OAuth.PrincipalStore, :principal_kinds},

  # host policy modules (preferred install surface)
  client_store: MyApp.OAuth.ClientStore,
  principal_store: MyApp.OAuth.PrincipalStore,
  scope_policy: MyApp.OAuth.ScopePolicy,
  consent_policy: MyApp.OAuth.ConsentPolicy,
  claims_provider: MyApp.OIDC.ClaimsProvider,
  event_sink: MyApp.OAuth.Events,

  # --- optional policy ---
  scopes_supported: ["profile", "email", "read:*", "write:*"],
  send_error: &MyApp.OAuthErrors.render/3,
  #   (conn, status, body_map -> conn), optional custom OAuth error envelope
  client_auth_signing_algs: Attesto.SigningAlg.fapi_algs(),
  client_auth_enforce_fapi_alg_policy: true,
  request_object_policy: Attesto.RequestObject.Policy.generic(),

  # --- optional deployment + features ---
  # Incoming request transport gate only; issuer and advertised endpoint URLs
  # remain HTTPS-only regardless of this value.
  require_https: true,
  trusted_proxies: ["10.0.0.0/8"],     # honor X-Forwarded-* only from these
  access_token_ttl: 900,
  refresh_token_ttl: 1_209_600,
  authorization_code_ttl: 60,
  authorization_grant_id_claim: "https://api.example.com/claims/oauth_grant_id",
  dpop_enabled: true,
  dpop_nonce_required: false,
  mtls_enabled: false,                 # RFC 8705 certificate-bound tokens
  # The terminator must overwrite, never append/forward, the client-cert header.
  # This callback is invoked only from trusted_proxies:
  forwarded_cert_der: &MyApp.TLS.forwarded_client_cert_der/1,
  client_certificate_chain_validated?: &MyApp.TLS.chain_validated?/2,
  token_endpoint_auth_methods_supported: ["private_key_jwt", "tls_client_auth"],
  client_mtls_metadata: &MyApp.OAuth.Clients.mtls_metadata/1,
  mtls_endpoint_aliases: %{
    "token_endpoint" => "https://mtls.auth.example.com/oauth/token"
  },
  registration_enabled: false,         # if true, also set registration callbacks

  # RFC 8707 resource indicators (optional; see below)
  resource_indicators: [
    allowed_resources: ["https://api.example.com/a", "https://api.example.com/b"],
    allowed_resources_for: {MyApp.OAuth, :resources_for}  # optional per-client (client -> [uri])
  ]
```

Build the validated struct wherever you need it:

```elixir
config = AttestoPhoenix.Config.from_otp_app(:my_app)
```

Required keys are validated at build time so misconfiguration fails fast.
`AttestoPhoenix.Plug.PutConfig` performs that resolution for mounted routes and
places both the host config and its derived `Attesto.Config` in `conn.private`.
Direct mTLS adapters expose the authenticated certificate through peer data;
TLS terminators configure `:forwarded_cert_der` plus `:trusted_proxies`.

### Authorization-grant identity

Set `:authorization_grant_id_claim` when a protected resource needs a stable
signed correlation handle for access tokens descended from one authorization
code:

```elixir
config :my_app, AttestoPhoenix.Config,
  authorization_grant_id_claim: "https://api.example.com/claims/oauth_grant_id"
```

The feature is disabled by default. When configured, Attesto Phoenix generates
a 128-bit authorization family ID (22 unpadded Base64URL characters), stores it
as the authorization code's `family_id`, and signs that exact value into the
initial and refreshed access tokens. Refresh rotation and lost-response retry
preserve the family ID while every access token receives a fresh `jti`.

Within access tokens the library owns the value: host principal/code claims
cannot replace it, and other grant types strip the configured claim instead of
signing a fabricated or inherited value. That ownership is access-token
specific — `:build_id_token_claims` and `:build_userinfo_claims` are trusted
host callbacks whose output is not filtered, so a host that stamps the same
claim name into an ID Token or UserInfo response owns that value itself. An
authorization-code grant that does not issue a refresh token still receives the
access-token claim but creates no refresh row.

A code issued without a `family_id` — possible only when a host mints codes
itself rather than through the authorization endpoint — is permanently
ineligible. Neither its initial nor any refreshed access token carries the
claim, so claim presence never changes within one family. Redemption may still
create an internal refresh family. Refresh-token rotation continues normally,
and refresh-token reuse detection continues to revoke that family.
Authorization-code replay, however, cannot revoke it: the code carries no
`family_id` linking it to the descendant family, so there is nothing for reuse
detection to match on. The
claim is a
correlation handle, not proof that a refresh family exists or remains active.
No migration is required because issuance reuses the existing `family_id`
fields. Use a private claim name under a namespace you control; do not use OIDC
`sid`, which identifies an OP browser session with a different lifecycle.

### Resource indicators (RFC 8707)

When one authorization server fronts more than one protected resource (say an
admin API and an end-user API, or several MCP endpoints), a single fixed `aud`
cannot separate a token meant for one from a token meant for another — only
scope would, and scope is application policy, not a cryptographic boundary.
RFC 8707 fixes that: a client names the resource it wants with a `resource`
parameter, and the AS mints the token's `aud` to that identifier, so a token
issued for resource A is structurally invalid at sibling resource B.

It works across every grant. A client sends `resource` on the authorization
request (bound to the code) or the token request (`client_credentials`, token
exchange, jwt-bearer); the token endpoint mints `aud` from it, refresh carries
and may narrow it (subset-only), and token exchange cannot widen `aud` beyond
the subject token's. One or more resources are allowed (a multi-resource grant
mints a JWT `aud` array). A requested resource the server does not serve is
rejected with `invalid_target`.

`resource_indicators[:allowed_resources]` lists the resource identifiers this
server is willing to mint for (besides its own `:audience`, always served);
`:allowed_resources_for` is an optional `(client -> [uri])` callback for
per-client scoping. With neither set and no `resource` requested, issuance keeps
the single configured `:audience` — so single-resource deployments need no
change. This is the issuer half of the RFC 9728 ↔ RFC 8707 chain: a resource
advertises its identifier via protected-resource metadata, the client echoes it
as `resource`, the AS mints that `aud`, and the resource server validates it.
See [`attesto_mcp_server`](https://hex.pm/packages/attesto_mcp_server) for the
complete MCP integration or [`attesto_mcp`](https://hex.pm/packages/attesto_mcp)
for only the lower-level resource boundary.

### Native apps (RFC 8252)

[RFC 8252](https://datatracker.ietf.org/doc/html/rfc8252) (BCP 212) profiles
OAuth for applications installed on the end user's own device. Most of it binds
the *client*; the authorization server's obligations are narrow, and they are
all keyed on one host-supplied fact — a `:client_native?` callback saying this
client is an installed app:

```elixir
config :my_app, AttestoPhoenix.Config,
  client_native?: {MyApp.OAuth, :client_native?}   # (client -> boolean), default false
```

That callback is the whole decision. A client it returns `true` for gets the
RFC 8252 profile; everything else is untouched, and a deployment that never
wires it has no native clients and so behaves exactly as before.

Marking a client native applies three rules to it:

- **Loopback interface redirection (§7.3).** A native app that cannot use a
  private-use URI scheme binds an ephemeral loopback port at runtime, so its
  `http://127.0.0.1/...` or `http://[::1]/...` redirect URI matches the
  registered one on **any port**, while scheme, host, path, and query still
  compare exactly. Nothing else relaxes — `https`, private-use schemes, remote
  hosts, non-native clients, and the hostname `localhost` (§8.3 discourages it)
  all stay byte-exact, and an unmatched redirect URI is still refused directly
  rather than redirected to. §7.3 states this as a MUST, which is why it takes
  no further opt-in.
- **PKCE is required (§8.1).** Forced for a native client regardless of the
  global `:require_pkce` flag. (`S256` is required and `plain` rejected for
  every client already.)
- **No client secret (§8.4).** A native client may only authenticate at the
  token endpoint with `none`. Presenting `client_secret_basic`,
  `client_secret_post`, or `private_key_jwt` is rejected — a credential shipped
  inside an installed binary is readable by anyone who has the app, so accepting
  it authenticates possession of the app rather than possession of a secret. The
  one exception is a native client you *explicitly* mark confidential
  (`client_public?` returning `false`), which is §8.4's carve-out for
  per-instance credentials issued by dynamic registration.

> **Three things to know before marking a client native.**
>
> 1. Where no `:client_public?` callback is configured at all, a native client
>    counts as public — so marking it native both refuses its secret and admits
>    it on `none` + PKCE.
> 2. A native *public* client cannot use PAR: that endpoint refuses secretless
>    clients and §8.4 refuses this one a secret, so a deployment running
>    `require_pushed_authorization_requests: true` cannot also serve native
>    public clients.
> 3. §7.3 is the only rule here that *widens* a check, and exact redirect-URI
>    matching is assumed by the OpenID Connect and FAPI profiles. A deployment
>    certifying against those normally has no native clients, so the answer is
>    simply not to mark any — but `native_apps: [loopback_redirect: false]`
>    forbids the exception server-wide if you need a hard switch.

Two compatibility/posture rules are genuinely opt-in, because unlike the three
above they apply server-wide rather than expressing a per-client fact:

```elixir
config :my_app, AttestoPhoenix.Config,
  native_apps: [
    loopback_include_localhost: true,
    reject_embedded_user_agents: true
  ]
```

- **`loopback_include_localhost: true`** accepts a varying port for a registered
  `http://localhost/...` loopback redirect while keeping scheme, hostname,
  path, and query exact. RFC 8252 §8.3 prefers literal loopback IP addresses,
  so the default remains `false`; enable it for deployed native clients that
  publish a portless `localhost` callback and bind an ephemeral port at runtime.
  `localhost` never cross-matches `127.0.0.1` or `[::1]`.
- **`reject_embedded_user_agents: true` (§8.12)** refuses an authorization
  request that appears to come from an in-app webview, whose host application
  can read the page and capture the user's credentials. Detection is a
  `User-Agent` heuristic
  (`AttestoPhoenix.RequestContext.embedded_user_agent?/1`), so it produces false
  positives and is trivially spoofable — defense in depth, not a boundary, which
  is why it is opt-in. It applies to every client, since the embedding
  application need not be the OAuth client.

Serving the platform association files (`apple-app-site-association`,
`assetlinks.json`) that claim HTTPS app links is app distribution, not OAuth,
and is left to the host.

### URL client metadata for native clients

Some clients identify themselves with an HTTPS Client ID Metadata Document URL
instead of a row in the host client registry. Enable CIMD only when that client
class is required:

```elixir
config :my_app, AttestoPhoenix.Config,
  client_id_metadata: [
    enabled: true,
    allowed_hosts: ["client.example"]
  ],
  native_apps: [loopback_include_localhost: true]
```

The default CIMD fetcher requires the package's optional `Req` dependency. The
resolver validates the HTTPS client ID, applies DNS/IP SSRF controls, bounds the
document and timeout, validates redirect URIs and keys, and caches only the
validated result. Keep `allowed_hosts` narrow when the clients are known in
advance. The `localhost` option affects only redirect matching; it does not
allow loopback client-metadata URLs or weaken the outbound fetch guard.

### Host policy modules

The preferred install surface groups host-owned callbacks by concern:

- **client registry** -> `:client_store`
  (`load_client`, `verify_client_secret`, `client_jwks`, client metadata)
- **principals** -> `:principal_store`
  (`load_principal`, `build_principal`, principal kinds)
- **scope policy** -> `:scope_policy`
  (`authorize_scope`, supported scopes)
- **login / consent** -> `:consent_policy`
  (`authenticate_resource_owner`, `consent`)
- **claims** -> `:claims_provider`
  (`build_userinfo_claims/3`, `build_id_token_claims/4`)
- **audit / telemetry** -> `:event_sink` (`on_event`)
- **dynamic registration** -> `:registration` (only with registration)

Flat callback keys such as `:load_client`, `:verify_client_secret`,
`:client_jwks`, `:load_principal`, and `:authorize_scope` are still accepted and
take precedence when present. Use them for small installs or targeted overrides;
use behaviour modules for production wiring.

Other deployment callbacks remain flat because they are endpoint mechanics, not
domain policy: `:send_error`, `:www_authenticate`, `:no_store`, `:cert_der`,
`:require_https`, and `:trusted_proxies`.

## Mounting the routes

Use the router macro to mount the server endpoints under a scope you choose:

```elixir
defmodule MyAppWeb.Router do
  use MyAppWeb, :router
  use AttestoPhoenix.Router

  pipeline :attesto_phoenix_config do
    plug AttestoPhoenix.Plug.PutConfig, otp_app: :my_app
  end

  scope "/" do
    attesto_routes(pipeline: :attesto_phoenix_config)
  end
end
```

The installer writes this pipeline and repairs route output from older
installer releases that mounted `attesto_routes/1` without it. Add any shared
transport-only plugs to the same pipeline; use `:route_pipelines` for browser
session or content-negotiation differences.

When interactive routes need host session/resource-owner support that protocol
clients must not inherit, classify the generated routes without hand-writing
the route catalog:

```elixir
attesto_routes(
  pipeline: :oauth_common,
  route_pipelines: [
    interactive: [:oauth_interactive, :oauth_common]
  ],
  registration: true
)
```

`:metadata` covers discovery, OpenID configuration, JWKS, and protected-resource
metadata; `:interactive` covers authorization, device verification, end-session,
and check-session; `:protocol` covers the remaining OAuth/OIDC endpoints. Each
override is the complete ordered list for that class, while omitted classes use
`pipeline:`. The host owns the actual session, resource-owner authentication,
CSRF, and content-negotiation policy. In particular, do not place externally
submitted OAuth POST endpoints behind generic browser CSRF or browser-only
`Accept` handling. Write pipeline names as literal atoms/lists inside the
Phoenix `scope`; module attributes are not available when Phoenix expands the
nested route macro.

The OIDC-only local route mounts default on for compatibility. An OAuth
authorization server that does not act as an OpenID Provider can retain
authorization, token, PAR, revocation, introspection, JWKS, and RFC 8414
metadata while omitting both declarations:

```elixir
attesto_routes(
  userinfo: false,
  openid_configuration: false
)
```

These flags are compile-time route-mount controls; metadata is built later from
runtime `AttestoPhoenix.Config`. `userinfo: false` removes both local UserInfo
verbs. `openid_configuration: false` removes only the OIDC Provider Metadata
route; the RFC 8414 authorization-server document remains mounted and its
contents are unchanged.

UserInfo metadata keeps explicit host intent separate from a mechanically
derived local endpoint:

- `userinfo_endpoint: nil` preserves the released behavior and omits the member.
- `userinfo_endpoint: :derived` advertises the URL derived from `:issuer` and
  `:userinfo_path`. When `userinfo: false`, the retained Provider Metadata route
  suppresses this value only if it is route-equivalent to the removed bundled
  route.
- An explicit HTTPS URL is authoritative and always remains advertised,
  including at the same origin and path. This is the supported form when a host
  replaces the bundled UserInfo controller or serves UserInfo elsewhere.

For example, a host can remount its own implementation at the canonical path
without losing discovery:

```elixir
scope "/" do
  attesto_routes(userinfo: false)
  get "/oauth/userinfo", MyAppWeb.UserInfoController, :show
end
```

```elixir
config :my_app, AttestoPhoenix.Config,
  userinfo_endpoint: "https://issuer.example/oauth/userinfo"
```

The derived-path comparison models Phoenix/Plug dispatch rather than generic
URI cleanup: adapters discard empty path segments, Phoenix decodes each request
segment once, and `.`/`..` segments remain significant. It therefore handles
leading, repeated, and trailing slashes, percent-encoded request segments,
static or dynamic surrounding scopes, non-default ports, and forwarded router
mounts without conflating a distinct route with the removed one.

A dynamic macro `:prefix` is not available to the root Provider Metadata
request. Consequently, `userinfo: false` with retained OpenID configuration
rejects a dynamic `:prefix` at compile time instead of silently advertising a
dead derived endpoint. Put the dynamic portion in a surrounding Phoenix scope,
where the metadata request realizes the same scope, or also set
`openid_configuration: false`. Static prefixes remain supported.

OIDC conformance for features such as CIBA, logout, and session management
relies on Provider Metadata, so those deployments must keep OpenID
configuration enabled unless the host serves equivalent metadata separately. A
dynamically discovered and dynamically registered OpenID Provider that issues
access tokens must still satisfy OIDC's Discovery and UserInfo requirements;
these independent macro controls do not make every route combination an
OIDC-conformant deployment. If OpenID configuration is disabled, any configured
UserInfo endpoint is advertised nowhere unless the host publishes an equivalent
Provider Metadata document.

The bundled well-known routes are the standards-derived forms for an
origin-only issuer such as `https://issuer.example`. If the issuer contains a
path, OIDC Discovery and RFC 8414 derive two different path-bearing well-known
locations; mount those routes explicitly instead of using the macro's fixed
root discovery routes. Because the macro always owns its RFC 8414 route, a
path-bearing issuer requires a manually declared route catalog rather than
adding duplicate discovery routes alongside `attesto_routes/1`. Derived
endpoint URLs are likewise resolved against the issuer *origin*: the issuer's
path is not prepended, so a path-bearing issuer must also set
`:oauth_path_prefix` (or the per-endpoint path overrides) so the advertised
endpoints sit under its path.

`attesto_routes/1` mounts:

- `GET  /.well-known/oauth-authorization-server` (RFC 8414 metadata)
- `GET  /.well-known/openid-configuration` (OIDC Discovery metadata; omitted
  with `openid_configuration: false`)
- `GET  /.well-known/jwks.json` (RFC 7517 JWK Set)
- `GET  /.well-known/oauth-protected-resource` (RFC 9728 metadata)
- `GET  /oauth/authorize` and `POST /oauth/authorize`
- `POST /oauth/token`
- `POST /oauth/par` (RFC 9126)
- `POST /oauth/revoke` (RFC 7009)
- `POST /oauth/introspect` (RFC 7662)
- `POST /oauth/register` (RFC 7591, only with `registration: true`)
- `DELETE /oauth/register/:client_id` (RFC 7592, with registration)
- `GET  /oauth/userinfo` (omitted with `userinfo: false`)
- `POST /oauth/userinfo` (omitted with `userinfo: false`)
- `POST /oauth/bc-authorize` (CIBA, only with `attesto_routes(ciba: true)`)
- `POST /oauth/device_authorization` (RFC 8628, only with `device: true`)
- `GET  /oauth/device_verification` and `POST /oauth/device_verification` (device user-code entry, with `device: true`)
- `GET  /oauth/end_session` and `POST /oauth/end_session` (RP-Initiated Logout, only with `logout: true`)
- `GET  /oauth/check_session` (Session Management `check_session_iframe`, only with `session_management: true`)

Discovery and JWKS are public; the token and revocation endpoints authenticate
the client via your `:load_client` / `:verify_client_secret` callbacks.
The token endpoint also accepts `private_key_jwt` when `:client_jwks` is wired,
and RFC 8705 `tls_client_auth` / `self_signed_tls_client_auth` when
`:client_mtls_metadata` is wired (the self-signed method also uses
`:client_jwks`). That callback returns `nil` only for a client without an mTLS
authentication registration; lookup errors and malformed results fail client
authentication closed. A forwarded certificate is read only through
`:forwarded_cert_der` from an adapter-reported immediate socket peer in
`:trusted_proxies`; public requests cannot make an XFCC-style header
authoritative, even if middleware rewrites `conn.remote_ip` from a forwarded
header. Standard scheme/host/port rewrites are likewise ignored for an
untrusted socket peer when deriving HTTPS and DPoP `htu`. The deprecated
`:cert_der` callback is subject to the same gate so
older header-based deployments fail closed until they configure their proxy
allowlist and migrate. PKI authentication
also requires `:client_certificate_chain_validated?` to return `true`. The TLS
terminator must delete any client-supplied certificate header and replace it
only from a successful client-certificate handshake; the application listener
should be network-isolated so only the configured trusted terminators can
reach it. TLS passthrough/direct peer certificates avoid this header boundary
and are preferred when the deployment permits them. The
token endpoint supports authorization-code, refresh-token, client-credentials,
OAuth token-exchange, and JWT-assertion (`jwt-bearer`) grants. The PAR endpoint accepts the same confidential-client
secret methods plus `private_key_jwt`, then stores the authorization request
behind a one-time `request_uri`.

When `:client_auth_signing_algs` is omitted, client assertions use Attesto's
FAPI allowlist and enforce its key policy: RSA signatures require a modulus of
at least 2048 bits, and legacy `EdDSA` is FAPI-compatible only over Ed25519.
The default discovery metadata includes both legacy `EdDSA` and RFC 9864's
exact `Ed25519` identifier. Supplying an explicit algorithm list selects a
non-FAPI policy for compatibility; pair a narrowed FAPI list with
`client_auth_enforce_fapi_alg_policy: true` as in the example above. An
enforced list must be a subset of `Attesto.SigningAlg.fapi_algs/0`; invalid or
incoherent lists fail when the server configuration is built rather than being
advertised and rejected only at request time.

`:client_assertion_audiences` controls which `aud` values a `private_key_jwt`
assertion may carry at the **token endpoint** (RFC 7523 §3). It defaults to the
issuer identifier *and* the token endpoint URL, because the profiles disagree:
FAPI 2.0 Security Profile Final §5.3.2.1 requires the issuer, while FAPI-CIBA
ID1 audiences a token-endpoint assertion to the token endpoint URL. A
deployment certifying to only one of them can narrow it to `[config.issuer]`.
The other endpoints (PAR, introspection, device authorization) are
issuer-only already. Narrowing is a conformance choice rather than a security
one: both values name *this* server, so accepting either does not admit an
assertion minted for a different authorization server.

When `:request_object_policy` is configured, signed request objects are verified
at PAR submission and re-verified at `/authorize`; verified request-object
parameters are authoritative over unsigned request body/query values. Set
`Attesto.RequestObject.Policy.fapi_message_signing/0` to enforce the FAPI 2.0
Message Signing JAR profile. Request-object policies follow the same presence
rule: an explicit `accepted_algs` list is non-FAPI unless
`enforce_fapi_alg_policy` is `true`. The named FAPI policy sets it to `true`, so
copying that policy and narrowing `accepted_algs` retains the RSA-strength and
Edwards-curve gate.

The authorization endpoint also emits JARM responses when the validated request
uses `response_mode=jwt`, `query.jwt`, `fragment.jwt`, or `form_post.jwt`.
Discovery advertises the supported response modes and the server signing
algorithms used for authorization response JWTs.

The route plumbing is profile-neutral. A permissive standards-compliant OAuth
deployment can admit PKCE-bound public clients and select its supported grants.
A FAPI 2.0 Security Profile deployment coordinates policy settings and
callbacks that require PAR, PKCE, asymmetric confidential-client
authentication, sender-constrained access tokens, and the applicable algorithm
constraints. The optional Message Signing profile adds signed request-object
enforcement and JARM; `Attesto.RequestObject.Policy.fapi_message_signing/0`
provides the request-object policy for that profile. These are coordinated
settings rather than a single profile switch, and they use the same token,
authorization, PAR, discovery, DPoP, and mTLS implementations.

### OpenID for Verifiable Credentials (OID4VC / EU wallet)

`attesto_phoenix` mounts the HTTP surface for the OpenID4VCI **issuer** and
OpenID4VP **verifier** roles behind an EUDI-wallet-facing service, targeting the
[HAIP](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html)
profile. The protocol logic and cryptography live in
[`attesto`](https://hexdocs.pm/attesto) (SD-JWT VC + mdoc + jwt_vc_json
issue/verify, DCQL, Token Status List, SIOPv2, OpenID Federation); these routes
wire it to Phoenix. All paths derive from configurable `Config` tails (nothing
hardcoded) and mount only behind their feature flag:

```elixir
attesto_routes(
  credential_issuance: true,   # OID4VCI issuer
  presentation: true,          # OID4VP verifier
  status_list: true,           # Token Status List revocation
  federation: true             # OpenID Federation entity configuration
)
```

**`credential_issuance: true`** mounts the OID4VCI issuer endpoints:

- `GET  /.well-known/openid-credential-issuer` — Credential Issuer Metadata.
- `POST /oauth/nonce` — the `c_nonce` endpoint (public, OID4VCI §7).
- `POST /oauth/credential` — the credential endpoint. Access-token protected;
  checks the token's bound `credential_configuration_ids`, verifies the holder
  key proof(s) (with `c_nonce` freshness), and issues a credential — **SD-JWT VC,
  ISO mdoc (`mso_mdoc`), or `jwt_vc_json`**, dispatched by the credential
  configuration's `format` — bound to the holder key. Batch `proofs` supported.
  Issuance runs through the host `:build_credential` callback.
- `GET  /oauth/credential_offer/:id` — by-reference credential offer retrieval
  (the `credential_offer_uri` a wallet dereferences).
- `POST /oauth/deferred_credential` — deferred issuance (OID4VCI §9);
  token-protected, driven by the `:build_deferred_credential` callback, which
  returns `issuance_pending` until the credential is ready.
- Grants on `POST /oauth/token`: the **pre-authorized_code** grant is added
  automatically when a `:pre_authorized_code_store` is configured; the ordinary
  **authorization_code** flow issues credentials when the request carries
  `openid_credential` `authorization_details`.

Requires: `:build_credential`, `:credential_configurations_supported`, a
`:pre_authorized_code_store` and `:c_nonce_store`, the `:credential_offer_store`
(for by-reference offers), and the `:keystore` (issuer signing key).

A wallet may also authenticate to the token endpoint with a **Client Attestation
JWT + PoP** (`attest_jwt_client_auth`, the `OAuth-Client-Attestation` /
`-PoP` headers) when `:trusted_wallet_provider_jwks` is configured — advertised
in `token_endpoint_auth_methods_supported`.

**`presentation: true`** mounts the OID4VP verifier endpoints:

- `GET  /oauth/presentation_request/:id` — serves the signed request object
  (`application/oauth-authz-req+jwt`).
- `POST /oauth/presentation_response` — the `direct_post` (and encrypted
  `direct_post.jwt`) response endpoint; verifies the `vp_token` against the
  session's bound nonce/audience (single-use, uniform error). SD-JWT VC and
  mdoc presentations both verify.

The host drives it through `AttestoPhoenix.Verifier`: `create_presentation_request/2`
builds + signs the request object (optionally with an `x509_san_dns` client-id +
`x5c`), and `presentation_result/2` polls the verified claims. Requires a
`:presentation_session_store`, `:verifier_client_id` (or the x509 config), and
the `:keystore`. Request-object signatures keep using that main keystore and
derive their `alg` from its configured key. Encrypted `direct_post.jwt`
responses additionally require a dedicated EC P-256
`:verifier_encryption_keystore`; there is deliberately no fallback to the main
signing key.

**`status_list: true`** mounts `GET /oauth/statuslist/:id`, serving a signed
`statuslist+jwt` built from the `:status_list_store` — the revocation target
referenced by issued credentials.

**`federation: true`** mounts `GET /.well-known/openid-federation`, serving the
signed OpenID Federation **Entity Configuration**
(`application/entity-statement+jwt`) built from `:federation_authority_hints` and
`:federation_entity_metadata` — the trust-chain anchor a federation resolver
starts from.

### Backchannel authentication (CIBA)

For **decoupled authentication** — where the device consuming the API is not the
device the user approves on, such as a call-center agent's console, a POS
terminal, or an AI agent acting on a user's behalf — mount CIBA with
`attesto_routes(ciba: true)` and enable it in `AttestoPhoenix.Config`
(`ciba: [enabled: true]`). The client calls `POST /oauth/bc-authorize` to start a
flow the user approves out of band on their own phone, then collects the tokens
at the token endpoint: in `poll` mode the client polls until the user approves,
and in `ping` mode the AS calls the client's notification endpoint when the
tokens are ready. Signed authentication requests follow the FAPI-CIBA profile.
The default CIBA request algorithm list (`PS256` and `ES256`) retains the same
FAPI key-strength checks. An explicit `ciba: [request_signing_algs: ...]` list
is treated as non-FAPI unless paired with `enforce_fapi_alg_policy: true`; this
lets a generic deployment opt into additional algorithms without weakening a
narrowed FAPI policy accidentally. An enforced FAPI-CIBA list is limited to
`PS256` and `ES256`, as required by the profile.
Because signed CIBA request JWTs carry replay-sensitive `jti` values, enabling
the default signed-request policy also requires an explicit atomic
`:replay_check`; the installer configures the cluster-safe Ecto implementation.
The stored replay identity is a fixed-length digest scoped to the authenticated
client, not the raw `jti`.
An intentionally unsigned generic profile may opt out with
`ciba: [enabled: true, require_signed_request: false]`; if that profile accepts
an optional signed request, the request is still rejected unless a replay
callback is configured.

### Device Authorization Grant (RFC 8628)

For **sign-in on input-constrained devices** — a smart TV, a CLI, an IoT box with
no browser or keyboard — mount the device grant with `attesto_routes(device:
true)`. `POST /oauth/device_authorization` returns a `device_code` and a short
human-typable `user_code`; the user enters that code on a second device at the
verification page (`/oauth/device_verification`), while the device polls the
token endpoint with the `device_code` until the user approves.

### Logout and session management

**Single-logout across relying parties and browser-session change detection.**
An ID Token minted for a session records the RPs to notify, and the end-session
flow fans out to them:

- **RP-Initiated Logout** (certified) — `GET`/`POST /oauth/end_session`, mounted
  with `attesto_routes(logout: true)`. An RP redirects the browser here to end
  the OP session and return to a registered `post_logout_redirect_uri`.
- **Back-Channel Logout** (certified) — the OP delivers a signed logout token
  server-to-server to every RP that registered a `backchannel_logout_uri`, so
  sessions end even when the user's browser never returns to those RPs.
- **Front-Channel Logout** — the end-session page renders each RP's
  `frontchannel_logout_uri` in an iframe, so browser-reachable RPs clear their
  session within the same logout navigation.
- **Session Management** — `GET /oauth/check_session` serves the
  `check_session_iframe` and the authorization endpoint returns `session_state`,
  letting an RP detect a change to the OP login session without a full redirect.
  Mount with `attesto_routes(session_management: true)`.

## Protecting resources

```elixir
pipeline :api_protected do
  plug AttestoPhoenix.Plug.Authenticate
end

scope "/api", MyAppWeb do
  pipe_through [:api, :api_protected]

  scope "/reports" do
    plug AttestoPhoenix.Plug.RequireScopes, "read:reports"
    get "/", ReportController, :index
  end
end
```

`AttestoPhoenix.Plug.Authenticate` verifies the Bearer JWT, enforces DPoP and
mTLS binding when enabled, resolves the subject via `:load_principal`, emits
neutral `:auth_succeeded` / `:auth_denied` events through `:on_event`, and
assigns:

- `conn.assigns.attesto_claims` - the verified JWT claims
- `conn.assigns.attesto_principal` - the host principal returned by
  `:load_principal`
- `conn.assigns.attesto_context` - a neutral `%{subject, client_id, scope,
  claims, cnf, principal}` map

Bearer credentials default to the `Authorization` header only, matching
`bearer_methods_supported: ["header"]` in protected-resource metadata. Configure
`bearer_methods_supported: ["header", "body"]` only for resource servers that
intentionally accept RFC 6750 form-body `access_token` credentials.

`AttestoPhoenix.Plug.RequireScopes` enforces route-level scope authorization
using `Attesto.Scope` grant-form algebra. It accepts either a single scope
string or a list of required scopes.

When `:resource_metadata` is set on the config, a 401 challenge carries that
static RFC 9728 `resource_metadata` pointer, preserving the single-resource
default. A host serving several protected resources can instead select the
correct pointer per request, or return `nil` when that surface has no applicable
metadata declaration:

```elixir
resource_metadata: "https://api.example/.well-known/oauth-protected-resource",
resource_metadata_resolver: {MyAppWeb.ResourceMetadata, :for_request}
```

```elixir
def for_request(%Plug.Conn{request_path: "/alpha"}) do
  "https://api.example/.well-known/oauth-protected-resource/alpha"
end

def for_request(%Plug.Conn{request_path: "/beta"}) do
  "https://api.example/.well-known/oauth-protected-resource/beta"
end

def for_request(_conn), do: nil
```

The resolver is authoritative when present; it does not fall back to the static
URL when it returns `nil`. An invalid runtime return is safely omitted rather
than turned into a challenge or a request-time exception. A static Config value
is validated by `AttestoPhoenix.Config.new/1`; a non-`nil` per-plug value is
validated when `AttestoPhoenix.Plug.Authenticate` is initialized (at compile
time under Phoenix's default Plug initialization mode). Explicit per-plug `nil`
remains a valid, authoritative omission. Function callbacks must accept one
argument, and MFA tuples must export the effective arity (the request plus any
extra arguments, which are appended after it). The explicit per-plug option
wins on core verification, TLS, revocation, and principal failures and skips
the resolver.

The resolver is trusted configuration. Return pinned or allowlisted HTTPS URLs;
do not construct a metadata authority from untrusted Host, forwarded, query, or
arbitrary header values. The returned URL is never fetched or used as a
redirect, and it is validated with the same HTTPS/host/no-fragment rules as the
static value before it can enter a quoted challenge. The resolver runs once per
protected-resource request — including requests that authenticate successfully,
since the pointer must be selected before verification renders any challenge —
so keep it fast and total. Resolver exceptions are not
rescued: a callback that raises propagates the exception and fails the request
(successful ones included) instead of rendering an authentication challenge.

The protected-resource integration still owns the actual RFC 9728 declarations.
Publish one document per exact resource identifier, with the path-inserted
well-known URI and matching `resource`
member; do not collapse multiple identifiers into a root document. When no
resource owns the origin root, use `protected_resource_root: false` and let the
per-resource integration mount only the documents it owns.

For first-party web flows, keep cookie semantics in your app and pass a generic
credential extractor to the plug:

```elixir
plug AttestoPhoenix.Plug.Authenticate,
  credential_from_conn: &MyAppWeb.Auth.access_token_from_cookie/1
```

The extractor returns `{:ok, :bearer, token}`, `{:ok, :dpop, token}`, or
`:missing`. Attesto still verifies the token through the same JWT/DPoP/mTLS
path; the cookie format and CSRF policy remain host concerns.

### Req DPoP clients

`attesto_phoenix` is the server-side Phoenix layer. If you also use
[`Req`](https://hex.pm/packages/req) for OAuth clients in tests or internal
tooling, [`req_dpop`](https://hex.pm/packages/req_dpop) generates RFC 9449 DPoP
proofs that interoperate with `AttestoPhoenix.Plug.Authenticate`. It is not a
runtime dependency of this package; `attesto_phoenix` uses it only in tests as
an external client compatibility check.

## Database migration

The generated migration owns the operational tables backing the attesto store
behaviours: `attesto_authorization_codes`, `attesto_refresh_tokens`,
`dpop_nonces`, `dpop_replays`, and `attesto_pushed_authorization_requests`, plus
two feature tables — `attesto_client_id_metadata` (the CIMD client-metadata
cache) and `attesto_consent_grants` (the single-use, request-bound consent-grant
primitive). It does **not** own a clients table (that is yours, behind
`:load_client`).

Generate the migration into your app:

```bash
mix attesto_phoenix.gen.migration --repo MyApp.Repo
```

Then run it:

```bash
mix ecto.migrate
```

### Clustering

Every mutable OAuth store has a Postgres-backed implementation, so a clustered
or load-balanced deployment holds no OAuth state per node — a request can bounce
across machines mid-flow. Access tokens are stateless signed JWTs (any node
validates any token against the shared keystore); everything else lives in
Postgres with atomic single-use enforcement (`DELETE … RETURNING` for codes and
PAR references, conditional `UPDATE` for nonces, `INSERT … ON CONFLICT` for the
replay cache, transactional refresh rotation/family revocation).

To be fully clusterable, wire the Ecto stores (the `mix attesto_phoenix.install`
config block does this by default):

```elixir
code_store:    AttestoPhoenix.Store.EctoCodeStore,
refresh_store: AttestoPhoenix.Store.EctoRefreshStore,
nonce_store:   AttestoPhoenix.Store.EctoNonceStore,
replay_check:  {AttestoPhoenix.Store.EctoReplayCheck, :check_and_record},
par_store:     AttestoPhoenix.Store.EctoPARStore
```

Single-node deployments may instead use the in-memory ETS implementations for
nonces, replay, and PAR; the Ecto variants exist for clustered correctness.
Signed CIBA still requires an explicit `:replay_check`, so a single-node host
using ETS must supervise `Attesto.DPoP.ReplayCache` and point the callback at
`&Attesto.DPoP.ReplayCache.check_and_record/2`.
**PAR is the one to watch**: its default is single-node ETS, but FAPI 2.0
*requires* PAR, so a clustered FAPI deployment must set
`par_store: AttestoPhoenix.Store.EctoPARStore` or a pushed `request_uri` will not
resolve on the node that later handles `/authorize`.

## Local HTTPS for development

attesto requires an **https** issuer (RFC 8414 §2), so a plain `http://localhost`
dev server can't drive the OAuth / MCP flow — and there is deliberately no
"disable https" switch. Instead, serve a locally-trusted
[mkcert](https://github.com/FiloSottile/mkcert) certificate so `https://localhost`
works with no tunnel and no downgrade.

Generate the certificate once:

```bash
mix attesto_phoenix.gen.dev_https
```

Then wire it into `config/dev.exs` in one line:

```elixir
config :my_app, MyAppWeb.Endpoint,
  https: AttestoPhoenix.DevTLS.https_opts(port: 4443)
```

Point your issuer at `https://localhost:4443` and discovery, DPoP, and the RFC
8707 resource identifiers all line up. `AttestoPhoenix.DevTLS.https_opts/1`
raises (pointing back at the generator) if the certificate is missing — it never
falls back to http. See the [Local HTTPS guide](guides/local_https.md) for the
full walkthrough and the tunnel-vs-mkcert tradeoff.

## Guides and examples

- [Example configurations](guides/examples.md) - confidential and public-client
  configuration sketches.
- [Local HTTPS for development](guides/local_https.md) - serve a locally-trusted
  mkcert certificate so the OAuth / MCP flow runs over `https://localhost` with no
  tunnel and no downgrade.
- [Consumer migration](guides/consumer_migration.md) - moving from a custom or
  legacy OAuth route surface while keeping historical migrations compiling.
- [Proxy and canonical host](guides/proxy_canonical_host.md) - issuer,
  forwarded header, and HTTPS behavior behind proxies/CDNs.
- [Replay and nonce production notes](guides/replay_nonce_production.md) -
  shared-store requirements for clustered DPoP replay and nonce handling.
- [Error envelope hooks](guides/error_envelope.md) - using `:send_error` and
  related callbacks to keep a host application's API error format.
- [Identity Assertion grant (ID-JAG / MCP EMA)](guides/identity_assertion_grant.md) -
  enabling the `jwt-bearer` grant, configuring trusted issuers, and wiring the
  subject-resolution callback.
- [Livebook demo](notebooks/attesto_phoenix_demo.livemd) - a self-contained
  Phoenix/Bandit resource-server demo using `Req` + `req_dpop`.

## Development

```bash
mix deps.get
mix precommit
mix test --include ecto   # requires Postgres
```

## License

MIT. See [LICENSE](LICENSE).
