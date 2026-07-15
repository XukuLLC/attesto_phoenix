# AttestoPhoenix

[![Hex.pm](https://img.shields.io/hexpm/v/attesto_phoenix)](https://hex.pm/packages/attesto_phoenix)
[![Hexdocs.pm](https://img.shields.io/badge/docs-hexdocs.pm-blue)](https://hexdocs.pm/attesto_phoenix)
[![Elixir CI](https://github.com/XukuLLC/attesto_phoenix/actions/workflows/elixir.yml/badge.svg)](https://github.com/XukuLLC/attesto_phoenix/actions/workflows/elixir.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](https://github.com/XukuLLC/attesto_phoenix/blob/main/LICENSE)
[![Elixir](https://img.shields.io/badge/elixir-%E2%89%A5%201.18-purple)](https://elixir-lang.org)
[![OpenID Certified](https://img.shields.io/badge/OpenID-Certified-F78C40)](https://openid.net/certification/certified-openid-connect-implementations/)

An opinionated Phoenix/Ecto OAuth 2.0 / OIDC authorization server on top of
[attesto](https://hex.pm/packages/attesto).

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

It deliberately does **not** own your client registry, principal store, secret
hashing, scope catalog, or audit log. Those are application policy and are
supplied through a small set of neutral configuration callbacks.

## What you can build with it

- **An API that AI assistants can connect to.** Assistant connectors — ChatGPT,
  Claude — authorize through OAuth: PKCE, dynamic client registration, pushed
  authorization requests, sender-constrained tokens, and protected-resource
  discovery. `attesto_phoenix` mounts that whole surface with one router macro,
  so your app can expose tools and data to an assistant without hand-rolling an
  OAuth server. Pair it with
  [`attesto_mcp`](https://github.com/XukuLLC/attesto_mcp) to protect the MCP
  endpoint itself as an OAuth resource server — the `WWW-Authenticate` challenge
  and protected-resource metadata (RFC 9728) that assistant clients discover.
- **Your own authorization server.** Issue short-lived, scoped JWT access tokens
  and OIDC ID tokens for first-party apps and machine clients, instead of
  outsourcing to a hosted identity provider.
- **A resource server that resists stolen tokens.** Verify access tokens locally
  — signature, issuer, audience, and DPoP / mTLS sender-constraint — with no
  token database or introspection call on the hot path, so a leaked bearer token
  alone can't call the API.

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
    {:attesto_phoenix, "~> 1.2"}
  ]
end
```

The optional Igniter installer needs `igniter` available while you run it. It is
not a runtime dependency of this package:

```elixir
def deps do
  [
    {:attesto_phoenix, "~> 1.2"},
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
config :my_app, AttestoPhoenix.Config,
  # --- required ---
  issuer: "https://auth.example.com",
  keystore: MyApp.Keystore,            # implements Attesto.Keystore
  repo: MyApp.Repo,                    # Ecto.Repo for the token stores

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
  request_object_policy: Attesto.RequestObject.Policy.generic(),

  # --- optional deployment + features ---
  require_https: true,
  trusted_proxies: ["10.0.0.0/8"],     # honor X-Forwarded-* only from these
  access_token_ttl: 900,
  refresh_token_ttl: 1_209_600,
  authorization_code_ttl: 60,
  dpop_enabled: true,
  dpop_nonce_required: false,
  mtls_enabled: false,                 # if true, also set :cert_der
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

Required keys are validated at build time; a missing key (or a missing
dependency such as `:cert_der` when mTLS is enabled) raises immediately so
misconfiguration fails fast.

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
as `resource`, the AS mints that `aud`, and the resource server validates it
(see `attesto_mcp` for the resource-server half).

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

  pipeline :oauth do
    plug :accepts, ["json"]
  end

  scope "/" do
    pipe_through :oauth
    attesto_routes()
  end
end
```

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
`Accept` handling.

`attesto_routes/1` mounts:

- `GET  /.well-known/oauth-authorization-server` (RFC 8414 metadata)
- `GET  /.well-known/openid-configuration` (OIDC Discovery metadata)
- `GET  /.well-known/jwks.json` (RFC 7517 JWK Set)
- `GET  /.well-known/oauth-protected-resource` (RFC 9728 metadata)
- `GET  /oauth/authorize` and `POST /oauth/authorize`
- `POST /oauth/token`
- `POST /oauth/par` (RFC 9126)
- `POST /oauth/revoke` (RFC 7009)
- `POST /oauth/introspect` (RFC 7662)
- `POST /oauth/register` (RFC 7591, only with `registration: true`)
- `DELETE /oauth/register/:client_id` (RFC 7592, with registration)
- `GET  /oauth/userinfo`
- `POST /oauth/userinfo`
- `POST /oauth/bc-authorize` (CIBA, only with `attesto_routes(ciba: true)`)
- `POST /oauth/device_authorization` (RFC 8628, only with `device: true`)
- `GET  /oauth/device_verification` and `POST /oauth/device_verification` (device user-code entry, with `device: true`)
- `GET  /oauth/end_session` and `POST /oauth/end_session` (RP-Initiated Logout, only with `logout: true`)
- `GET  /oauth/check_session` (Session Management `check_session_iframe`, only with `session_management: true`)

Discovery and JWKS are public; the token and revocation endpoints authenticate
the client via your `:load_client` / `:verify_client_secret` callbacks.
The token endpoint also accepts `private_key_jwt` when `:client_jwks` is wired,
and supports authorization-code, refresh-token, client-credentials, OAuth
token-exchange, and JWT-assertion (`jwt-bearer`) grants. The PAR endpoint accepts the same confidential-client
secret methods plus `private_key_jwt`, then stores the authorization request
behind a one-time `request_uri`.

When `:request_object_policy` is configured, signed request objects are verified
at PAR submission and re-verified at `/authorize`; verified request-object
parameters are authoritative over unsigned request body/query values. Set
`Attesto.RequestObject.Policy.fapi_message_signing/0` to enforce the FAPI 2.0
Message Signing JAR profile.

The authorization endpoint also emits JARM responses when the validated request
uses `response_mode=jwt`, `query.jwt`, `fragment.jwt`, or `form_post.jwt`.
Discovery advertises the supported response modes and the server signing
algorithms used for authorization response JWTs.

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

When `:resource_metadata` is set on the config, a 401 challenge carries the
RFC 9728 `resource_metadata` pointer to the `/.well-known/oauth-protected-resource`
document (mounted by `attesto_routes/1`), so a client refused without a valid
token can discover which authorization server issues tokens for the resource.

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

Single-node deployments may instead leave the defaults (in-memory ETS for
nonces, replay, and PAR); the Ecto variants exist for clustered correctness.
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
