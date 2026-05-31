defmodule AttestoPhoenix do
  @moduledoc """
  A Phoenix/Ecto OAuth 2.0 / OIDC authorization-server and
  resource-server layer built on top of `Attesto`.

  `Attesto` is transport-agnostic: it implements the pure, effect-free
  protocol primitives - JWT mint/verify with per-key algorithm metadata
  (RFC 7519), DPoP sender-constraint proofs (RFC 9449), mutual-TLS binding
  (RFC 8705), PKCE (RFC 7636), the JWK Set (RFC 7517), authorization-server
  metadata (RFC 8414), `private_key_jwt` client assertions (RFC 7523),
  signed request objects (RFC 9101), and the scope grant-form algebra. It
  deliberately carries no HTTP, no persistence, and no identity model.

  `attesto_phoenix` adds exactly the two things a running server needs and
  the core leaves out: a transport (HTTP endpoints and protected-resource
  plugs) and persistence (Ecto-backed implementations of the core store
  behaviours). Everything that is inherently application policy stays the
  host's, supplied through a small set of neutral configuration callbacks.

  ## The split

  The library keeps the same boundary `Attesto` draws - *protocol* versus
  *policy* - and adds a third concern, *transport*:

    * **Protocol (core).** `Attesto.Token`, `Attesto.DPoP`,
      `Attesto.MTLS`, `Attesto.PKCE`, `Attesto.Scope`, `Attesto.JWKS`,
      `Attesto.ClientAssertion`, `Attesto.RequestObject`, and
      `Attesto.Discovery`. Pure functions over bytes and claims. This layer
      is reused verbatim; this package adds no crypto and forwards every
      protocol decision to it.

    * **Transport (here).** Controllers behind a router macro that mount
      authorization, token, pushed-authorization-request (RFC 9126),
      revocation (RFC 7009), discovery (RFC 8414), JWK Set (RFC 7517),
      UserInfo, and optional dynamic-registration (RFC 7591) endpoints, plus
      protected-resource plugs that verify a Bearer/DPoP access token and
      enforce its sender-constraint binding. The controllers and plugs use
      the core OAuth-error / `WWW-Authenticate` helpers so every failure is
      an RFC 6749 §5.2 / RFC 6750 §3 response, never a silent reject.

    * **Persistence (here).** Ecto schemas that implement the core store
      behaviours for authorization codes and refresh tokens, and - for
      clustered correctness - DPoP nonces and proof `jti` replay records.
      Migration scaffolding is a `mix` generator that writes the migration
      into the host application; this package owns no migration of its own.

    * **Policy (host application).** The client registry and its
      revocation rule, client-secret hashing, the subject/principal model,
      the scope catalog, signing keys, and the audit log. These are
      injected as the callbacks documented on `AttestoPhoenix.Config`, so
      the library never hardcodes one application's identity model.

  ## Configuration

  All behaviour is centralized in `AttestoPhoenix.Config`. It is the single
  source of truth read by every controller and plug: it validates the
  required keys at build time (raising `ArgumentError` so misconfiguration
  fails closed at boot), applies neutral defaults, and derives the
  `Attesto.Config` the protocol layer runs against via
  `AttestoPhoenix.Config.to_attesto_config/2`.

  Anything that is application policy is a callback rather than a baked-in
  assumption, named in OAuth terms:

    * client lookup -> `:load_client`
    * client-secret verification -> `:verify_client_secret`
    * client public keys -> `:client_jwks`
    * subject/principal resolution -> `:load_principal`
    * scope catalog / narrowing -> `:scopes_supported` and/or
      `:authorize_scope`
    * audit / telemetry -> `:on_event` (optional, no-op by default)
    * dynamic client persistence -> `:register_client` (only when
      registration is enabled)
    * mTLS certificate extraction -> `:cert_der` (only when mTLS is
      enabled)
    * HTTPS / proxy trust -> `:require_https` and `:trusted_proxies`

  See `AttestoPhoenix.Config` for the full key reference and the default
  for each value.

  ## Mounting the routes

  `AttestoPhoenix.Router` provides the `attesto_routes/1` macro, which
  mounts the authorization-server endpoints under a scope the host chooses.
  Discovery and the JWK Set are public; the token and revocation endpoints
  authenticate the client via the `:load_client` / `:verify_client_secret`
  callbacks.

  ## Entry points

    * `AttestoPhoenix.Config` - the validated configuration every
      controller and plug reads, and the derivation of the protocol
      `Attesto.Config`.
    * `AttestoPhoenix.Router` - the `attesto_routes/1` macro that mounts
      the HTTP surface.

  See the `README` for the supply/own breakdown, the router and plug usage,
  and the migration generator.
  """
end
