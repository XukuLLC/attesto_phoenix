# Local HTTPS for development (mkcert)

attesto is the OAuth 2.0 / OpenID Connect authorization server, and it requires an
**https** issuer — the discovery documents, DPoP `htu`, and RFC 9728 protected-
resource identifiers are all https by spec, and attesto enforces that at
config-build time (RFC 8414 §2: the issuer identifier MUST be an `https` URL). So
a plain `http://localhost` dev server cannot drive the OAuth / MCP flow.

There is deliberately no "disable https" switch in the library — that would defeat
the point of a certified security layer. Instead, `attesto_phoenix` makes the
_right_ path frictionless: serve a **locally-trusted** certificate on
`https://localhost`, so everything lines up with no tunnel and no downgrade.

## Two ways to get https locally

- **A tunnel** (ngrok / cloudflared) — points a public https host at your local
  http port. Set your issuer / URL config to the tunnel host. Use this when you
  need a _publicly reachable_ URL (for example, an MCP client on another device,
  or a mobile browser).
- **mkcert (this guide)** — serves a locally-trusted certificate on
  `https://localhost` directly, no tunnel, no downgrade. Best for everyday local
  dev where the client runs on the same machine.

[mkcert](https://github.com/FiloSottile/mkcert) creates a certificate authority
that it trusts in your OS/browser trust stores, then issues certificates from it.
Your machine trusts `https://localhost` with no `-k` and no self-signed warnings.

## One command

```sh
mix attesto_phoenix.gen.dev_https
```

That task:

1. checks `mkcert` is installed (printing install guidance if not),
2. creates `priv/cert/`,
3. runs `mkcert -install` (idempotent — trusts the local CA on this machine),
4. writes `priv/cert/localhost.pem` + `priv/cert/localhost-key.pem` for
   `localhost 127.0.0.1 ::1`, and
5. ensures `priv/cert/` is git-ignored.

If `mkcert` isn't on your `PATH`, install it first:

```sh
brew install mkcert nss     # macOS; nss adds Firefox trust
# Linux / Windows: https://github.com/FiloSottile/mkcert#installation
```

`priv/cert/` is git-ignored — every developer generates their own. The
certificate is trusted only by _your_ machine's CA, so there is nothing to share
or commit.

## Wire it into the dev endpoint (one line)

In `config/dev.exs`, hand the endpoint's `https:` listener to
`AttestoPhoenix.DevTLS.https_opts/1`:

```elixir
config :my_app, MyAppWeb.Endpoint,
  https: AttestoPhoenix.DevTLS.https_opts(port: 4443)
```

`https_opts/1` returns the full `https:` keyword — port, `cipher_suite: :strong`,
the resolved `certfile`/`keyfile`, and a raised `max_header_length` (DPoP proofs
and long tokens can exceed Bandit's default per-header cap). It resolves the
conventional `priv/cert/localhost.pem` + `priv/cert/localhost-key.pem` against
your app, and it **raises** (pointing back at `mix attesto_phoenix.gen.dev_https`)
if the certificate is missing — it never silently falls back to http.

Keep the plain http listener too if you want non-MCP routes on http as well; the
`https:` and `http:` keys coexist on the endpoint.

### Options

`https_opts/1` accepts:

- `:port` — the TLS port (default `4443`).
- `:certfile` / `:keyfile` — explicit paths, if you don't use the convention.
- `:otp_app` — resolve the default cert/key paths via `Application.app_dir/2`
  instead of relative to the current working directory (release-safe; the plain
  default is the idiomatic `mix phx.server`-from-app-root spelling).
- `:max_header_length` — override the Bandit `http_1_options` max header length.

## Point the issuer at the https port

Set your `AttestoPhoenix.Config` issuer (and any RFC 8707 resource identifiers
derived from it) to the mkcert https origin, so discovery, DPoP `htu`, and the
resource identifiers all match what a client discovers:

```elixir
config :my_app, AttestoPhoenix.Config,
  issuer: "https://localhost:4443",
  audience: "https://localhost:4443/mcp"
```

Verify — no `-k`, because the certificate is trusted:

```sh
mix phx.server
curl https://localhost:4443/.well-known/oauth-authorization-server
```

Point your MCP client (mcp-remote, Claude Desktop, etc.) at the concrete MCP
transport URL on the same https origin — the OAuth dance then runs entirely over
trusted https with no tunnel.

**Node clients (mcp-remote) need one extra step.** `mkcert -install` trusts the
CA in the system/browser stores, but Node ships its own root store, so a
Node-based MCP client rejects the cert until you point Node at the mkcert CA:

```sh
export NODE_EXTRA_CA_CERTS="$(mkcert -CAROOT)/rootCA.pem"
```

(`curl` succeeds without this because it uses the system store; Node does not.)

## Notes and caveats

- **Not a replacement for a tunnel when you need a public URL.** mkcert only
  trusts _your_ machine. If a client on another device or the public internet
  must reach your dev server, use ngrok / cloudflared and set the issuer to the
  tunnel host instead.
- **Certificates expire** (mkcert defaults to ~2 years). Regenerate by re-running
  `mix attesto_phoenix.gen.dev_https`.
- **Never on a server or in CI.** `mkcert -install` trusts a CA on the local
  machine; the certificates are dev-only. Production terminates TLS with a real
  CA certificate at the load balancer / ingress.
- **The https guarantee stays intact.** Nothing here disables attesto's
  https-only requirement — you are serving real (locally-trusted) TLS, which is
  exactly what the issuer requires.
