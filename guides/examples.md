# Example configurations

Three minimal `AttestoPhoenix.Config` setups. They use the host wiring below:

```elixir
config :attesto_phoenix, otp_app: :my_app, repo: MyApp.Repo

pipeline :attesto_phoenix_config do
  plug AttestoPhoenix.Plug.PutConfig, otp_app: :my_app
end

scope "/" do
  attesto_routes(pipeline: :attesto_phoenix_config)
end
```

## Confidential client (server-side app, client secret)

A confidential client authenticates with a secret at the token endpoint
(RFC 6749 §2.3.1). This config issues access and refresh tokens for the
authorization-code grant and serves discovery.

```elixir
AttestoPhoenix.Config.new(
  issuer: "https://auth.example",
  audience: "https://api.example",
  keystore: MyApp.Keystore,
  repo: MyApp.Repo,
  principal_kinds: &MyApp.AuthZ.principal_kinds/0,

  # Client registry (AttestoPhoenix.ClientStore).
  load_client: &MyApp.AuthZ.load_client/1,
  verify_client_secret: &MyApp.AuthZ.verify_client_secret/2,
  client_id: &MyApp.AuthZ.client_id/1,
  client_redirect_uris: &MyApp.AuthZ.client_redirect_uris/1,
  client_public?: fn _client -> false end,

  # Subject (AttestoPhoenix.PrincipalStore).
  load_principal: &MyApp.AuthZ.load_principal/1,
  build_principal: &MyApp.AuthZ.build_principal/3,

  # Login + consent (AttestoPhoenix.ConsentPolicy).
  authenticate_resource_owner: &MyApp.AuthZ.authenticate_resource_owner/3,
  consent: &MyApp.AuthZ.consent/3,

  # Scope policy (AttestoPhoenix.ScopePolicy); omit to default to
  # "subset of :scopes_supported".
  authorize_scope: &MyApp.AuthZ.authorize_scope/2,
  scopes_supported: ["openid", "profile", "email"],

  # Shared production token stores.
  code_store: AttestoPhoenix.Store.EctoCodeStore,
  refresh_store: AttestoPhoenix.Store.EctoRefreshStore,
  replay_check: &AttestoPhoenix.Store.EctoReplayCheck.check_and_record/2,
  nonce_store: AttestoPhoenix.Store.EctoNonceStore,
  sweep_interval_ms: 60_000
)
```

## Public PKCE client (native / SPA, no secret)

A public client holds no secret and proves possession of the authorization
code with PKCE (RFC 7636). It authenticates at the token endpoint with
`none`.

```elixir
AttestoPhoenix.Config.new(
  issuer: "https://auth.example",
  audience: "https://api.example",
  keystore: MyApp.Keystore,
  repo: MyApp.Repo,
  principal_kinds: &MyApp.AuthZ.principal_kinds/0,

  load_client: &MyApp.AuthZ.load_client/1,
  # A public client presents no secret; verification always fails closed if a
  # secret is somehow presented.
  verify_client_secret: fn _client, _secret -> false end,
  client_id: &MyApp.AuthZ.client_id/1,
  client_redirect_uris: &MyApp.AuthZ.client_redirect_uris/1,
  client_public?: fn _client -> true end,

  load_principal: &MyApp.AuthZ.load_principal/1,
  build_principal: &MyApp.AuthZ.build_principal/3,
  authenticate_resource_owner: &MyApp.AuthZ.authenticate_resource_owner/3,

  # require_pkce defaults to true; PKCE is enforced for the code grant.
  scopes_supported: ["openid", "profile"],

  code_store: AttestoPhoenix.Store.EctoCodeStore,
  refresh_store: AttestoPhoenix.Store.EctoRefreshStore,
  replay_check: &AttestoPhoenix.Store.EctoReplayCheck.check_and_record/2,
  nonce_store: AttestoPhoenix.Store.EctoNonceStore,
  sweep_interval_ms: 60_000
)
```

## Installed native app (RFC 8252)

A native app is a public PKCE client that additionally runs on the end user's
own device, which RFC 8252 (BCP 212) treats as its own case. Mark it with
`:client_native?` and the whole profile applies to it: PKCE is required (§8.1),
no token-endpoint credential is accepted (§8.4), and its loopback redirect URI
matches on any port (§7.3, a MUST). No further configuration.

A deployment that must forbid the §7.3 relaxation server-wide — one certifying
against a profile that mandates exact redirect-URI matching — sets
`native_apps: [loopback_redirect: false]`. Such a deployment usually has no
native clients in the first place, in which case nothing is needed at all.

```elixir
AttestoPhoenix.Config.new(
  issuer: "https://auth.example",
  audience: "https://api.example",
  keystore: MyApp.Keystore,
  repo: MyApp.Repo,
  principal_kinds: &MyApp.AuthZ.principal_kinds/0,

  load_client: &MyApp.AuthZ.load_client/1,
  verify_client_secret: fn _client, _secret -> false end,
  client_id: &MyApp.AuthZ.client_id/1,
  # Registered as `http://127.0.0.1:0/cb` (and/or `http://[::1]:0/cb`) - the
  # port is ignored under §7.3, so any placeholder will do. Prefer the literal
  # IP; clients fixed to a localhost callback require the explicit option below.
  client_redirect_uris: &MyApp.AuthZ.client_redirect_uris/1,
  client_public?: fn _client -> true end,
  client_native?: &MyApp.AuthZ.client_native?/1,

  # Optional §8.12 in-app-webview refusal; a User-Agent heuristic, so it can
  # misjudge honest browsers. Unlike the rest of the profile this is a
  # server-wide posture, so it is a flag rather than a per-client property.
  native_apps: [
    loopback_include_localhost: false,
    reject_embedded_user_agents: false
  ],

  load_principal: &MyApp.AuthZ.load_principal/1,
  build_principal: &MyApp.AuthZ.build_principal/3,
  authenticate_resource_owner: &MyApp.AuthZ.authenticate_resource_owner/3,

  scopes_supported: ["openid", "profile"],

  code_store: AttestoPhoenix.Store.EctoCodeStore,
  refresh_store: AttestoPhoenix.Store.EctoRefreshStore,
  replay_check: &AttestoPhoenix.Store.EctoReplayCheck.check_and_record/2,
  nonce_store: AttestoPhoenix.Store.EctoNonceStore,
  sweep_interval_ms: 60_000
)
```

## Mounting somewhere other than `/oauth`

Both configs above advertise the historic `/oauth/*` endpoints. To advertise a
different mount (for example `/mcp/oauth`), add a single key:

```elixir
oauth_path_prefix: "/mcp/oauth"
```

See `guides/consumer_migration.md` for the details.
