# Identity Assertion grant (ID-JAG / MCP Enterprise-Managed Authorization)

The **Identity Assertion JWT Authorization Grant** (ID-JAG,
[`draft-ietf-oauth-identity-assertion-authz-grant-04`](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/))
is the grant behind **MCP Enterprise-Managed Authorization (EMA)**. It lets an
enterprise IdP centrally provision access to a resource application with no
browser redirect and no consent screen.

The flow has two token steps; attesto is the **resource application's**
authorization server and implements only the second:

1. *(not attesto's job)* The client performs an RFC 8693 token exchange **at the
   IdP**, trading the user's ID token / SAML assertion for an **ID-JAG**: a
   short-lived JWT, signed by the IdP, asserting one user for one resource
   application.
2. *(attesto's job)* The client presents that ID-JAG to attesto's token endpoint
   as an RFC 7523 §4 JWT-bearer authorization grant and receives a normal access
   token:

   ```http
   POST /oauth/token
   Authorization: Basic <client credentials>     # the grant requires client auth
   Content-Type: application/x-www-form-urlencoded

   grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
   &assertion=<the ID-JAG JWT>
   &scope=mcp:read            # optional; bounded by the assertion's scope claim
   ```

This is **not** `private_key_jwt` client authentication (RFC 7523 §3, which
asserts the *client's* identity) and **not** the
`urn:ietf:params:oauth:grant-type:token-exchange` grant (RFC 8693, which runs at
the IdP).

## What attesto validates

`Attesto.IdentityAssertion` verifies the assertion and the token core maps every
failure to RFC 6749 §5.2 `invalid_grant` (a missing `assertion` parameter is
`invalid_request`):

- JOSE header `typ` is `oauth-id-jag+jwt`.
- the signature verifies against the **trusted issuer's** JWKS.
- `iss` is a configured trusted issuer (an unconfigured issuer is denied without
  revealing the trusted set).
- `aud` is exactly this server's issuer identifier.
- the required `iss`, `sub`, `aud`, `client_id`, `jti`, `exp`, `iat` claims are
  present; `exp`/`iat`/`nbf` are within skew and the assertion is not expired.
- the `client_id` claim matches the **authenticated** client.
- the `jti` has not been replayed.

The asserted `scope` claim (when present) is the **ceiling** on what the issued
token may carry; your `:authorize_scope` policy narrows from there.

## Configuration

The feature is **off by default**. Enable it under `:jwt_bearer`:

```elixir
config :my_app, AttestoPhoenix.Config,
  # ... issuer, keystore, repo, the usual callbacks ...
  jwt_bearer: [
    enabled: true,
    issuers: %{
      # A trusted enterprise IdP with STATIC keys:
      "https://idp.example.com" => [
        jwks: %{"keys" => [%{"kty" => "RSA", "kid" => "...", "n" => "...", "e" => "AQAB"}]},
        allowed_algs: ["RS256", "ES256"]   # optional; defaults to all supported
      ],
      # ...or one whose keys are fetched (and cached) from its JWKS URI:
      "https://idp.other.com" => [
        jwks_uri: "https://idp.other.com/.well-known/jwks.json"
      ]
    },
    assertion_max_lifetime_seconds: 300   # optional ceiling on exp - iat
  ],
  resolve_jwt_bearer_subject: &MyApp.AuthZ.resolve_jwt_bearer_subject/1
```

When enabled, `urn:ietf:params:oauth:grant-type:jwt-bearer` is added to
`grant_types_supported` (both discovery documents and the token endpoint honour
it). Config validation fails closed at boot if you enable the grant without a
trusted-issuer source or without the subject-resolution callback.

### `:jwt_bearer` options

| key | meaning |
| --- | --- |
| `:enabled` | turns the grant on (default `false`) |
| `:issuers` | `%{issuer_url => issuer_opts}`; `issuer_opts` carries `:jwks` (static), `:jwks_uri` (fetched + cached), `:allowed_algs`, and an optional `:audience` override (defaults to the AS issuer) |
| `:assertion_max_lifetime_seconds` | reject an assertion whose `exp - iat` exceeds this (default `300`) |
| `:jwks_resolver` | optional `(issuer, issuer_opts) -> {:ok, jwks}`; full host control, bypasses `:jwks`/`:jwks_uri` |
| `:jwks_fetcher` / `:jwks_cache` | the SSRF-guarded remote-JWKS fetch + cache for `:jwks_uri` issuers (reused from the CIMD seam; default `Req` + the Ecto cache) |

`jti` replay reuses the configured `:replay_check` (the same store as DPoP),
namespaced so an ID-JAG `jti` never collides with a DPoP proof's. In a cluster,
set `:replay_check` to `{AttestoPhoenix.Store.EctoReplayCheck, :check_and_record}`
as you would for DPoP.

## Wiring the subject-resolution callback

The asserted `sub` is the IdP's identifier for the user; you map it to your
local subject. The callback receives the **validated** claims (signature, trust,
`client_id` binding, `jti` replay already checked) and returns the local subject
or denies. It is also installable as `resolve_jwt_bearer_subject/1` on an
`AttestoPhoenix.PrincipalStore` module.

```elixir
def resolve_jwt_bearer_subject(claims) do
  # `claims["sub"]` is unique when scoped with `claims["iss"]`; `claims["email"]`
  # is often also present. Map to YOUR account model however you choose.
  case MyApp.Accounts.fetch_by_external_id(claims["iss"], claims["sub"]) do
    {:ok, user} -> {:ok, "user:#{user.id}"}   # the subject the token is minted for
    :error -> {:error, :no_local_account}     # a deny becomes invalid_grant
  end
end
```

The returned subject string is exactly what your `:build_principal` callback then
receives, so token claim-shaping is unchanged from the other grants.

A refresh token is issued only when `offline_access` is granted and a
`:refresh_store` is configured (the same policy as the authorization-code grant).
