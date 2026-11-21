# Identity Assertion grant (ID-JAG / MCP Enterprise-Managed Authorization)

An enterprise identity provider (IdP) can authorize access to a resource without
a browser redirect or a consent screen. The client first performs an RFC 8693
token exchange at the IdP, presenting the user's ID token or SAML assertion.
The IdP issues a short-lived Identity Assertion JWT Authorization Grant
(ID-JAG) for the client to redeem at the resource authorization server.
[ID-JAG draft -06](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06).

The client sends the ID-JAG as an RFC 7523 §4 JWT-bearer authorization grant.

```http
POST /oauth/token
Authorization: Basic <client credentials>
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
&assertion=<ID-JAG>
&scope=records:read
```

The server checks the JOSE type `oauth-id-jag+jwt`, issuer signature, exact
issuer and audience, request client ID, timestamps, and `jti` replay. The
asserted `scope` is the ceiling for the host's `:authorize_scope` policy. The
server enforces any signed `resource` and `cnf` claims. Invalid assertions
return `invalid_grant`. A missing `assertion` returns `invalid_request`. A
subject or principal denial returns `access_denied` without information about
the user. [RFC 6749 §5.2](https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2).
[ID-JAG draft -06 §§4.4.1, 4.4.3 and 10](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-4.4.1).

## Configuration

The grant defaults to disabled. Enable it with `jwt_bearer: [enabled: true]`,
at least one trusted issuer or a trust resolver, and a
`:resolve_jwt_bearer_subject` callback.

```elixir
jwt_bearer: [
  enabled: true,
  issuers: %{
    "https://idp.example.com/organizations/example" => [discovery: true],
    "https://idp.other.example" => [jwks_uri: "https://idp.other.example/keys.json"]
  },
  assertion_max_lifetime_seconds: 300
]
```

With the default grant catalog, the authorization server advertises
`urn:ietf:params:oauth:grant-type:jwt-bearer` in `grant_types_supported`.
If you set an explicit grant catalog, include that URN to make the grant
available. The server pairs it with
`urn:ietf:params:oauth:grant-profile:id-jag` in
`authorization_grant_profiles_supported`.

| Option | Behavior |
| --- | --- |
| `:issuers` | Map from exact issuer identifiers to options. An entry can supply `:jwks`, `:jwks_uri`, `:discovery`, `:allowed_algs`, and an `:audience` override. The audience defaults to the authorization server issuer. |
| `:resolve_trusted_issuer` | Host callback `(iss, aud_tenant, client)` that supplies issuer options and recipient-tenant context. |
| `:assertion_max_lifetime_seconds` | Maximum `exp - iat`. Defaults to 300 seconds. |
| `:public_clients` | `:deny` by default. Set `:allow` to permit public clients. |
| `:authorization_details_types_supported` | RFC 9396 detail types the host grants on this grant. Defaults to an empty list. |
| `:jwks_resolver` | Optional `(issuer, issuer_opts) -> {:ok, jwks}` key source. The host still configures issuer trust. |
| `:jwks_fetcher` and `:jwks_cache` | Remote discovery and key fetcher and cache. The defaults are the SSRF-guarded Req fetcher and Ecto cache shared with client metadata. |
| `:jwks_cache_ttl_bounds` | Default freshness when headers provide none and maximum freshness, in seconds. Defaults to `{300, 86_400}`. |

The server selects keys from a custom `:jwks_resolver` first, then static
`:jwks`. An issuer can use a configured `:jwks_uri` or set `discovery: true`
to use metadata. The server uses discovery by default when neither key option is configured.
Set `discovery: false` to require a configured key source.

For discovery, the server inserts `/.well-known/oauth-authorization-server`
before the issuer path. On HTTP 404 it appends `/.well-known/openid-configuration`
to the issuer. A document containing only `issuer` and `jwks_uri` suffices.
The issuer value must match the trusted issuer exactly, including its path,
and the key URL must use HTTPS. The server caches metadata and keys according
to response freshness headers and the configured TTL bounds. An unseen
`kid` in a fresh cached key set can trigger one key refresh per issuer per node
within a 30-second window. The server ignores assertion header keys and key
URLs. [RFC 8414 §3](https://www.rfc-editor.org/rfc/rfc8414.html#section-3).
[OpenID Connect Discovery §4](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig).
[ID-JAG draft -06 §§4.4.1 and 7.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-7.1).

The server grants signed authorization details with types listed in
`:authorization_details_types_supported`, preserves their fields, and
includes them in the access token and token response. Configure only types
whose fields the resource server can enforce for the applicable scopes and
resources. [RFC 9396 §§2, 7 and 9](https://www.rfc-editor.org/rfc/rfc9396.html).

The server uses the configured `:replay_check` for the assertion's `jti`, with
a separate namespace from DPoP. For a cluster, use
`{AttestoPhoenix.Store.EctoReplayCheck, :check_and_record}` as with DPoP.

## Resolve the recipient tenant and subject

Configure `:resolve_trusted_issuer` for host-managed trust records. When set,
this callback governs every issuer, including issuers also in the static map.
This lets the host refuse an ambiguous or revoked trust relationship without
a static fallback. Without the callback the server uses an exact lookup in
`:issuers`.

The callback receives the unverified `iss` and `aud_tenant` (`nil` when
absent) and the request client. Client metadata document clients arrive as
metadata maps, as for scope callbacks. Direct `JwtBearer.prepare/3` and
`authorize/3` calls supply the client ID. Use the unverified claims only to
look up trust. Return `{:ok, issuer_opts, context}` for one matching record,
`{:error, :not_found}` for none, or `{:error, :ambiguous}` for several.
Use the full issuer URL as the lookup key. You can return the record's exact
issuer in `:issuer` so the library also checks that pin before fetching keys.

For a multi-tenant service, use `aud_tenant` to select a tenant that trusts
the exact issuer. When `aud_tenant` is absent, use the tenant identified by the
validated audience or by an unambiguous issuer trust record. Return an
issuer-specific `:audience` when the record pins the recipient audience.
When the IdP itself serves multiple tenants, verify the signed `tenant`
against the selected trust record before resolving a user.
[ID-JAG draft -06 §4.4.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-4.4.1).

The two-argument subject callback receives verified claims and
`%{issuer_context: context, aud_tenant: aud_tenant}`. Static entries supply
`nil` as `:issuer_context`. The original one-argument callback still receives
the claims, including any `aud_tenant`. Both arities can be installed on
`AttestoPhoenix.PrincipalStore`. Resolve `sub` only within the selected
recipient tenant. Return `{:ok, subject}` or a subject string to authorize,
or `{:error, reason}` to deny. A principal builder can also return
`{:error, :access_denied}` for this grant. The server records the replay
claim after subject and principal authorization, so a replay can reach these
callbacks. Keep their side effects idempotent.

## Clients that present client ID metadata documents

A client may publish two distinct client IDs, one URL for its public document
and one for its authenticated document. Accept the exact URLs for the modes
you support. Each document must declare the JWT-bearer grant. Clients that
select a document from authorization server metadata can present the
authenticated document when `token_endpoint_auth_methods_supported` lists
`private_key_jwt`. The server verifies the RFC 7523 client assertion against
that document's `jwks_uri` or inline keys. Adding or removing
`private_key_jwt` can change the client ID an IdP must put in the ID-JAG.
Configure the IdP with the same client ID that the client sends to the token
endpoint.

The server requires client authentication for this grant by default. Setting
`jwt_bearer: [public_clients: :allow]` permits a public client to redeem a
bearer assertion, which departs from draft -06 §4.4. The token request is no
longer bound to a client credential. The assertion's `client_id` binding,
issuer signature, short lifetime, and `jti` replay check still apply. A
present `cnf` still requires proof of possession.

When an issuer assigns opaque, issuer-specific subjects, map a signed
`email` to a local address only within the recipient tenant. Compare the
entire email address case-insensitively. Use email lookup only when the
address or its domain has been verified under the issuer trust policy.

Set the access-token lifetime according to the longest a removed tenant
member may retain already-issued access. The server issues no refresh token
for this grant.
