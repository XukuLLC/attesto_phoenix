# Upgrading to 3.4.1

Version 3.4.1 coordinates protocol-boundary hardening with Attesto 2.2.2,
closes an authentication downgrade, and bounds outbound CIMD work. Upgrade
the core package first, then deploy Attesto Phoenix 3.4.1 to every
authorization-server node. It adds no database migration beyond the existing
3.4 migration.

Hosts using the bundled Ecto stores that have not applied the 3.4 migration
must still generate and run it before deploying the new writers:

```bash
mix attesto_phoenix.gen.migration --upgrade 3.4 --repo MyApp.Repo
mix ecto.migrate
```

## Refresh families require reauthorization

New refresh families persist the configured authorization-server issuer and
verify it before rotation, retry, introspection, or revocation. This prevents a
second issuer that shares the same refresh store and client identifier from
accepting or mutating the family.

Families issued before 3.4.1 do not contain that binding and fail closed.
Retire those families through a trusted administrative process and have users
authorize again. The new endpoints cannot introspect or revoke their unbound
credentials. Do not run old and new token endpoint nodes together: an old node
can still accept an unbound family. Drain or upgrade every writer and token
endpoint as one rollout. Existing families are never bound to an issuer or
Client Instance Key on first reuse.

Hosts that configure `:build_refresh_principal` receive the verified `:issuer`,
subject, session, authorization context, and family identity. Use this callback
to recheck locked or deactivated users, terminated sessions, and invalid tenant
context before issuing a refreshed access token. Its successful principal is
used without a second `:build_principal` lookup; protocol-owned claims and the
authenticated `client_id` are reconciled before minting. Returning
`{:error, :invalid_grant}` revokes the family and returns a generic OAuth
`invalid_grant` response. Immediate lost-response retries can invoke the
callback again, so keep it side-effect-free or idempotent. When the callback is
omitted, the existing `:build_principal` behavior remains in use.

## Expose the registered authentication method

Return each client's trusted `token_endpoint_auth_method` through your client
store or a flat callback. Do not derive it from the incoming request, and do not
infer it from which credentials the client happens to present.

```elixir
defmodule MyApp.OAuth.ClientStore do
  @behaviour AttestoPhoenix.ClientStore

  # Other ClientStore callbacks remain host-owned.
  @impl true
  def client_auth_method(client), do: client.token_endpoint_auth_method
end
```

For hosts using flat callbacks:

```elixir
config :my_app, AttestoPhoenix,
  client_auth_method: &MyApp.OAuth.ClientStore.client_auth_method/1
```

The callback may return a known method string or atom, or `{:ok, method}`.
Unknown methods, errors, `nil`, and malformed results reject authentication.
The presented method must match exactly: `client_secret_basic` and
`client_secret_post` are separate registrations. This check applies to token,
PAR, introspection, revocation, device authorization, and CIBA.

When no method callback is installed, host-owned confidential clients fail
authentication, even if the server currently supports only one method. Narrowing
the server catalog cannot establish a previously registered client's method.
Explicitly public clients may use `none`; CIMD clients use their validated
metadata document's declared method. A configured callback never falls back
when it returns invalid data.

Registration now generates secrets only for `client_secret_basic` and
`client_secret_post` authentication.
Existing secrets issued to private-key JWT, mTLS, or attestation clients cannot
bypass their registered method. Hosts should remove unused stored secrets from
those registrations according to their own registry and retention policies.

## CIMD outbound and cache limits

For CIMD-enabled deployments, invalidate persisted metadata and attached JWKS
caches during the upgrade, after stopping older writers. Old records do not
contain the response headers needed to correct their previous freshness, and
the new resolver discards origin-supplied internal cache annotations. Call the
built-in cache's `delete_all/0` for each repository/schema-prefix context;
install that context for the Ecto cache as shown below. Use your own
invalidation mechanism for a custom backend. The built-in
ETS cache is empty on a fresh node; clear it explicitly for an in-place upgrade.

```elixir
AttestoPhoenix.Config.with_request_config(config, fn ->
  AttestoPhoenix.ClientIdMetadata.Cache.Ecto.delete_all()
end)
```

CIMD remains disabled by default. When enabled, metadata and remote JWKS share
node-wide outbound limits: 16 concurrent requests, 4 per host, 120 requests per
minute, and 30 per host per minute. Concurrent identical resolutions share one
request, with up to 32 followers. Failures receive a one-second backoff, and
host buckets and failure markers are each bounded to 1,024 entries. Over-limit requests fail
closed rather than fetching metadata without a bound.

The current host allow/block policy is checked before a remote JWKS cache
lookup. A valid, unexpired key cache hit performs no DNS lookup, outbound
request, or flow-control admission. Cache misses enter the outbound limits and
recheck the cache after admission before fetching under the configured
fetcher's DNS and IP screening, pinning, redirect, timeout, and size controls.
Cached keys never outlive their metadata document. Caches without the optional
atomic entry API fetch keys on each request. Basic and form-post client
authentication do not resolve unused remote JWKS.

The built-in caches retain at most 1,024 records: node-wide for ETS and per
repository/schema prefix for Ecto. Each serialized record is limited to 16 KiB,
including attached JWKS. Expired records are pruned, then records with the
earliest expiry are evicted as necessary.
Custom caches must provide their own capacity and size controls. Application
instances share Ecto capacity enforcement; outbound quotas are per node, so
cluster operators should also limit aggregate traffic at their ingress or proxy.

All limits are positive integer members of `:client_id_metadata`; see
`AttestoPhoenix.Config` for their names and defaults. Keep `allowed_hosts`
narrow where possible. Hostnames are compared and resolved as lowercase IDNA
ASCII names after removing one terminal DNS root dot. IP destination screening
and pinning remain active.

HTTP cache freshness now subtracts response age. A `max-age=3600` response
already aged 3,599 seconds has at most one second of remaining freshness.
These are shared caches: `s-maxage` takes precedence over `max-age` when
present, and `private` responses are not retained. Duplicate and malformed
freshness headers are handled conservatively, including quoted directive
values, response `Age` and `Date`, transport delay, and local residence time.
The first `cache_ttl_bounds` value is a fallback for responses without explicit
freshness and never increases an explicit publisher lifetime. `no-cache` and
`no-store` responses are not retained. Conditional 304 responses remain rejected
because the bundled fetcher does not send validators.

Registered assertion clients can now revoke using issuer-audience JWTs, and
registered mTLS and attestation clients can use their own credentials. The
revocation endpoint preserves attestation Challenge and fresh-attestation
errors so wallets can retry without falling back to a secret.

## Configure duplicate detection before body parsing

Configure the endpoint's existing `Plug.Parsers` entry with Attesto's body
reader before the router:

```elixir
plug Plug.Parsers,
  parsers: [:urlencoded, :multipart, :json],
  pass: ["*/*"],
  json_decoder: Phoenix.json_library(),
  body_reader: {AttestoPhoenix.DuplicateParameterGuard, :read_body, []}
```

Query strings are checked automatically. The body reader lets protocol
controllers reject repeated scalar form fields and duplicate JSON object names
at every nesting level before Phoenix turns the body into a map. Repeated RFC
8707 `resource` values remain supported. If the endpoint already uses a custom
body reader, forward its MFA through `AttestoPhoenix.DuplicateParameterGuard`
as described in that module's documentation.

## Public clients require an explicit consent decision

Authorization requests from public clients no longer inherit the historical
implicit allow behavior when no consent callback is configured. Provide
`c:AttestoPhoenix.ConsentPolicy.consent/3` or the flat `:consent` callback for
every deployment that serves public clients.

## Dynamic registration is stricter

The registration endpoint now requires `registration_enabled: true`, a
registration callback, a single JSON Content-Type header, and a JSON object
body. Mounting the route alone does not enable registration. The endpoint
bounds collections and text, rejects external plain-HTTP redirects, applies an
HTTPS-only logout callback profile, validates public JWK and RFC 8705 identity
metadata, and requires private-key JWT keys to satisfy the configured algorithm
policy.

An omitted `grant_types` member now receives RFC 7591's
`["authorization_code"]` default. A present JSON `null` value for
`grant_types`, `redirect_uris`, or `scope` is invalid rather than equivalent to
an omitted member.

An explicit `token_endpoint_auth_methods_supported` catalog is now validated
at boot against Attesto Phoenix's accepted catalog. Remove `client_secret_jwt`
and custom extension names before upgrading; those values now fail
configuration instead of being advertised or offered to registration. The
already documented `attest_jwt_client_auth_dpop` combined value remains
unsupported and is omitted from the effective catalog.

If the host dereferences a registered `jwks_uri`, the host callback must screen
DNS and connected addresses, reject redirects, pin the approved destination,
and bound response bytes, media type, and time. Registered display metadata is
still untrusted and must be escaped at every HTML rendering sink.

## Encrypted presentation responses have stricter boundaries

OID4VP `direct_post.jwt` responses now reject oversized encrypted envelopes,
duplicate JSON object members, and non-canonical Base64URL encodings before
decryption. The controller also enforces direct ECDH key agreement and the
required AES-GCM IV and authentication-tag lengths. Wallets must produce the
standard compact JWE encoding; malformed encodings no longer reach the
cryptographic dependency.
