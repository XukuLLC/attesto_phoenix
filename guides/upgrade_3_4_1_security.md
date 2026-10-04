# Upgrading to 3.4.1

Version 3.4.1 closes an authentication downgrade and bounds outbound CIMD work.
It adds no database migration beyond the existing 3.4 migration.

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

Registration now generates secrets only for secret-based authentication.
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
The first `cache_ttl_bounds` value is a fallback for responses without explicit
freshness and never increases an explicit publisher lifetime. `no-cache` and
`no-store` responses are not retained. Conditional 304 responses remain rejected
because the bundled fetcher does not send validators.

Registered assertion clients can now revoke using issuer-audience JWTs, and
registered mTLS and attestation clients can use their own credentials. The
revocation endpoint preserves attestation Challenge and fresh-attestation
errors so wallets can retry without falling back to a secret.
