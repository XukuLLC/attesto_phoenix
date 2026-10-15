# Upgrading to AttestoPhoenix 4.0

AttestoPhoenix 4.0 is a major release because it changes the public success
contract of the `:build_deferred_credential` callback. It also requires
Attesto 2.4.0 so the Phoenix persistence layer and authorization endpoints can
use the matching replay-deadline, CIBA resource, and signed JAR
`authorization_details` APIs.

Plan this as a coordinated application and database deployment. Publish or
otherwise make Attesto 2.4.0 resolvable first, update this application's lock,
stop token writers while applying any missing migrations, and then deploy
AttestoPhoenix 4.0. Update the deferred-credential callback before the new
endpoint receives traffic.

## Dependency versions

Update the application dependency:

```elixir
{:attesto_phoenix, "~> 4.0"}
```

AttestoPhoenix 4.0 accepts Attesto `>= 2.4.0 and < 3.0.0`. Applications that
also declare `:attesto` directly must use a compatible requirement, for
example:

```elixir
{:attesto, "~> 2.4"}
```

This ordering is required. The Phoenix source uses APIs absent from the 2.2.2
release currently recorded in this repository's lock. A Hex build cannot use a
local path override, so publish Attesto 2.4.0, run `mix deps.update attesto`, and
verify the resolved version before building or publishing AttestoPhoenix 4.0.

## POST endpoint query strings

The token, introspection, revocation, and PAR controllers now reject every
non-empty query string. This is broader than checking only known OAuth names:
`POST /oauth/token?trace_id=123` is rejected even when all protocol parameters
are in the request body. Remove tracing, tenant, routing, and intermediary-added
query parameters from these endpoint URLs before upgrading.

## Consent-grant compatibility

Consent grants now bind the subject and request with a type-tagged,
length-framed encoding that also includes `resource`, `claims`, and `dpop_jkt`.
A grant minted by 3.x does not verify under 4.0. These grants are short-lived
and single-use; drain the consent window during cutover or expect users with an
in-flight consent page to restart authorization.

`AttestoPhoenix.ConsentGrant.binding_from_params/2` now raises `ArgumentError`
for malformed raw input. A consent controller operating directly on untrusted
parameters should use the non-raising API:

```elixir
with {:ok, binding} <-
       AttestoPhoenix.ConsentGrant.safe_binding_from_params(params, subject) do
  # Mint the consent grant from the validated binding.
end
```

## Router mount controls

Every route-mount option passed to `attesto_routes/1` must expand at compile
time to `true` or `false`. This applies to `registration`, `device`,
`credential_issuance`, `federation`, `status_list`, `presentation`, `ciba`,
`logout`, `session_management`, `userinfo`, `openid_configuration`, and
`protected_resource_root`. Replace runtime expressions with compile-time
booleans. The stricter contract prevents a truthy non-boolean from silently
mounting a security-sensitive endpoint.

## Default audience

The 3.x `Config` typespec allowed `:audience` to be a string or a list. Version
4.0 requires one absolute HTTPS resource identifier:

```elixir
audience: "https://api.example.com"
```

Use RFC 8707 `resource` parameters and `:resource_indicators` for additional
targets. A list now fails during configuration validation.

## Deferred credential callback

The old callback could return credential claims alone:

```elixir
{:ok, %{claims: %{"degree" => "Bachelor"}}}
```

That result does not contain enough information to bind a deferred credential
to the public key proven during the original credential request. Version 4.0
therefore rejects it.

Persist the credential configuration ID and the verified public holder JWK
with the deferred transaction when the original request is accepted. The
callback must resolve the transaction within the authenticated `subject` and
return all three values:

```elixir
build_deferred_credential: fn subject, transaction_id ->
  with {:ok, transaction} <- MyApp.DeferredCredentials.fetch(subject, transaction_id) do
    {:ok,
     %{
       credential_configuration_id: transaction.credential_configuration_id,
       holder_jwk: transaction.public_holder_jwk,
       credential: transaction.credential
     }}
  end
end
```

The success map uses atom keys. `credential_configuration_id` must be a
non-empty string, `holder_jwk` must be the public verification JWK captured
from the original proof, and `credential` must be the format-specific map that
the immediate `:build_credential` callback would return. Never persist or
return private JWK members.

Keep returning `{:error, :issuance_pending}` while work is incomplete. Other
error values are reported as `invalid_credential_request` without exposing the
host reason. Malformed success values also fail closed.

The callback remains responsible for checking that `transaction_id` belongs
to `subject`. Resolving by transaction ID alone permits one authenticated
wallet to poll another wallet's transaction.

## mdoc validity

For an `mso_mdoc` credential configuration, the credential result returned by
either issuance callback must contain a non-negative integer `:valid_until`
strictly after `:valid_from`. Version 3.x defaulted the missing value to the
current instant, producing an already-expired mdoc; version 4.0 rejects the
result as `invalid_credential` instead.

## Database migrations

A fresh installation generates one complete migration:

```sh
mix attesto_phoenix.gen.migration --repo MyApp.Repo
```

For an existing installation, inventory which milestone migrations have
already been applied, then generate and apply every missing milestone in this
order:

```sh
mix attesto_phoenix.gen.migration --upgrade 3.0 --repo MyApp.Repo
mix attesto_phoenix.gen.migration --upgrade 3.1 --repo MyApp.Repo
mix attesto_phoenix.gen.migration --upgrade 3.4 --repo MyApp.Repo
mix attesto_phoenix.gen.migration --upgrade 3.6 --repo MyApp.Repo
mix attesto_phoenix.gen.migration --upgrade 3.7 --repo MyApp.Repo
```

Pass the same `--schema-prefix` used by the runtime stores to every command
when the deployment uses an explicit PostgreSQL schema. Review the generated
files before running `mix ecto.migrate`.

The milestones provide:

- **3.0:** durable refresh-family revocation tombstones and the unique
  `(family_id, generation)` index.
- **3.1:** promotion of the historical authorization-code unique index to the
  primary key used by the current schema.
- **3.4:** refresh-family deadlines, independent Client Instance Key bindings,
  and the full-width CIBA client notification token.
- **3.6:** `text` storage for Client ID Metadata cache URLs. Request admission
  remains limited to 2,048 bytes.
- **3.7:** the authorization-code `replay_retain_until` deadline. Successful
  legacy rows linked to a refresh family retain `NULL`. The 4.0 sweeper keeps
  such a marker while the refresh-token table contains an unexpired family
  member and deletes it after the family ends.

A database already upgraded through an earlier 3.x release only needs later
milestones it has not applied. Do not generate a second migration for a
milestone already present under another timestamp.

## Rollout checklist

1. Publish or otherwise make Attesto 2.4.0 resolvable.
2. Update the application lock and verify that Attesto 2.4.0 is selected.
3. Update and test the deferred-credential and mdoc callback contracts.
4. Drain in-flight consent grants, then stop and drain token writers.
5. Generate, review, and apply all missing migration milestones in order.
6. Deploy AttestoPhoenix 4.0.
7. Exercise authorization-code replay handling, CIBA resource requests, signed
   JAR credential authorization details, and immediate and deferred credential
   issuance in the deployment environment.

The migration generators validate the canonical historical objects they adopt
and stop on incompatible custom layouts. A rejection requires a reviewed custom
migration; do not bypass the validation.

## Development-only Bandit pin

The 4.0 development lock pins Bandit to the exact upstream commit containing
the CVE-2026-105659 fix. Bandit is test-only and is absent from the published
package requirements. Replace that git dependency with the first patched Hex
release once available, then refresh the lock and rerun the outbound HTTP test
suite.
