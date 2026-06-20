# ID-JAG + RFC 9728 — release, conformance & MCP status

Internal status notes (not published — `notes/` is excluded from the Hex package
and the docs `extras`). Captures the strategic context behind the
`id-jag-jwt-bearer-grant` branch that is not already recorded in code or the
CHANGELOGs.

_Last updated: 2026-06-20._

## What's on the branch

Branch `id-jag-jwt-bearer-grant` (both repos), one feature commit each ahead of
`main`, plus the working-tree changes from this round. Target versions:
**attesto 0.8.0**, **attesto_phoenix 0.10.0** (changes accumulated under
`## [Unreleased]`).

- **jwt-bearer / ID-JAG grant** (RFC 7523 §4; `draft-ietf-oauth-identity-assertion-authz-grant-04`):
  `Attesto.IdentityAssertion` verifier + `AttestoPhoenix.AuthorizationServer.JwtBearer`
  handler, per-issuer trust allowlist with SSRF-safe JWKS fetch (reuses the CIMD
  fetcher), `jti` single-use replay (namespaced `idjag:` on the DPoP replay seam),
  scope ceiling, host `:resolve_jwt_bearer_subject`. Aligned to spec this round:
  **no refresh tokens** for this grant, and **RFC 8707 `resource` → access-token
  `aud`** (single absolute-URI-no-fragment resource; else `config.audience`;
  invalid/multiple → `invalid_target`).
- **RFC 9728 protected-resource metadata:** `Attesto.ProtectedResourceMetadata`
  renderer, `resource_metadata` pointer on the `WWW-Authenticate` challenge
  (§5.1), and a served `GET /.well-known/oauth-protected-resource` endpoint
  (`AttestoPhoenix.Controller.ProtectedResourceController`).
- **Hardening:** total RFC 6749 §5.2 error-code resolution (atoms, no
  `to_existing_atom` round-trip); `:audience` required at config build time;
  DCR → `client_credentials` proven via the `:build_principal` seam (no new
  callback, prefix kept).

## Conformance coverage of the new features

Verified from primary sources:

- **FAPI 2.0 Security Profile (final) does not reference RFC 8707 or RFC 9728.**
  So the FAPI2 / OIDC OP cert plans currently run on the box do **not** exercise
  the `resource` parameter or protected-resource metadata.
- **jwt-bearer / ID-JAG: no cert program** — it's a pre-adoption IETF draft.
- **Only live intersection: token-endpoint error totality** (the error-atom
  item). OIDC/FAPI plans assert clean RFC 6749 §5.2 error bodies
  (`oidcc-refresh-token`, `unsupported_grant_type`, FAPI error cases), so the
  atom hardening protects a path the suite genuinely hits. (The retired
  `to_existing_atom` round-trip produced a real 500 in a prior shipped release.)

Net: the new *features* are ahead of the cert programs; their safety net is the
library's own test suite plus the Codex review.

## MCP protected-resource test track

- **The OpenID Foundation conformance suite has no runnable RFC 9728 / MCP
  resource-server test today.** Only inert plumbing exists:
  `FetchOauthProtectedResourceMetadata` (unwired, landed as Shared-Signals
  groundwork) and a permissive OpenID-Federation entity-statement validator.
  There is no resource-server-under-test role, no §2 field validation, and no
  §5.1 `WWW-Authenticate` challenge assertion. You cannot point
  certification.openid.net at our RS plugs and get a pass/fail.
- **Real MCP conformance lives in the MCP project's own suite**
  (`modelcontextprotocol`), gated by **SEP-985** ("Align PRM with RFC 9728") and
  tied to the **MCP 2026-07-28** spec line (RC published 2026-05-21). MCP servers
  MUST implement RFC 9728 (serve `/.well-known/oauth-protected-resource` + the
  `resource_metadata` 401 challenge).
- **Our RFC 9728 work is exactly the MCP-server (protected-resource) surface.**
  Today's validation is our own tests; the future signal is the MCP project's
  suite once the SEP-985 scenario ships (≈ post 2026-07-28).
- **Action when ready:** run the MCP project's conformance suite against our RS
  plugs after SEP-985 lands.

Sources: FAPI 2.0 Security Profile (final), RFC 8707, RFC 9728,
gitlab.com/openid/conformance-suite, modelcontextprotocol SEP-985,
MCP 2026-07-28 release candidate.

## Use-case positioning

The attesto_phoenix README now leads with use cases rather than a standards
list: (1) an API AI assistants (ChatGPT, Claude) can connect to over OAuth, (2)
your own authorization server, (3) a stolen-token-resistant resource server. The
RFC tables remain as reference, demoted below the use cases.

## Release readiness

- **Publish gate:** attesto_phoenix requires `attesto ~> 0.8`; Hex `attesto` is
  still 0.7.2. Dev/test against the path dep with `ATTESTO_PATH=1`. Publish
  **attesto 0.8.0 first**, then **attesto_phoenix 0.10.0**.
- **Pending:** Codex deep-dive review (fix → review loop until clean).
