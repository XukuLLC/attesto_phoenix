# Design: Client ID Metadata Documents (CIMD) for attesto

Status: design, ready to build. Target: `attesto` (pure validation) + `attesto_phoenix`
(HTTP fetch, SSRF guard, caching, wiring).

## 1. What & why

CIMD (`draft-ietf-oauth-client-id-metadata-document-01`, IETF OAuth WG, Mar 2026;
formerly `draft-parecki-…`) lets a client identify itself with **no prior
registration** by using an **HTTPS URL as its `client_id`**. The AS dereferences
that URL to fetch a JSON **client metadata document** (the RFC 7591 Dynamic Client
Registration metadata field set) and uses it as the client.

Motivation: OpenAI's ChatGPT MCP connector *prefers* CIMD (with token auth via
`none` or `private_key_jwt`). attesto already serves ChatGPT's **fallback** (RFC 7591
DCR + `none`/`private_key_jwt` — both supported), so this is a "better-citizen"
interop feature, not a blocker. It is an active, fielded WG draft; build it
feature-flagged and conservative so a draft bump is a small change.

## 2. Spec requirements we must honor (from draft-01)

- **`client_id` URL grammar (§2):** HTTPS scheme; MUST have a path component; MUST NOT
  contain a fragment; MUST NOT contain userinfo (username/password); MUST NOT contain
  single-dot or double-dot path segments. Ports allowed; query discouraged but allowed.
- **Fetch:** GET the URL. Response MUST be `200 OK` (treat all other status as error).
  The AS MUST NOT follow HTTP redirects. Body MUST be JSON (`application/json` or
  `application/<as-defined>+json`). Recommended max response size **5 KB**.
- **Document contents:** fields are the OAuth Dynamic Client Registration Metadata
  registry values. The document **MUST contain a `client_id`** equal to the URL
  (simple string comparison). `token_endpoint_auth_method` MUST NOT be
  `client_secret_basic` / `client_secret_post` / `client_secret_jwt` (no shared
  symmetric secret); `client_secret` / `client_secret_expires_at` MUST NOT be present.
- **redirect_uris:** per RFC 9700 the AS MUST require registered redirect URIs and
  exact-match the request's. The AS MAY additionally require same-origin between
  `redirect_uri` and the `client_id` URL.
- **SSRF (Security Considerations):** the AS MUST validate the `client_id` URL does
  **not resolve to special-use IP addresses (RFC 6890)** — except when the AS itself
  runs on loopback. The AS SHOULD NOT fetch URLs *inside* the document (e.g.
  `logo_uri`) that resolve to special-use IPs.
- **Caching:** SHOULD respect HTTP cache headers (RFC 9111), MAY clamp to its own
  min/max. MUST NOT cache error responses, MUST NOT cache invalid/malformed documents.
- **Discovery:** advertise `client_id_metadata_document_supported` (OPTIONAL boolean)
  in RFC 8414 AS metadata.

## 3. Architecture (fits attesto's neutral-core / host-policy model)

```
                       attesto (pure, conn-free, NO http)
  ┌───────────────────────────────────────────────────────────────┐
  │ Attesto.ClientIdMetadata                                       │
  │   client_id_url?/1     validate_client_id/1                    │
  │   validate_document/2  (client_id match, reject symmetric auth)│
  └───────────────────────────────────────────────────────────────┘
                       attesto_phoenix (http, ssrf, cache, wiring)
  ┌───────────────────────────────────────────────────────────────┐
  │ AttestoPhoenix.ClientIdMetadata.Resolver  (orchestrator)       │
  │   resolve/2 : cache → Fetcher → core validate → cache → client │
  │ .Fetcher (behaviour + Req default)   ← SSRF-guarded GET        │
  │ .Cache   (behaviour + ETS default; Ecto option for clusters)  │
  └───────────────────────────────────────────────────────────────┘
                              ▲ hooked into existing client resolution
        authorize_controller (:load_client)   client_authentication (token/PAR)
```

- **Pure validation in `attesto` core.** URL grammar + document validation are
  conn-free, HTTP-free, unit-testable — same style as `Attesto.AuthorizationRequest`.
- **HTTP + SSRF + caching in `attesto_phoenix`.** The only place allowed to make the
  outbound request; the core stays dependency-free.
- **Host override + opt-in.** The whole feature is config-gated (default OFF). The
  fetcher is pluggable so a host can use a CIMD proxy service (spec-recommended for
  dev) or its own HTTP stack.

## 4. New modules & signatures

### attesto core — `Attesto.ClientIdMetadata`
```elixir
@spec client_id_url?(term()) :: boolean()
# true iff a binary that parses as an https URL with a path and no fragment/userinfo/
# dot-segments. Used to decide "is this a CIMD client_id?" before any network work.

@spec validate_client_id(String.t()) :: {:ok, URI.t()} | {:error, reason}
# full §2 grammar; reason :: :not_https | :no_path | :has_fragment | :has_userinfo |
#                            :dot_segments | :not_a_url

@spec validate_document(client_id :: String.t(), doc :: map()) ::
        {:ok, metadata :: map()} | {:error, reason}
# - doc["client_id"] == client_id (simple string compare) else {:error, :client_id_mismatch}
# - reject client_secret / client_secret_expires_at -> {:error, :symmetric_secret}
# - reject token_endpoint_auth_method in ~w(client_secret_basic client_secret_post client_secret_jwt)
# - normalize redirect_uris (required, non-empty list of strings), grant_types,
#   response_types, scope, jwks / jwks_uri, client_name, logo_uri, etc. into the
#   client shape attesto's resolution expects (mirror the RFC 7591 register path).
```
No new deps in core.

### attesto_phoenix — `AttestoPhoenix.ClientIdMetadata.Fetcher` (behaviour + default)
```elixir
@callback fetch(url :: String.t(), opts :: keyword()) ::
            {:ok, %{body: binary(), cache_control: keyword()}} | {:error, reason}
```
Default impl (`...Fetcher.Req`) performs the **SSRF-guarded** GET (§5). A host may
supply `{Mod, :fun}` or a proxy-service URL builder instead.

### attesto_phoenix — `AttestoPhoenix.ClientIdMetadata.Cache` (behaviour + ETS default)
```elixir
@callback get(url :: String.t()) :: {:ok, metadata :: map()} | :miss
@callback put(url :: String.t(), metadata :: map(), expires_at :: DateTime.t()) :: :ok
```
ETS default (per-node; re-fetch on miss is correct, so per-node is acceptable). Provide
`...Cache.Ecto` for cluster coherence + to bound outbound fetch fan-out (optional,
matches the clustering work — table `attesto_client_id_metadata`, key = url, value =
jsonb metadata + `expires_at`, swept by `Store.Sweeper`).

### attesto_phoenix — `AttestoPhoenix.ClientIdMetadata.Resolver`
```elixir
@spec resolve(client_id :: String.t(), Config.t()) ::
        {:ok, client :: map()} | {:error, reason}
# 1. Attesto.ClientIdMetadata.validate_client_id(client_id)  (fail fast, no network)
# 2. Cache.get/1 -> hit returns immediately
# 3. Fetcher.fetch/2  (SSRF-guarded)
# 4. JSON decode (size already capped) -> Attesto.ClientIdMetadata.validate_document/2
# 5. Cache.put/3 with expiry from cache_control (clamped to config bounds); NEVER on error
# 6. return the normalized client
```

## 5. SSRF hardening (the load-bearing part)

`Fetcher.Req.fetch/2` algorithm — all steps MUST pass or it errors closed:

1. **Re-validate** the URL is https + §2 grammar (defense in depth; never trust caller).
2. **Resolve** the host to A/AAAA records (`:inet.getaddrs/2` or Finch's resolver). No
   records → `{:error, :unresolvable}`.
3. **Reject special-use IPs (RFC 6890)** for *every* resolved address:
   loopback `127.0.0.0/8`,`::1`; private `10/8`,`172.16/12`,`192.168/16`,`fc00::/7`;
   link-local `169.254/16`,`fe80::/10`; CGNAT `100.64/10`; `0.0.0.0/8`; multicast;
   reserved; IPv4-mapped IPv6 of any of these. Exception: allow loopback only when
   `allow_loopback: true` (dev). Helper: `special_use_ip?/1` with an explicit CIDR table.
4. **Pin to a validated IP** to close the DNS-rebinding TOCTOU: connect to a checked IP
   directly (Mint/Finch `connect(:https, ip, port, hostname: host, …)`) so TLS SNI +
   cert verification still use the original hostname, but the socket cannot be rebound
   to an internal address between check and connect.
5. **GET** with `Accept: application/json`, connect+receive **timeouts** (default 5s),
   **redirects: 0** (spec MUST), follow-nothing.
6. **Status**: only `200`; else `{:error, {:status, code}}`.
7. **Content-Type**: must be `application/json` or `application/*+json`, else
   `{:error, :bad_content_type}`.
8. **Size cap**: stream and abort if the body exceeds `max_document_bytes` (default
   5 KB) → `{:error, :too_large}`.
9. Return `{:ok, %{body: body, cache_control: parse_cache_control(headers)}}`.

(The same IP-validation is reused if/when we prefetch `logo_uri` — v2.)

## 6. Caching

- Key = the `client_id` URL. Value = the **validated** metadata + `expires_at` derived
  from `Cache-Control: max-age` / `Expires` (RFC 9111), clamped to `cache_ttl_bounds`
  (default `{60, 86_400}`).
- **MUST NOT** cache error responses or invalid/malformed documents (cache only after
  `validate_document/2` succeeds).
- Default ETS, per-node. Optional Ecto cache for clusters (cluster-coherent; also caps
  outbound fetch fan-out under load).

## 7. Integration points

- **Authorization endpoint** (`authorize_controller`, today `:load_client` at the
  request `client_id`): when `enabled` and `client_id_url?(client_id)`, resolve via
  `Resolver.resolve/2` instead of the host `:load_client`. `redirect_uri` is
  exact-matched against the document's `redirect_uris` (RFC 9700). Optional
  `require_same_origin_redirect_uri` adds the spec's same-origin tightening.
- **Token / PAR** (`client_authentication`): a CIMD client authenticates as a **public
  client (`none` + PKCE)** or **`private_key_jwt`** (keys via the doc's `jwks`/
  `jwks_uri`). `client_secret_*` is impossible for CIMD clients (excluded by
  `validate_document/2`), so the existing method gate already refuses it.
- **Precedence**: a `client_id` that is a CIMD URL resolves via CIMD; an opaque
  `client_id` resolves via `:load_client` (unchanged). Hosts can disable entirely.
- A resolved CIMD client is shaped identically to a `:load_client` result, so
  downstream (scopes, redirect match, JARM, DPoP) needs no changes.

## 8. Discovery

- `attesto` `Discovery`: add `client_id_metadata_document_supported` to the host fields
  (boolean), emitted when the feature is enabled.
- `attesto_phoenix` `Config`: when `client_id_metadata[:enabled]`, discovery advertises
  `true`.

## 9. Config surface (`attesto_phoenix` `Config`)

```elixir
client_id_metadata: [
  enabled: false,                                   # master switch (default OFF)
  fetcher: AttestoPhoenix.ClientIdMetadata.Fetcher.Req,   # DECISION: Req default
  cache: AttestoPhoenix.ClientIdMetadata.Cache.Ecto,      # DECISION: Ecto (cluster-coherent)
  allow_loopback: false,                            # dev only
  max_document_bytes: 5_120,
  request_timeout_ms: 5_000,
  cache_ttl_bounds: {60, 86_400},
  require_same_origin_redirect_uri: true,           # DECISION: same-origin enforced
  allowed_hosts: nil,                               # optional allowlist (nil = any public)
  blocked_hosts: []
]
```

## 10. Dependency decision

The default fetcher needs an HTTP client; `attesto_phoenix` currently has none.
Recommendation: add **`{:req, "~> 0.5", optional: true}`** (Req → Finch → Mint, which
gives redirect control, timeouts, and IP-pinning via Mint). Keep it *optional*: a host
that does not enable CIMD pays nothing; enabling it without `req` raises a clear
boot-time error pointing at the `:fetcher` override (so a host can bring its own HTTP /
a proxy service instead). No core (`attesto`) dependency change.

## 11. Test plan

**Core (`attesto`)** — pure, no network:
- URL grammar: accept `https://app.example/cb`; reject `http://`, fragment, userinfo,
  `..`/`.` segments, no-path, non-URL.
- Document: `client_id` match vs mismatch; reject `client_secret` /
  `client_secret_expires_at`; reject symmetric `token_endpoint_auth_method`; extract
  `redirect_uris`/`jwks`/`jwks_uri`.

**`attesto_phoenix`**:
- Fetcher SSRF (mock resolver): reject loopback/private/link-local/CGNAT/0.0.0.0/
  IPv4-mapped; allow loopback only with `allow_loopback: true`. Reject non-200, any
  redirect, body > 5 KB, non-JSON content-type, timeout. **DNS-rebinding**: connection
  pins to the first validated IP.
- Cache: respects `max-age`; clamps to bounds; never caches error/invalid; Ecto variant
  cluster round-trip (string-keyed jsonb).
- Resolver: end-to-end against a `Bypass`/`Plug` stub server.
- Integration: authorize with a CIMD `client_id` URL issues a code; `redirect_uri`
  mismatch rejected; same-origin enforcement when on; token endpoint treats it as
  public / `private_key_jwt`; discovery advertises `client_id_metadata_document_supported`.

## 12. Slice / build order

1. `attesto` `Attesto.ClientIdMetadata` (URL + document validation) + tests. *(no deps)*
2. `attesto` `Discovery` field + `attesto_phoenix` `Config` plumbing + discovery wiring.
3. `attesto_phoenix` `Fetcher` behaviour + SSRF guard + Req default + tests (`Bypass`).
4. `Cache` behaviour + **`Cache.Ecto` default** (schema `attesto_client_id_metadata`,
   `gen.migration` table, `Sweeper` entry) + `Cache.ETS` opt-out + tests.
5. `Resolver` + `authorize_controller` integration (incl. same-origin `redirect_uri`)
   + tests.
6. Token/PAR path: confirm CIMD client auth = `none` / `private_key_jwt` + tests.
7. *(v2)* `logo_uri` prefetch; metadata-change grant invalidation / re-consent hook.

## 13. Decisions (settled)

- **Fetcher dep**: ✅ Req-based default (`{:req, "~> 0.5", optional: true}`); host may
  override `:fetcher` (e.g. a CIMD proxy service).
- **Cache backend default**: ✅ Ecto (`...Cache.Ecto`) — cluster-coherent, consistent
  with the rest of the Postgres-backed stores; caps outbound fetch fan-out. Table
  `attesto_client_id_metadata` (key = url, jsonb metadata, `expires_at`), swept by
  `Store.Sweeper`, generated by `mix attesto_phoenix.gen.migration`. (An ETS cache stays
  available as a single-node opt-out.)
- **Same-origin redirect_uri**: ✅ enforced by default (`require_same_origin_redirect_uri:
  true`) — the request `redirect_uri` must be same-origin as the `client_id` URL, on top
  of the exact-match against the document's `redirect_uris`.
- **Still open — which instances enable it**: the OIDC-basic instance fits ChatGPT's
  public-client CIMD; FAPI profiles could additionally require `private_key_jwt` CIMD.
  (Per-deployment config, not a library decision.)

## 14. Conformance / validation

There is **no CIMD test in the OpenID conformance suite** (the draft is too new; the
suite covers OIDC/FAPI/Federation/VC only). Validation is therefore on us:

- The §11 test plan — especially the **SSRF / DNS-rebinding** cases, which no generic
  suite would exercise — is the primary safety net.
- Interop: point the AS at **client.dev** (a community CIMD test client serving a static
  metadata doc) and/or Authlete's reference CIMD AS.
- Acceptance: a real **ChatGPT MCP connect** against the OIDC instance (same approach we
  used to certify the Claude flow).

## Sources
- draft-ietf-oauth-client-id-metadata-document-01 — https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-01
- OAuth Client ID Metadata Document (overview) — https://oauth.net/2/client-id-metadata-document/
