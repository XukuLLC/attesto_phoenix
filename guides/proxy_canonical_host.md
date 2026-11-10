# Issuer, resource, and redirect URL correctness behind a proxy

Behind Fly, NGINX, a CDN, or any reverse proxy, the request the application
sees is not the request the client sent: the scheme is often plain HTTP after
TLS termination, and the `Host` header may be an internal name. OAuth and OIDC
URL correctness depends on the **canonical, client-visible** host and scheme,
not on whatever reached the application socket.

## Why this matters

  * The **issuer** (`iss`) is minted into every token and published in the
    discovery documents (RFC 8414 §2). It MUST be the canonical `https` URL
    clients use. Deriving it from a live request behind a proxy can leak an
    internal host or an `http` scheme.

  * The **DPoP `htu`** (RFC 9449 §4.3) is the URL the client signed. If the
    server computes `htu` from a proxied request it may not match what the
    client signed, and valid proofs are rejected.

  * **Redirect URIs** are exact-matched (RFC 6749 §3.1.2.3). A host/scheme
    mismatch breaks the match.

## Configure the canonical identity, not the request

`AttestoPhoenix.Config`:

  * `:issuer` - set this to the fixed canonical `https` issuer URL. The library
    derives the discovery issuer and the advertised endpoint URLs from it (via
    the `:oauth_path_prefix` / per-endpoint path resolvers), so it never needs
    to reconstruct the host from a request. This is stable behind any TLS
    terminator.

  * `:trusted_proxies` - the list of trusted proxy CIDRs/IPs that controls
    whether `X-Forwarded-*` headers are honored. Default `[]` (no forwarded
    trust): nothing is taken from a `Forwarded` / `X-Forwarded-*` header unless
    the immediate peer is in this list. Set it to your proxy's address range so
    forwarded scheme/host are trusted only from your proxy and never from an
    arbitrary client.

  * `:require_https` - keep this `true` (the default) in production so the
    endpoints enforce HTTPS.

  * `:resource_origin` - the fixed canonical `https` origin of the protected
    resources, such as `"https://api.example.com"`. The DPoP `htu` at every
    protected resource (`AttestoPhoenix.Plug.Authenticate`, the bundled
    UserInfo and credential endpoints) is this origin followed by the request
    path, so neither the proxy hop nor a client-chosen `Host` affects it. It is
    independent of `:issuer`, because the resource server and the
    authorization server may live on different origins.

  * `:htu` - `(conn -> canonical_url_string)`. When neither the configured
    URLs nor `:resource_origin` describe the topology (protected resources on
    several origins, a path-rewriting proxy), override exactly how the DPoP
    `htu` is computed. Return the canonical URL the client would have signed,
    built from configured origins rather than request headers. Mutually
    exclusive with `:resource_origin`.

## Where the DPoP `htu` comes from

  * Token, PAR, and device authorization endpoints: their configured public
    URL (derived from `:issuer`), or an exact `:mtls_endpoint_aliases` entry
    when the request arrives on that alias.
  * Protected resources: `:htu` if set; otherwise `:resource_origin` followed
    by the request path; otherwise the URL rebuilt from the request through
    `:trusted_proxies`. The last form takes its host from the request `Host`
    header (or the forwarded host from a trusted proxy), so a server that
    answers more than one `Host` accepts a DPoP-bound token with a proof made
    for another server.

## Checklist

  - [ ] `:issuer` is the fixed canonical `https` URL (no internal host).
  - [ ] `:resource_origin` is the canonical `https` origin of your protected
        resources if they accept DPoP-bound tokens.
  - [ ] `:trusted_proxies` lists your proxy's address range, nothing wider.
  - [ ] `:require_https` is `true`.
  - [ ] Advertised endpoint paths match the mount via `:oauth_path_prefix` (see
        the consumer migration guide).
  - [ ] If proofs are rejected behind the proxy and `:resource_origin` does not
        describe the topology, set `:htu` to return the canonical signed URL.
