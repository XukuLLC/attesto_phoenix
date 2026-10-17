defmodule AttestoPhoenix.Controller.DiscoveryController do
  @moduledoc """
  RFC 8414 - OAuth 2.0 Authorization Server Metadata endpoint.

  Serves the discovery document at
  `/.well-known/oauth-authorization-server` (RFC 8414 §3) so that clients
  can discover the issuer, the endpoint URLs, and the capabilities the
  authorization server advertises.

  The document is assembled by `Attesto.Discovery.metadata/2`; this
  controller contributes transport concerns only and adds no policy of its
  own. Every protocol member - the issuer, the token endpoint
  (`token_endpoint`), the JWKS location (`jwks_uri`), the PKCE challenge
  methods (`code_challenge_methods_supported`, fixed to `S256` per RFC 7636
  §4.2), and the DPoP algorithms (`dpop_signing_alg_values_supported`, RFC
  9449) - is derived by the core builder from the protocol configuration.

  The capability members reflect exactly what the server supports:
  `grant_types_supported` is read from `AttestoPhoenix.Config.grant_types_supported/1`
  (every grant the token endpoint dispatches by default — `authorization_code`,
  `refresh_token`, `client_credentials`, and OAuth token exchange — narrowed when
  the host configures `:grant_types_supported`, and the token endpoint enforces
  the same set; enabled optional grants are added only when that setting is nil,
  while an explicit list must contain their exact URNs);
  `token_endpoint_auth_methods_supported` lists the client-authentication
  methods it accepts. Its default is `client_secret_basic`,
  `client_secret_post`, `private_key_jwt`, and `none` for PKCE-using public
  clients; an explicit config list may add mTLS or wallet-attestation methods.
  The PAR
  endpoint is advertised separately as `pushed_authorization_request_endpoint`.

  The host-specific members - the supported scopes (`scopes_supported`),
  the authorization endpoint, and the dynamic registration endpoint
  (`registration_endpoint`, RFC 7591, advertised only when registration is
  enabled) - are read from `AttestoPhoenix.Config` and passed through,
  never hardcoded here.

  The response carries no secrets and is identical for every caller, so it
  is served unauthenticated. RFC 8414 §3.1 permits caching of the metadata
  response, so a public, cacheable `Cache-Control` header is set.

  ## Wiring

  The router pipeline must place the `AttestoPhoenix.Config` under
  `conn.private[:attesto_phoenix_config]` (the same key the other endpoints
  read) and the derived `Attesto.Config` under
  `conn.private[:attesto_protocol_config]`. Both are required; a missing
  value raises rather than serving a partial document, because a partial
  discovery document would misdirect clients to endpoints that may not
  exist.
  """

  use AttestoPhoenix.Controller, formats: [:json]

  alias Attesto.Discovery
  alias AttestoPhoenix.AuthorizationServer.Metadata
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Controller.MetadataSupport

  # RFC 8414 §3: the metadata document is static for a given server
  # configuration, so it may be cached by clients and intermediaries. One
  # hour balances picking up configuration changes against request volume.
  @cache_max_age_seconds 3600

  @doc """
  Render the RFC 8414 metadata document as JSON.

  Fails closed with `ArgumentError` when either required configuration value
  is absent from `conn.private`, since serving a document that omits
  required members would misdirect clients.
  """
  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, _params) do
    config = Config.resolve!(conn)
    protocol_config = MetadataSupport.protocol_config!(conn, __MODULE__)

    metadata =
      protocol_config
      |> Discovery.metadata(discovery_opts(config))
      |> Metadata.enrich_common(config)

    conn
    |> MetadataSupport.put_public_cache(@cache_max_age_seconds)
    |> json(metadata)
  end

  # OAuth-only members remain here; the endpoint and capability members shared
  # with OpenID Provider Metadata are added by Metadata.enrich_common/2.
  @spec discovery_opts(Config.t()) :: keyword()
  defp discovery_opts(%Config{} = config) do
    [scopes_supported: config |> Config.effective_scopes_supported() |> presence()]
  end

  # An empty list means "not advertised": collapse it to nil so the core
  # builder omits the member instead of publishing an empty array.
  @spec presence([term()]) :: [term()] | nil
  defp presence([]), do: nil
  defp presence(list) when is_list(list), do: list
end
