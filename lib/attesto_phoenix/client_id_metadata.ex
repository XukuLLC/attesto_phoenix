defmodule AttestoPhoenix.ClientIdMetadata do
  @moduledoc """
  Integration façade for Client ID Metadata Documents - CIMD
  (`draft-ietf-oauth-client-id-metadata-document-01`, IETF OAuth WG).

  CIMD lets a client identify itself with no prior registration by using an
  HTTPS URL as its `client_id`; the authorization server dereferences that URL
  to a JSON client metadata document and uses it as the client. The pure URL/
  document validation lives in `Attesto.ClientIdMetadata`, the SSRF-guarded
  fetch in `AttestoPhoenix.ClientIdMetadata.Fetcher`, the cache in
  `AttestoPhoenix.ClientIdMetadata.Cache`, and the orchestration in
  `AttestoPhoenix.ClientIdMetadata.Resolver`. This module is the thin seam the
  HTTP endpoints (the authorization endpoint and the token / PAR client
  authentication path) call to decide whether a presented `client_id` is a CIMD
  URL and, when it is, to resolve it into a client.

  ## When CIMD applies

  A presented `client_id` is resolved through CIMD only when both hold
  (`cimd_client_id?/2`):

    * the feature is enabled for the deployment
      (`AttestoPhoenix.Config.client_id_metadata_enabled?/1`), and
    * the `client_id` is a well-formed CIMD URL
      (`Attesto.ClientIdMetadata.client_id_url?/1`).

  An opaque (non-URL) `client_id`, or any `client_id` when the feature is off,
  is left to the host's `:load_client` registry exactly as before - CIMD never
  changes the resolution of a registered client.

  ## The resolved client

  `resolve/2` returns the normalized, string-keyed metadata map
  `Attesto.ClientIdMetadata.validate_document/2` produced (carrying at least
  `client_id` and `redirect_uris`). It is *not* the host's opaque client value,
  so the host's `:client_id` / `:client_redirect_uris` / `:client_jwks`
  callbacks do not apply to it; the accessors here
  (`client_id/1`, `redirect_uris/1`, `jwks/1`) read the document directly, and
  the calling endpoint uses them in place of the host callbacks for a CIMD
  client. A resolved CIMD client authenticates only as a public client
  (`none` + PKCE) or with `private_key_jwt`; the no-symmetric-secret rule the
  document validation enforces guarantees `client_secret_*` can never apply.

  ## redirect_uri policy (RFC 9700 + draft §2)

  RFC 9700 requires the request `redirect_uri` to exact-match one of the
  document's `redirect_uris`; the calling endpoint performs that match through
  the same `Attesto.AuthorizationRequest` path it uses for a registered client,
  feeding it `redirect_uris/1` as the registered set. The draft additionally
  permits requiring the `redirect_uri` to be same-origin (scheme + host + port)
  with the `client_id` URL; `same_origin_redirect_uri?/2` is that check, applied
  by the authorization endpoint when `:require_same_origin_redirect_uri` is set
  (the default).
  """

  alias Attesto.ClientIdMetadata, as: Core
  alias AttestoPhoenix.ClientIdMetadata.Resolver
  alias AttestoPhoenix.Config

  @typedoc """
  A resolved CIMD client: the normalized, string-keyed metadata map
  `Attesto.ClientIdMetadata.validate_document/2` returns.
  """
  @type client :: map()

  @doc """
  Returns `true` iff `client_id` must be resolved through CIMD for `config`:
  the feature is enabled and `client_id` is a well-formed CIMD URL.

  This is the single gate the endpoints consult before reaching for the
  resolver, so an opaque `client_id` (or any `client_id` while the feature is
  disabled) is never sent to the network and always flows through the host's
  `:load_client` registry.
  """
  @spec cimd_client_id?(term(), Config.t()) :: boolean()
  def cimd_client_id?(client_id, %Config{} = config) do
    Config.client_id_metadata_enabled?(config) and Core.client_id_url?(client_id)
  end

  @doc """
  Resolve a CIMD `client_id` URL into its normalized client metadata map.

  Delegates to `AttestoPhoenix.ClientIdMetadata.Resolver.resolve/2`. The caller
  is expected to have gated on `cimd_client_id?/2` first; the resolver
  re-validates the URL grammar regardless, so a non-CIMD `client_id` reaching
  here still fails closed. Returns `{:ok, client}` or `{:error, reason}` (a
  fetch, decode, validation, or host-policy failure - never cached).
  """
  @spec resolve(String.t(), Config.t()) :: {:ok, client()} | {:error, Resolver.error()}
  def resolve(client_id, %Config{} = config) when is_binary(client_id) do
    Resolver.resolve(client_id, config)
  end

  @doc """
  The CIMD client's `client_id` - the URL the document was fetched from and is
  bound to (`Attesto.ClientIdMetadata.validate_document/2` guarantees the
  document's `client_id` equals it).
  """
  @spec client_id(client()) :: String.t()
  def client_id(%{"client_id" => client_id}), do: client_id

  @doc """
  The CIMD client's registered redirect URIs (RFC 9700), used by the
  authorization endpoint as the exact-match set in place of the host's
  `:client_redirect_uris` callback. Document validation guarantees a non-empty
  list of strings.
  """
  @spec redirect_uris(client()) :: [String.t()]
  def redirect_uris(%{"redirect_uris" => redirect_uris}), do: redirect_uris

  @doc """
  The CIMD client's verification keys for `private_key_jwt` client
  authentication (RFC 7523 / OIDC Core §9), taken from the document's inline
  `jwks` (preferred) or its `jwks_uri`. Returns `nil` when the document carried
  neither, which makes `private_key_jwt` impossible for the client (it then
  authenticates only as a public client).
  """
  @spec jwks(client()) :: map() | String.t() | nil
  def jwks(%{"jwks" => jwks}) when is_map(jwks), do: jwks
  def jwks(%{"jwks_uri" => jwks_uri}) when is_binary(jwks_uri), do: jwks_uri
  def jwks(_client), do: nil

  @doc """
  Returns `true` iff `redirect_uri` is same-origin (scheme, host, and port) with
  the CIMD `client_id` URL (draft §2's optional same-origin tightening).

  The port comparison uses each URI's effective port, so an explicit default
  port and an omitted one compare equal. A `redirect_uri` that does not parse as
  an absolute URL with a host is not same-origin.
  """
  @spec same_origin_redirect_uri?(String.t(), String.t()) :: boolean()
  def same_origin_redirect_uri?(client_id, redirect_uri) when is_binary(client_id) and is_binary(redirect_uri) do
    with %URI{scheme: cs, host: ch} = client_uri when is_binary(ch) <- URI.parse(client_id),
         %URI{scheme: rs, host: rh} = redirect <- URI.parse(redirect_uri),
         true <- is_binary(rh) do
      cs == rs and ch == rh and effective_port(client_uri) == effective_port(redirect)
    else
      _ -> false
    end
  end

  def same_origin_redirect_uri?(_client_id, _redirect_uri), do: false

  # The effective port: the explicit `:port` when present, else the scheme's
  # default (`URI.default_port/1`), so `https://h/p` and `https://h:443/p`
  # compare equal.
  defp effective_port(%URI{port: port}) when is_integer(port), do: port
  defp effective_port(%URI{scheme: scheme}), do: URI.default_port(scheme)
end
