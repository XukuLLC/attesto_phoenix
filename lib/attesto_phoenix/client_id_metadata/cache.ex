defmodule AttestoPhoenix.ClientIdMetadata.Cache do
  @moduledoc """
  Behaviour for caching a validated Client ID Metadata Document - CIMD
  (`draft-ietf-oauth-client-id-metadata-document-01`, IETF OAuth WG).

  CIMD lets a client identify itself with no prior registration by using an
  HTTPS URL as its `client_id`; the authorization server dereferences that URL
  (`AttestoPhoenix.ClientIdMetadata.Fetcher`) and validates the returned
  document (`Attesto.ClientIdMetadata.validate_document/2`). This behaviour is
  the seam through which the resolver remembers a *successfully validated*
  document so that not every authorization request reaches out to the network.

  ## What may be cached

  Only a document that has passed validation is stored, and only with an
  `expires_at` the resolver derives from the response's HTTP freshness
  directives (`Cache-Control: max-age` / `Expires`, RFC 9111), clamped to the
  host's configured bounds. The draft (§6) and RFC 9111 forbid caching error
  responses or invalid/malformed documents, so an implementation of this
  behaviour is only ever handed metadata the caller already accepted; it does
  no validation of its own.

  ## Cache key and value

  The key is the CIMD `client_id` URL (the same string the client presented and
  the document's `client_id` equals). The value is the validated, string-keyed
  metadata map together with its `expires_at`. `get/1` MUST treat an expired
  entry as a miss - freshness is re-checked on read, never honored past
  `expires_at` - so an implementation that cannot cheaply evict still cannot
  serve a stale document.

  ## Default and the opt-out

  The default implementation is `AttestoPhoenix.ClientIdMetadata.Cache.Ecto`,
  which persists the entry to Postgres (table `attesto_client_id_metadata`,
  swept by `AttestoPhoenix.Store.Sweeper`) so the cache is coherent across a
  cluster and the outbound fetch fan-out is bounded under load. A single-node
  deployment may opt into the per-node
  `AttestoPhoenix.ClientIdMetadata.Cache.ETS` instead - a per-node cache is
  correct here because a miss simply re-fetches - by configuring the `:cache`
  module under `AttestoPhoenix.Config`'s `:client_id_metadata` key.
  """

  @typedoc """
  A validated, string-keyed CIMD metadata map - the document
  `Attesto.ClientIdMetadata.validate_document/2` returned and the caller
  accepted. Only such a map is ever stored or returned.
  """
  @type metadata :: map()

  @doc """
  Looks up the cached metadata for a CIMD `client_id` URL.

  Returns `{:ok, metadata}` only for an entry that is present AND still fresh
  (`expires_at` strictly in the future); an absent or expired entry is a
  `:miss`. Expiry MUST be re-checked here, so an implementation never serves a
  document past the `expires_at` it was stored with - an unswept expired row is
  a miss, not a stale hit.
  """
  @callback get(url :: String.t()) :: {:ok, metadata()} | :miss

  @doc """
  Stores validated `metadata` for a CIMD `client_id` URL until `expires_at`.

  The caller passes this only after `Attesto.ClientIdMetadata.validate_document/2`
  succeeds and after deriving `expires_at` from the response's HTTP freshness
  directives clamped to the configured bounds; an implementation MUST NOT be
  asked to cache an error or an invalid document (draft §6 / RFC 9111). A
  re-fetched document legitimately supersedes a stale one, so `put/3` replaces
  any existing entry for the same `url` rather than failing on conflict.
  """
  @callback put(url :: String.t(), metadata :: metadata(), expires_at :: DateTime.t()) :: :ok

  @doc """
  Evicts the cached document for a CIMD `client_id` URL, if one is present.

  A cached document is otherwise honored until the `expires_at` it was stored
  with — up to 24 hours under the default `:cache_ttl_bounds`. That is the wrong
  behavior once the document is known to have rotated or to be compromised,
  because the stale copy keeps authorizing the client with superseded `jwks`,
  `redirect_uris`, and auth metadata. This is the operator's lever for that.

  Optional: a cache that cannot evict simply does not implement it, and callers
  must handle its absence (see `AttestoPhoenix.ClientIdMetadata.Cache.evict/2`).
  """
  @callback delete(url :: String.t()) :: :ok

  @doc """
  Evicts every cached document. Optional; see `c:delete/1`.
  """
  @callback delete_all() :: :ok

  @optional_callbacks delete: 1, delete_all: 0

  @doc """
  Evicts `url` from `cache`, or returns `{:error, :not_supported}` when that
  implementation cannot evict.

  Dispatching through here rather than calling a backend directly is what keeps
  eviction available on whichever cache a deployment configured — the shipped
  ETS and Ecto caches both support it, and the default is Ecto.
  """
  @spec evict(module(), String.t()) :: :ok | {:error, :not_supported}
  def evict(cache, url) when is_atom(cache) and is_binary(url) do
    if Code.ensure_loaded?(cache) and function_exported?(cache, :delete, 1) do
      cache.delete(url)
    else
      {:error, :not_supported}
    end
  end

  @doc """
  Evicts every document from `cache`, or returns `{:error, :not_supported}`.
  See `evict/2`.
  """
  @spec evict_all(module()) :: :ok | {:error, :not_supported}
  def evict_all(cache) when is_atom(cache) do
    if Code.ensure_loaded?(cache) and function_exported?(cache, :delete_all, 0) do
      cache.delete_all()
    else
      {:error, :not_supported}
    end
  end
end
