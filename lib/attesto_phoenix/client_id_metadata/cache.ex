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
end
