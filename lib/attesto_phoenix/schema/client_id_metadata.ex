defmodule AttestoPhoenix.Schema.ClientIdMetadata do
  @moduledoc """
  Ecto schema for one cached Client ID Metadata Document - CIMD
  (`draft-ietf-oauth-client-id-metadata-document-01`, IETF OAuth WG).

  CIMD lets a client identify itself with no prior registration by using an
  HTTPS URL as its `client_id`; the authorization server dereferences that URL
  and validates the returned document. The default cache,
  `AttestoPhoenix.ClientIdMetadata.Cache.Ecto`, persists each *successfully
  validated* document so the cache is coherent across a cluster (a document
  fetched on one node is served from every node) and the outbound fetch
  fan-out is bounded under load. This schema backs that store, one row per
  cached `client_id` URL.

  Per the draft (§6) and RFC 9111, only a validated document is ever written
  here - error responses and malformed documents are never cached - so a row's
  presence means the document was accepted at fetch time. Freshness is still
  re-checked on read against `expires_at`, so an unswept expired row is treated
  as a miss and never served.

  ## Columns

    * `url` - the CIMD `client_id` URL the document was fetched from (and which
      the document's own `client_id` equals). It is the PRIMARY KEY, so the
      cache lookup (`get/1`) hits the primary key directly and a re-fetch of the
      same URL upserts the single row rather than accumulating duplicates.
    * `metadata` - the validated, string-keyed client metadata map (the RFC 7591
      Dynamic Client Registration field set the AS uses as the client).
      Persisted as `jsonb`; the cache reads back the same string-keyed map it
      stored.
    * `expires_at` - when the cached document stops being fresh, derived from the
      response's `Cache-Control: max-age` / `Expires` (RFC 9111) clamped to the
      host's configured bounds. The store rejects an expired row on read, so an
      unswept expired entry is never honored.
    * `inserted_at` - when the document was cached (diagnostic; never a lookup
      key).
  """

  use Ecto.Schema

  import Ecto.Changeset

  @typedoc "A persisted cached Client ID Metadata Document row."
  @type t :: %__MODULE__{
          url: String.t() | nil,
          metadata: map() | nil,
          expires_at: DateTime.t() | nil,
          inserted_at: DateTime.t() | nil
        }

  # A cached document is fully described by its URL, the validated metadata, and
  # the two instants; there is no surrogate id. A re-fetch replaces the metadata
  # and expiry of the existing row (upsert), so every field is supplied on write.
  @insert_fields [:url, :metadata, :expires_at, :inserted_at]

  @primary_key {:url, :string, autogenerate: false}
  schema "attesto_client_id_metadata" do
    field :metadata, :map
    field :expires_at, :utc_datetime
    field :inserted_at, :utc_datetime
  end

  @doc """
  Changeset for caching a freshly fetched, validated metadata document.

  Requires the `url` key, the validated `metadata`, and both instants. A cached
  document with no expiry would never fail closed on read, so a missing
  `:expires_at` is a hard validation error rather than a silently unlimited
  cache entry.
  """
  @spec put_changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def put_changeset(entry \\ %__MODULE__{}, attrs) do
    entry
    |> cast(attrs, @insert_fields)
    |> validate_required(@insert_fields)
  end
end
