defmodule AttestoPhoenix.ClientIdMetadata.Cache.Ecto do
  @moduledoc """
  Postgres-backed `AttestoPhoenix.ClientIdMetadata.Cache` for clustered
  deployments - CIMD (`draft-ietf-oauth-client-id-metadata-document-02`, IETF
  OAuth WG).

  CIMD lets a client identify itself with no prior registration by using an
  HTTPS URL as its `client_id`; the authorization server dereferences that URL
  and validates the returned document. Caching the validated document keeps
  every authorization request from reaching out to the network. The per-node
  `AttestoPhoenix.ClientIdMetadata.Cache.ETS` opt-out would re-fetch on each
  node and offers no coherence; this store persists each entry so a document
  fetched on one node is served from every node and the outbound fetch fan-out
  is bounded under load. It is the cache default for exactly the same reason the
  code/refresh/nonce/replay/PAR stores default to Ecto.

  Only a *validated* document is ever written (the caller stores after
  `Attesto.ClientIdMetadata.validate_document/2` succeeds, with an `expires_at`
  derived from the response's freshness directives clamped to the configured
  bounds); the draft (§6) and RFC 9111 forbid caching errors or malformed
  documents, so this store never validates and never sees an unaccepted
  document.

  ## Behaviour callbacks

    * `get/1` resolves a live (unexpired) cached document WITHOUT consuming it.
      Expiry is re-checked on read (`expires_at > now`), so an unswept expired
      row is a `:miss`, never a stale hit.
    * `put/3` upserts the validated metadata and its expiry. A re-fetched
      document legitimately supersedes a stale one, so a conflicting `url`
      replaces the existing row's `metadata` and `expires_at` rather than
      failing - the freshest fetch wins.

  Expired reads delete their row, and writes prune all expired rows before
  storing. Under a cross-node transaction lock, writes retain at most the
  configured `:cache_max_entries` records (default 1,024), evicting the earliest
  expiries first. The serialized URL and metadata, including attached remote
  keys, must fit `:cache_max_record_bytes` (default 16 KiB). With those defaults,
  a schema holds at most 16 MiB of serialized payload, excluding database
  overhead. The periodic sweeper remains additional housekeeping.

  The repository module is supplied by the host application (`:repo` under the
  `:attesto_phoenix` app) and read at call time; a cache with no backing
  repository fails closed rather than silently no-opping.
  """

  @behaviour AttestoPhoenix.ClientIdMetadata.Cache

  import Ecto.Query, only: [from: 2]

  alias AttestoPhoenix.ClientIdMetadata.Cache
  alias AttestoPhoenix.ClientIdMetadata.CacheCapacity
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Schema.ClientIdMetadata
  alias AttestoPhoenix.Store.Sweeper

  @doc """
  Resolves a live cached document for a CIMD `client_id` URL.

  Returns `{:ok, metadata}` when a row exists and has not expired, or `:miss`
  when it is absent or expired. `metadata` is round-tripped through `jsonb`, so
  the caller reads back the same string-keyed map it stored. Freshness is
  enforced on read (`expires_at > now`); resolution does not consume the entry,
  so it serves every request until it expires or is replaced.
  """
  @impl Cache
  @spec get(String.t()) :: {:ok, map()} | :miss
  def get(url) when is_binary(url) do
    case get_entry(url) do
      {:ok, metadata, _expiry} -> {:ok, Cache.metadata_only(metadata)}
      :miss -> :miss
    end
  end

  @impl Cache
  def get_entry(url) when is_binary(url) do
    prefix = Config.table_prefix()
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    query =
      from c in ClientIdMetadata,
        where: c.url == ^url and c.expires_at > ^now,
        select: {c.metadata, c.expires_at}

    case repo().one(query, prefix: prefix, log: false, telemetry_event: nil) do
      nil ->
        prune_expired_url(url, now, prefix)
        :miss

      {metadata, expiry} ->
        {:ok, metadata, expiry}
    end
  end

  @doc """
  Caches validated `metadata` for a CIMD `client_id` URL until `expires_at`.

  `metadata` is the validated, string-keyed map; it is round-tripped through
  `jsonb`. The `url` is the primary key, so a re-fetch upserts the single row:
  on conflict the stored `metadata` and `expires_at` are replaced with the
  freshly fetched values (the freshest accepted document wins), rather than
  raising or keeping a stale entry.
  """
  @impl Cache
  @spec put(String.t(), map(), DateTime.t()) :: :ok | {:error, :too_large}
  def put(url, metadata, %DateTime{} = expires_at) when is_binary(url) and is_map(metadata) do
    metadata = Cache.metadata_only(metadata)

    if CacheCapacity.fits?(url, metadata) do
      bounded_put(url, metadata, expires_at)
    else
      {:error, :too_large}
    end
  end

  defp bounded_put(url, metadata, expires_at) do
    prefix = Config.table_prefix()
    repo = repo()
    Sweeper.check_running_for_store(repo, prefix)
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    expires_at = DateTime.truncate(expires_at, :second)

    entry = %{url: url, metadata: metadata, expires_at: expires_at, inserted_at: now}

    case repo.transaction(fn -> locked_put(repo, prefix, entry) end, log: false, telemetry_event: nil) do
      {:ok, _} -> :ok
      {:error, _} -> raise "CIMD cache transaction did not commit"
    end
  end

  defp locked_put(repo, prefix, entry) do
    # This table lock is shared across nodes and also serializes Ecto's
    # concurrent row updates/deletes. Counting followed by an unlocked
    # insert would allow every miss to claim the same final cache slot.
    lock_cache(repo, prefix)
    prune_expired(repo, prefix, entry.inserted_at)

    if DateTime.after?(entry.expires_at, entry.inserted_at) do
      make_room(repo, prefix, entry.url, CacheCapacity.limit())

      %ClientIdMetadata{}
      |> ClientIdMetadata.put_changeset(entry, prefix: prefix)
      |> repo.insert!(
        on_conflict: [set: [metadata: entry.metadata, expires_at: entry.expires_at]],
        conflict_target: :url,
        prefix: prefix,
        log: false,
        telemetry_event: nil
      )
    else
      repo.delete_all(from(c in ClientIdMetadata, where: c.url == ^entry.url), sql_opts(prefix))
    end
  end

  defp lock_cache(repo, prefix) do
    Config.validate_schema_prefix!(prefix)
    table = if prefix, do: ~s("#{prefix}"."attesto_client_id_metadata"), else: ~s("attesto_client_id_metadata")
    repo.query!("LOCK TABLE #{table} IN SHARE ROW EXCLUSIVE MODE", [], log: false, telemetry_event: nil)
  end

  defp prune_expired_url(url, now, prefix) do
    query = from c in ClientIdMetadata, where: c.url == ^url and c.expires_at <= ^now
    repo().delete_all(query, sql_opts(prefix))
  end

  defp prune_expired(repo, prefix, now) do
    repo.delete_all(from(c in ClientIdMetadata, where: c.expires_at <= ^now), sql_opts(prefix))
  end

  defp make_room(repo, prefix, url, capacity) do
    keep_count = capacity - 1

    keepers =
      from c in ClientIdMetadata,
        where: c.url != ^url,
        order_by: [desc: c.expires_at, desc: c.url],
        limit: ^keep_count,
        select: c.url

    # Keep the bounded set in Postgres: a pre-upgrade over-capacity cache
    # must not materialize every excess URL in the requesting process.
    query = from c in ClientIdMetadata, where: c.url != ^url and c.url not in subquery(keepers)
    repo.delete_all(query, sql_opts(prefix))
  end

  defp sql_opts(prefix), do: [prefix: prefix, log: false, telemetry_event: nil]

  @impl Cache
  def put_jwks(url, expected_metadata, %DateTime{} = expires_at, keys) do
    prefix = Config.table_prefix()
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    expires_at = DateTime.truncate(expires_at, :second)
    metadata = Cache.with_resolved_jwks(expected_metadata, keys)

    query =
      from c in ClientIdMetadata,
        where:
          c.url == ^url and c.metadata == ^expected_metadata and
            c.expires_at == ^expires_at and c.expires_at > ^now

    if CacheCapacity.fits?(url, metadata) do
      case repo().update_all(query, [set: [metadata: metadata]], prefix: prefix, log: false, telemetry_event: nil) do
        {1, _} -> :ok
        {0, _} -> :stale
      end
    else
      {:error, :too_large}
    end
  end

  @doc """
  Evicts the cached document for `url`, if any.

  Cluster-wide by construction: the row is the shared cache, so deleting it
  evicts on every node at once. That is the point of having this on the DEFAULT
  backend rather than only on the per-node ETS one — a rotated or compromised
  CIMD document is otherwise honored until `expires_at`, up to 24 hours under
  the default `:cache_ttl_bounds`, on every node independently.
  """
  @impl Cache
  @spec delete(String.t()) :: :ok
  def delete(url) when is_binary(url) do
    prefix = Config.table_prefix()
    repo = repo()
    Sweeper.check_running_for_store(repo, prefix)

    repo.delete_all(from(c in ClientIdMetadata, where: c.url == ^url),
      prefix: prefix,
      log: false,
      telemetry_event: nil
    )

    :ok
  end

  @doc """
  Evicts every cached document, cluster-wide. See `delete/1`.
  """
  @impl Cache
  @spec delete_all() :: :ok
  def delete_all do
    prefix = Config.table_prefix()
    repo = repo()
    Sweeper.check_running_for_store(repo, prefix)

    repo.delete_all(ClientIdMetadata,
      prefix: prefix,
      log: false,
      telemetry_event: nil
    )

    :ok
  end

  defp repo, do: Config.ecto_repo!()
end
