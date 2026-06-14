defmodule AttestoPhoenix.ClientIdMetadata.Cache.Ecto do
  @moduledoc """
  Postgres-backed `AttestoPhoenix.ClientIdMetadata.Cache` for clustered
  deployments - CIMD (`draft-ietf-oauth-client-id-metadata-document-01`, IETF
  OAuth WG).

  CIMD lets a client identify itself with no prior registration by using an
  HTTPS URL as its `client_id`; the authorization server dereferences that URL
  and validates the returned document. Caching the validated document keeps
  every authorization request from reaching out to the network. The default
  per-node `AttestoPhoenix.ClientIdMetadata.Cache.ETS` would re-fetch on each
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

  Expired rows are reclaimed by `AttestoPhoenix.Store.Sweeper`, but sweeping is
  housekeeping only: `get/1` already refuses an expired row.

  The repository module is supplied by the host application (`:repo` under the
  `:attesto_phoenix` app) and read at call time; a cache with no backing
  repository fails closed rather than silently no-opping.
  """

  @behaviour AttestoPhoenix.ClientIdMetadata.Cache

  import Ecto.Query, only: [from: 2]

  alias AttestoPhoenix.ClientIdMetadata.Cache
  alias AttestoPhoenix.Schema.ClientIdMetadata

  @app :attesto_phoenix

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
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    query =
      from c in ClientIdMetadata,
        where: c.url == ^url and c.expires_at > ^now,
        select: c.metadata

    case repo().one(query) do
      nil -> :miss
      metadata -> {:ok, metadata}
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
  @spec put(String.t(), map(), DateTime.t()) :: :ok
  def put(url, metadata, %DateTime{} = expires_at) when is_binary(url) and is_map(metadata) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    expires_at = DateTime.truncate(expires_at, :second)

    entry = %{url: url, metadata: metadata, expires_at: expires_at, inserted_at: now}

    %ClientIdMetadata{}
    |> ClientIdMetadata.put_changeset(entry)
    |> repo().insert!(
      on_conflict: [set: [metadata: metadata, expires_at: expires_at]],
      conflict_target: :url
    )

    :ok
  end

  defp repo do
    case Application.get_env(@app, :repo) do
      nil ->
        # Fail closed: a cache with no backing repository cannot share a
        # validated document across nodes, so refuse rather than silently no-op.
        raise ArgumentError,
              "AttestoPhoenix: no :repo configured. Set `config #{inspect(@app)}, repo: MyApp.Repo`"

      repo ->
        repo
    end
  end
end
