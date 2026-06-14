defmodule AttestoPhoenix.ClientIdMetadata.Cache.EctoTest do
  @moduledoc """
  Behaviour-conformance tests for the Postgres-backed Client ID Metadata
  Document cache (`draft-ietf-oauth-client-id-metadata-document-01`):
  cross-node coherence, string-keyed jsonb round-trip, `:miss` on absence,
  expiry re-checked on read, and upsert on re-fetch.

  The cache reads its repo from the `:attesto_phoenix` application environment,
  which `AttestoPhoenix.DataCase` points at the sandboxed test repo.
  """

  use AttestoPhoenix.DataCase, async: true

  alias AttestoPhoenix.ClientIdMetadata.Cache.Ecto, as: Cache
  alias AttestoPhoenix.Schema.ClientIdMetadata
  alias AttestoPhoenix.TestRepo

  @moduletag :ecto

  @url "https://app.example/oauth/client-metadata.json"
  @metadata %{
    "client_id" => @url,
    "client_name" => "Example App",
    "redirect_uris" => ["https://app.example/cb"],
    "token_endpoint_auth_method" => "none",
    "grant_types" => ["authorization_code", "refresh_token"],
    "response_types" => ["code"],
    "scope" => "openid profile"
  }

  defp soon, do: DateTime.utc_now() |> DateTime.add(3600, :second)

  test "put then get round-trips the validated metadata verbatim (string-keyed jsonb)" do
    assert :ok = Cache.put(@url, @metadata, soon())

    assert {:ok, fetched} = Cache.get(@url)
    assert fetched == @metadata
  end

  test "get is :miss for an unknown url" do
    assert :miss = Cache.get("https://other.example/client-metadata.json")
  end

  test "an expired entry is not honored on read and yields :miss" do
    # Insert directly with an expiry in the past to exercise the read-time
    # freshness check (put/3 derives expiry from the caller, so drive it here).
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    %{url: @url, metadata: @metadata, expires_at: DateTime.add(now, -1, :second), inserted_at: now}
    |> then(&ClientIdMetadata.put_changeset(%ClientIdMetadata{}, &1))
    |> TestRepo.insert!()

    assert :miss = Cache.get(@url)
  end

  test "put upserts - a re-fetched document replaces the stale entry" do
    stale = Map.put(@metadata, "client_name", "Old Name")
    fresh = Map.put(@metadata, "client_name", "New Name")

    assert :ok = Cache.put(@url, stale, soon())
    assert :ok = Cache.put(@url, fresh, soon())

    # The freshest accepted document wins; there is a single row for the URL.
    assert {:ok, %{"client_name" => "New Name"}} = Cache.get(@url)
    assert TestRepo.aggregate(ClientIdMetadata, :count, :url) == 1
  end

  test "put refreshes an expired entry on re-fetch (replaces metadata and expiry)" do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    %{
      url: @url,
      metadata: Map.put(@metadata, "client_name", "Expired"),
      expires_at: DateTime.add(now, -1, :second),
      inserted_at: now
    }
    |> then(&ClientIdMetadata.put_changeset(%ClientIdMetadata{}, &1))
    |> TestRepo.insert!()

    assert :miss = Cache.get(@url)

    # A re-fetch upserts the same primary key with a future expiry, reviving the
    # entry rather than failing on the existing (expired) row.
    assert :ok = Cache.put(@url, @metadata, soon())
    assert {:ok, fetched} = Cache.get(@url)
    assert fetched == @metadata
  end
end
