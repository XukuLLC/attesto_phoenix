defmodule AttestoPhoenix.ClientIdMetadata.Cache.EctoTest do
  @moduledoc """
  Behaviour-conformance tests for the Postgres-backed Client ID Metadata
  Document cache (`draft-ietf-oauth-client-id-metadata-document-01`):
  cross-node coherence, string-keyed jsonb round-trip, `:miss` on absence,
  expiry re-checked on read, and upsert on re-fetch.

  The cache reads its repo from the `:attesto_phoenix` application environment,
  which `AttestoPhoenix.DataCase` points at the sandboxed test repo.
  """

  use AttestoPhoenix.DataCase, async: false

  import ExUnit.CaptureLog

  alias AttestoPhoenix.ClientIdMetadata.Cache, as: CacheAPI
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

  # Eviction is the operator's answer to a rotated or compromised document,
  # which is otherwise honoured until `expires_at` - up to 24h under the default
  # `:cache_ttl_bounds`. It lives on THIS backend because this is the default;
  # having it only on the per-node ETS opt-out would leave the lever missing
  # where it is actually needed.
  describe "delete/1 and delete_all/0" do
    test "delete/1 evicts exactly the named document" do
      other = "https://other.example/metadata.json"
      expires = DateTime.add(DateTime.utc_now(), 300, :second)

      :ok = Cache.put(@url, %{"client_id" => @url}, expires)
      :ok = Cache.put(other, %{"client_id" => other}, expires)

      assert :ok = Cache.delete(@url)

      assert Cache.get(@url) == :miss
      assert {:ok, %{"client_id" => ^other}} = Cache.get(other)
    end

    test "delete/1 on an absent url is a no-op" do
      assert :ok = Cache.delete("https://never.cached.example/metadata.json")
    end

    test "delete_all/0 evicts every document" do
      expires = DateTime.add(DateTime.utc_now(), 300, :second)
      :ok = Cache.put(@url, %{"client_id" => @url}, expires)
      :ok = Cache.put("https://other.example/m.json", %{"client_id" => "x"}, expires)

      assert :ok = Cache.delete_all()

      assert Cache.get(@url) == :miss
      assert Cache.get("https://other.example/m.json") == :miss
    end

    # The resolver reaches the cache through the configured module, so eviction
    # has to be reachable that way rather than only as a direct call.
    test "is reachable through the behaviour dispatch helper" do
      expires = DateTime.add(DateTime.utc_now(), 300, :second)
      :ok = Cache.put(@url, %{"client_id" => @url}, expires)

      assert :ok = CacheAPI.evict(Cache, @url)
      assert Cache.get(@url) == :miss

      assert :ok = CacheAPI.evict_all(Cache)
    end

    test "the dispatch helper reports a cache that cannot evict" do
      defmodule NoEvictCache do
        @moduledoc false
        @behaviour CacheAPI

        @impl true
        def get(_url), do: :miss

        @impl true
        def put(_url, _metadata, _expires_at), do: :ok
      end

      assert CacheAPI.evict(NoEvictCache, @url) == {:error, :not_supported}
      assert CacheAPI.evict_all(NoEvictCache) == {:error, :not_supported}
    end
  end

  test "sensitive cache operations emit no query telemetry or debug SQL" do
    capture = AttestoPhoenix.TestTelemetryCapture.attach(TestRepo)
    on_exit(fn -> AttestoPhoenix.TestTelemetryCapture.detach(capture) end)
    {_id, ref} = capture

    assert is_integer(TestRepo.aggregate(ClientIdMetadata, :count, :url))
    assert AttestoPhoenix.TestTelemetryCapture.collect(ref) != []

    url = "https://telemetry.example/client-metadata.json"
    metadata = %{"client_id" => url, "client_name" => "telemetry-metadata-sentinel"}

    log =
      capture_log([level: :debug], fn ->
        assert :ok = Cache.put(url, metadata, soon())
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
        assert {:ok, ^metadata} = Cache.get(url)
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
        assert :ok = Cache.delete(url)
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
        assert :ok = Cache.put(url, metadata, soon())
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
        assert :ok = Cache.delete_all()
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
      end)

    refute log =~ url
    refute log =~ "telemetry-metadata-sentinel"
  end
end
