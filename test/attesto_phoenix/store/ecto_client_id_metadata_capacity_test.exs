defmodule AttestoPhoenix.ClientIdMetadata.Cache.EctoCapacityTest do
  use AttestoPhoenix.DataCase, async: false

  import Ecto.Query

  alias AttestoPhoenix.ClientIdMetadata.Cache.Ecto, as: Cache
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Schema.ClientIdMetadata
  alias Ecto.Adapters.SQL.Sandbox

  defp config(opts) do
    %Config{issuer: "https://issuer.example", keystore: TestRepo, repo: TestRepo, client_id_metadata: opts}
  end

  defp expiry, do: DateTime.utc_now() |> DateTime.add(300, :second) |> DateTime.truncate(:second)

  test "expired reads and writes reclaim persistent rows without waiting for a sweeper" do
    old = DateTime.add(expiry(), -400, :second)

    for url <- ["https://expired.example/read", "https://expired.example/write"] do
      %ClientIdMetadata{}
      |> ClientIdMetadata.put_changeset(%{url: url, metadata: %{}, expires_at: old, inserted_at: old})
      |> TestRepo.insert!()
    end

    assert :miss = Cache.get("https://expired.example/read")
    refute TestRepo.get(ClientIdMetadata, "https://expired.example/read")
    assert :ok = Cache.put("https://live.example/client", %{}, expiry())
    refute TestRepo.get(ClientIdMetadata, "https://expired.example/write")
  end

  test "record bytes and attached JWKS are bounded without losing the prior document" do
    host = config(cache_max_record_bytes: 200)
    url = "https://cache.example/client"
    metadata = %{"client_id" => url}
    deadline = expiry()

    Config.with_request_config(host, fn ->
      assert :ok = Cache.put(url, metadata, deadline)
      assert {:error, :too_large} = Cache.put(url, Map.put(metadata, "data", String.duplicate("x", 300)), deadline)
      assert {:error, :too_large} = Cache.put_jwks(url, metadata, deadline, %{"data" => String.duplicate("x", 300)})
      assert {:ok, ^metadata, ^deadline} = Cache.get_entry(url)
    end)
  end

  test "capacity is atomic across independent concurrent SQL transactions" do
    unique = System.unique_integer([:positive])
    urls = for index <- 1..25, do: "https://concurrent-#{unique}.example/#{index}"
    host = config(cache_max_entries: 3)
    deadline = expiry()

    # Each worker checks out an unsandboxed connection. Sharing a test's one
    # sandbox connection would serialize writes before the cache lock and
    # would fail to exercise the actual count/insert race across transactions.
    on_exit(fn ->
      Sandbox.unboxed_run(TestRepo, fn ->
        TestRepo.delete_all(from(c in ClientIdMetadata, where: c.url in ^urls), log: false, telemetry_event: nil)
      end)
    end)

    urls
    |> Task.async_stream(
      fn url ->
        Sandbox.unboxed_run(TestRepo, fn ->
          Config.with_request_config(host, fn ->
            assert :ok = Cache.put(url, %{"client_id" => url}, deadline)
            assert TestRepo.aggregate(ClientIdMetadata, :count, :url) <= 3
          end)
        end)
      end,
      max_concurrency: 8,
      timeout: 10_000
    )
    |> Enum.each(fn {:ok, _} -> :ok end)

    assert TestRepo.aggregate(ClientIdMetadata, :count, :url) == 3
  end

  test "an over-capacity legacy cache is trimmed in SQL by earliest expiry" do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    entries =
      for index <- 1..30,
          do: %{
            url: "https://legacy.example/#{index}",
            metadata: %{},
            expires_at: DateTime.add(now, index + 300, :second),
            inserted_at: now
          }

    TestRepo.insert_all(ClientIdMetadata, entries)
    host = config(cache_max_entries: 3)

    Config.with_request_config(host, fn ->
      assert :ok = Cache.put("https://new.example/client", %{}, expiry())
    end)

    urls = TestRepo.all(from(c in ClientIdMetadata, select: c.url))
    assert Enum.sort(urls) == ["https://legacy.example/29", "https://legacy.example/30", "https://new.example/client"]
  end

  test "only the remote-key attachment callback can populate the internal annotation" do
    url = "https://origin.example/client.json"
    metadata = %{"client_id" => url, "__attesto_resolved_jwks" => %{"keys" => "untrusted"}}
    assert :ok = Cache.put(url, metadata, expiry())
    assert {:ok, stored, _} = Cache.get_entry(url)
    assert stored == %{"client_id" => url}
  end
end
