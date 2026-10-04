defmodule AttestoPhoenix.ClientIdMetadataJWKSTest do
  use ExUnit.Case, async: true

  alias AttestoPhoenix.{ClientIdMetadata, Config}
  alias AttestoPhoenix.ClientIdMetadata.Cache
  alias AttestoPhoenix.ClientIdMetadata.Cache.ETS
  alias AttestoPhoenix.ClientIdMetadata.FlowControl

  setup do
    Process.put(FlowControl, start_supervised!({FlowControl, []}))
    :ok
  end

  defmodule Fetcher do
    def preflight(uri, opts) do
      send(Keyword.fetch!(opts, :test_pid), {:preflight, uri})
      Keyword.get(opts, :test_preflight, :ok)
    end

    def fetch(uri, opts) do
      send(Keyword.fetch!(opts, :test_pid), {:fetch, uri})
      if callback = Keyword.get(opts, :test_on_fetch), do: callback.()

      {:ok,
       %{
         body: JSON.encode!(Keyword.fetch!(opts, :test_keys)),
         cache_control: Keyword.get(opts, :test_cache_control, [])
       }}
    end
  end

  defmodule LegacyFetcher do
    defdelegate fetch(uri, opts), to: Fetcher
  end

  test "resolves remote public keys and rejects private material from either source" do
    keys = %{"keys" => [%{"kty" => "EC", "crv" => "P-256", "x" => "x", "y" => "y"}]}

    config = %Config{
      issuer: "https://issuer.example",
      keystore: Fetcher,
      repo: Fetcher,
      client_id_metadata: [
        fetcher: Fetcher,
        test_pid: self(),
        test_keys: keys,
        flow_control_server: Process.get(FlowControl)
      ]
    }

    uri = "https://client.example/keys.json"
    assert {:ok, ^keys} = ClientIdMetadata.resolve_jwks(%{"jwks_uri" => uri}, config)
    assert_receive {:fetch, ^uri}

    private = put_in(keys, ["keys", Access.at(0), "d"], "private")
    assert {:error, :private_key_material} = ClientIdMetadata.resolve_jwks(%{"jwks" => private}, config)
    config = %{config | client_id_metadata: Keyword.put(config.client_id_metadata, :test_keys, private)}
    assert {:error, :missing_client_jwks} = ClientIdMetadata.resolve_jwks(%{"jwks_uri" => uri}, config)
  end

  test "applies host policy before fetching a JWK URI" do
    config = %Config{
      issuer: "https://issuer.example",
      keystore: Fetcher,
      repo: Fetcher,
      client_id_metadata: [
        fetcher: Fetcher,
        test_pid: self(),
        blocked_hosts: ["blocked.example"],
        flow_control_server: Process.get(FlowControl)
      ]
    }

    assert {:error, :missing_client_jwks} =
             ClientIdMetadata.resolve_jwks(%{"jwks_uri" => "https://blocked.example/keys.json"}, config)

    refute_receive {:fetch, _}
  end

  test "remote JWK block policy screens case, root-dot and IDNA aliases before DNS or fetch" do
    for {host, blocked} <- [
          {"BLOCKED.Example", "blocked.example"},
          {"blocked.example.", "Blocked.Example"},
          {"blocked.example", "BLOCKED.Example."},
          {"xn--bcher-kva.example", "bücher.example"},
          {"XN--BCHER-KVA.example.", "BÜCHER.Example"}
        ] do
      config = %Config{
        issuer: "https://issuer.example",
        keystore: Fetcher,
        repo: Fetcher,
        client_id_metadata: [
          fetcher: Fetcher,
          test_pid: self(),
          blocked_hosts: [blocked],
          flow_control_server: Process.get(FlowControl)
        ]
      }

      assert {:error, :missing_client_jwks} =
               ClientIdMetadata.resolve_jwks(%{"jwks_uri" => "https://#{host}/keys.json"}, config)
    end

    refute_received {:preflight, _}
    refute_received {:fetch, _}
  end

  test "remote JWK allow policy compares canonical names while retaining the exact URI" do
    uri = "https://XN--BCHER-KVA.example./keys.json"
    keys = %{"keys" => [%{"kty" => "EC", "crv" => "P-256", "x" => "x", "y" => "y"}]}

    config = %Config{
      issuer: "https://issuer.example",
      keystore: Fetcher,
      repo: Fetcher,
      client_id_metadata: [
        fetcher: Fetcher,
        test_pid: self(),
        test_keys: keys,
        allowed_hosts: ["BÜCHER.example"],
        flow_control_server: Process.get(FlowControl)
      ]
    }

    assert {:ok, ^keys} = ClientIdMetadata.resolve_jwks(%{"jwks_uri" => uri}, config)
    assert_received {:fetch, ^uri}
  end

  defp cached_client(directives \\ [max_age: 300], ttl \\ 600) do
    id = "https://cache-#{System.unique_integer([:positive])}.example/client.json"
    uri = String.replace(id, "client.json", "keys.json")

    {:ok, metadata} =
      Attesto.ClientIdMetadata.validate_document(id, %{
        "client_id" => id,
        "redirect_uris" => ["https://client.example/cb"],
        "token_endpoint_auth_method" => "private_key_jwt",
        "jwks_uri" => uri
      })

    {_, public} = JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_public_map()
    keys = %{"keys" => [Map.put(public, "kid", "version-1")]}
    expiry = DateTime.utc_now() |> DateTime.add(ttl, :second) |> DateTime.truncate(:second)
    :ok = ETS.put(id, metadata, expiry)
    on_exit(fn -> ETS.delete(id) end)

    config = %Config{
      issuer: "https://issuer.example",
      keystore: Fetcher,
      repo: Fetcher,
      client_id_metadata: [
        fetcher: Fetcher,
        flow_control_server: Process.get(FlowControl),
        cache: ETS,
        cache_ttl_bounds: {30, 3600},
        test_pid: self(),
        test_keys: keys,
        test_cache_control: directives
      ]
    }

    {metadata, uri, keys, expiry, config}
  end

  defp with_option(config, key, value),
    do: %{config | client_id_metadata: Keyword.put(config.client_id_metadata, key, value)}

  test "caches valid keys within the document record and rechecks DNS before hits" do
    {metadata, uri, keys, expiry, config} = cached_client()
    assert {:ok, ^keys} = ClientIdMetadata.resolve_jwks(metadata, config)
    assert_receive {:preflight, ^uri}
    assert_receive {:fetch, ^uri}
    assert {:ok, ^keys} = ClientIdMetadata.resolve_jwks(metadata, config)
    assert_receive {:preflight, ^uri}
    refute_receive {:fetch, _}
    assert {:ok, stored, ^expiry} = ETS.get_entry(metadata["client_id"])
    assert Cache.resolved_jwks(stored)["uri"] == uri
    assert {:ok, ^metadata} = ETS.get(metadata["client_id"])
    assert {:ok, ^metadata} = ClientIdMetadata.resolve(metadata["client_id"], config)

    denied = with_option(config, :test_preflight, {:error, {:blocked_ip, {127, 0, 0, 1}}})
    assert {:error, :missing_client_jwks} = ClientIdMetadata.resolve_jwks(metadata, denied)
    assert_receive {:preflight, ^uri}
    refute_receive {:fetch, _}
    denied = with_option(config, :blocked_hosts, [URI.parse(uri).host])
    assert {:error, :missing_client_jwks} = ClientIdMetadata.resolve_jwks(metadata, denied)
    refute_receive {:preflight, _}
  end

  test "custom fetchers without preflight continue working and never cache remote keys" do
    {metadata, uri, keys, _, config} = cached_client()
    config = with_option(config, :fetcher, LegacyFetcher)

    for _ <- 1..2 do
      assert {:ok, ^keys} = ClientIdMetadata.resolve_jwks(metadata, config)
      assert_receive {:fetch, ^uri}
    end

    refute_receive {:preflight, _}
    assert {:ok, stored, _} = ETS.get_entry(metadata["client_id"])
    assert Cache.resolved_jwks(stored) == nil
  end

  test "bounds key freshness by HTTP max-age and document expiry, then refetches rotated keys" do
    {metadata, uri, keys, document_expiry, config} = cached_client(max_age: 300, age: 295)
    assert {:ok, ^keys} = ClientIdMetadata.resolve_jwks(metadata, config)
    assert_receive {:fetch, ^uri}
    assert {:ok, stored, ^document_expiry} = ETS.get_entry(metadata["client_id"])
    cached = Cache.resolved_jwks(stored)
    assert cached["expires_at"] <= System.system_time(:second) + 5
    # Simulate expiry directly to test rotation without wall-clock sleeps.
    :ok =
      ETS.put_jwks(
        metadata["client_id"],
        stored,
        document_expiry,
        Map.put(cached, "expires_at", System.system_time(:second) - 1)
      )

    rotated = put_in(keys, ["keys", Access.at(0), "kid"], "version-2")
    assert {:ok, ^rotated} = ClientIdMetadata.resolve_jwks(metadata, with_option(config, :test_keys, rotated))
    assert_receive {:fetch, ^uri}
    assert {:ok, current, ^document_expiry} = ETS.get_entry(metadata["client_id"])
    assert Cache.resolved_jwks(current)["keys"] == rotated

    {short_metadata, _, _, short_expiry, short_config} = cached_client([max_age: 1000], 60)
    assert {:ok, _} = ClientIdMetadata.resolve_jwks(short_metadata, short_config)
    assert {:ok, short_stored, ^short_expiry} = ETS.get_entry(short_metadata["client_id"])
    assert Cache.resolved_jwks(short_stored)["expires_at"] == DateTime.to_unix(short_expiry)
  end

  test "never caches no-store, no-cache, zero freshness, invalid keys or an expired document" do
    for directives <- [[no_store: true], [no_cache: true], [max_age: 0], [max_age: 300, age: 300]] do
      {metadata, uri, keys, _, config} = cached_client(directives)

      for _ <- 1..2 do
        assert {:ok, ^keys} = ClientIdMetadata.resolve_jwks(metadata, config)
        assert_receive {:fetch, ^uri}
      end

      assert {:ok, stored, _} = ETS.get_entry(metadata["client_id"])
      assert Cache.resolved_jwks(stored) == nil
    end

    {metadata, uri, keys, _, config} = cached_client()
    private = put_in(keys, ["keys", Access.at(0), "d"], "private")

    assert {:error, :missing_client_jwks} =
             ClientIdMetadata.resolve_jwks(metadata, with_option(config, :test_keys, private))

    assert_receive {:fetch, ^uri}

    assert {:error, :missing_client_jwks} =
             ClientIdMetadata.resolve_jwks(metadata, with_option(config, :test_keys, private))

    refute_receive {:fetch, _}

    assert {:ok, stored, _} = ETS.get_entry(metadata["client_id"])
    assert Cache.resolved_jwks(stored) == nil

    :ok = ETS.put(metadata["client_id"], metadata, DateTime.add(DateTime.utc_now(), -1, :second))

    for _ <- 1..2 do
      assert {:ok, ^keys} = ClientIdMetadata.resolve_jwks(metadata, config)
      assert_receive {:fetch, ^uri}
    end

    assert :miss = ETS.get_entry(metadata["client_id"])
  end

  test "binds keys to metadata and URI and cannot resurrect an evicted or concurrently rotated record" do
    {metadata, uri, keys, expiry, config} = cached_client()
    assert {:ok, ^keys} = ClientIdMetadata.resolve_jwks(metadata, config)
    assert_receive {:fetch, ^uri}
    rotated = Map.put(metadata, "jwks_uri", String.replace(uri, "keys.json", "rotated.json"))
    :ok = ETS.put(metadata["client_id"], rotated, expiry)
    assert {:ok, ^keys} = ClientIdMetadata.resolve_jwks(metadata, config)
    assert_receive {:fetch, ^uri}
    assert {:ok, ^rotated, ^expiry} = ETS.get_entry(metadata["client_id"])

    eviction = with_option(config, :test_on_fetch, fn -> ETS.delete(metadata["client_id"]) end)
    :ok = ETS.put(metadata["client_id"], metadata, expiry)
    assert {:ok, ^keys} = ClientIdMetadata.resolve_jwks(metadata, eviction)
    assert :miss = ETS.get_entry(metadata["client_id"])

    :ok = ETS.put(metadata["client_id"], metadata, expiry)
    rotation = with_option(config, :test_on_fetch, fn -> ETS.put(metadata["client_id"], rotated, expiry) end)
    assert {:ok, ^keys} = ClientIdMetadata.resolve_jwks(metadata, rotation)
    assert {:ok, ^rotated, ^expiry} = ETS.get_entry(metadata["client_id"])

    assert :stale = ETS.put_jwks(metadata["client_id"], metadata, expiry, %{})
    :ok = ETS.delete(metadata["client_id"])
    assert :stale = ETS.put_jwks(metadata["client_id"], rotated, expiry, %{})
  end
end
