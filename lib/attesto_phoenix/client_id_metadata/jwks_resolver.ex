defmodule AttestoPhoenix.ClientIdMetadata.JWKSResolver do
  @moduledoc false

  alias Attesto.ClientIdMetadata, as: Core
  alias AttestoPhoenix.ClientIdMetadata.{Cache, FlowControl, HostPolicy, Resolver}

  require Logger

  # The entry is attached to the existing document record: eviction and
  # rotation remove the keys with it, and there is at most one key set per
  # document. A fetch cannot extend the document's deadline or revive a row.
  def resolve(metadata, uri, opts) do
    fetcher = Keyword.fetch!(opts, :fetcher)
    cache = Keyword.get(opts, :cache)

    with {:ok, host} <- HostPolicy.canonicalize(URI.parse(uri).host) do
      # Cache hits still perform DNS preflight. Admit that outbound work too,
      # rather than allowing unauthenticated callers to bypass the DNS budget.
      FlowControl.run(host, uri, {:jwks, metadata, fetcher, cache, opts}, opts, fn ->
        do_resolve(fetcher, cache, metadata, uri, opts)
      end)
    end
  end

  defp do_resolve(fetcher, cache, metadata, uri, opts) do
    if cache_supported?(cache, fetcher) do
      resolve_cached(fetcher, cache, metadata, uri, opts)
    else
      fetch_and_cache(fetcher, cache, metadata, uri, nil, opts)
    end
  end

  defp resolve_cached(fetcher, cache, metadata, uri, opts) do
    with :ok <- fetcher.preflight(uri, opts) do
      entry = current_document(cache, metadata)

      case cached_keys(entry, uri) do
        {:ok, keys} -> {:ok, keys}
        :miss -> fetch_and_cache(fetcher, cache, metadata, uri, entry, opts)
      end
    end
  end

  defp cache_supported?(cache, fetcher) do
    Code.ensure_loaded?(cache) and function_exported?(cache, :get_entry, 1) and
      function_exported?(cache, :put_jwks, 4) and Code.ensure_loaded?(fetcher) and
      function_exported?(fetcher, :preflight, 2)
  end

  defp current_document(cache, %{"client_id" => client_id} = metadata) do
    with {:ok, expected} <- Core.validate_document(client_id, metadata),
         {:ok, stored, %DateTime{} = expiry} <- cache.get_entry(client_id),
         true <- DateTime.after?(expiry, DateTime.utc_now()),
         {:ok, current} <- Core.validate_document(client_id, Cache.metadata_only(stored)),
         true <- expected == current do
      {stored, expiry}
    else
      _ -> nil
    end
  rescue
    _ -> cache_read_fault()
  catch
    _, _ -> cache_read_fault()
  end

  defp current_document(_cache, _metadata), do: nil

  defp cached_keys({metadata, document_expiry}, uri) do
    with %{"uri" => ^uri, "keys" => keys, "expires_at" => expiry} <- Cache.resolved_jwks(metadata),
         true <- is_integer(expiry) and expiry > System.system_time(:second),
         true <- expiry <= DateTime.to_unix(document_expiry),
         :ok <- Core.validate_public_jwks(keys) do
      {:ok, keys}
    else
      _ -> :miss
    end
  end

  defp cached_keys(nil, _uri), do: :miss

  defp fetch_and_cache(fetcher, cache, metadata, uri, entry, opts) do
    with {:ok, %{body: body} = response} <- fetcher.fetch(uri, opts),
         {:ok, keys} <- JSON.decode(body),
         :ok <- Core.validate_public_jwks(keys) do
      cache_keys(cache, metadata, uri, keys, entry, Map.get(response, :cache_control, []), opts)
      {:ok, keys}
    end
  end

  defp cache_keys(cache, %{"client_id" => client_id}, uri, keys, {stored, document_expiry}, directives, opts) do
    if not Keyword.get(directives, :no_store, false) and not Keyword.get(directives, :no_cache, false) do
      http_expiry = Resolver.key_cache_expires_at(directives, opts)
      expiry = min(DateTime.to_unix(document_expiry), DateTime.to_unix(http_expiry))

      if expiry > System.system_time(:second) do
        resolved = %{"uri" => uri, "keys" => keys, "expires_at" => expiry}
        cache.put_jwks(client_id, stored, document_expiry, resolved)
      end
    end

    :ok
  rescue
    _ -> cache_write_fault()
  catch
    _, _ -> cache_write_fault()
  end

  defp cache_keys(_cache, _metadata, _uri, _keys, _entry, _directives, _opts), do: :ok

  defp cache_read_fault do
    Logger.warning("AttestoPhoenix CIMD key cache failed; fetching fresh public keys")
    nil
  end

  defp cache_write_fault do
    Logger.warning("AttestoPhoenix CIMD key cache failed; fresh public keys were not cached")
    :ok
  end
end
