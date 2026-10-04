defmodule AttestoPhoenix.ClientIdMetadata.CacheCapacity do
  @moduledoc false

  alias AttestoPhoenix.Config

  @default_capacity 1_024
  @default_record_bytes 16_384

  def limit do
    option(:cache_max_entries, @default_capacity)
  end

  def fits?(url, metadata) do
    :erlang.external_size({url, metadata}) <= option(:cache_max_record_bytes, @default_record_bytes)
  end

  defp option(key, default) do
    case Config.request_config() do
      %Config{} = config -> config |> Config.client_id_metadata() |> Keyword.get(key, default)
      nil -> default
    end
  end
end
