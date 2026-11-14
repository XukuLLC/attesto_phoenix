defmodule AttestoPhoenix.Store.PAR.Capacity do
  @moduledoc false

  alias AttestoPhoenix.Config

  @default_max_entries 1_024
  @default_interaction_max_entries 8_192
  @default_max_record_bytes 262_144

  @spec max_entries() :: pos_integer()
  def max_entries, do: option(:par_max_entries, @default_max_entries)

  @spec interaction_max_entries() :: pos_integer()
  def interaction_max_entries, do: option(:interaction_max_entries, @default_interaction_max_entries)

  @spec fits?(String.t(), map(), integer()) :: boolean()
  def fits?(request_uri, params, expires_at) do
    fits_limit?(request_uri, params, expires_at, option(:par_max_record_bytes, @default_max_record_bytes))
  end

  @spec fits?(String.t(), map(), integer(), Config.t()) :: boolean()
  def fits?(request_uri, params, expires_at, %Config{par_max_record_bytes: limit}) do
    fits_limit?(request_uri, params, expires_at, limit)
  end

  defp fits_limit?(request_uri, params, expires_at, limit) do
    :erlang.external_size({request_uri, params, expires_at}) <= limit
  rescue
    _error -> false
  catch
    _kind, _reason -> false
  end

  defp option(key, default) do
    case Config.request_config() do
      %Config{} = config -> Map.fetch!(config, key)
      nil -> default
    end
  end
end
