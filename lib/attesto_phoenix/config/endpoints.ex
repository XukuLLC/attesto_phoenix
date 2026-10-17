defmodule AttestoPhoenix.Config.Endpoints do
  @moduledoc false

  @spec path(map(), String.t() | nil, String.t()) :: String.t()
  def path(_config, override, _tail) when is_binary(override) and override != "", do: override

  def path(%{oauth_path_prefix: prefix}, _override, tail) when is_binary(tail) do
    join_path(prefix, tail)
  end

  @spec join_path(term(), term()) :: String.t()
  def join_path(prefix, tail) do
    prefix = String.trim_trailing(to_string(prefix), "/")
    tail = "/" <> String.trim_leading(to_string(tail), "/")
    prefix <> tail
  end

  @spec url(map(), String.t()) :: String.t()
  def url(%{issuer: issuer}, path) when is_binary(path) do
    Attesto.Config.append_endpoint_path(issuer, path)
  end
end
