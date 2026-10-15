defmodule AttestoPhoenix.ClientIdMetadata.HostPolicy do
  @moduledoc false

  import Bitwise, only: [&&&: 2, >>>: 2, <<<: 2]

  @type ip :: :inet.ip_address()

  @ipv4_special_use [
    {{0, 0, 0, 0}, 8},
    {{10, 0, 0, 0}, 8},
    {{100, 64, 0, 0}, 10},
    {{127, 0, 0, 0}, 8},
    {{169, 254, 0, 0}, 16},
    {{172, 16, 0, 0}, 12},
    {{192, 0, 0, 0}, 24},
    {{192, 0, 2, 0}, 24},
    {{192, 88, 99, 0}, 24},
    {{192, 168, 0, 0}, 16},
    {{198, 18, 0, 0}, 15},
    {{198, 51, 100, 0}, 24},
    {{203, 0, 113, 0}, 24},
    {{224, 0, 0, 0}, 4},
    {{240, 0, 0, 0}, 4}
  ]

  @ipv6_special_use [
    {{0xFC00, 0, 0, 0, 0, 0, 0, 0}, 7},
    {{0xFE80, 0, 0, 0, 0, 0, 0, 0}, 10},
    {{0xFF00, 0, 0, 0, 0, 0, 0, 0}, 8},
    {{0x2001, 0x0000, 0, 0, 0, 0, 0, 0}, 32},
    {{0x2001, 0x0020, 0, 0, 0, 0, 0, 0}, 28},
    {{0x2001, 0x0DB8, 0, 0, 0, 0, 0, 0}, 32},
    {{0x0100, 0, 0, 0, 0, 0, 0, 0}, 64},
    {{0x2001, 0x0002, 0, 0, 0, 0, 0, 0}, 48},
    {{0x3FFF, 0, 0, 0, 0, 0, 0, 0}, 20},
    {{0x5F00, 0, 0, 0, 0, 0, 0, 0}, 16}
  ]

  @spec check(term(), keyword()) :: :ok | {:error, :blocked_host}
  def check(host, opts) do
    with {:ok, canonical} <- canonicalize(host),
         {:ok, blocked} when is_list(blocked) <- canonicalize_hosts(Keyword.get(opts, :blocked_hosts, [])),
         {:ok, allowed} <- canonicalize_hosts(Keyword.get(opts, :allowed_hosts)) do
      if canonical in blocked or (is_list(allowed) and canonical not in allowed),
        do: {:error, :blocked_host},
        else: :ok
    else
      _ -> {:error, :blocked_host}
    end
  end

  @spec canonicalize(term()) :: {:ok, String.t()} | {:error, :invalid_host}
  def canonicalize(host) when is_binary(host) and byte_size(host) > 0 do
    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, address} -> {:ok, address |> :inet.ntoa() |> List.to_string()}
      {:error, _} -> canonicalize_dns(host)
    end
  rescue
    _ -> {:error, :invalid_host}
  catch
    _, _ -> {:error, :invalid_host}
  end

  def canonicalize(_host), do: {:error, :invalid_host}

  @spec special_use_literal?(term()) :: boolean()
  def special_use_literal?(host) when is_binary(host) do
    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, ip} -> special_use_ip?(ip)
      {:error, _reason} -> false
    end
  rescue
    _exception -> false
  end

  def special_use_literal?(_host), do: false

  @spec special_use_ip?(ip()) :: boolean()
  def special_use_ip?({_a, _b, _c, _d} = ip), do: in_any?(ip, @ipv4_special_use)

  def special_use_ip?({0, 0, 0, 0, 0, 0xFFFF, w7, w8}) do
    special_use_ip?(embedded_v4(w7, w8))
  end

  def special_use_ip?({0x0064, 0xFF9B, 0, 0, 0, 0, w7, w8}) do
    special_use_ip?(embedded_v4(w7, w8))
  end

  # RFC 8215 reserves the entire 64:ff9b:1::/48 for local-use NAT64. The
  # operator may choose any RFC 6052 embedding layout beneath it, so attempting
  # to decode one layout leaves the others open. Refuse the whole prefix.
  def special_use_ip?({0x0064, 0xFF9B, 0x0001, _w4, _w5, _w6, _w7, _w8}), do: true

  def special_use_ip?({0x2002, w2, w3, _w4, _w5, _w6, _w7, _w8}) do
    special_use_ip?(embedded_v4(w2, w3))
  end

  def special_use_ip?({0, 0, 0, 0, 0, 0, 0, 1}), do: true
  def special_use_ip?({0, 0, 0, 0, 0, 0, 0, 0}), do: true

  def special_use_ip?({0, 0, 0, 0, 0, 0, w7, w8}) do
    special_use_ip?(embedded_v4(w7, w8))
  end

  def special_use_ip?({_a, _b, _c, _d, _e, _f, _g, _h} = ip) do
    in_any?(ip, @ipv6_special_use)
  end

  def special_use_ip?(_ip), do: true

  @spec authority(URI.t()) :: String.t()
  def authority(%URI{host: host, port: port, scheme: scheme}) when is_binary(host) and is_integer(port) do
    host_part = if String.contains?(host, ":"), do: "[" <> host <> "]", else: host

    if default_port?(scheme, port),
      do: host_part,
      else: host_part <> ":" <> Integer.to_string(port)
  end

  defp canonicalize_dns(host) do
    labels =
      host
      |> String.replace(~r/[。．｡]/u, ".")
      |> String.replace_suffix(".", "")
      |> String.split(".")

    if Enum.any?(labels, &(&1 == "")),
      do: {:error, :invalid_host},
      else: encode_dns(host, length(labels))
  end

  defp encode_dns(host, label_count) do
    canonical =
      host
      |> String.to_charlist()
      |> :idna.encode([:uts46, :std3_rules])
      |> List.to_string()
      |> String.downcase(:ascii)
      |> String.replace_suffix(".", "")

    labels = String.split(canonical, ".")

    if byte_size(canonical) <= 253 and length(labels) == label_count and Enum.all?(labels, &(byte_size(&1) in 1..63)),
      do: {:ok, canonical},
      else: {:error, :invalid_host}
  end

  defp canonicalize_hosts(nil), do: {:ok, nil}

  defp canonicalize_hosts(hosts) when is_list(hosts) do
    Enum.reduce_while(hosts, {:ok, []}, fn host, {:ok, acc} ->
      case canonicalize(host) do
        {:ok, canonical} -> {:cont, {:ok, [canonical | acc]}}
        error -> {:halt, error}
      end
    end)
  end

  defp canonicalize_hosts(_hosts), do: {:error, :invalid_host}

  defp default_port?("https", 443), do: true
  defp default_port?("http", 80), do: true
  defp default_port?(_scheme, _port), do: false

  defp embedded_v4(hi, lo), do: {hi >>> 8, hi &&& 0xFF, lo >>> 8, lo &&& 0xFF}

  defp in_any?(ip, table) do
    Enum.any?(table, fn {network, prefix_len} -> in_cidr?(ip, network, prefix_len) end)
  end

  defp in_cidr?(ip, network, prefix_len) when tuple_size(ip) == 4 do
    cidr_match?(Tuple.to_list(ip), Tuple.to_list(network), prefix_len, 8)
  end

  defp in_cidr?(ip, network, prefix_len) when tuple_size(ip) == 8 do
    cidr_match?(Tuple.to_list(ip), Tuple.to_list(network), prefix_len, 16)
  end

  defp cidr_match?(_ip, _network, remaining, _width) when remaining <= 0, do: true

  defp cidr_match?([ip_part | ip_rest], [network_part | network_rest], remaining, width) do
    take = min(remaining, width)
    mask = element_mask(width, take)

    (ip_part &&& mask) == (network_part &&& mask) and
      cidr_match?(ip_rest, network_rest, remaining - width, width)
  end

  defp element_mask(width, take) do
    full = (1 <<< width) - 1
    full - ((1 <<< (width - take)) - 1)
  end
end
