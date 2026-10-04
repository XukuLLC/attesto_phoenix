defmodule AttestoPhoenix.ClientIdMetadata.HostPolicy do
  @moduledoc false

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

  defp canonicalize_dns(host) do
    canonical =
      host
      |> String.to_charlist()
      |> :idna.encode([:uts46, :std3_rules])
      |> List.to_string()
      |> String.downcase(:ascii)
      |> String.replace_suffix(".", "")

    labels = String.split(canonical, ".")

    if byte_size(canonical) <= 253 and Enum.all?(labels, &(byte_size(&1) in 1..63)),
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
end
