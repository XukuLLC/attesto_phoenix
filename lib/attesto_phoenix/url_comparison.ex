defmodule AttestoPhoenix.URLComparison do
  @moduledoc false

  # RFC 3986 §6.2.2 HTTPS-origin equivalence, shared by boot-time
  # configuration validation (`AttestoPhoenix.Config`, which keeps a derived
  # UserInfo endpoint pinned to the `:issuer` origin) and request-time
  # Provider Metadata suppression
  # (`AttestoPhoenix.Controller.OpenIDConfigurationController`, which decides
  # whether a derived endpoint resolves to the removed local UserInfo route).
  # The two decisions must agree on what "same origin" means, so the
  # comparison lives here exactly once.

  @doc """
  Whether `left` and `right` are the same HTTPS origin.

  Accepts URLs as strings or already-parsed `URI` structs. Scheme and host are
  compared case-insensitively and percent-encoded unreserved host bytes are
  equivalent to their decoded form (RFC 3986 §6.2.2.1/§6.2.2.2); an absent
  port is the HTTPS default 443. Anything that is not an HTTPS URL with a
  host compares as `false`.
  """
  @spec same_https_origin?(URI.t() | String.t() | term(), URI.t() | String.t() | term()) :: boolean()
  def same_https_origin?(left, right) do
    with %URI{scheme: "https", host: left_host} = left_uri when is_binary(left_host) <- to_uri(left),
         %URI{scheme: "https", host: right_host} = right_uri when is_binary(right_host) <- to_uri(right) do
      normalize_host(left_host) == normalize_host(right_host) and
        effective_https_port(left_uri) == effective_https_port(right_uri)
    else
      _other -> false
    end
  end

  defp to_uri(%URI{} = uri), do: uri

  defp to_uri(value) when is_binary(value) do
    case URI.new(value) do
      {:ok, uri} -> uri
      {:error, _reason} -> nil
    end
  end

  defp to_uri(_value), do: nil

  defp effective_https_port(%URI{port: nil}), do: 443
  defp effective_https_port(%URI{port: port}), do: port

  # RFC 3986 §6.2.2.1/§6.2.2.2: scheme and host are case-insensitive, and
  # percent-encoded unreserved host bytes are equivalent to their decoded form.
  defp normalize_host(host) do
    host
    |> normalize_percent_encoding(&URI.char_unreserved?/1)
    |> String.downcase()
  end

  defp normalize_percent_encoding(value, decoded_char?) do
    Regex.replace(~r/%[0-9A-Fa-f]{2}/, value, fn "%" <> hex ->
      byte = String.to_integer(hex, 16)

      if decoded_char?.(byte), do: <<byte>>, else: "%" <> String.upcase(hex)
    end)
  end
end
