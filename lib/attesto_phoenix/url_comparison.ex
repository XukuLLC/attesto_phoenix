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
    with {:ok, "https://" <> _ = left_origin} <- to_origin(left),
         {:ok, "https://" <> _ = right_origin} <- to_origin(right) do
      left_origin == right_origin
    else
      _other -> false
    end
  end

  defp to_origin(%URI{} = uri), do: uri |> URI.to_string() |> Attesto.URI.origin()
  defp to_origin(value) when is_binary(value), do: Attesto.URI.origin(value)
  defp to_origin(_value), do: {:error, :invalid_uri}
end
