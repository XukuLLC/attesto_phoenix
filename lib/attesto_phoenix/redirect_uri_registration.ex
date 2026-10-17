defmodule AttestoPhoenix.RedirectURIRegistration do
  @moduledoc false

  alias Attesto.RedirectURI
  alias AttestoPhoenix.ClientIdMetadata
  alias AttestoPhoenix.ClientIdMetadata.HostPolicy

  @max_uri_bytes 2_048
  @private_scheme ~r/\A[a-z][a-z0-9]*(?:\.[a-z0-9][a-z0-9-]*)+\z/

  @spec valid?(term(), keyword()) :: boolean()
  def valid?(value, opts \\ [])

  def valid?(value, opts) when is_binary(value) and value != "" and is_list(opts) do
    with true <- byte_size(value) <= @max_uri_bytes,
         true <- String.valid?(value),
         false <- Regex.match?(~r/\p{Cc}/u, value),
         false <- String.contains?(value, "\\"),
         false <- Regex.match?(~r/%(?![0-9A-Fa-f]{2})/, value),
         true <- RedirectURI.unambiguous?(value),
         {:ok, %URI{fragment: nil, userinfo: nil} = uri} <- URI.new(value) do
      acceptable?(uri, value, opts)
    else
      _other -> false
    end
  rescue
    _exception -> false
  catch
    _kind, _reason -> false
  end

  def valid?(_value, _opts), do: false

  defp acceptable?(%URI{scheme: "https", host: host, port: port}, _original, _opts) do
    valid_host?(host) and valid_port?(port, false)
  end

  defp acceptable?(%URI{scheme: "http", port: port}, original, opts) do
    case Keyword.get(opts, :loopback_mode) do
      mode when mode in [:exact_allow_loopback_port, :exact_allow_loopback_port_including_localhost] ->
        valid_port?(port, true) and ClientIdMetadata.loopback_redirect_uri?(original, mode)

      _other ->
        false
    end
  end

  defp acceptable?(%URI{scheme: scheme, host: host, path: path, port: port}, _original, opts) do
    Keyword.get(opts, :allow_private_use, false) and
      is_binary(scheme) and Regex.match?(@private_scheme, scheme) and
      valid_port?(port, false) and
      ((is_nil(host) and is_binary(path) and path != "") or
         (is_binary(host) and host != ""))
  end

  defp valid_host?(host) when is_binary(host) and host != "" do
    match?({:ok, _canonical}, HostPolicy.canonicalize(host))
  end

  defp valid_host?(_host), do: false

  defp valid_port?(nil, _allow_zero?), do: true
  defp valid_port?(0, true), do: true
  defp valid_port?(port, _allow_zero?) when is_integer(port), do: port in 1..65_535
end
