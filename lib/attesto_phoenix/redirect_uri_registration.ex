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
         true <- Attesto.URI.valid_percent_encoding?(value),
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

  defp acceptable?(%URI{scheme: "https", host: host, port: port}, original, _opts) do
    valid_host?(host) and Attesto.URI.valid_port?(original, port)
  end

  defp acceptable?(%URI{scheme: "http", port: port}, original, opts) do
    case Keyword.get(opts, :loopback_mode) do
      mode when mode in [:exact_allow_loopback_port, :exact_allow_loopback_port_including_localhost] ->
        valid_loopback_port?(original, port) and ClientIdMetadata.loopback_redirect_uri?(original, mode)

      _other ->
        false
    end
  end

  defp acceptable?(%URI{scheme: scheme, host: host, path: path, port: port}, original, opts) do
    Keyword.get(opts, :allow_private_use, false) and
      is_binary(scheme) and Regex.match?(@private_scheme, scheme) and
      Attesto.URI.valid_port?(original, port) and
      ((is_nil(host) and is_binary(path) and path != "") or
         (is_binary(host) and host != ""))
  end

  defp valid_loopback_port?(original, 0), do: Attesto.URI.valid_port?(original, nil)
  defp valid_loopback_port?(original, port), do: Attesto.URI.valid_port?(original, port)

  defp valid_host?(host) when is_binary(host) and host != "" do
    match?({:ok, _canonical}, HostPolicy.canonicalize(host))
  end

  defp valid_host?(_host), do: false
end
