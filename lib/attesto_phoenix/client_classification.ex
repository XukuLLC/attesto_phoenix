defmodule AttestoPhoenix.ClientClassification do
  @moduledoc """
  Resolves the OAuth public/confidential classification supplied by a host.

  A registered client is `:unknown` when the host has not configured the
  `:client_public?` callback. Callers deliberately interpret that state in
  their own security context: client authentication treats it as confidential,
  while authorization-request validation keeps PKCE required.

  Client ID Metadata Document clients are self-asserted clients rather than host
  registrations. They are therefore classified as public even when they prove
  control of a document key with `private_key_jwt`; that proof must never unlock
  grants reserved for registered confidential clients.
  """

  alias AttestoPhoenix.{Callback, Config}
  alias AttestoPhoenix.ClientIdMetadata.Client, as: CIMDClient

  @typedoc "A client's resolved OAuth classification."
  @type t :: :public | :confidential | :unknown

  @doc "Resolve a client's public/confidential classification without choosing a caller-specific default."
  @spec classify(Config.t(), term()) :: t()
  def classify(%Config{}, %CIMDClient{}), do: :public

  def classify(%Config{} = config, client) do
    case Config.client_public_fun(config) do
      nil ->
        :unknown

      callback ->
        if Callback.invoke_boolean(callback, [client], false, :client_public?),
          do: :public,
          else: :confidential
    end
  end
end
