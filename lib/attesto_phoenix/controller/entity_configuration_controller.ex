defmodule AttestoPhoenix.Controller.EntityConfigurationController do
  @moduledoc """
  OpenID Federation 1.0 Entity Configuration endpoint.

  Builds a self-issued Entity Statement from the configured issuer, signing
  key, authority hints, and entity metadata.
  """

  use Phoenix.Controller, formats: [:json]

  import Plug.Conn, only: [put_resp_header: 3, send_resp: 3]

  alias Attesto.Federation.EntityStatement
  alias AttestoPhoenix.Config

  @content_type "application/entity-statement+jwt"

  @doc "Serve the signed OpenID Federation Entity Configuration."
  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, _params) do
    config = Config.resolve!()

    entity_configuration =
      EntityStatement.entity_configuration(
        config.keystore,
        config.issuer,
        entity_configuration_options(config)
      )

    conn
    |> put_resp_header("content-type", @content_type)
    |> send_resp(200, entity_configuration)
  end

  defp entity_configuration_options(config) do
    [
      authority_hints: Config.federation_authority_hints(config),
      metadata: Config.federation_entity_metadata(config)
    ]
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
  end
end
