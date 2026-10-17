defmodule AttestoPhoenix.Controller.JwtVcIssuerMetadataController do
  @moduledoc """
  SD-JWT VC JWT VC Issuer Metadata endpoint
  (`draft-ietf-oauth-sd-jwt-vc` §5).

  Publishes the public verification keys for the keystore that signs issued
  Verifiable Credentials. This is intentionally independent of the OIDC JWKS,
  which publishes the authorization server's main keystore.
  """

  use AttestoPhoenix.Controller, formats: [:json]

  alias Attesto.JWKS
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Controller.MetadataSupport

  @cache_max_age_seconds 3600

  @doc "Render the JWT VC Issuer Metadata document as JSON."
  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, _params) do
    config = Config.resolve!(conn)

    metadata = %{
      "issuer" => config.issuer,
      "jwks" => config |> Config.vc_keystore() |> JWKS.from_keystore()
    }

    conn
    |> MetadataSupport.put_public_cache(@cache_max_age_seconds)
    |> json(metadata)
  end
end
