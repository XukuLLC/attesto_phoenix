defmodule AttestoPhoenix.Controller.CredentialIssuerMetadataController do
  @moduledoc """
  OID4VCI Credential Issuer Metadata endpoint
  (`draft-ietf-oauth-openid4vci` §11.2).

  Builds the issuer document from the configured credential catalog and the
  convention-derived credential and nonce endpoint paths.
  """

  use Phoenix.Controller, formats: [:json]

  import Plug.Conn, only: [put_resp_header: 3]

  alias Attesto.CredentialIssuerMetadata
  alias AttestoPhoenix.Config

  @oauth_prefix "/oauth"
  @credential_path @oauth_prefix <> Config.credential_tail()
  @nonce_path @oauth_prefix <> Config.nonce_tail()
  @cache_max_age_seconds 3600

  @doc "Render the OID4VCI Credential Issuer Metadata document as JSON."
  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, _params) do
    config = Config.resolve!()

    metadata =
      CredentialIssuerMetadata.build(
        credential_issuer: config.issuer,
        credential_endpoint: endpoint_url(config.issuer, @credential_path),
        nonce_endpoint: endpoint_url(config.issuer, @nonce_path),
        credential_configurations_supported: Config.credential_configurations_supported(config)
      )

    conn
    |> put_cache_control()
    |> json(metadata)
  end

  defp endpoint_url(issuer, path) do
    issuer
    |> URI.parse()
    |> URI.merge(path)
    |> URI.to_string()
  end

  defp put_cache_control(conn) do
    put_resp_header(conn, "cache-control", "public, max-age=#{@cache_max_age_seconds}")
  end
end
