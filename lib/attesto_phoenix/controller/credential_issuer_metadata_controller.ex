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

  @cache_max_age_seconds 3600

  @doc "Render the OID4VCI Credential Issuer Metadata document as JSON."
  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, _params) do
    config = Config.resolve!()

    metadata =
      CredentialIssuerMetadata.build(
        credential_issuer: config.issuer,
        credential_endpoint: Config.credential_endpoint_url(config),
        nonce_endpoint: Config.nonce_endpoint_url(config),
        deferred_credential_endpoint: deferred_credential_endpoint(config),
        credential_configurations_supported: Config.credential_configurations_supported(config)
      )

    conn
    |> put_cache_control()
    |> json(metadata)
  end

  # Advertised only once the host has actually wired deferred-issuance
  # completion: an issuer that never defers a credential should not point
  # wallets at an endpoint whose host callback is unconfigured.
  defp deferred_credential_endpoint(config) do
    if Config.build_deferred_credential_fun(config), do: Config.deferred_credential_endpoint_url(config)
  end

  defp put_cache_control(conn) do
    put_resp_header(conn, "cache-control", "public, max-age=#{@cache_max_age_seconds}")
  end
end
