defmodule AttestoPhoenix.Controller.CredentialIssuerMetadataController do
  @moduledoc """
  OID4VCI Credential Issuer Metadata endpoint
  (`draft-ietf-oauth-openid4vci` §11.2).

  Builds the issuer document from the configured credential catalog and the
  convention-derived credential and nonce endpoint paths.
  """

  use Phoenix.Controller, formats: [:json]

  import Plug.Conn,
    only: [get_req_header: 2, put_resp_content_type: 2, put_resp_header: 3, send_resp: 3]

  alias Attesto.CredentialIssuerMetadata
  alias AttestoPhoenix.Config

  @cache_max_age_seconds 3600
  @signed_metadata_content_type "application/jwt"

  @doc """
  Render the OID4VCI Credential Issuer Metadata document.

  Serves the JSON document, or - when the wallet requests it with
  `Accept: application/jwt` and the host has a VC signing key - the signed JWT
  representation (OID4VCI §11.2.2).
  """
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

    conn = put_cache_control(conn)

    if wants_signed_metadata?(conn) do
      signed = CredentialIssuerMetadata.signed(metadata, pem: Config.vc_signing_pem(config))

      conn
      |> put_resp_content_type(@signed_metadata_content_type)
      |> send_resp(200, signed)
    else
      json(conn, metadata)
    end
  end

  # OID4VCI §11.2.2: a wallet requests the signed representation by listing
  # `application/jwt` in the Accept header.
  defp wants_signed_metadata?(conn) do
    conn
    |> get_req_header("accept")
    |> Enum.any?(&String.contains?(&1, @signed_metadata_content_type))
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
