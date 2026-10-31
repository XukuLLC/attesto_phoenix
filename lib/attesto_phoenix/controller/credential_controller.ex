defmodule AttestoPhoenix.Controller.CredentialController do
  @moduledoc """
  OID4VCI Credential Endpoint (`draft-ietf-oauth-openid4vci` §8.2).

  This endpoint authenticates the access token, delegates request validation,
  entitlement checking, holder-key proof verification, `c_nonce` consumption,
  and format-specific credential issuance to the library's internal credential
  issuer, and renders the HTTP response or `WWW-Authenticate` challenge.

  For SD-JWT VC and mdoc issuance, a successful `:build_credential` result may
  include `:issued_at`, an integer NumericDate copied to the signed `iat` claim
  or MSO `validityInfo.signed`, respectively. The default remains the current
  time. Hosts can round issuance timestamps under
  RFC 9901 §10.1 to reduce correlation; an explicitly supplied invalid value
  denies issuance instead of signing an invalid credential.
  """

  use AttestoPhoenix.Controller, formats: [:json]

  import AttestoPhoenix.Controller.OID4VCIHelpers, only: [body_params: 2, invalid_request: 4]
  import Plug.Conn

  alias AttestoPhoenix.Callback
  alias AttestoPhoenix.{Config, CredentialIssuer, ProtectedResource}
  alias AttestoPhoenix.OAuthError, as: PhoenixOAuthError

  @doc """
  Issue the credential(s) requested by an authenticated wallet.

  The action accepts either the single `proof` form or the batch `proofs`
  form; each holder-key proof yields its own holder-bound credential in the
  response. Every proof must verify (fresh c_nonce, correct audience, valid
  signature) or the whole request fails with the same `invalid_proof` error,
  regardless of which proof or how many failed. Credential identifiers and any
  other proof or request failure are returned as the OID4VCI JSON error
  envelope with status 400.
  """
  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, params) do
    config = Config.resolve!(conn)
    resource_metadata = Config.resource_metadata_url(config, conn)

    case ProtectedResource.authenticate(conn, config, resource_metadata) do
      {:ok, conn, claims} ->
        respond(conn, config, body_params(conn, params), resource_metadata, claims)

      {:halt, conn} ->
        conn
    end
  end

  defp respond(conn, config, request, resource_metadata, claims) do
    case CredentialIssuer.issue_request(config, claims, request) do
      {:ok, response} ->
        conn
        |> PhoenixOAuthError.no_store(config)
        |> json(response)

      {:error, :not_entitled} ->
        not_entitled(conn, config, claims, resource_metadata)

      {:error, error_code, description} ->
        invalid_request(conn, config, error_code, description)
    end
  end

  defp not_entitled(conn, config, claims, resource_metadata) do
    description = "The access token does not authorize this credential."
    scheme = ProtectedResource.scheme_of(claims)

    challenge =
      PhoenixOAuthError.format_challenge(
        scheme,
        [{"error", "insufficient_scope"}, {"error_description", description}] ++
          resource_metadata_param(resource_metadata)
      )

    body = %{"error" => "insufficient_scope", "error_description" => description}

    conn
    |> PhoenixOAuthError.no_store(config)
    |> apply_www_authenticate(config, challenge)
    |> send_scope_error(config, body)
  end

  defp apply_www_authenticate(conn, %Config{www_authenticate: nil}, challenge),
    do: put_resp_header(conn, "www-authenticate", challenge)

  defp apply_www_authenticate(conn, %Config{www_authenticate: callback}, challenge),
    do: Callback.invoke(callback, [conn, challenge])

  defp send_scope_error(conn, %Config{send_error: nil}, body) do
    conn
    |> put_status(:forbidden)
    |> json(body)
  end

  defp send_scope_error(conn, %Config{send_error: callback}, body), do: Callback.invoke(callback, [conn, 403, body])

  defp resource_metadata_param(url) when is_binary(url), do: [{"resource_metadata", url}]
  defp resource_metadata_param(_url), do: []
end
