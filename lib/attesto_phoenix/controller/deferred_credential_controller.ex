defmodule AttestoPhoenix.Controller.DeferredCredentialController do
  @moduledoc """
  OID4VCI Deferred Credential Endpoint (`OpenID4VCI 1.0`, 2025-09-16, §9).

  Completes a credential whose issuance was deferred at the Credential
  endpoint. The wallet polls this endpoint with the same access token and the
  `transaction_id` it was given at deferral. This controller owns the HTTP
  framing (`ProtectedResource.authenticate/3`, `no-store` cache headers, and
  error rendering) and delegates deferred builder invocation, entitlement
  checking, and format-specific signing to the library's internal credential
  issuer.

  Issuance completion is host policy through `:build_deferred_credential`.
  Bearer auth alone is NOT sufficient authorization here: it proves the caller
  holds *some* valid token, not that the `transaction_id` is theirs. The host
  callback MUST bind the `transaction_id` to that `subject` and refuse a
  mismatch — otherwise any authenticated wallet can poll another's
  `transaction_id` and receive its credential (IDOR). See
  `t:AttestoPhoenix.Config`'s `:build_deferred_credential` for the contract.
  The callback must also return the credential configuration ID and public
  holder JWK persisted from the original proof. Results without that binding
  state fail closed; the deferred request carries no new holder proof from
  which the library could reconstruct it.
  """

  use AttestoPhoenix.Controller, formats: [:json]

  import AttestoPhoenix.Controller.OID4VCIHelpers,
    only: [invalid_request: 4, read_credential_request: 3, send_credential_response: 4]

  alias AttestoPhoenix.{Config, CredentialIssuer, ProtectedResource, RequestContext}

  @doc """
  Complete a deferred credential for an authenticated wallet.

  Returns the same immediate-issuance response shape as the Credential
  endpoint (`Attesto.CredentialResponse.build/2`) once the host reports the
  credential is ready. `{:error, :issuance_pending}` from the host's
  `:build_deferred_credential` callback is reported as the OID4VCI
  `issuance_pending` error (status 400) so the wallet retries later; any
  other host error maps to `invalid_credential_request`.
  """
  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, params) do
    config = Config.resolve!(conn)
    resource_metadata = Config.resource_metadata_url(config, conn)

    htu_override = [
      htu: fn req_conn ->
        RequestContext.canonical_url(
          req_conn,
          config,
          Config.deferred_credential_endpoint_url(config),
          "deferred_credential_endpoint"
        )
      end
    ]

    case ProtectedResource.authenticate(conn, config, resource_metadata, core_overrides: htu_override) do
      {:ok, conn, claims} ->
        respond(conn, params, config, claims)

      {:halt, conn} ->
        conn
    end
  end

  defp respond(conn, params, config, claims) do
    with {:ok, request, encrypted_request?, conn} <- read_credential_request(conn, params, config),
         {:ok, response, response_encryption} <-
           CredentialIssuer.issue_deferred_request(config, claims, request, encrypted_request?: encrypted_request?) do
      send_credential_response(conn, config, response, response_encryption)
    else
      {:error, error_code, description} ->
        invalid_request(conn, config, error_code, description)
    end
  end
end
