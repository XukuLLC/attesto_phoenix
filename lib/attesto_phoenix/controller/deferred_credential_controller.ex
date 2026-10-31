defmodule AttestoPhoenix.Controller.DeferredCredentialController do
  @moduledoc """
  OID4VCI Deferred Credential Endpoint (`draft-ietf-oauth-openid4vci` §9).

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

  import AttestoPhoenix.Controller.OID4VCIHelpers, only: [body_params: 2, invalid_request: 4]

  alias AttestoPhoenix.{Config, CredentialIssuer, ProtectedResource}
  alias AttestoPhoenix.OAuthError, as: PhoenixOAuthError

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

    case ProtectedResource.authenticate(conn, config, resource_metadata) do
      {:ok, conn, claims} ->
        respond(conn, config, body_params(conn, params), claims)

      {:halt, conn} ->
        conn
    end
  end

  defp respond(conn, config, request, claims) do
    case CredentialIssuer.issue_deferred_request(config, claims, request) do
      {:ok, response} ->
        conn
        |> PhoenixOAuthError.no_store(config)
        |> json(response)

      {:error, error_code, description} ->
        invalid_request(conn, config, error_code, description)
    end
  end
end
