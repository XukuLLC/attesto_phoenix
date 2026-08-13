defmodule AttestoPhoenix.Controller.DeferredCredentialController do
  @moduledoc """
  OID4VCI Deferred Credential Endpoint (`draft-ietf-oauth-openid4vci` §9).

  Completes a credential whose issuance was deferred at the Credential
  endpoint. The wallet polls this endpoint with the same access token and the
  `transaction_id` it was given at deferral. The library owns access-token
  verification (RFC 6750 bearer / RFC 9449 DPoP via
  `AttestoPhoenix.ProtectedResource`) and SD-JWT VC signing/response framing,
  and passes the token's verified `subject` to the host callback.

  Issuance completion is host policy through `:build_deferred_credential`.
  Bearer auth alone is NOT sufficient authorization here: it proves the caller
  holds *some* valid token, not that the `transaction_id` is theirs. The host
  callback MUST bind the `transaction_id` to that `subject` and refuse a
  mismatch — otherwise any authenticated wallet can poll another's
  `transaction_id` and receive its credential (IDOR). See
  `t:AttestoPhoenix.Config`'s `:build_deferred_credential` for the contract.
  """

  use Phoenix.Controller, formats: [:json]

  import AttestoPhoenix.Controller.OID4VCIHelpers,
    only: [body_params: 2, invalid_request: 4, maybe_put_option: 3]

  alias Attesto.{CredentialResponse, SdJwtVc}
  alias AttestoPhoenix.{Config, ProtectedResource}
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
    config = Config.resolve!()
    resource_metadata = Config.resource_metadata_url(config, conn)

    case ProtectedResource.authenticate(conn, config, resource_metadata) do
      {:ok, conn, claims} ->
        issue(conn, config, body_params(conn, params), claims)

      {:halt, conn} ->
        conn
    end
  end

  defp issue(conn, config, request, claims) do
    with {:ok, transaction_id} <- transaction_id(request),
         {:ok, result} <- Config.build_deferred_credential(config, claims["sub"], transaction_id),
         {:ok, credential} <- issue_credential(config, result) do
      conn
      |> PhoenixOAuthError.no_store(config)
      |> json(CredentialResponse.build(credential))
    else
      {:error, :missing_transaction_id} ->
        invalid_request(conn, config, "invalid_credential_request", "transaction_id is required")

      {:error, :issuance_pending} ->
        invalid_request(conn, config, "issuance_pending", "The credential is not yet ready.")

      {:error, _reason} ->
        invalid_request(conn, config, "invalid_credential_request", "credential unavailable")
    end
  end

  defp transaction_id(%{"transaction_id" => id}) when is_binary(id) and id != "", do: {:ok, id}
  defp transaction_id(_request), do: {:error, :missing_transaction_id}

  defp issue_credential(config, %{vct: vct, claims: claims} = result) do
    {:ok,
     SdJwtVc.issue(
       [
         iss: config.issuer,
         vct: vct,
         keystore: Config.vc_keystore(config)
       ],
       [claims: claims]
       |> maybe_put_option(:exp, Map.get(result, :valid_until))
       |> maybe_put_option(:nbf, Map.get(result, :valid_from))
     )}
  end

  defp issue_credential(_config, _result), do: {:error, :invalid_credential}
end
