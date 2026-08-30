defmodule AttestoPhoenix.Controller.CredentialOfferController do
  @moduledoc """
  OID4VCI by-reference Credential Offer endpoint
  (`draft-ietf-oauth-openid4vci` §4.1.3).

  Serves the stored Credential Offer object a wallet dereferences from a
  `credential_offer_uri`. The offer is created and stored elsewhere - by the
  host, through `Attesto.CredentialOffer.store_by_reference/3`, which generates
  the unguessable id it embeds in the link - when it hands the wallet the offer
  link; this endpoint only serves the document back, non-consuming, until it
  expires or is unknown. Because the endpoint is unauthenticated and the offer
  may carry a redeemable `pre-authorized_code`, that generated id is the sole
  capability protecting it - hosts must not mint their own.
  """

  use Phoenix.Controller, formats: [:json]

  import Plug.Conn, only: [send_resp: 3]

  alias AttestoPhoenix.{Config, OAuthError, RequestContext}

  @doc "Serve the stored Credential Offer object for `:id`."
  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, %{"id" => id}) do
    config = Config.resolve!(conn)
    conn = OAuthError.no_store(conn, config)

    with :ok <- check_https(conn, config),
         {:ok, store} <- credential_offer_store(config),
         {:ok, offer} <- store.fetch(id) do
      json(conn, offer)
    else
      :error -> send_resp(conn, 404, "")
      {:error, %OAuthError{} = error} -> OAuthError.render(conn, error, config: config)
    end
  end

  defp check_https(conn, config) do
    case RequestContext.check_https(conn, config) do
      :ok -> :ok
      {:error, :insecure_transport} -> {:error, OAuthError.new(:invalid_request, "TLS required", status: 400)}
    end
  end

  defp credential_offer_store(config) do
    case Config.credential_offer_store(config) do
      store when is_atom(store) and not is_nil(store) -> {:ok, store}
      _ -> :error
    end
  end
end
