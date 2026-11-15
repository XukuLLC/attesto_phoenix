if Code.ensure_loaded?(Req) do
  defmodule AttestoPhoenix.BackChannelLogout.Req do
    @moduledoc """
    Default `AttestoPhoenix.BackChannelLogout` deliverer, using a one-shot Mint
    connection to the SSRF-screened address.

    POSTs the `logout_token` to the Relying Party's `backchannel_logout_uri` as
    `application/x-www-form-urlencoded` (OpenID Connect Back-Channel Logout 1.0
    §2.5). Redirects and retries are disabled and the timeout is short: logout
    delivery is best-effort and must not let a slow or hostile RP stall the
    end-session response. A 2xx is success; anything else (non-2xx, transport
    error) is reported so the caller can log it.

    `Req` is an optional dependency. A host that enables Back-Channel Logout with
    the default deliverer must have `:req` available; one that supplies its own
    `logout: [http_client: ...]` does not.
    """

    @behaviour AttestoPhoenix.BackChannelLogout

    @impl AttestoPhoenix.BackChannelLogout
    @spec post(String.t(), String.t()) :: :ok | {:error, term()}
    def post(backchannel_logout_uri, logout_token) when is_binary(backchannel_logout_uri) and is_binary(logout_token) do
      AttestoPhoenix.PinnedDelivery.post(
        backchannel_logout_uri,
        [
          {"accept", "application/json"},
          {"content-type", "application/x-www-form-urlencoded"}
        ],
        URI.encode_query(%{"logout_token" => logout_token})
      )
    end
  end
end
