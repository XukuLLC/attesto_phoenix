if Code.ensure_loaded?(Req) do
  defmodule AttestoPhoenix.BackChannelLogout.Req do
    @moduledoc """
    Default `AttestoPhoenix.BackChannelLogout` deliverer, built on `Req`.

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

    # Logout delivery is best-effort; keep the RP from stalling the user's logout.
    @timeout_ms 5_000

    @impl AttestoPhoenix.BackChannelLogout
    @spec post(String.t(), String.t()) :: :ok | {:error, term()}
    def post(backchannel_logout_uri, logout_token) when is_binary(backchannel_logout_uri) and is_binary(logout_token) do
      [
        url: backchannel_logout_uri,
        method: :post,
        form: [logout_token: logout_token],
        headers: [{"accept", "application/json"}],
        redirect: false,
        retry: false,
        receive_timeout: @timeout_ms,
        decode_body: false
      ]
      |> Req.new()
      |> Req.request()
      |> case do
        {:ok, %Req.Response{status: status}} when status in 200..299 -> :ok
        {:ok, %Req.Response{status: status}} -> {:error, {:status, status}}
        {:error, reason} -> {:error, reason}
      end
    end
  end
end
