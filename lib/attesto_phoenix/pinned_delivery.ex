if Code.ensure_loaded?(Req) do
  defmodule AttestoPhoenix.PinnedDelivery do
    @moduledoc false

    # Best-effort outbound notifications (CIBA ping, Back-Channel Logout) keep
    # a slow or hostile peer from stalling the authorization server.
    @timeout_ms 5_000

    @spec post(String.t(), [{String.t(), String.t()}], String.t()) :: :ok | {:error, term()}
    def post(url, headers, body) when is_binary(url) and is_list(headers) and is_binary(body) do
      screen_opts = [allow_loopback: Application.get_env(:attesto_phoenix, :allow_loopback_delivery, false)]

      with {:ok, %{url: pinned_url, host: host, authority: authority}} <-
             AttestoPhoenix.SSRFGuard.screen(url, screen_opts) do
        Attesto.PinnedHTTP.request(
          :post,
          pinned_url,
          host,
          [{"host", authority} | headers],
          body,
          @timeout_ms,
          :discard
        )
        |> case do
          {:ok, %{status: status}} when status in 200..299 -> :ok
          {:ok, %{status: status}} -> {:error, {:status, status}}
          {:error, reason} -> {:error, reason}
        end
      end
    end
  end
end
