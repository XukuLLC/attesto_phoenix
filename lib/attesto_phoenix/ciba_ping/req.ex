if Code.ensure_loaded?(Req) do
  defmodule AttestoPhoenix.CIBAPing.Req do
    @moduledoc """
    Default `AttestoPhoenix.CIBAPing` deliverer, built on `Req`.

    POSTs `{"auth_req_id": ...}` as `application/json` to the client's registered
    `backchannel_client_notification_endpoint` with
    `Authorization: Bearer <client_notification_token>` (OpenID Connect CIBA Core
    1.0 §10.2). Redirects and retries are disabled and the timeout is short:
    notification delivery is best-effort and must never let a slow or hostile
    client stall the OP - the tokens are already available at the token endpoint,
    and a client that misses the ping falls back to polling.

    A 2xx (200/204) is success; anything else (a non-2xx status - including the
    401/403 the suite's non-retry module returns, or a 3xx that must NOT be
    followed - or a transport error) is reported so the caller can log it and
    move on.

    `Req` is an optional dependency. A host that enables CIBA ping mode with the
    default deliverer must have `:req` available; one that supplies its own
    `ciba_ping_http_client: ...` does not.
    """

    @behaviour AttestoPhoenix.CIBAPing

    # Notification delivery is best-effort; keep a slow/hostile client from
    # stalling the OP (the tokens are already available at the token endpoint).
    @timeout_ms 5_000

    @impl AttestoPhoenix.CIBAPing
    @spec post(String.t(), String.t(), String.t()) :: :ok | {:error, term()}
    def post(endpoint, client_notification_token, auth_req_id)
        when is_binary(endpoint) and is_binary(client_notification_token) and is_binary(auth_req_id) do
      [
        url: endpoint,
        method: :post,
        json: %{auth_req_id: auth_req_id},
        headers: [
          {"authorization", "Bearer " <> client_notification_token},
          {"accept", "application/json"}
        ],
        # SSRF posture: a 3xx from the notification endpoint is a failure, never
        # followed. No retry on any status (including 401/403 - the flow outcome
        # is unaffected). The body is ignored.
        redirect: false,
        retry: false,
        receive_timeout: @timeout_ms,
        decode_body: false,
        # FAPI transport: the notification is a server-to-server FAPI channel, so
        # offer TLS 1.3 (FAPI 1.0 Advanced §8.5 / FAPI-CIBA), preferring it while
        # still allowing 1.2 for endpoints that don't yet support 1.3.
        connect_options: [transport_opts: [versions: [:"tlsv1.3", :"tlsv1.2"]]]
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
