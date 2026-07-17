defmodule AttestoPhoenix.CIBAPing do
  @moduledoc """
  The seam for delivering a CIBA ping-mode notification to a client
  (OpenID Connect CIBA Core 1.0 §10.2).

  When a `ping`-mode authentication request reaches a terminal decision
  (approval OR denial - §10.2 fires on both), the OP notifies the client by
  POSTing to its registered `backchannel_client_notification_endpoint` with
  `Authorization: Bearer <client_notification_token>` and the JSON body
  `{"auth_req_id": ...}`. The client then redeems the tokens at the token
  endpoint exactly as a poll-mode client would; the ping only spares it the
  polling.

  Delivery is best-effort by design (mirroring
  `AttestoPhoenix.BackChannelLogout`): the token stays available at the token
  endpoint whether or not the notification lands, so a client that misses the
  ping simply falls back to polling (§10.2 treats a ping client that polls as a
  poll client). The default implementation is `AttestoPhoenix.CIBAPing.Req`; a
  host overrides it with `ciba_ping_http_client: MyDeliverer`.

  ## Conformance-locked semantics (fapi-ciba-id1 ping modules)

  The delivery MUST NOT follow redirects (a 3xx from the notification endpoint
  is a failure, never followed - SSRF posture), MUST NOT retry on a 401/403
  (the flow outcome is unaffected; the tokens stay available), and MUST ignore
  the response body. These are asserted by the suite's
  `FAPICIBAID1PingNotificationEndpointReturnsRedirectRequest`,
  `...Returns401AndRequireServerDoesNotRetry`, and `...ReturnsABody` modules.
  """

  @doc """
  POST the CIBA ping notification to `endpoint`, carrying
  `client_notification_token` as a bearer credential and `auth_req_id` in the
  JSON body. Returns `:ok` when the client responded with a 2xx,
  `{:error, reason}` otherwise.
  """
  @callback post(
              endpoint :: String.t(),
              client_notification_token :: String.t(),
              auth_req_id :: String.t()
            ) :: :ok | {:error, term()}
end
