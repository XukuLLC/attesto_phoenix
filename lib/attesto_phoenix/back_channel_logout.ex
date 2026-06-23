defmodule AttestoPhoenix.BackChannelLogout do
  @moduledoc """
  The seam for delivering a Back-Channel Logout `logout_token` to a Relying
  Party (OpenID Connect Back-Channel Logout 1.0 §2.5).

  An implementation POSTs the token to the RP's `backchannel_logout_uri` as
  `application/x-www-form-urlencoded` with a single `logout_token` parameter,
  and reports whether the RP accepted it. Delivery is best-effort by design:
  the end-session endpoint logs failures but never blocks the user's logout on
  an unreachable RP. The default implementation is
  `AttestoPhoenix.BackChannelLogout.Req`; a host overrides it with
  `logout: [http_client: MyDeliverer]`.
  """

  @doc """
  POST `logout_token` to `backchannel_logout_uri`. Returns `:ok` when the RP
  responded with a 2xx, `{:error, reason}` otherwise.
  """
  @callback post(backchannel_logout_uri :: String.t(), logout_token :: String.t()) ::
              :ok | {:error, term()}
end
