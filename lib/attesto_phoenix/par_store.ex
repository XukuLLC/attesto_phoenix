defmodule AttestoPhoenix.PARStore do
  @moduledoc """
  Behaviour for Pushed Authorization Request storage (RFC 9126).

  The store keeps normalized authorization request parameters behind a PAR
  `request_uri` reference. Values are opaque maps because the authorization
  endpoint still runs the normal `Attesto.AuthorizationRequest` validation after
  the reference is resolved.

  The authorization endpoint uses `fetch/1`, not `take/1`, because host
  applications commonly establish login or consent and then re-enter the
  authorization endpoint with the same `request_uri`. Stores should expire
  entries by TTL; they should not consume them simply because the front channel
  was resolved. When `:require_pushed_authorization_requests` is enabled, the
  configured store must also implement atomic `take/1`; otherwise completion
  fails closed instead of issuing a code without a single-use claim.
  """

  @callback put(String.t(), map(), pos_integer()) :: :ok | {:error, term()}
  @callback fetch(String.t()) :: {:ok, map()} | :error
  @callback take(String.t()) :: {:ok, map()} | :error

  @optional_callbacks take: 1
end
