defmodule AttestoPhoenix.PARStore do
  @moduledoc """
  Behaviour for Pushed Authorization Request storage (RFC 9126).

  The store keeps normalized authorization request parameters behind a
  one-time `request_uri` reference. Values are opaque maps because the
  authorization endpoint still runs the normal `Attesto.AuthorizationRequest`
  validation after the reference is resolved.
  """

  @callback put(String.t(), map(), pos_integer()) :: :ok | {:error, term()}
  @callback take(String.t()) :: {:ok, map()} | :error
end
