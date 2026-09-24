defmodule AttestoPhoenix.EventSink do
  @moduledoc """
  The host-owned audit/telemetry contract.

  The library emits `%AttestoPhoenix.Event{}` structs at authorization-server
  milestones (token issuance, revocation, client registration, and so on) but
  never stores them itself. A host implements this behaviour and wires the
  callback into `AttestoPhoenix.Config` under `:on_event`; this module is the
  contract that key installs and the recommended production configuration. When the key
  is unset, event emission is a no-op.
  """

  @doc """
  Handle an authorization-server event. The return value does not alter the
  request path; an explicit `{:error, reason}` emits a fixed warning that does
  not include the reason or event payload. The host owns persistence, metrics,
  and logging. The callback must not raise on the request path (a failing audit
  sink should degrade, not break token issuance).

  Protected-resource `:auth_denied` events run before the 401 response is sent,
  including before a custom error transport. A host that needs durable denial
  records must commit the write before returning from this callback. An
  asynchronous enqueue or a surrounding transaction committed after the
  response does not provide that guarantee. Explicit errors remain visible as
  warnings and the request is refused; exceptions propagate without sending
  the authentication response.
  """
  @callback on_event(event :: AttestoPhoenix.Event.t()) :: any()
end
