defmodule AttestoPhoenix.ScopePolicy do
  @moduledoc """
  The host-owned scope-authorization contract (RFC 6749 §3.3).

  The library performs the scope algebra (`Attesto.Scope`), but which scopes a
  given client may be granted is host policy. A host implements this behaviour
  and wires the callback into `AttestoPhoenix.Config` under `:authorize_scope`;
  this module is the contract that key installs and the recommended production
  interface. When the key is unset, the library requires every requested scope
  to appear in the effective authorization-server scope catalog.
  """

  @doc """
  Validate and narrow a requested scope for a client (RFC 6749 §3.3).

  Returns `{:ok, granted_scope}` with the (possibly narrowed) scope to issue,
  or `{:error, :invalid_scope}` (RFC 6749 §5.2) to reject. `requested_scope`
  is the list of requested scope strings.
  """
  @callback authorize_scope(client :: term(), requested_scope :: [String.t()]) ::
              {:ok, [String.t()]} | {:error, :invalid_scope}
end
