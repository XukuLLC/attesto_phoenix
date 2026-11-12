defmodule AttestoPhoenix.ScopePolicy do
  @moduledoc """
  The host-owned scope-authorization contract (RFC 6749 §3.3).

  The library performs the scope algebra (`Attesto.Scope`), but which scopes a
  given client may be granted is host policy. A host implements this behaviour
  and wires the callback into `AttestoPhoenix.Config` under `:authorize_scope`;
  this module is the contract that key installs and the recommended production
  interface. When the key is unset, the library requires every requested scope
  to appear in the effective authorization-server scope catalog.

  A module implements `authorize_scope/2`, `authorize_scope/3`, or both; the
  three-argument form is used when present.
  """

  @doc """
  Validate and narrow a requested scope for a client (RFC 6749 §3.3).

  Returns `{:ok, granted_scope}` with the (possibly narrowed) scope to issue,
  or `{:error, :invalid_scope}` (RFC 6749 §5.2) to reject. `requested_scope`
  is the list of requested scope strings.
  """
  @callback authorize_scope(client :: term(), requested_scope :: [String.t()]) ::
              {:ok, [String.t()]} | {:error, :invalid_scope}

  @doc """
  The same decision with the request's resolved RFC 8707 resource indicators.

  Optional, and preferred over `authorize_scope/2` when a module exports it; a
  module may export this form alone. `resources` is the list of resource
  indicators the request resolved to (empty when it named none). The policy
  runs at the authorization endpoint and at the token endpoint with the same
  arguments.

  Returns `{:ok, granted_scope}`, `{:error, :invalid_scope}`, or
  `{:error, :invalid_target}` when the refusal is about a resource, or about
  the combination of a resource and a scope (RFC 8707 §2, §2.1). A refusal
  that names no resource is `:invalid_scope`.
  """
  @callback authorize_scope(client :: term(), requested_scope :: [String.t()], resources :: [String.t()]) ::
              {:ok, [String.t()]} | {:error, :invalid_scope | :invalid_target}

  @optional_callbacks authorize_scope: 2, authorize_scope: 3
end
