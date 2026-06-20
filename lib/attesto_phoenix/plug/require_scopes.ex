defmodule AttestoPhoenix.Plug.RequireScopes do
  @moduledoc """
  Phoenix alias for `Attesto.Plug.RequireScopes`.

  Scope authorization is protocol logic, so the implementation remains in the
  core `attesto` package and uses `Attesto.Scope` grant-form algebra. This
  module exists to give Phoenix routers a stable `AttestoPhoenix.Plug.*` surface
  alongside `AttestoPhoenix.Plug.Authenticate`.

  ## RFC 9728 `resource_metadata` on the 403

  Unlike `AttestoPhoenix.Plug.Authenticate` (which sources the
  `resource_metadata` pointer from `AttestoPhoenix.Config`), this plug is a thin,
  config-independent protocol alias so it stays usable in a resource-server-only
  deployment with no host config. Its `insufficient_scope` (403) challenge
  therefore omits the pointer unless one is passed explicitly:

      plug AttestoPhoenix.Plug.RequireScopes,
        scopes: ["read:reports"],
        resource_metadata: "https://api.example/.well-known/oauth-protected-resource"

  This is intentional, not a discovery gap: a 403 is only reached *after* the
  request authenticated, so the client already received the pointer on the
  initial unauthenticated 401 from `Authenticate`, and RFC 9728 §5.1 makes the
  `resource_metadata` auth-param OPTIONAL on a challenge.
  """

  @behaviour Plug

  alias Attesto.Plug.RequireScopes, as: CoreRequireScopes

  @impl Plug
  def init(scope) when is_binary(scope), do: CoreRequireScopes.init([scope])
  def init(opts), do: CoreRequireScopes.init(opts)

  @impl Plug
  def call(conn, opts), do: CoreRequireScopes.call(conn, opts)
end
