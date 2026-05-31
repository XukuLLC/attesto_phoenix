defmodule AttestoPhoenix.Plug.RequireScopes do
  @moduledoc """
  Phoenix alias for `Attesto.Plug.RequireScopes`.

  Scope authorization is protocol logic, so the implementation remains in the
  core `attesto` package and uses `Attesto.Scope` grant-form algebra. This
  module exists to give Phoenix routers a stable `AttestoPhoenix.Plug.*` surface
  alongside `AttestoPhoenix.Plug.Authenticate`.
  """

  @behaviour Plug

  alias Attesto.Plug.RequireScopes, as: CoreRequireScopes

  @impl Plug
  def init(scope) when is_binary(scope), do: CoreRequireScopes.init([scope])
  def init(opts), do: CoreRequireScopes.init(opts)

  @impl Plug
  def call(conn, opts), do: CoreRequireScopes.call(conn, opts)
end
