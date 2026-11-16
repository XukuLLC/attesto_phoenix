defmodule AttestoPhoenix.Controller.CORSController do
  @moduledoc false

  use AttestoPhoenix.Controller, cors: false, formats: [:json]

  alias AttestoPhoenix.Plug.CORS

  defoverridable action: 2

  def action(conn, options) do
    conn = CORS.reject_disabled_preflight(conn)
    if conn.halted, do: conn, else: super(conn, options)
  end

  @spec preflight(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def preflight(conn, _params) do
    CORS.preflight(conn)
  end
end
