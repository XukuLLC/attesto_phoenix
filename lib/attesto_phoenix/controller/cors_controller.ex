defmodule AttestoPhoenix.Controller.CORSController do
  @moduledoc false

  use AttestoPhoenix.Controller, cors: false, formats: [:json]

  alias AttestoPhoenix.Plug.CORS

  @spec preflight(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def preflight(conn, _params) do
    CORS.preflight(conn)
  end
end
