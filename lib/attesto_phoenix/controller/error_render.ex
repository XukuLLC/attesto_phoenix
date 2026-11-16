defmodule AttestoPhoenix.Controller.ErrorRender do
  @moduledoc false

  import Plug.Conn

  alias AttestoPhoenix.{Callback, HTTPAccept}

  require Logger

  @spec invoke_hook(Plug.Conn.t(), term(), term(), (Plug.Conn.t() -> Plug.Conn.t()), String.t()) :: Plug.Conn.t()
  def invoke_hook(conn, callback, error, fallback_fun, failure_message)
      when is_function(fallback_fun, 1) and is_binary(failure_message) do
    case Callback.invoke(callback, [conn, error]) do
      %Plug.Conn{state: state} = rendered when state in [:sent, :chunked, :file] ->
        rendered

      _not_a_sent_conn ->
        Logger.error("error renderer did not return a sent connection", detail: failure_message)
        fallback_fun.(conn)
    end
  end

  @spec negotiated(Plug.Conn.t(), Plug.Conn.status(), String.t(), term()) :: Plug.Conn.t()
  def negotiated(conn, status, html, json_body) do
    if HTTPAccept.accepts?(get_req_header(conn, "accept"), "text/html") do
      conn
      |> put_resp_content_type("text/html")
      |> send_resp(status, html)
    else
      conn
      |> put_resp_content_type("application/json")
      |> send_resp(status, JSON.encode!(json_body))
    end
  end
end
