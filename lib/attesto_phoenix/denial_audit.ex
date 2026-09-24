defmodule AttestoPhoenix.DenialAudit do
  @moduledoc false

  import Plug.Conn

  alias AttestoPhoenix.{Callback, Event, RequestContext}

  # Compose after transport overrides have been resolved. The core's existing
  # send_error contract covers every 401, including nonce and step-up challenges.
  def wrap(opts, config) do
    transport = Keyword.get(opts, :send_error)
    Keyword.put(opts, :send_error, &send_error(&1, &2, &3, config, transport))
  end

  def emit(config, conn, result) do
    Event.emit(config, :auth_denied, %{
      result: result,
      metadata: %{
        method: conn.method,
        path: conn.request_path,
        client_ip: RequestContext.client_ip(conn, config)
      }
    })
  end

  def send_error(conn, status, body, config, transport) do
    if status == 401 and not is_nil(config), do: emit(config, conn, :invalid_token)
    send_response(conn, status, body, transport)
  end

  defp send_response(conn, status, body, transport) when is_function(transport, 3) or is_tuple(transport) do
    Callback.invoke(transport, [conn, status, body])
  end

  defp send_response(conn, status, body, _transport) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, JSON.encode!(body))
    |> halt()
  end
end
