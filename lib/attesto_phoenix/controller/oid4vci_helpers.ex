defmodule AttestoPhoenix.Controller.OID4VCIHelpers do
  @moduledoc false

  alias AttestoPhoenix.OAuthError
  alias Plug.Conn.Unfetched

  def maybe_put_option(opts, _key, nil), do: opts
  def maybe_put_option(opts, key, value), do: Keyword.put(opts, key, value)

  def body_params(%Plug.Conn{body_params: %Unfetched{}}, fallback), do: fallback
  def body_params(%Plug.Conn{body_params: body_params}, _fallback) when is_map(body_params), do: body_params

  def invalid_request(conn, config, error, description) do
    conn
    |> OAuthError.no_store(config)
    |> Plug.Conn.put_status(:bad_request)
    |> Phoenix.Controller.json(%{"error" => error, "error_description" => description})
  end
end
