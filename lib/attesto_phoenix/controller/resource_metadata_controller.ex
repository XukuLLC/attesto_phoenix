defmodule AttestoPhoenix.Controller.ResourceMetadataController do
  @moduledoc "Serves the per-resource documents mounted by `AttestoPhoenix.Router`."
  use Phoenix.Controller, formats: [:json]

  alias Attesto.Plug.ResourceMetadata
  alias AttestoPhoenix.Plug.CORS

  @doc "Serve the RFC 9728 document selected by the route."
  def show(conn, _params) do
    opts = Map.get(conn.private, :attesto_resource_metadata_opts, [])
    path = Map.fetch!(conn.private, :attesto_resource_path)

    conn
    |> CORS.apply_headers(cors_opts(conn))
    |> ResourceMetadata.call(Keyword.put(opts, :resource_path, path))
  end

  @doc "Answer the CORS preflight request for a resource document."
  def preflight(conn, _params), do: CORS.preflight(conn, cors_opts(conn))

  # The route's own `:cors_origins` wins; otherwise `AttestoPhoenix.Plug.CORS`
  # falls back to the request's AttestoPhoenix config and then to `:*`, the
  # policy the root protected-resource document is served under.
  defp cors_opts(conn) do
    case Map.get(conn.private, :attesto_resource_cors_origins) do
      nil -> []
      policy -> [origins: policy]
    end
  end
end
