defmodule AttestoPhoenix.Controller.PresentationRequestController do
  @moduledoc """
  Public OID4VP `request_uri` endpoint.

  A wallet dereferences the opaque presentation-session identifier to obtain
  the signed authorization request object created by `AttestoPhoenix.Verifier`.
  """

  use AttestoPhoenix.Controller, formats: [:json]

  import Plug.Conn, only: [put_resp_header: 3, send_resp: 3]

  alias Attesto.PresentationSession
  alias AttestoPhoenix.{Config, OAuthError, RequestContext}

  @request_object_content_type "application/oauth-authz-req+jwt"

  @doc "Serve a pending presentation session's signed request object."
  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, %{"id" => id}) do
    config = Config.resolve!(conn)
    conn = OAuthError.no_store(conn, config)

    with :ok <- check_https(conn, config),
         {:ok, store} <- presentation_session_store(config),
         {:ok, request_object} <- PresentationSession.request_object(store, id) do
      conn
      |> put_resp_header("content-type", @request_object_content_type)
      |> send_resp(200, request_object)
    else
      :error -> send_resp(conn, 404, "")
      {:error, %OAuthError{} = error} -> OAuthError.render(conn, error, config: config)
    end
  end

  defp check_https(conn, config) do
    case RequestContext.check_https(conn, config) do
      :ok -> :ok
      {:error, :insecure_transport} -> invalid_request()
    end
  end

  defp presentation_session_store(config) do
    case Config.presentation_session_store(config) do
      store when is_atom(store) and not is_nil(store) -> {:ok, store}
      _ -> invalid_request()
    end
  end

  defp invalid_request, do: {:error, OAuthError.new(:invalid_request, nil, status: 400)}
end
