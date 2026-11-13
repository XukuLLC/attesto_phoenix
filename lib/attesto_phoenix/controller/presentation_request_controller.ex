defmodule AttestoPhoenix.Controller.PresentationRequestController do
  @moduledoc """
  Public OID4VP `request_uri` endpoint.

  A wallet dereferences the opaque presentation-session identifier to obtain
  the signed authorization request object created by `AttestoPhoenix.Verifier`.
  For a DC API session, the page receives JSON containing `protocol` and
  `data.request` (OpenID4VP 1.0 §A.1 and §A.3.2.1). Redirect sessions retain
  their `application/oauth-authz-req+jwt` response.
  """

  use AttestoPhoenix.Controller, formats: [:json]

  import Plug.Conn, only: [put_resp_header: 3, send_resp: 3]

  alias AttestoPhoenix.{Config, OAuthError, Verifier}

  @request_object_content_type "application/oauth-authz-req+jwt"

  @doc "Serve a pending presentation session's signed request object."
  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, %{"id" => id}) do
    config = Config.resolve!(conn)
    conn = OAuthError.no_store(conn, config)

    with :ok <- require_https(conn, config, invalid_request()),
         {:ok, _store} <- presentation_session_store(config),
         {:ok, flow, request} <- Verifier.presentation_request(config, id) do
      case flow do
        :dc_api ->
          json(conn, request)

        :redirect ->
          conn
          |> put_resp_header("content-type", @request_object_content_type)
          |> send_resp(200, request)
      end
    else
      :error -> send_resp(conn, 404, "")
      {:error, %OAuthError{} = error} -> OAuthError.render(conn, error, config: config)
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
