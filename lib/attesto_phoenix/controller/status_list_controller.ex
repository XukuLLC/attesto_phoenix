defmodule AttestoPhoenix.Controller.StatusListController do
  @moduledoc """
  IETF Token Status List endpoint.

  Serves a signed Status List Token for the status list identified by `:id`.
  The token is built fresh from the configured `Attesto.StatusListStore` on
  every request: allocation and status updates happen elsewhere (the host's
  credential-issuance and revocation flows), so this endpoint has no
  persistence of its own - it only packs, compresses, and signs whatever the
  store currently reports.
  """

  use Phoenix.Controller, formats: [:json]

  import Plug.Conn, only: [put_resp_header: 3, send_resp: 3]

  alias Attesto.StatusList
  alias AttestoPhoenix.{Config, OAuthError, RequestContext}

  @content_type "application/statuslist+jwt"

  # RFC-to-be "ttl" claim / advertised Cache-Control max-age: how long a
  # relying party may cache this Status List Token before re-fetching it.
  @cache_ttl_seconds 300

  @doc "Serve the signed Status List Token for the status list `:id`."
  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, %{"id" => id}) do
    config = Config.resolve!(conn)
    uri = Config.status_list_endpoint_url(config) <> "/" <> id

    with :ok <- check_https(conn, config),
         {:ok, store} <- status_list_store(config),
         [_ | _] = statuses <- store.statuses(uri) do
      token = StatusList.issue(config.keystore, uri, statuses, ttl: @cache_ttl_seconds)

      conn
      |> put_resp_header("content-type", @content_type)
      |> put_cache_control()
      |> send_resp(200, token)
    else
      :error -> send_resp(conn, 404, "")
      [] -> send_resp(conn, 404, "")
      {:error, %OAuthError{} = error} -> OAuthError.render(conn, error, config: config)
    end
  end

  defp check_https(conn, config) do
    case RequestContext.check_https(conn, config) do
      :ok -> :ok
      {:error, :insecure_transport} -> {:error, OAuthError.new(:invalid_request, "TLS required", status: 400)}
    end
  end

  defp status_list_store(config) do
    case Config.status_list_store(config) do
      store when is_atom(store) and not is_nil(store) -> {:ok, store}
      _ -> :error
    end
  end

  defp put_cache_control(conn) do
    put_resp_header(conn, "cache-control", "public, max-age=#{@cache_ttl_seconds}")
  end
end
