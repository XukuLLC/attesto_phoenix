defmodule AttestoPhoenix.Controller.NonceController do
  @moduledoc """
  OID4VCI c_nonce endpoint (`draft-ietf-oauth-openid4vci` §7).

  Issues a fresh, short-lived c_nonce from the configured store. The endpoint
  is intentionally unauthenticated: the nonce is a freshness challenge that a
  wallet presents later in its credential proof.
  """

  use Phoenix.Controller, formats: [:json]

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.OAuthError
  alias AttestoPhoenix.RequestContext

  @default_nonce_ttl_seconds 300

  @doc "Issue a fresh c_nonce for a wallet credential proof."
  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, _params) do
    config = Config.resolve!()
    conn = OAuthError.no_store(conn, config)

    with :ok <- check_https(conn, config),
         {:ok, store} <- c_nonce_store(config),
         {:ok, nonce} <- issue_nonce(store) do
      json(conn, %{"c_nonce" => nonce})
    else
      {:error, %OAuthError{} = error} -> OAuthError.render(conn, error, config: config)
    end
  end

  defp check_https(conn, config) do
    case RequestContext.check_https(conn, config) do
      :ok -> :ok
      {:error, :insecure_transport} -> {:error, OAuthError.new(:invalid_request, "TLS required", status: 400)}
    end
  end

  defp c_nonce_store(config) do
    case Config.c_nonce_store(config) do
      store when is_atom(store) -> {:ok, store}
      _ -> {:error, OAuthError.new(:invalid_request, "c_nonce_store is required", status: 400)}
    end
  end

  defp issue_nonce(store) do
    cond do
      function_exported?(store, :issue, 0) ->
        {:ok, store.issue()}

      function_exported?(store, :issue, 1) ->
        {:ok, store.issue(@default_nonce_ttl_seconds)}

      true ->
        {:error, OAuthError.new(:invalid_request, "c_nonce_store does not support issuing nonces", status: 400)}
    end
  end
end
