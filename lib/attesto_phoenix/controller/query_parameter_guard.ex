defmodule AttestoPhoenix.Controller.QueryParameterGuard do
  @moduledoc false

  alias AttestoPhoenix.OAuthError

  @error_description "request parameters must be sent in the request body, not the query string"

  @doc "Reject query parameters on POST protocol endpoints whose parameters belong in the request body."
  @spec reject(Plug.Conn.t()) :: :ok | {:error, :query_parameters_not_allowed}
  def reject(%Plug.Conn{query_string: query_string}) when is_binary(query_string) and byte_size(query_string) == 0,
    do: :ok

  def reject(%Plug.Conn{}), do: {:error, :query_parameters_not_allowed}

  @doc false
  @spec error() :: OAuthError.t()
  def error, do: OAuthError.new(:invalid_request, @error_description, status: 400)
end
