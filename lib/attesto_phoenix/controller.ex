defmodule AttestoPhoenix.Controller do
  @moduledoc false

  alias AttestoPhoenix.RequestContext

  @doc false
  @spec require_https(Plug.Conn.t(), AttestoPhoenix.Config.t(), term()) :: :ok | term()
  def require_https(conn, config, insecure_result) do
    case RequestContext.check_https(conn, config) do
      :ok -> :ok
      {:error, :insecure_transport} -> insecure_result
    end
  end

  @doc false
  defmacro __using__(opts) do
    quote do
      use Phoenix.Controller, unquote(opts)

      import AttestoPhoenix.Controller, only: [require_https: 3]

      alias AttestoPhoenix.{Config, DuplicateParameterGuard}

      def action(conn, options) do
        body_analysis_missing? = DuplicateParameterGuard.body_analysis_missing?(conn)

        conn =
          case DuplicateParameterGuard.validate_and_forget(conn) do
            {:ok, conn} ->
              conn

            {:error, _reason, _conn} ->
              raise Plug.BadRequestError, message: "request contains an ambiguous parameter"
          end

        config = Config.resolve!(conn)

        if body_analysis_missing? and Config.oauth_body_guard(config) == :required do
          raise Plug.BadRequestError, message: "request body validation is unavailable"
        end

        Config.with_request_config(config, fn ->
          super(conn, options)
        end)
      end
    end
  end
end
