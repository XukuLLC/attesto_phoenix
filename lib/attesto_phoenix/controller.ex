defmodule AttestoPhoenix.Controller do
  @moduledoc false

  alias AttestoPhoenix.{AuthorizationRefusal, Config, DuplicateParameterGuard, RequestContext}
  alias AttestoPhoenix.Controller.AuthorizeController

  @doc false
  @spec require_https(Plug.Conn.t(), AttestoPhoenix.Config.t(), term()) :: :ok | term()
  def require_https(conn, config, insecure_result) do
    case RequestContext.check_https(conn, config) do
      :ok -> :ok
      {:error, :insecure_transport} -> insecure_result
    end
  end

  @doc false
  def validate_request!(conn, controller) do
    missing? = DuplicateParameterGuard.body_analysis_missing?(conn)

    case DuplicateParameterGuard.validate_and_forget(conn) do
      {:error, reason, conn} ->
        refuse!(conn, controller, reason, "request contains an ambiguous parameter")

      {:ok, conn} ->
        cond do
          missing? ->
            refuse!(
              conn,
              controller,
              :missing_body_analysis,
              "request body validation is unavailable; install AttestoPhoenix.DuplicateParameterGuard.read_body/2 as the endpoint body reader"
            )

          controller == AuthorizeController and conn.method == "POST" and conn.query_string != "" ->
            refuse!(conn, controller, :query_on_post, "authorization POST requests must not contain query parameters")

          true ->
            conn
        end
    end
  end

  defp refuse!(conn, controller, reason, message) do
    if controller == AuthorizeController do
      AuthorizationRefusal.emit(conn, Config.resolve!(conn), "invalid_request", reason)
    end

    raise Plug.BadRequestError, message: message
  end

  @doc false
  defmacro __using__(opts) do
    {cors?, controller_opts} = Keyword.pop(opts, :cors, true)

    apply_cors_ast =
      if cors? do
        quote(do: conn = CORS.apply_headers(conn))
      end

    quote do
      use Phoenix.Controller, unquote(controller_opts)

      import AttestoPhoenix.Controller, only: [require_https: 3]

      alias AttestoPhoenix.Config
      alias AttestoPhoenix.Plug.CORS

      def action(conn, options) do
        conn = AttestoPhoenix.Controller.validate_request!(conn, __MODULE__)
        config = Config.resolve!(conn)

        unquote(apply_cors_ast)

        Config.with_request_config(config, fn ->
          super(conn, options)
        end)
      end
    end
  end
end
