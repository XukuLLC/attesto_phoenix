defmodule AttestoPhoenix.Controller do
  @moduledoc false

  @doc false
  defmacro __using__(opts) do
    quote do
      use Phoenix.Controller, unquote(opts)

      alias AttestoPhoenix.{Config, DuplicateParameterGuard}

      def action(conn, options) do
        conn =
          case DuplicateParameterGuard.validate_and_forget(conn) do
            {:ok, conn} ->
              conn

            {:error, _reason, _conn} ->
              raise Plug.BadRequestError, message: "request contains an ambiguous parameter"
          end

        config = Config.resolve!(conn)

        Config.with_request_config(config, fn ->
          super(conn, options)
        end)
      end
    end
  end
end
