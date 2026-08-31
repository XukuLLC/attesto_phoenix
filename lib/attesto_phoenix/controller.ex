defmodule AttestoPhoenix.Controller do
  @moduledoc false

  @doc false
  defmacro __using__(opts) do
    quote do
      use Phoenix.Controller, unquote(opts)

      alias AttestoPhoenix.Config

      def action(conn, options) do
        config = Config.resolve!(conn)

        Config.with_request_config(config, fn ->
          super(conn, options)
        end)
      end
    end
  end
end
