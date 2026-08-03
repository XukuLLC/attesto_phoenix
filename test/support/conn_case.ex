defmodule AttestoPhoenix.ConnCase do
  @moduledoc false

  use ExUnit.CaseTemplate

  using opts do
    endpoint = Keyword.fetch!(opts, :endpoint)

    quote do
      import Phoenix.ConnTest
      import Plug.Conn

      @endpoint unquote(endpoint)
    end
  end

  setup do
    {:ok, conn: Phoenix.ConnTest.build_conn()}
  end
end
