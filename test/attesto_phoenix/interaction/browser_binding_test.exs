defmodule AttestoPhoenix.Interaction.BrowserBindingTest do
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias AttestoPhoenix.Interaction.BrowserBinding

  test "creates a 256-bit session secret and preserves other session data" do
    conn = conn(:get, "/") |> init_test_session(subject: "user-42") |> bind()

    assert {:ok, bytes} = Base.url_decode64(BrowserBinding.binding(conn), padding: false)
    assert byte_size(bytes) == 32
    assert get_session(conn, :subject) == "user-42"
  end

  test "repeated calls retain the existing binding" do
    conn = conn(:get, "/") |> init_test_session(%{}) |> bind()
    binding = BrowserBinding.binding(conn)
    assert BrowserBinding.binding(bind(conn)) == binding
  end

  test "separate browser sessions get different secrets" do
    first = conn(:get, "/") |> init_test_session(%{}) |> bind()
    second = conn(:get, "/") |> init_test_session(%{}) |> bind()
    assert BrowserBinding.binding(first) != BrowserBinding.binding(second)
  end

  test "the callback only reads and returns nil before the plug runs" do
    conn = conn(:get, "/") |> init_test_session(%{})
    assert BrowserBinding.binding(conn) == nil
    assert get_session(conn) == %{}
  end

  test "requires a fetched session" do
    assert_raise ArgumentError, ~r/session not fetched/, fn -> bind(conn(:get, "/")) end
  end

  defp bind(conn), do: BrowserBinding.call(conn, BrowserBinding.init([]))
end
