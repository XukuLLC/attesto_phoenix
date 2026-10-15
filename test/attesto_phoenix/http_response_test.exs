defmodule AttestoPhoenix.HTTPResponseTest do
  use ExUnit.Case, async: true

  alias AttestoPhoenix.HTTPResponse

  test "discard collector halts without retaining an ignored response chunk" do
    collector = HTTPResponse.discard_body_collector()
    response = %{body: nil, status: 200}
    chunk = String.duplicate("x", 8_000_000)

    assert {:halt, {:request, %{body: "", status: 200}}} =
             collector.({:data, chunk}, {:request, response})
  end
end
