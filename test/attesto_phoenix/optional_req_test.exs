defmodule AttestoPhoenix.OptionalReqTest do
  use ExUnit.Case, async: true

  test "bundled Req implementations compile when Req is available" do
    assert Code.ensure_loaded?(Elixir.Req)

    assert Code.ensure_loaded?(:"Elixir.AttestoPhoenix.BackChannelLogout.Req")
    assert Code.ensure_loaded?(:"Elixir.AttestoPhoenix.CIBAPing.Req")
    assert Code.ensure_loaded?(:"Elixir.AttestoPhoenix.ClientIdMetadata.Fetcher.Req")
  end
end
