defmodule AttestoPhoenix.Store.PAR.ETSTest do
  use ExUnit.Case, async: false

  alias AttestoPhoenix.Store.PAR.ETS

  @table :attesto_phoenix_par_requests

  setup do
    if :ets.whereis(@table) != :undefined do
      :ets.delete(@table)
    end

    :ok
  end

  test "concurrent first writes tolerate table creation races" do
    results =
      1..200
      |> Task.async_stream(
        fn i ->
          ETS.put("urn:ietf:params:oauth:request_uri:#{i}", %{"i" => i}, 60)
        end,
        max_concurrency: 50,
        timeout: 5_000
      )
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.uniq(results) == [:ok]
  end
end
