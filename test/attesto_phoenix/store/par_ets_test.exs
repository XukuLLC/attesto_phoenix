defmodule AttestoPhoenix.Store.PAR.ETSTest do
  use ExUnit.Case, async: false

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Store.PAR.ETS

  @table :attesto_phoenix_par_requests

  setup do
    if :ets.whereis(@table) != :undefined do
      :ets.delete_all_objects(@table)
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

  test "serializes concurrent admission at the configured live-entry limit" do
    config = request_config(par_max_entries: 10)

    results =
      1..100
      |> Task.async_stream(
        fn i ->
          Config.with_request_config(config, fn ->
            ETS.put("urn:ietf:params:oauth:request_uri:capacity-#{i}", %{"i" => i}, 60)
          end)
        end,
        max_concurrency: 50,
        timeout: 5_000
      )
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.count(results, &(&1 == :ok)) == 10
    assert Enum.count(results, &(&1 == {:error, :capacity})) == 90
    assert :ets.info(@table, :size) == 10
  end

  test "prunes expired entries before rejecting a new live entry" do
    config = request_config(par_max_entries: 1)

    Config.with_request_config(config, fn ->
      assert :ok = ETS.put("expired", %{"old" => true}, 60)
      true = :ets.insert(@table, {"expired", %{"old" => true}, System.system_time(:second) - 1})
      assert :ok = ETS.put("new", %{"new" => true}, 60)
    end)

    assert :error = ETS.fetch("expired")
    assert {:ok, %{"new" => true}} = ETS.fetch("new")
    assert :ets.info(@table, :size) == 1
  end

  test "rejects oversized records without retaining them" do
    config = request_config(par_max_record_bytes: 1)

    assert {:error, :record_too_large} =
             Config.with_request_config(config, fn -> ETS.put("large", %{"request" => "payload"}, 60) end)

    assert :ets.whereis(@table) == :undefined or :ets.info(@table, :size) == 0
  end

  test "does not overwrite an existing live request URI" do
    assert :ok = ETS.put("same", %{"value" => 1}, 60)
    assert {:error, :conflict} = ETS.put("same", %{"value" => 2}, 60)
    assert {:ok, %{"value" => 1}} = ETS.fetch("same")
  end

  test "take remains atomic with exactly one concurrent winner" do
    assert :ok = ETS.put("single-use", %{"value" => 1}, 60)

    results =
      1..50
      |> Task.async_stream(fn _ -> ETS.take("single-use") end, max_concurrency: 50, timeout: 5_000)
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.count(results, &(&1 == {:ok, %{"value" => 1}})) == 1
    assert Enum.count(results, &(&1 == :error)) == 49
  end

  defp request_config(overrides) do
    struct!(
      Config,
      Keyword.merge(
        [issuer: "https://issuer.example", keystore: __MODULE__.Keystore, repo: __MODULE__.Repo],
        overrides
      )
    )
  end
end
