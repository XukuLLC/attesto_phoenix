defmodule AttestoPhoenix.Store.ETSOwnerLifecycleTest do
  @moduledoc false
  # The ETS-backed stores keep their table in a singleton owner process started
  # lazily by whichever caller touches the store first. In a running server that
  # caller is an ordinary request process.
  #
  # If the owner were LINKED to it, an abnormal exit in that request - an
  # unhandled exception, a timeout, a shutdown - would propagate and kill the
  # owner, destroying the table. For the CIMD cache that silently empties a
  # cache; for the PAR store, which is the DEFAULT `:par_store`, it discards
  # every stored `request_uri` on the node and breaks in-flight authorization
  # flows for every client at once.
  #
  # These tests pin that a crashing caller cannot take the store down.

  use ExUnit.Case, async: false

  alias AttestoPhoenix.ClientIdMetadata.Cache.ETS, as: CIMDCache
  alias AttestoPhoenix.Store.ETSOwner
  alias AttestoPhoenix.Store.PAR.ETS, as: PARStore

  @par_table :attesto_phoenix_par_requests
  @cimd_table :attesto_phoenix_client_id_metadata
  @table_options [:set, :public, :named_table, read_concurrency: true]

  # Run `fun` inside a process that then dies abnormally, and wait for it to go.
  defp in_crashing_process(fun) do
    parent = self()

    {pid, ref} =
      spawn_monitor(fn ->
        fun.()
        send(parent, :did_work)
        exit(:boom)
      end)

    assert_receive :did_work, 1_000
    assert_receive {:DOWN, ^ref, :process, ^pid, :boom}, 1_000
  end

  describe "PAR store (the default :par_store)" do
    test "survives a crashing caller with its contents intact" do
      in_crashing_process(fn -> :ok = PARStore.put("urn:test:survives", %{"client_id" => "c1"}, 90) end)

      # The table outlived the process that created it, and so did the record.
      assert {:ok, %{"client_id" => "c1"}} = PARStore.fetch("urn:test:survives")
    end

    test "a crashing caller does not discard OTHER clients' pushed requests" do
      :ok = PARStore.put("urn:test:bystander", %{"client_id" => "other"}, 90)

      in_crashing_process(fn -> :ok = PARStore.put("urn:test:crasher", %{"client_id" => "c1"}, 90) end)

      assert {:ok, %{"client_id" => "other"}} = PARStore.fetch("urn:test:bystander")
    end
  end

  describe "CIMD metadata cache" do
    test "survives a crashing caller" do
      url = "https://client.example/metadata-survives"
      expires = DateTime.add(DateTime.utc_now(), 300, :second)

      in_crashing_process(fn -> :ok = CIMDCache.put(url, %{"client_id" => url}, expires) end)

      assert {:ok, %{"client_id" => ^url}} = CIMDCache.get(url)
    end
  end

  describe "CIMD cache eviction" do
    test "delete/1 evicts exactly the named document" do
      expires = DateTime.add(DateTime.utc_now(), 300, :second)
      a = "https://a.example/m.json"
      b = "https://b.example/m.json"

      :ok = CIMDCache.put(a, %{"client_id" => a}, expires)
      :ok = CIMDCache.put(b, %{"client_id" => b}, expires)

      assert :ok = CIMDCache.delete(a)

      assert CIMDCache.get(a) == :miss
      assert {:ok, %{"client_id" => ^b}} = CIMDCache.get(b)
    end

    test "delete_all/0 evicts every document" do
      expires = DateTime.add(DateTime.utc_now(), 300, :second)
      :ok = CIMDCache.put("https://c.example/m.json", %{"client_id" => "c"}, expires)

      assert :ok = CIMDCache.delete_all()
      assert CIMDCache.get("https://c.example/m.json") == :miss
    end
  end

  describe "owner process" do
    test "is not linked to the caller that starts it" do
      # Directly pin the property the fix rests on: after a caller that touched
      # the store dies abnormally, the owner is still alive.
      in_crashing_process(fn -> :ok = PARStore.put("urn:test:link-check", %{}, 90) end)

      owner = Process.whereis(ETSOwner)

      assert is_pid(owner) and Process.alive?(owner),
             "the ETS owner must outlive the request process that first touched the store"
    end

    test "concurrent ensures create one table and preserve all data" do
      table = :"attesto_phoenix_ets_owner_#{System.unique_integer([:positive])}"

      on_exit(fn ->
        if :ets.whereis(table) != :undefined do
          :ets.delete(table)
        end
      end)

      results =
        1..200
        |> Task.async_stream(
          fn i ->
            ^table = ETSOwner.ensure(table, @table_options)
            true = :ets.insert(table, {i, {:value, i}})
            table
          end,
          max_concurrency: 100,
          timeout: 5_000
        )
        |> Enum.to_list()

      assert Enum.uniq(results) == [{:ok, table}]
      assert :ets.whereis(table) != :undefined
      assert :ets.info(table, :name) == table
      assert :ets.info(table, :type) == :set
      assert :ets.info(table, :protection) == :public
      assert :ets.info(table, :read_concurrency)
      assert Enum.sort(:ets.tab2list(table)) == Enum.map(1..200, &{&1, {:value, &1}})
    end

    test "PAR first use tolerates concurrent table creation and preserves data" do
      delete_table(@par_table)

      results =
        1..200
        |> Task.async_stream(
          fn i ->
            uri = "urn:test:concurrent-par:#{i}"
            :ok = PARStore.put(uri, %{"i" => i}, 60)
            PARStore.fetch(uri)
          end,
          max_concurrency: 100,
          timeout: 5_000
        )
        |> Enum.to_list()

      assert Enum.sort(results) == Enum.map(1..200, &{:ok, {:ok, %{"i" => &1}}})
    end

    test "CIMD cache first use tolerates concurrent table creation and preserves data" do
      delete_table(@cimd_table)
      expires_at = DateTime.add(DateTime.utc_now(), 60, :second)

      results =
        1..200
        |> Task.async_stream(
          fn i ->
            url = "https://concurrent-cimd.example/#{i}"
            :ok = CIMDCache.put(url, %{"i" => i}, expires_at)
            CIMDCache.get(url)
          end,
          max_concurrency: 100,
          timeout: 5_000
        )
        |> Enum.to_list()

      assert Enum.sort(results) == Enum.map(1..200, &{:ok, {:ok, %{"i" => &1}}})
    end
  end

  defp delete_table(table) do
    if :ets.whereis(table) != :undefined do
      :ets.delete(table)
    end
  end
end
