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
  alias AttestoPhoenix.Store.PAR.ETS, as: PARStore
  alias AttestoPhoenix.Store.PAR.ETS.Owner

  # Run `fun` inside a process that then dies abnormally, and wait for it to go.
  defp in_crashing_process(fun) do
    parent = self()

    pid =
      spawn(fn ->
        fun.()
        send(parent, :did_work)
        exit(:boom)
      end)

    ref = Process.monitor(pid)
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

  describe "owner process" do
    test "is not linked to the caller that starts it" do
      # Directly pin the property the fix rests on: after a caller that touched
      # the store dies abnormally, the owner is still alive.
      in_crashing_process(fn -> :ok = PARStore.put("urn:test:link-check", %{}, 90) end)

      owner = Process.whereis(Owner)

      assert is_pid(owner) and Process.alive?(owner),
             "the ETS owner must outlive the request process that first touched the store"
    end
  end
end
