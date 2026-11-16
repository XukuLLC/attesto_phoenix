defmodule AttestoPhoenix.Store.EctoCodeStoreContractTest do
  use AttestoPhoenix.DataCase, async: false

  use Attesto.Test.CodeStoreContract,
    store: AttestoPhoenix.Store.EctoCodeStore,
    start: fn -> :ok end
end
