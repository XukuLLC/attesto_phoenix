Code.require_file(Path.join(Mix.Project.deps_paths()[:attesto], "test/support/code_store_contract.ex"))

defmodule AttestoPhoenix.Store.EctoCodeStoreContractTest do
  use AttestoPhoenix.DataCase, async: false

  use Attesto.CodeStoreContract,
    store: AttestoPhoenix.Store.EctoCodeStore,
    start: fn -> :ok end
end
