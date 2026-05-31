defmodule AttestoPhoenixTest do
  use ExUnit.Case, async: true

  # `AttestoPhoenix` is the library's top-level entry surface: it carries no
  # logic, only the integration moduledoc that re-points to the config and
  # router. These tests pin the contract that surface promises - that the
  # module exists, documents itself, and adds no callable functions of its
  # own (every behaviour lives behind `AttestoPhoenix.Config` and the
  # protocol primitives in `Attesto`).

  describe "module surface" do
    test "the entry module is loaded" do
      assert Code.ensure_loaded?(AttestoPhoenix)
    end

    test "exposes no public runtime functions of its own" do
      # The entry point is documentation only; behaviour is reached through
      # AttestoPhoenix.Config and the router macro, never a function here. A
      # stray export would mean logic crept into the entry surface.
      exported = AttestoPhoenix.__info__(:functions)
      assert exported == []
    end

    test "carries a non-trivial moduledoc" do
      {:docs_v1, _anno, :elixir, _format, %{"en" => doc}, _meta, _entries} =
        Code.fetch_docs(AttestoPhoenix)

      assert is_binary(doc)
      assert String.length(doc) > 0
    end
  end

  describe "moduledoc re-points to the documented entry points" do
    setup do
      {:docs_v1, _anno, :elixir, _format, %{"en" => doc}, _meta, _entries} =
        Code.fetch_docs(AttestoPhoenix)

      %{doc: doc}
    end

    test "names the configuration entry point", %{doc: doc} do
      assert doc =~ "AttestoPhoenix.Config"
    end

    test "names the router entry point", %{doc: doc} do
      assert doc =~ "AttestoPhoenix.Router"
    end

    test "delegates the protocol layer to the core engine", %{doc: doc} do
      # The split the moduledoc must describe: this package owns transport
      # and persistence, the core owns the crypto/protocol.
      assert doc =~ "Attesto"
    end
  end

  describe "vendor-neutral OAuth vocabulary" do
    setup do
      {:docs_v1, _anno, :elixir, _format, %{"en" => doc}, _meta, _entries} =
        Code.fetch_docs(AttestoPhoenix)

      %{doc: doc}
    end

    test "speaks only OAuth/OIDC terms", %{doc: doc} do
      # The library documents its callbacks in protocol vocabulary, not any
      # host application's domain nouns.
      for term <- ~w(client scope token DPoP) do
        assert doc =~ term, "moduledoc should mention OAuth term #{inspect(term)}"
      end
    end

    test "documents the neutral policy callbacks", %{doc: doc} do
      for callback <- ~w(:load_client :verify_client_secret :load_principal) do
        assert doc =~ callback,
               "moduledoc should reference the neutral callback #{callback}"
      end
    end
  end
end
