defmodule AttestoPhoenix.Store.NonceStoreTest do
  @moduledoc """
  Unit tests for `AttestoPhoenix.Store.NonceStore`, the dispatcher that threads
  the live `%AttestoPhoenix.Config{}` to a config-aware nonce store
  (`issue/2` / `valid?/2`) and falls back to the behaviour arities
  (`issue/1` via `issue/0`, `valid?/1`) for a config-free store.
  """
  use ExUnit.Case, async: true

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Store.NonceStore

  # A persistent-style store: only its config-aware entrypoints work; the
  # config-free behaviour arities raise, so a passing test proves config was
  # threaded.
  defmodule ConfigAware do
    @moduledoc false
    @behaviour Attesto.DPoP.NonceStore

    @impl true
    def issue(_ttl), do: raise("config-free issue/1 must not be called")

    @impl true
    def valid?(_nonce), do: raise("config-free valid?/1 must not be called")

    def issue(%Config{issuer: issuer}, ttl), do: "issued:#{issuer}:#{ttl}"
    def valid?(%Config{issuer: issuer}, nonce), do: nonce == "live:#{issuer}"
  end

  # A config-free store implementing the `Attesto.DPoP.NonceStore` behaviour
  # EXACTLY - only `issue/1` and `valid?/1`, with no arity-0 convenience. The
  # dispatcher must call `issue/1` (not `issue/0`); a regression to `store.issue()`
  # would crash here.
  defmodule ConfigFree do
    @moduledoc false
    @behaviour Attesto.DPoP.NonceStore

    @impl true
    def issue(ttl), do: "free-issued:#{ttl}"

    @impl true
    def valid?(nonce), do: nonce == "free-live"
  end

  defp config do
    struct!(Config,
      issuer: "https://issuer.example",
      audience: "https://api.example.com",
      keystore: __MODULE__,
      repo: __MODULE__,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end
    )
  end

  describe "issue/2" do
    test "threads the live config to a config-aware store's issue/2" do
      assert NonceStore.issue(config(), ConfigAware) == "issued:https://issuer.example:300"
    end

    test "uses the behaviour's config-free issue/0 for a store without issue/2" do
      assert NonceStore.issue(config(), ConfigFree) == "free-issued:300"
    end
  end

  describe "valid?/3" do
    test "threads the live config to a config-aware store's valid?/2" do
      assert NonceStore.valid?(config(), ConfigAware, "live:https://issuer.example")
      refute NonceStore.valid?(config(), ConfigAware, "stale")
    end

    test "uses the behaviour's config-free valid?/1 for a store without valid?/2" do
      assert NonceStore.valid?(config(), ConfigFree, "free-live")
      refute NonceStore.valid?(config(), ConfigFree, "nope")
    end
  end
end
