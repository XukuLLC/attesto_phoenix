defmodule AttestoPhoenix.Store.NonceStore do
  @moduledoc """
  Dispatch to the configured `Attesto.DPoP.NonceStore`, threading the live
  request `%AttestoPhoenix.Config{}` to stores that need it (RFC 9449 §8).

  The `Attesto.DPoP.NonceStore` behaviour (`issue/1`, `valid?/1`) carries no
  config, so a persistent store such as `AttestoPhoenix.Store.EctoNonceStore`
  would otherwise have to re-resolve its repo from a guessed `:otp_app` — which
  fails for any host that configures `AttestoPhoenix.Config` under its own
  application. The controllers and the token endpoint already hold the resolved
  config, so this hands it straight to the store's config-aware entrypoints
  (`issue/2`, `valid?/2`) when the store exports them, falling back to the
  behaviour callbacks (`issue/1`, `valid?/1`) for config-free stores (e.g. the
  bundled ETS store).

  This is the single seam that keeps a nonce store from ever having to guess an
  otp_app: the DPoP paths pass the config they already resolved.
  """

  alias AttestoPhoenix.Config

  # RFC 9449 §8 freshness window; passed explicitly to the behaviour's `issue/1`
  # (and to a config-aware `issue/2`) so threading config does not change the
  # nonce lifetime.
  @default_ttl_seconds 300

  @doc """
  Mint a fresh nonce, passing `config` to a config-aware store (`issue/2`) and
  falling back to the behaviour callback `issue/1`.
  """
  @spec issue(Config.t(), module()) :: String.t()
  def issue(%Config{} = config, store) when is_atom(store) do
    if function_exported?(store, :issue, 2) do
      store.issue(config, @default_ttl_seconds)
    else
      # The `Attesto.DPoP.NonceStore` behaviour guarantees only `issue/1`
      # (`ttl_seconds`); call it with an explicit TTL rather than relying on an
      # arity-0 default a spec-exact store need not expose.
      store.issue(@default_ttl_seconds)
    end
  end

  @doc """
  Report whether `nonce` is currently valid, passing `config` to a config-aware
  store (`valid?/2`) and falling back to the behaviour's `valid?/1`.
  """
  @spec valid?(Config.t(), module(), String.t()) :: boolean()
  def valid?(%Config{} = config, store, nonce) when is_atom(store) do
    if function_exported?(store, :valid?, 2) do
      store.valid?(config, nonce)
    else
      store.valid?(nonce)
    end
  end
end
