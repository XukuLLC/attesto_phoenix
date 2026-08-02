defmodule AttestoPhoenix.RefreshSuccessorCipher do
  @moduledoc """
  Authenticated encryption for the successor stored during refresh rotation.

  The ciphertext format is provided by `Plug.Crypto.MessageEncryptor` and is
  intentionally kept here with its existing AAD and derived keys. The
  application secret is read when encrypting or decrypting so a key change
  takes effect for both operations without changing the persisted wrapper.
  """

  alias Plug.Crypto.MessageEncryptor

  @app :attesto_phoenix
  @aad "attesto_phoenix:refresh_successor:v1"

  @doc """
  Encrypts a successor term with the configured refresh-successor secret.

  Returns `:error` when the secret is missing or too short. The caller owns
  the persisted version wrapper around the returned ciphertext.
  """
  @spec encrypt(term()) :: {:ok, binary()} | :error
  def encrypt(successor) do
    with {:ok, enc_key, sign_key} <- configured_keys() do
      ciphertext =
        successor
        |> :erlang.term_to_binary()
        |> MessageEncryptor.encrypt(@aad, enc_key, sign_key)

      {:ok, ciphertext}
    end
  end

  @doc """
  Decrypts and safely decodes a refresh-token successor ciphertext.

  Authentication failures and missing or invalid configuration return
  `:error`, matching the pre-consolidation call sites.
  """
  @spec decrypt(binary()) :: {:ok, term()} | :error
  def decrypt(ciphertext) when is_binary(ciphertext) do
    with {:ok, enc_key, sign_key} <- configured_keys(),
         {:ok, encoded} <- MessageEncryptor.decrypt(ciphertext, @aad, enc_key, sign_key) do
      {:ok, :erlang.binary_to_term(encoded, [:safe])}
    else
      _ -> :error
    end
  end

  @doc """
  Derives the encryption and signing keys from a refresh-successor secret.

  Kept public so the exact derivation has direct deterministic coverage.
  """
  @spec derive_keys(term()) :: {:ok, binary(), binary()} | :error
  def derive_keys(secret) when is_binary(secret) and byte_size(secret) >= 32 do
    {:ok, :crypto.hash(:sha256, "refresh-successor:enc:" <> secret),
     :crypto.hash(:sha256, "refresh-successor:sign:" <> secret)}
  end

  def derive_keys(_secret), do: :error

  defp configured_keys do
    @app
    |> Application.get_env(:refresh_successor_secret)
    |> derive_keys()
  end
end
