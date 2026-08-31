defmodule AttestoPhoenix.RefreshSuccessorCipher do
  @moduledoc """
  Authenticated encryption for the successor stored during refresh rotation.

  The ciphertext format is provided by `Plug.Crypto.MessageEncryptor` and is
  intentionally kept here with its existing AAD and derived keys. The
  application secret is read when encrypting or decrypting, but its value MUST
  remain stable across nodes and deployments. Changing it makes retry state
  written under the old value unreadable; drain past the configured grace
  window before an intentional rotation.
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
    encrypt(successor, @aad)
  end

  @doc """
  Encrypts a successor using an explicit authenticated-data value.

  The Ecto refresh store uses this form to bind the ciphertext to the parent
  token hash, family, generations, child hash, and fixed retry deadline. The
  successor itself remains inside the authenticated ciphertext.
  """
  @spec encrypt(term(), binary()) :: {:ok, binary()} | :error
  def encrypt(successor, aad) when is_binary(aad) do
    with {:ok, enc_key, sign_key} <- configured_keys() do
      ciphertext =
        successor
        |> :erlang.term_to_binary()
        |> MessageEncryptor.encrypt(aad, enc_key, sign_key)

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
    decrypt(ciphertext, @aad)
  end

  @doc "Decrypts a successor using the supplied authenticated-data value."
  @spec decrypt(binary(), binary()) :: {:ok, term()} | :error
  def decrypt(ciphertext, aad) when is_binary(ciphertext) and is_binary(aad) do
    with {:ok, enc_key, sign_key} <- configured_keys(),
         {:ok, encoded} <- MessageEncryptor.decrypt(ciphertext, aad, enc_key, sign_key) do
      safe_decode(encoded)
    else
      _ -> :error
    end
  end

  defp safe_decode(encoded) do
    {:ok, :erlang.binary_to_term(encoded, [:safe])}
  rescue
    ArgumentError -> :error
  end

  @doc """
  Reports whether a usable refresh-successor secret is configured.

  This checks only presence and the minimum 32-byte length. Operators must
  keep the value stable across every node and deployment that can serve the
  same refresh-token families.
  """
  @spec configured?() :: boolean()
  def configured? do
    match?({:ok, _enc_key, _sign_key}, configured_keys())
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

  @doc """
  Builds deterministic authenticated data for a persisted successor bundle.

  Term encoding avoids delimiter ambiguity in host-controlled identifiers.
  The payload and deadline are also authenticated by the encryption envelope;
  keeping the binding fields here prevents moving a valid ciphertext to a
  different parent, family, generation, or child row.
  """
  @spec binding_aad(String.t(), String.t(), non_neg_integer(), String.t(), integer()) ::
          binary()
  def binding_aad(parent_hash, family_id, parent_generation, child_hash, retry_until)
      when is_binary(parent_hash) and is_binary(family_id) and
             (is_integer(parent_generation) and is_binary(child_hash) and is_integer(retry_until)) do
    :erlang.term_to_binary({@aad, parent_hash, family_id, parent_generation, child_hash, retry_until})
  end

  defp configured_keys do
    @app
    |> Application.get_env(:refresh_successor_secret)
    |> derive_keys()
  end
end
