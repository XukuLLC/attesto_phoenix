defmodule AttestoPhoenix.RefreshSuccessorCipherTest do
  use ExUnit.Case, async: false

  alias AttestoPhoenix.RefreshSuccessorCipher
  alias Plug.Crypto.MessageEncryptor

  @secret String.duplicate("test-refresh-successor-", 4)

  setup do
    original = Application.get_env(:attesto_phoenix, :refresh_successor_secret)
    Application.put_env(:attesto_phoenix, :refresh_successor_secret, @secret)

    on_exit(fn ->
      if is_nil(original) do
        Application.delete_env(:attesto_phoenix, :refresh_successor_secret)
      else
        Application.put_env(:attesto_phoenix, :refresh_successor_secret, original)
      end
    end)

    :ok
  end

  @successor %{
    token: "successor-token",
    generation: 5,
    context: %{subject: "sub-1", scope: ["read"], claims: %{"tenant" => "t1"}}
  }

  test "encrypt then decrypt returns the original successor" do
    assert {:ok, ciphertext} = RefreshSuccessorCipher.encrypt(@successor)
    assert {:ok, @successor} = RefreshSuccessorCipher.decrypt(ciphertext)
  end

  test "decrypt under a wrong key fails" do
    assert {:ok, ciphertext} = RefreshSuccessorCipher.encrypt(@successor)

    Application.put_env(
      :attesto_phoenix,
      :refresh_successor_secret,
      String.duplicate("wrong-refresh-successor-", 4)
    )

    assert :error = RefreshSuccessorCipher.decrypt(ciphertext)
  end

  test "decrypt rejects a tampered ciphertext" do
    assert {:ok, ciphertext} = RefreshSuccessorCipher.encrypt(@successor)
    <<"XCP.", first_encoded_byte, rest::binary>> = ciphertext
    replacement = if first_encoded_byte == ?A, do: ?B, else: ?A
    tampered = <<"XCP.", replacement, rest::binary>>

    assert :error = RefreshSuccessorCipher.decrypt(tampered)
  end

  test "decrypt rejects ciphertext protected with a different AAD" do
    assert {:ok, enc_key, sign_key} = RefreshSuccessorCipher.derive_keys(@secret)

    ciphertext =
      @successor
      |> :erlang.term_to_binary()
      |> MessageEncryptor.encrypt("wrong-aad", enc_key, sign_key)

    assert :error = RefreshSuccessorCipher.decrypt(ciphertext)
  end

  test "key derivation is deterministic for the same secret" do
    assert RefreshSuccessorCipher.derive_keys(@secret) ==
             RefreshSuccessorCipher.derive_keys(@secret)
  end
end
