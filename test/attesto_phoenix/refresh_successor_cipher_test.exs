defmodule AttestoPhoenix.RefreshSuccessorCipherTest do
  use ExUnit.Case, async: false

  alias AttestoPhoenix.RefreshSuccessorCipher
  alias AttestoPhoenix.Schema.RefreshToken
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

  test "bound authenticated data cannot move a successor between parents" do
    aad = RefreshSuccessorCipher.binding_aad("parent-hash", "family-id", 4, "child-hash", 1_900_000_010)
    assert {:ok, ciphertext} = RefreshSuccessorCipher.encrypt(@successor, aad)
    assert {:ok, @successor} = RefreshSuccessorCipher.decrypt(ciphertext, aad)

    wrong_aad = RefreshSuccessorCipher.binding_aad("other-parent", "family-id", 4, "child-hash", 1_900_000_010)
    assert :error = RefreshSuccessorCipher.decrypt(ciphertext, wrong_aad)
  end

  test "configured?/0 reports only a usable application secret" do
    assert RefreshSuccessorCipher.configured?()

    Application.put_env(:attesto_phoenix, :refresh_successor_secret, "short")
    refute RefreshSuccessorCipher.configured?()

    Application.delete_env(:attesto_phoenix, :refresh_successor_secret)
    refute RefreshSuccessorCipher.configured?()
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

  test "decrypt rejects authenticated bytes that are not an Erlang term" do
    assert {:ok, enc_key, sign_key} = RefreshSuccessorCipher.derive_keys(@secret)

    ciphertext =
      MessageEncryptor.encrypt("not-an-external-term", "attesto_phoenix:refresh_successor:v1", enc_key, sign_key)

    assert :error = RefreshSuccessorCipher.decrypt(ciphertext)
  end

  test "the refresh schema rejects authenticated successor terms that are not maps" do
    for invalid <- [42, [], "scalar"] do
      assert {:ok, ciphertext} = RefreshSuccessorCipher.encrypt(invalid)

      row = %RefreshToken{
        token_hash: "parent-hash",
        family_id: "family-id",
        generation: 0,
        subject: "subject-id",
        scope: [],
        resource: [],
        claims: %{},
        consumed: true,
        consumed_at: ~U[2030-01-01 00:00:00Z],
        successor: %{"v" => 1, "ciphertext" => ciphertext},
        expires_at: ~U[2030-01-02 00:00:00Z]
      }

      assert RefreshToken.to_store_record(row).successor == nil
    end
  end

  test "key derivation is deterministic for the same secret" do
    assert RefreshSuccessorCipher.derive_keys(@secret) ==
             RefreshSuccessorCipher.derive_keys(@secret)
  end
end
