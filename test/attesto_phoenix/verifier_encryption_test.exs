defmodule AttestoPhoenix.VerifierEncryptionTest do
  use ExUnit.Case, async: false

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.VerifierEncryption

  defmodule Keystore do
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem, do: Application.fetch_env!(:attesto_phoenix, __MODULE__)

    @impl true
    def verification_pems, do: [signing_pem()]
  end

  setup do
    pem = JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_pem() |> elem(1)
    Application.put_env(:attesto_phoenix, Keystore, pem)
    on_exit(fn -> Application.delete_env(:attesto_phoenix, Keystore) end)
  end

  test "retains the 4.x private and public JWK compatibility API" do
    config = config(verifier_encryption_keystore: Keystore)
    private_jwk = Function.capture(VerifierEncryption, :private_jwk, 1)
    public_jwk = Function.capture(VerifierEncryption, :public_jwk, 1)

    assert {:ok, %JOSE.JWK{}} = private_jwk.(config)

    assert {:ok, %{"crv" => "P-256", "kty" => "EC"} = public} =
             public_jwk.(config)

    refute Map.has_key?(public, "d")
  end

  test "retains the compatibility errors" do
    private_jwk = Function.capture(VerifierEncryption, :private_jwk, 1)

    assert {:error, :verifier_encryption_keystore_required} =
             private_jwk.(config())
  end

  defp config(overrides \\ []) do
    struct!(Config, Keyword.merge([issuer: "https://issuer.example", keystore: Keystore, repo: __MODULE__], overrides))
  end
end
