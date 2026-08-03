defmodule AttestoPhoenix.VerifierEncryption do
  @moduledoc false

  alias Attesto.{Key, SigningAlg}
  alias AttestoPhoenix.Config

  @type key_error ::
          :verifier_encryption_keystore_required
          | :invalid_verifier_encryption_key

  @doc false
  @spec private_jwk(Config.t()) :: {:ok, JOSE.JWK.t()} | {:error, key_error()}
  def private_jwk(%Config{} = config) do
    case Config.verifier_encryption_keystore(config) do
      nil ->
        {:error, :verifier_encryption_keystore_required}

      keystore ->
        load_private_p256_jwk(keystore)
    end
  end

  @doc false
  @spec public_jwk(Config.t()) :: {:ok, map()} | {:error, key_error()}
  def public_jwk(%Config{} = config) do
    with {:ok, private_jwk} <- private_jwk(config) do
      {_kty, public_jwk} = JOSE.JWK.to_public_map(private_jwk)
      {:ok, public_jwk}
    end
  end

  defp load_private_p256_jwk(keystore) do
    with true <- Code.ensure_loaded?(keystore),
         true <- function_exported?(keystore, :signing_pem, 0),
         pem when is_binary(pem) <- keystore.signing_pem(),
         %JOSE.JWK{} = jwk <- Key.signing_jwk(pem),
         "ES256" <- SigningAlg.infer(jwk) do
      {:ok, jwk}
    else
      _other -> {:error, :invalid_verifier_encryption_key}
    end
  rescue
    _error -> {:error, :invalid_verifier_encryption_key}
  catch
    _kind, _reason -> {:error, :invalid_verifier_encryption_key}
  end
end
