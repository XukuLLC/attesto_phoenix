defmodule AttestoPhoenix.AuthorizationServer.SenderConstraintEctoTest do
  @moduledoc """
  Integration tests for the token-endpoint DPoP path against the real
  Postgres-backed stores, covering the two crashes that only surface under a
  standard host configuration and are therefore invisible to the function-stub
  unit tests:

    * a `{module, function}` MFA `:replay_check` (the form config holds, since
      it cannot hold a literal anonymous function) - `Attesto.DPoP.verify_proof/2`
      requires a bare 2-arity function, so the MFA must be adapted, not passed
      raw; and
    * `dpop_nonce_required: true` with `AttestoPhoenix.Config` resolved by the
      host under its OWN otp_app (not `:attesto_phoenix`) - the nonce store must
      use the threaded request config, never re-resolve a guessed otp_app.

  The `%Config{}` here is built directly (as a host's own otp_app resolution
  would yield) and never registered under `:attesto_phoenix, :config`, so any
  hidden re-resolution would raise rather than silently pass.
  """
  use AttestoPhoenix.DataCase, async: false

  alias AttestoPhoenix.AuthorizationServer.SenderConstraint
  alias AttestoPhoenix.{Config, OAuthError}
  alias AttestoPhoenix.Schema.{DPoPNonce, DPoPReplay}
  alias AttestoPhoenix.Store.{EctoNonceStore, EctoReplayCheck}

  @htu "https://issuer.example/oauth/token"
  @htm "POST"
  @plain %{id: "plain-1"}

  defmodule Keystore do
    @moduledoc false
  end

  # A config built directly against the sandboxed test repo, exactly as a host
  # resolving `AttestoPhoenix.Config` under its own otp_app would produce. The
  # MFA `:replay_check` is the standard documented form.
  defp config(overrides \\ []) do
    fields =
      [
        issuer: "https://issuer.example",
        audience: "https://api.example.com",
        keystore: Keystore,
        repo: AttestoPhoenix.TestRepo,
        load_client: fn _ -> {:error, :not_found} end,
        verify_client_secret: fn _, _ -> false end,
        load_principal: fn _ -> {:error, :not_found} end,
        dpop_enabled: true,
        replay_check: {EctoReplayCheck, :check_and_record}
      ]
      |> Keyword.merge(overrides)

    struct!(Config, fields)
  end

  defp input(proof) do
    %{dpop_proof: proof, mtls_cert_der: nil, http_uri: @htu, http_method: @htm}
  end

  defp dpop_proof_and_jkt(opts \\ []) do
    nonce = Keyword.get(opts, :nonce)
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, pub_map} = JOSE.JWK.to_public_map(jwk)

    payload =
      %{
        "htm" => @htm,
        "htu" => @htu,
        "iat" => System.system_time(:second),
        "jti" => Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
      }
      |> maybe_put("nonce", nonce)

    header = %{"alg" => "ES256", "typ" => "dpop+jwt", "jwk" => pub_map}
    {_, compact} = JOSE.JWS.compact(JOSE.JWT.sign(jwk, header, payload))
    {compact, Attesto.DPoP.compute_jkt(pub_map)}
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  describe "MFA-tuple replay_check against EctoReplayCheck" do
    test "a DPoP request with an MFA replay_check issues a DPoP-bound token (no ArgumentError)" do
      {proof, jkt} = dpop_proof_and_jkt()

      assert {:ok, {:dpop, ^jkt}, "DPoP"} =
               SenderConstraint.resolve(config(), input(proof), @plain)

      # The MFA store actually ran: the jti was recorded.
      assert TestRepo.aggregate(DPoPReplay, :count) == 1
    end

    test "a second presentation of the same proof is replay-rejected" do
      {proof, _jkt} = dpop_proof_and_jkt()
      config = config()

      assert {:ok, {:dpop, _jkt}, "DPoP"} = SenderConstraint.resolve(config, input(proof), @plain)

      assert {:error, %OAuthError{error: :invalid_dpop_proof}} =
               SenderConstraint.resolve(config, input(proof), @plain)
    end
  end

  describe "dpop_nonce_required with EctoNonceStore under a host's own otp_app" do
    test "the first request returns use_dpop_nonce + a DPoP-Nonce header (no struct crash)" do
      {proof, _jkt} = dpop_proof_and_jkt(nonce: nil)
      config = config(dpop_nonce_required: true, nonce_store: EctoNonceStore)

      assert {:error, %OAuthError{error: :use_dpop_nonce, headers: [{"dpop-nonce", nonce}]}} =
               SenderConstraint.resolve(config, input(proof), @plain)

      assert is_binary(nonce) and nonce != ""
      # The nonce was persisted via the threaded config's repo, not a guessed one.
      assert TestRepo.get_by(DPoPNonce, nonce: nonce)
    end

    test "the retry presenting the issued nonce succeeds" do
      config = config(dpop_nonce_required: true, nonce_store: EctoNonceStore)

      {proof_without_nonce, _} = dpop_proof_and_jkt(nonce: nil)

      assert {:error, %OAuthError{error: :use_dpop_nonce, headers: [{"dpop-nonce", nonce}]}} =
               SenderConstraint.resolve(config, input(proof_without_nonce), @plain)

      {proof_with_nonce, jkt} = dpop_proof_and_jkt(nonce: nonce)

      assert {:ok, {:dpop, ^jkt}, "DPoP"} =
               SenderConstraint.resolve(config, input(proof_with_nonce), @plain)
    end
  end
end
