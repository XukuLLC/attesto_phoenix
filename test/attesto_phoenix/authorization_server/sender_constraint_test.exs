defmodule AttestoPhoenix.AuthorizationServer.SenderConstraintTest do
  @moduledoc """
  Direct unit tests for the conn-free sender-constraint core
  (RFC 9449 / RFC 8705).

  These exercise `AttestoPhoenix.AuthorizationServer.SenderConstraint.resolve/3`
  against data only - the `input` map a controller builds from the request
  (`:dpop_proof`, `:mtls_cert_der`, `:http_uri`, `:http_method`) - with no conn
  involved. The focus is the precedence and fail-closed policy (RFC 9449 §5,
  RFC 8705 §3) and, critically, that a required-but-absent DPoP nonce surfaces
  as a `use_dpop_nonce` `OAuthError` carrying the fresh `DPoP-Nonce` value in
  its `:headers` so the controller can render the header verbatim
  (RFC 9449 §8 / §9).
  """
  use ExUnit.Case, async: false

  alias Attesto.DPoP.NonceStore.ETS
  alias AttestoPhoenix.AuthorizationServer.SenderConstraint
  alias AttestoPhoenix.{Config, OAuthError}

  @htu "https://issuer.example/oauth/token"
  @htm "POST"

  # A client whose binding requirements are read through the config callbacks.
  @plain %{id: "plain-1"}
  @dpop_required %{id: "dpop-1"}
  @mtls_required %{id: "mtls-1"}

  defmodule StubKeystore do
    @moduledoc false
  end

  defmodule StubRepo do
    @moduledoc false
  end

  # A replay store configured as a `{module, function}` MFA - the form a host
  # supplies in config (which cannot hold a literal anonymous function). Backed
  # by a named ETS table so a repeated `jti` is detected as a replay.
  defmodule MfaReplay do
    @moduledoc false

    def setup do
      if :ets.whereis(__MODULE__) == :undefined,
        do: :ets.new(__MODULE__, [:named_table, :public, :set])

      :ets.delete_all_objects(__MODULE__)
      :ok
    end

    def check_and_record(jti, _ttl_seconds) do
      if :ets.insert_new(__MODULE__, {jti}), do: :ok, else: {:error, :replay}
    end
  end

  # A nonce store that mimics a persistent (repo-backed) store: its config-FREE
  # behaviour entrypoints RAISE - exactly as `EctoNonceStore` does when it has
  # to guess an otp_app it was not configured under. So a passing test proves
  # the DPoP path threaded the live `%Config{}` to the config-aware `issue/2` /
  # `valid?/2`, never re-resolving config behind the scenes.
  defmodule ThreadedNonceStore do
    @moduledoc false
    @behaviour Attesto.DPoP.NonceStore

    @impl true
    def issue(_ttl_seconds), do: raise("config-free issue/1 must not be called; config must be threaded")

    @impl true
    def valid?(_nonce), do: raise("config-free valid?/1 must not be called; config must be threaded")

    @spec issue(Config.t(), pos_integer()) :: String.t()
    def issue(%Config{} = _config, ttl_seconds) when is_integer(ttl_seconds) and ttl_seconds > 0 do
      nonce = "threaded-nonce"
      Process.put(:threaded_nonce, nonce)
      nonce
    end

    @spec valid?(Config.t(), String.t()) :: boolean()
    def valid?(%Config{} = _config, nonce), do: is_binary(nonce) and Process.get(:threaded_nonce) == nonce
  end

  # The `%Config{}` enforced keys the sender-constraint core never reads;
  # supplied as inert stubs so a valid struct can be built for these data tests.
  defp required_fields do
    [
      issuer: "https://issuer.example",
      audience: "https://api.example.com",
      keystore: StubKeystore,
      repo: StubRepo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _client, _given -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      # The token endpoint records each DPoP proof's jti (RFC 9449 §11.1); these
      # data tests don't run the cache, so stub the check to a no-op.
      replay_check: fn _jti, _ttl -> :ok end
    ]
  end

  defp base_config(overrides \\ []) do
    fields =
      required_fields()
      |> Keyword.merge(
        client_requires_dpop?: fn client -> Map.get(client, :id) == "dpop-1" end,
        client_requires_mtls?: fn client -> Map.get(client, :id) == "mtls-1" end,
        client_public?: fn client -> Map.get(client, :public?, false) == true end
      )
      |> Keyword.merge(overrides)

    struct!(Config, fields)
  end

  defp bare_config, do: struct!(Config, required_fields())

  defp input(overrides) do
    %{
      dpop_proof: nil,
      mtls_cert_der: nil,
      http_uri: @htu,
      http_method: @htm
    }
    |> Map.merge(Map.new(overrides))
  end

  # A valid DPoP proof (RFC 9449 §4.2) bound to @htu/@htm, key freshly
  # generated per call; the matching `jkt` is returned for assertion.
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

  defp self_signed_cert_der do
    %{cert: der} = :public_key.pkix_test_root_cert(~c"CN=attesto-test", [])
    der
  end

  describe "DPoP binding (RFC 9449 §5)" do
    test "a valid proof binds {:dpop, jkt} and the DPoP token type" do
      {proof, jkt} = dpop_proof_and_jkt()
      config = base_config(dpop_enabled: true)

      assert {:ok, {:dpop, ^jkt}, "DPoP"} =
               SenderConstraint.resolve(config, input(dpop_proof: proof), @plain)
    end

    test "DPoP takes precedence over a presented certificate (RFC 9449 §5)" do
      {proof, jkt} = dpop_proof_and_jkt()
      config = base_config(dpop_enabled: true, mtls_enabled: true)

      assert {:ok, {:dpop, ^jkt}, "DPoP"} =
               SenderConstraint.resolve(
                 config,
                 input(dpop_proof: proof, mtls_cert_der: self_signed_cert_der()),
                 @plain
               )
    end

    test "a malformed proof is rejected with invalid_dpop_proof" do
      config = base_config(dpop_enabled: true)

      assert {:error, %OAuthError{error: :invalid_dpop_proof, status: 400}} =
               SenderConstraint.resolve(config, input(dpop_proof: "not-a-jwt"), @plain)
    end

    test "a proof is ignored when DPoP is disabled, falling back to Bearer" do
      {proof, _jkt} = dpop_proof_and_jkt()
      config = base_config(dpop_enabled: false)

      assert {:ok, :none, "Bearer"} =
               SenderConstraint.resolve(config, input(dpop_proof: proof), @plain)
    end
  end

  describe "DPoP nonce challenge (RFC 9449 §8 / §9)" do
    setup do
      store = ETS
      start_supervised!(store)
      {:ok, store: store}
    end

    test "a required-but-absent nonce yields use_dpop_nonce carrying a fresh DPoP-Nonce header",
         %{store: store} do
      {proof, _jkt} = dpop_proof_and_jkt(nonce: nil)

      config =
        base_config(dpop_enabled: true, dpop_nonce_required: true, nonce_store: store)

      assert {:error, %OAuthError{error: :use_dpop_nonce, status: 400, headers: headers}} =
               SenderConstraint.resolve(config, input(dpop_proof: proof), @plain)

      assert [{"dpop-nonce", nonce}] = headers
      assert is_binary(nonce) and nonce != ""
      assert store.valid?(nonce)
    end

    test "an invalid (stale) nonce is rejected with a fresh DPoP-Nonce header", %{store: store} do
      {proof, _jkt} = dpop_proof_and_jkt(nonce: "stale-nonce")

      config =
        base_config(dpop_enabled: true, dpop_nonce_required: true, nonce_store: store)

      assert {:error, %OAuthError{error: :use_dpop_nonce, headers: [{"dpop-nonce", fresh}]}} =
               SenderConstraint.resolve(config, input(dpop_proof: proof), @plain)

      assert store.valid?(fresh)
    end

    test "a currently-valid nonce binds DPoP", %{store: store} do
      nonce = store.issue()
      {proof, jkt} = dpop_proof_and_jkt(nonce: nonce)

      config =
        base_config(dpop_enabled: true, dpop_nonce_required: true, nonce_store: store)

      assert {:ok, {:dpop, ^jkt}, "DPoP"} =
               SenderConstraint.resolve(config, input(dpop_proof: proof), @plain)
    end
  end

  describe "mTLS binding (RFC 8705 §3)" do
    test "a presented certificate binds {:mtls, thumbprint} and keeps the Bearer type" do
      der = self_signed_cert_der()
      {:ok, thumbprint} = Attesto.MTLS.compute_thumbprint(der)
      config = base_config(mtls_enabled: true)

      assert {:ok, {:mtls, ^thumbprint}, "Bearer"} =
               SenderConstraint.resolve(config, input(mtls_cert_der: der), @plain)
    end

    test "a certificate is ignored when mTLS is disabled, falling back to Bearer" do
      config = base_config(mtls_enabled: false)

      assert {:ok, :none, "Bearer"} =
               SenderConstraint.resolve(
                 config,
                 input(mtls_cert_der: self_signed_cert_der()),
                 @plain
               )
    end

    test "an unparseable certificate is rejected with invalid_client" do
      config = base_config(mtls_enabled: true)

      assert {:error, %OAuthError{error: :invalid_client}} =
               SenderConstraint.resolve(config, input(mtls_cert_der: "not-a-cert"), @plain)
    end
  end

  describe "unbound Bearer and required-constraint refusal" do
    test "no constraint presented and none required yields an unbound Bearer" do
      config = base_config(dpop_enabled: true, mtls_enabled: true)

      assert {:ok, :none, "Bearer"} = SenderConstraint.resolve(config, input([]), @plain)
    end

    test "a DPoP-required client calling without a proof is refused (RFC 9449)" do
      config = base_config(dpop_enabled: true, mtls_enabled: true)

      assert {:error, %OAuthError{error: :invalid_request}} =
               SenderConstraint.resolve(config, input([]), @dpop_required)
    end

    test "an mTLS-required client calling without a certificate is refused (RFC 8705 §3)" do
      config = base_config(dpop_enabled: true, mtls_enabled: true)

      assert {:error, %OAuthError{error: :invalid_client}} =
               SenderConstraint.resolve(config, input([]), @mtls_required)
    end

    test "binding requirements fail open to not-required when callbacks are absent" do
      config = bare_config()

      assert {:ok, :none, "Bearer"} =
               SenderConstraint.resolve(config, input([]), @dpop_required)
    end
  end

  describe "a required sender-constraint cannot be satisfied by a different type (security)" do
    test "a DPoP-required client presenting a certificate but no proof is refused, not mTLS-bound" do
      config = base_config(dpop_enabled: true, mtls_enabled: true)

      assert {:error, %OAuthError{error: :invalid_request, error_description: "DPoP proof required"}} =
               SenderConstraint.resolve(
                 config,
                 input(mtls_cert_der: self_signed_cert_der()),
                 @dpop_required
               )
    end

    test "a DPoP-required client presenting a valid proof binds DPoP" do
      {proof, jkt} = dpop_proof_and_jkt()
      config = base_config(dpop_enabled: true, mtls_enabled: true)

      assert {:ok, {:dpop, ^jkt}, "DPoP"} =
               SenderConstraint.resolve(config, input(dpop_proof: proof), @dpop_required)
    end

    test "a DPoP-required client's proof binds DPoP even when a certificate is also presented" do
      {proof, jkt} = dpop_proof_and_jkt()
      config = base_config(dpop_enabled: true, mtls_enabled: true)

      assert {:ok, {:dpop, ^jkt}, "DPoP"} =
               SenderConstraint.resolve(
                 config,
                 input(dpop_proof: proof, mtls_cert_der: self_signed_cert_der()),
                 @dpop_required
               )
    end

    test "an mTLS-required client presenting a DPoP proof but no certificate is refused, not DPoP-bound" do
      {proof, _jkt} = dpop_proof_and_jkt()
      config = base_config(dpop_enabled: true, mtls_enabled: true)

      assert {:error, %OAuthError{error: :invalid_client, error_description: "client certificate required"}} =
               SenderConstraint.resolve(config, input(dpop_proof: proof), @mtls_required)
    end

    test "an mTLS-required client presenting a certificate binds mTLS" do
      der = self_signed_cert_der()
      {:ok, thumbprint} = Attesto.MTLS.compute_thumbprint(der)
      config = base_config(dpop_enabled: true, mtls_enabled: true)

      assert {:ok, {:mtls, ^thumbprint}, "Bearer"} =
               SenderConstraint.resolve(config, input(mtls_cert_der: der), @mtls_required)
    end

    test "an mTLS-required client's certificate binds mTLS even when a DPoP proof is also presented" do
      {proof, _jkt} = dpop_proof_and_jkt()
      der = self_signed_cert_der()
      {:ok, thumbprint} = Attesto.MTLS.compute_thumbprint(der)
      config = base_config(dpop_enabled: true, mtls_enabled: true)

      assert {:ok, {:mtls, ^thumbprint}, "Bearer"} =
               SenderConstraint.resolve(
                 config,
                 input(dpop_proof: proof, mtls_cert_der: der),
                 @mtls_required
               )
    end
  end

  describe "MFA-tuple replay_check (token endpoint, RFC 9449 §11.1)" do
    setup do
      MfaReplay.setup()
      :ok
    end

    test "an MFA `{module, function}` replay_check binds DPoP without an ArgumentError" do
      {proof, jkt} = dpop_proof_and_jkt()
      config = base_config(dpop_enabled: true, replay_check: {MfaReplay, :check_and_record})

      assert {:ok, {:dpop, ^jkt}, "DPoP"} =
               SenderConstraint.resolve(config, input(dpop_proof: proof), @plain)
    end

    test "a replayed proof is rejected through the MFA replay_check" do
      {proof, _jkt} = dpop_proof_and_jkt()
      config = base_config(dpop_enabled: true, replay_check: {MfaReplay, :check_and_record})

      assert {:ok, {:dpop, _jkt}, "DPoP"} =
               SenderConstraint.resolve(config, input(dpop_proof: proof), @plain)

      assert {:error, %OAuthError{error: :invalid_dpop_proof}} =
               SenderConstraint.resolve(config, input(dpop_proof: proof), @plain)
    end
  end

  describe "nonce issuance threads the live config (never re-resolving an otp_app)" do
    test "a required-but-absent nonce challenge issues via the config-aware store entrypoint" do
      {proof, _jkt} = dpop_proof_and_jkt(nonce: nil)

      config =
        base_config(
          dpop_enabled: true,
          dpop_nonce_required: true,
          nonce_store: ThreadedNonceStore
        )

      assert {:error, %OAuthError{error: :use_dpop_nonce, headers: [{"dpop-nonce", "threaded-nonce"}]}} =
               SenderConstraint.resolve(config, input(dpop_proof: proof), @plain)
    end

    test "a retry presenting the threaded nonce is validated via the config-aware store entrypoint" do
      config =
        base_config(
          dpop_enabled: true,
          dpop_nonce_required: true,
          nonce_store: ThreadedNonceStore
        )

      nonce = ThreadedNonceStore.issue(config, 300)
      {proof, jkt} = dpop_proof_and_jkt(nonce: nonce)

      assert {:ok, {:dpop, ^jkt}, "DPoP"} =
               SenderConstraint.resolve(config, input(dpop_proof: proof), @plain)
    end
  end

  describe "mint_opts/1" do
    test "maps each binding to the Attesto.Token confirmation opt" do
      assert SenderConstraint.mint_opts(:none) == []
      assert SenderConstraint.mint_opts({:dpop, "jkt-abc"}) == [dpop_jkt: "jkt-abc"]
      assert SenderConstraint.mint_opts({:mtls, "x5t-abc"}) == [mtls_cert_thumbprint: "x5t-abc"]
    end
  end

  describe "binding_jkt/1" do
    test "returns the DPoP thumbprint only for a DPoP binding" do
      assert SenderConstraint.binding_jkt({:dpop, "jkt-abc"}) == "jkt-abc"
      assert SenderConstraint.binding_jkt({:mtls, "x5t-abc"}) == nil
      assert SenderConstraint.binding_jkt(:none) == nil
    end
  end

  describe "refresh_binding_jkt/3" do
    test "public clients carry the DPoP thumbprint onto the refresh token (RFC 9449 §8)" do
      config = base_config()
      public = %{id: "p", public?: true}

      assert SenderConstraint.refresh_binding_jkt(config, public, {:dpop, "jkt-abc"}) == "jkt-abc"
    end

    test "confidential clients do not bind the refresh token to a DPoP key (RFC 6749 §6)" do
      config = base_config()
      confidential = %{id: "c", public?: false}

      assert SenderConstraint.refresh_binding_jkt(config, confidential, {:dpop, "jkt-abc"}) == nil
    end

    test "an mTLS binding never threads a DPoP thumbprint, even for a public client" do
      config = base_config()
      public = %{id: "p", public?: true}

      assert SenderConstraint.refresh_binding_jkt(config, public, {:mtls, "x5t-abc"}) == nil
    end
  end

  describe "client_requires_dpop?/2 and client_requires_mtls?/2" do
    test "read the config callbacks, failing open when absent" do
      config = base_config()
      bare = bare_config()

      assert SenderConstraint.client_requires_dpop?(config, @dpop_required)
      refute SenderConstraint.client_requires_dpop?(config, @plain)
      refute SenderConstraint.client_requires_dpop?(bare, @dpop_required)

      assert SenderConstraint.client_requires_mtls?(config, @mtls_required)
      refute SenderConstraint.client_requires_mtls?(config, @plain)
      refute SenderConstraint.client_requires_mtls?(bare, @mtls_required)
    end
  end
end
