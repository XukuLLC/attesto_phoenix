defmodule AttestoPhoenix.VerifierTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias Attesto.{JWS, PresentationRequest}
  alias Attesto.PresentationSessionStore.ETS, as: Store
  alias AttestoPhoenix.{Config, Verifier, X509TestCertificate}

  @issuer "https://issuer.example"
  @verifier_client_id "verifier-client-1"
  @verifier_dns "verifier.example"
  @query_id "identity"
  @rsa_signing_pem JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_pem() |> elem(1)

  defmodule Keystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem do
      :attesto_phoenix
      |> Application.fetch_env!(__MODULE__)
      |> Keyword.fetch!(:signing_pem)
    end

    @impl true
    def verification_pems, do: [signing_pem()]
  end

  defmodule EncryptionKeystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem do
      :attesto_phoenix
      |> Application.fetch_env!(__MODULE__)
      |> Keyword.fetch!(:signing_pem)
    end

    @impl true
    def verification_pems, do: [signing_pem()]
  end

  setup do
    start_supervised!(Store)

    request_pem = X509TestCertificate.private_key_pem()
    request_jwk = public_jwk(request_pem)
    {encryption_pem, encryption_jwk} = keypair()
    {_issuer_pem, issuer_jwk} = keypair()
    Application.put_env(:attesto_phoenix, Keystore, signing_pem: request_pem)
    Application.put_env(:attesto_phoenix, EncryptionKeystore, signing_pem: encryption_pem)

    config = config()

    on_exit(fn ->
      Application.delete_env(:attesto_phoenix, Keystore)
      Application.delete_env(:attesto_phoenix, EncryptionKeystore)
    end)

    %{config: config, encryption_jwk: encryption_jwk, issuer_jwk: issuer_jwk, request_jwk: request_jwk}
  end

  test "creates a stored signed request object with convention-derived endpoint URLs", ctx do
    assert {:ok, %{id: id, nonce: nonce, request_uri: request_uri}} =
             Verifier.create_presentation_request(ctx.config, request_attrs(ctx))

    assert request_uri == Config.presentation_request_endpoint_url(ctx.config) <> "/" <> id
    assert :error = Verifier.presentation_result(ctx.config, id)

    assert {:ok, %{data: session}} = Store.get(id)
    assert session.nonce == nonce
    assert session.state == id
    assert session.audience == @verifier_client_id
    assert session.expected_query_ids == [@query_id]
    assert session.status == :pending
    assert is_binary(session.request_object)

    candidates = JWS.verification_candidates(ctx.request_jwk)

    assert {:ok, claims} =
             JWS.verify_strict(session.request_object, candidates, claims_map?: true)

    assert {:ok, protected} = JWS.peek_json(session.request_object, :protected)
    assert protected["typ"] == "oauth-authz-req+jwt"
    refute Map.has_key?(protected, "x5c")

    assert claims["client_id"] == @verifier_client_id
    assert claims["iss"] == @verifier_client_id
    assert claims["aud"] == "https://self-issued.me/v2"
    assert claims["nonce"] == nonce
    assert claims["response_uri"] == Config.presentation_response_endpoint_url(ctx.config)
    assert claims["dcql_query"] == dcql_query()
    assert claims["state"] == id
    assert claims["response_type"] == "vp_token"
    assert claims["response_mode"] == "direct_post"
    assert is_integer(claims["exp"])
  end

  test "x509_san_dns signs with x5c and persists the effective client id", ctx do
    certificate_der = X509TestCertificate.der()

    config = %{
      ctx.config
      | verifier_client_id: nil,
        verifier_client_id_scheme: "x509_san_dns",
        verifier_dns: @verifier_dns,
        verifier_x5c: [certificate_der]
    }

    assert {:ok, %{id: id}} =
             Verifier.create_presentation_request(config, request_attrs(ctx))

    assert {:ok, %{data: session}} = Store.get(id)
    assert session.audience == "x509_san_dns:" <> @verifier_dns

    candidates = JWS.verification_candidates(ctx.request_jwk)

    assert {:ok, claims} =
             JWS.verify_strict(session.request_object, candidates, claims_map?: true)

    assert {:ok, protected} = JWS.peek_json(session.request_object, :protected)
    assert [encoded_certificate] = protected["x5c"]
    assert {:ok, ^certificate_der} = Base.decode64(encoded_certificate)

    assert claims["client_id"] == "x509_san_dns:" <> @verifier_dns
    assert claims["iss"] == "x509_san_dns:" <> @verifier_dns
  end

  test "derives the request-object algorithm from an RSA main keystore", ctx do
    Application.put_env(:attesto_phoenix, Keystore, signing_pem: @rsa_signing_pem)

    assert {:ok, %{id: id}} =
             Verifier.create_presentation_request(ctx.config, request_attrs(ctx))

    assert {:ok, %{data: session}} = Store.get(id)
    assert {:ok, protected} = JWS.peek_json(session.request_object, :protected)

    expected_alg = @rsa_signing_pem |> Attesto.Key.signing_jwk() |> Attesto.SigningAlg.infer()
    assert protected["alg"] == expected_alg
    assert expected_alg == "RS256"

    candidates = @rsa_signing_pem |> public_jwk() |> JWS.verification_candidates()
    assert {:ok, _claims} = JWS.verify_strict(session.request_object, candidates, claims_map?: true)
  end

  test "direct_post.jwt advertises the verifier public encryption key and algorithms", ctx do
    config = %{ctx.config | presentation_response_mode: "direct_post.jwt"}

    assert {:ok, %{id: id}} =
             Verifier.create_presentation_request(config, request_attrs(ctx))

    assert {:ok, %{data: session}} = Store.get(id)
    candidates = JWS.verification_candidates(ctx.request_jwk)

    assert {:ok, claims} =
             JWS.verify_strict(session.request_object, candidates, claims_map?: true)

    assert claims["response_mode"] == "direct_post.jwt"

    assert %{
             "jwks" => %{"keys" => [encryption_jwk]},
             "encrypted_response_enc_values_supported" => ["A128GCM", "A256GCM"]
           } = claims["client_metadata"]

    assert encryption_jwk["kty"] == "EC"
    assert encryption_jwk["crv"] == "P-256"
    assert encryption_jwk["use"] == "enc"
    assert encryption_jwk["alg"] == "ECDH-ES"
    # The advertised key is ephemeral (per-request), keyed by the session id.
    assert encryption_jwk["kid"] == id
    refute encryption_jwk["x"] == ctx.request_jwk["x"]
    refute Map.has_key?(encryption_jwk, "d")

    # Its private half is persisted on the session so the direct-post endpoint
    # can decrypt.
    assert %{"kty" => "EC", "crv" => "P-256", "kid" => ^id, "d" => d} =
             session.response_encryption_jwk

    assert is_binary(d)
    assert session.response_encryption_jwk["x"] == encryption_jwk["x"]
  end

  test "direct_post.jwt supplies a fresh ephemeral encryption key per request", ctx do
    # OID4VP 1.0 final / HAIP §5: verifiers MUST NOT reuse a response-encryption
    # key across Authorization Requests.
    config = %{ctx.config | presentation_response_mode: "direct_post.jwt"}

    assert {:ok, %{id: id1}} = Verifier.create_presentation_request(config, request_attrs(ctx))
    assert {:ok, %{id: id2}} = Verifier.create_presentation_request(config, request_attrs(ctx))

    assert {:ok, %{data: %{response_encryption_jwk: jwk1}}} = Store.get(id1)
    assert {:ok, %{data: %{response_encryption_jwk: jwk2}}} = Store.get(id2)

    refute jwk1["x"] == jwk2["x"]
    assert jwk1["kid"] == id1
    assert jwk2["kid"] == id2
  end

  test "returns host-facing errors when verifier configuration or attrs are absent", ctx do
    missing_store = %{ctx.config | presentation_session_store: nil}
    missing_client_id = %{ctx.config | verifier_client_id: nil}

    assert {:error, :presentation_session_store_required} =
             Verifier.create_presentation_request(missing_store, request_attrs(ctx))

    assert {:error, :verifier_client_id_required} =
             Verifier.create_presentation_request(missing_client_id, request_attrs(ctx))

    assert {:error, :invalid_attrs} = Verifier.create_presentation_request(ctx.config, %{})
    assert :error = Verifier.presentation_result(missing_store, "id")
  end

  test "x509_san_dns requires both verifier_dns and a non-empty verifier_x5c", ctx do
    certificate_der = X509TestCertificate.der()

    incomplete_configs = [
      %{ctx.config | verifier_client_id_scheme: "x509_san_dns", verifier_x5c: [certificate_der]},
      %{
        ctx.config
        | verifier_client_id_scheme: "x509_san_dns",
          verifier_dns: "",
          verifier_x5c: [certificate_der]
      },
      %{ctx.config | verifier_client_id_scheme: "x509_san_dns", verifier_dns: @verifier_dns},
      %{
        ctx.config
        | verifier_client_id_scheme: "x509_san_dns",
          verifier_dns: @verifier_dns,
          verifier_x5c: []
      }
    ]

    for config <- incomplete_configs do
      assert {:error, :x509_config_required} =
               Verifier.create_presentation_request(config, request_attrs(ctx))
    end
  end

  defp request_attrs(ctx) do
    %{
      dcql_query: dcql_query(),
      expected_query_ids: [@query_id],
      issuer_trust: {:issuer_jwks, ctx.issuer_jwk}
    }
  end

  defp dcql_query do
    PresentationRequest.dcql_query(%{
      credentials: [
        %{
          id: @query_id,
          format: "dc+sd-jwt",
          meta: %{vct_values: ["identity"]},
          claims: [%{path: ["given_name"]}]
        }
      ]
    })
  end

  defp config do
    Config.new(
      issuer: @issuer,
      audience: @issuer,
      keystore: Keystore,
      repo: __MODULE__.Repo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      presentation_session_store: Store,
      verifier_encryption_keystore: EncryptionKeystore,
      verifier_client_id: @verifier_client_id
    )
  end

  defp keypair do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    pem = jwk |> JOSE.JWK.to_pem() |> elem(1)
    {_kty, public} = JOSE.JWK.to_public_map(jwk)
    {pem, public}
  end

  defp public_jwk(pem) do
    {_kty, public} = pem |> JOSE.JWK.from_pem() |> JOSE.JWK.to_public_map()
    public
  end
end
