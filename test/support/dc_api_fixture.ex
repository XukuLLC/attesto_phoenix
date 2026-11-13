defmodule AttestoPhoenix.DCApiFixture do
  @moduledoc false

  alias Attesto.{Cose, JWS, Mdoc, SdJwtVc, Thumbprint}
  alias AttestoPhoenix.X509TestCertificate

  @doc_type "org.iso.18013.5.1.mDL"
  @namespace "org.iso.18013.5.1"

  def doc_type, do: @doc_type
  def namespace, do: @namespace
  def public(key), do: key |> JOSE.JWK.to_public_map() |> elem(1)
  def pem(key), do: key |> JOSE.JWK.to_pem() |> elem(1)

  def mdoc(issuer, holder, session, encryption_jwk, opts) do
    now = System.system_time(:second)

    {:ok, issued} =
      Mdoc.issue(
        doc_type: @doc_type,
        namespaces: %{@namespace => %{"given_name" => "Alice"}},
        device_key: public(holder),
        issuer_pem: X509TestCertificate.private_key_pem(),
        validity: %{signed: now - 10, valid_from: now - 5, valid_until: now + 3600}
      )

    issuer_signed = issued |> Base.url_decode64!(padding: false) |> decode!()
    [_protected, _header, payload, _signature] = issuer_signed["issuerAuth"]
    issuer_signed = Map.put(issuer_signed, "issuerAuth", issuer_auth(issuer, payload, opts))

    # Construct the wallet transcript independently of Mdoc.session_transcript/1.
    {:ok, thumbprint} = Thumbprint.of_jwk(Keyword.get(opts, :binding_jwk, encryption_jwk))
    thumbprint = thumbprint |> Base.url_decode64!(padding: false) |> bytes()
    nonce = Keyword.get(opts, :nonce, session.nonce)

    {identifier, info} =
      case Keyword.get(opts, :flow, :dc_api) do
        :dc_api -> {"OpenID4VPDCAPIHandover", [Keyword.fetch!(opts, :origin), nonce, thumbprint]}
        :redirect -> {"OpenID4VPHandover", [session.client_id, nonce, thumbprint, Keyword.fetch!(opts, :response_uri)]}
      end

    transcript = [nil, nil, [identifier, bytes(:crypto.hash(:sha256, CBOR.encode(info)))]]
    namespaces = tagged(%{})
    authentication = CBOR.encode(tagged(["DeviceAuthentication", transcript, @doc_type, namespaces]))
    signature = holder |> pem() |> Cose.sign1_detached(authentication, []) |> decode!()

    document = %{
      "docType" => @doc_type,
      "issuerSigned" => issuer_signed,
      "deviceSigned" => %{"nameSpaces" => namespaces, "deviceAuth" => %{"deviceSignature" => signature}}
    }

    Base.url_encode64(CBOR.encode(%{"documents" => [document], "status" => 0, "version" => "1.0"}), padding: false)
  end

  def sd_jwt(issuer, holder, session, audience) do
    now = System.system_time(:second)

    vc =
      SdJwtVc.issue([iss: "https://issuer.example", vct: "identity", pem: pem(issuer)],
        claims: %{"given_name" => "Alice"},
        cnf: %{"jwk" => public(holder)},
        iat: now
      )

    vc <>
      JWS.sign_compact_jwk(holder, %{"alg" => "ES256", "typ" => "kb+jwt"}, %{
        "nonce" => session.nonce,
        "aud" => audience,
        "iat" => now,
        "sd_hash" => Base.url_encode64(:crypto.hash(:sha256, vc), padding: false)
      })
  end

  def encrypt(jwk, params, enc \\ "A128GCM") do
    ephemeral = JOSE.JWK.generate_key({:ec, "P-256"})
    header = %{"alg" => "ECDH-ES", "enc" => enc, "kid" => jwk["kid"]}

    {JOSE.JWK.from_map(jwk), ephemeral}
    |> JOSE.JWE.block_encrypt(JSON.encode!(params), header)
    |> JOSE.JWE.compact()
    |> elem(1)
  end

  defp issuer_auth(key, payload, opts) do
    alg = Keyword.get(opts, :alg, "ES256")

    {cose_alg, hash, curve, width} =
      case alg do
        "ES256" -> {-7, :sha256, :secp256r1, 32}
        "ES384" -> {-35, :sha384, :secp384r1, 48}
        "ES512" -> {-36, :sha512, :secp521r1, 66}
      end

    protected = bytes(CBOR.encode(%{1 => cose_alg}))
    input = CBOR.encode(["Signature1", protected, bytes(<<>>), payload])
    {_modules, fields} = JOSE.JWK.to_map(key)
    private = Base.url_decode64!(fields["d"], padding: false)
    der = :crypto.sign(:ecdsa, hash, input, [private, curve])
    {_, r, s} = :public_key.der_decode(:"ECDSA-Sig-Value", der)
    signature = <<r::unsigned-big-integer-size(width * 8), s::unsigned-big-integer-size(width * 8)>>

    header =
      case Keyword.get(opts, :x5chain) do
        nil -> %{}
        chain -> %{33 => Enum.map(chain, &bytes/1)}
      end

    [protected, header, payload, bytes(signature)]
  end

  defp bytes(data), do: %CBOR.Tag{tag: :bytes, value: data}
  defp tagged(value), do: %CBOR.Tag{tag: 24, value: bytes(CBOR.encode(value))}

  defp decode!(data) do
    {:ok, value, ""} = CBOR.decode(data)
    value
  end
end
