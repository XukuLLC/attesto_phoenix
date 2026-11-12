defmodule AttestoPhoenix.IssuerCertificateFixture do
  @moduledoc false

  # Synthetic certificates and presentations using OTP's test certificate
  # generator, as in core's X509Fixture. No trust decisions are made here.
  alias Attesto.{Cose, JWS, Mdoc, SdJwtVc}

  require Record

  @records Record.extract_all(from_lib: "public_key/include/public_key.hrl")
  Record.defrecordp(:certificate, :OTPCertificate, @records[:OTPCertificate])
  Record.defrecordp(:tbs_certificate, :OTPTBSCertificate, @records[:OTPTBSCertificate])
  Record.defrecordp(:extension, :Extension, @records[:Extension])

  @curve {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}
  @issuer "https://issuer.example"
  @doc_type "org.iso.18013.5.1.mDL"
  @namespace "org.iso.18013.5.1"

  def issuer, do: @issuer
  def doc_type, do: @doc_type
  def namespace, do: @namespace
  def root, do: :public_key.pkix_test_root_cert(~c"synthetic-issuer-root", key: @curve)

  def chain(root, format, opts \\ []) do
    extensions = [san(Keyword.get(opts, :issuer, @issuer)) | purpose_extensions(format)]
    peer = Keyword.merge([key: @curve, extensions: extensions], Keyword.get(opts, :peer, []))

    data =
      :public_key.pkix_test_data(%{
        root: root,
        intermediates: [[key: @curve]],
        peer: peer
      })

    %{
      format: format,
      chain: [data[:cert] | Enum.reject(data[:cacerts], &(&1 == root.cert))],
      key: data[:key] |> elem(1) |> JOSE.JWK.from_der(),
      anchors: [root.cert]
    }
  end

  def invalid(:unknown_root, fixture, _root), do: %{fixture | anchors: [root().cert]}
  def invalid(:embedded_anchor, fixture, _root), do: %{fixture | chain: fixture.chain ++ fixture.anchors}

  def invalid(:expired_leaf, fixture, root),
    do: chain(root, fixture.format, peer: [validity: {{2000, 1, 1}, {2001, 1, 1}}])

  def invalid(:self_signed_leaf, fixture, _root) do
    root =
      :public_key.pkix_test_root_cert(~c"synthetic-self-signed-leaf",
        key: @curve,
        extensions:
          [
            san(@issuer),
            non_ca(),
            {:Extension, {2, 5, 29, 15}, true, [:digitalSignature]}
          ] ++ purpose_extensions(fixture.format)
      )

    %{fixture | chain: [root.cert], anchors: [root.cert], key: JOSE.JWK.from_key(root.key)}
  end

  def invalid(:non_ca_intermediate, fixture, root) do
    [leaf, intermediate] = fixture.chain
    tbs = intermediate |> :public_key.pkix_decode_cert(:otp) |> certificate(:tbsCertificate)
    extensions = Enum.reject(tbs_certificate(tbs, :extensions), &(extension(&1, :extnID) == {2, 5, 29, 19}))
    intermediate = tbs |> tbs_certificate(extensions: [non_ca() | extensions]) |> :public_key.pkix_sign(root.key)
    %{fixture | chain: [leaf, intermediate]}
  end

  def presentation(fixture, holder, session, response_uri, opts \\ [])

  def presentation(%{format: :sd_jwt_vc} = fixture, holder, session, _response_uri, opts) do
    now = System.system_time(:second)

    certificate_options =
      if Keyword.get(opts, :omit_chain), do: [], else: [x5c: Enum.map(fixture.chain, &Base.encode64/1)]

    vc =
      SdJwtVc.issue(
        [iss: @issuer, vct: "identity", pem: pem(fixture.key)],
        [claims: %{"given_name" => "Alice"}, cnf: %{"jwk" => public(holder)}, iat: now] ++ certificate_options
      )

    kb =
      JWS.sign_compact_jwk(holder, %{"alg" => "ES256", "typ" => "kb+jwt"}, %{
        "nonce" => session.nonce,
        "aud" => session.client_id,
        "iat" => now,
        "sd_hash" => Base.url_encode64(:crypto.hash(:sha256, vc), padding: false)
      })

    vc <> kb
  end

  def presentation(%{format: :mdoc} = fixture, holder, session, response_uri, opts) do
    issuer_signed = issue_mdoc(fixture, holder)

    issuer_signed =
      if Keyword.get(opts, :omit_chain) do
        [protected, header, payload, signature] = issuer_signed["issuerAuth"]
        Map.put(issuer_signed, "issuerAuth", [protected, Map.delete(header, 33), payload, signature])
      else
        issuer_signed
      end

    hash = :crypto.hash(:sha256, CBOR.encode([session.client_id, session.nonce, nil, response_uri]))
    transcript = [nil, nil, ["OpenID4VPHandover", bytes(hash)]]
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

  def public(key), do: key |> JOSE.JWK.to_public_map() |> elem(1)

  defp issue_mdoc(fixture, holder) do
    now = System.system_time(:second)

    {:ok, issued} =
      Mdoc.issue(
        doc_type: @doc_type,
        namespaces: %{@namespace => %{"given_name" => "Alice"}},
        device_key: public(holder),
        issuer_pem: pem(fixture.key),
        x5chain: fixture.chain,
        validity: %{signed: now - 10, valid_from: now - 5, valid_until: now + 3600}
      )

    issued |> Base.url_decode64!(padding: false) |> decode!()
  end

  defp purpose_extensions(:sd_jwt_vc), do: []
  defp purpose_extensions(:mdoc), do: [{:Extension, {2, 5, 29, 37}, true, [{1, 0, 18_013, 5, 1, 2}]}]
  defp san(issuer), do: {:Extension, {2, 5, 29, 17}, false, [{:uniformResourceIdentifier, String.to_charlist(issuer)}]}
  defp non_ca, do: {:Extension, {2, 5, 29, 19}, true, {:BasicConstraints, false, :asn1_NOVALUE}}
  defp pem(key), do: key |> JOSE.JWK.to_pem() |> elem(1)
  defp tagged(value), do: %CBOR.Tag{tag: 24, value: bytes(CBOR.encode(value))}
  defp bytes(value), do: %CBOR.Tag{tag: :bytes, value: value}

  defp decode!(encoded) do
    {:ok, decoded, ""} = CBOR.decode(encoded)
    decoded
  end
end
