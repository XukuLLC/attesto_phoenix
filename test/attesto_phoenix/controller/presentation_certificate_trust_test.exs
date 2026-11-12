defmodule AttestoPhoenix.CertificatePresentationTestRouter do
  @moduledoc false
  use Phoenix.Router
  use AttestoPhoenix.Router

  alias AttestoPhoenix.Plug.PutConfig

  pipeline :wallet_protocol do
    plug PutConfig, otp_app: :attesto_phoenix
    plug Plug.Parsers, parsers: [:urlencoded, :json], pass: ["*/*"], json_decoder: JSON
  end

  scope "/" do
    pipe_through :wallet_protocol
    attesto_routes(presentation: true)
  end
end

defmodule AttestoPhoenix.Controller.PresentationCertificateTrustTest do
  use AttestoPhoenix.ConnCase, endpoint: AttestoPhoenix.CertificatePresentationTestRouter

  alias Attesto.{JWS, PresentationRequest}
  alias Attesto.PresentationSessionStore.ETS, as: Store
  alias AttestoPhoenix.{Config, Verifier, X509TestCertificate}
  alias AttestoPhoenix.IssuerCertificateFixture, as: Fixture

  defmodule Keystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem, do: X509TestCertificate.private_key_pem()
    @impl true
    def verification_pems, do: [signing_pem()]
  end

  defmodule Policy do
    @moduledoc false
    def reject(chain), do: reject(chain, self())

    def reject(chain, observer) do
      send(observer, {:certificate_policy, chain})
      {:error, :denied}
    end

    def resolve(_issuer, key, observer) do
      send(observer, :issuer_resolved)
      {:ok, key}
    end
  end

  setup_all do
    root = Fixture.root()

    %{
      root: root,
      sd_jwt_vc: Fixture.chain(root, :sd_jwt_vc),
      mdoc: Fixture.chain(root, :mdoc),
      holder: JOSE.JWK.generate_key({:ec, "P-256"})
    }
  end

  setup do
    start_supervised!(Store)
    previous = Application.get_env(:attesto_phoenix, Config)
    previous_app = Application.get_env(:attesto_phoenix, :otp_app)
    Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)

    on_exit(fn ->
      restore_env(Config, previous)
      restore_env(:otp_app, previous_app)
    end)

    %{config_opts: config_options()}
  end

  for format <- [:sd_jwt_vc, :mdoc] do
    @format format

    test "controllers accept #{@format} chained to a configured anchor and consume the result once", ctx do
      fixture = ctx[@format]
      config = configure(ctx, fixture)
      session = create_request(config, @format)
      assert {:ok, entry} = Store.get(session.id)
      assert entry.data.issuer_trust == {:trusted_certificates, fixture.anchors}
      assert :erlang.binary_to_term(:erlang.term_to_binary(entry)) == entry
      refute Map.has_key?(entry.data, :certificate_trust)
      refute Map.has_key?(entry.data, :verifier_certificate_trust)

      params = response_params(ctx, fixture, session, config)
      response = post(build_conn(), Config.presentation_response_path(config), params)
      assert response.status == 200
      assert get_resp_header(response, "cache-control") == ["no-store"]
      assert {:ok, %{data: %{status: :completed}}} = Store.get(session.id)

      replay = post(build_conn(), Config.presentation_response_path(config), params)
      assert_invalid_request(replay, session.id, :completed)

      code = response_code(response)
      assert {:ok, %{"identity" => [result]}} = Verifier.presentation_result(config, code)
      assert_claims(@format, result)
      assert :error = Verifier.presentation_result(config, code)
    end

    for failure <- [:unknown_root, :expired_leaf, :self_signed_leaf, :embedded_anchor, :non_ca_intermediate] do
      @failure failure

      test "controllers refuse #{@format} #{@failure} and keep the session pending", ctx do
        fixture = Fixture.invalid(@failure, ctx[@format], ctx.root)
        {response, session, _config} = submit(ctx, fixture)
        assert_invalid_request(response, session.id)
      end
    end

    test "controllers enforce rejecting #{@format} certificate policies in every callback form", ctx do
      fixture = ctx[@format]

      for callback <- [&Policy.reject/1, {Policy, :reject}, {Policy, :reject, [self()]}] do
        {response, session, _config} = submit(ctx, fixture, verifier_certificate_trust: callback)
        assert_invalid_request(response, session.id)
        assert_received {:certificate_policy, chain}
        assert chain == fixture.chain
        assert {:ok, entry} = Store.get(session.id)
        refute Map.has_key?(entry.data, :certificate_trust)
      end
    end

    test "an allowing policy cannot override an untrusted #{@format} chain", ctx do
      observer = self()
      policy = fn _chain -> send(observer, :policy_called) && :ok end
      fixture = Fixture.invalid(:unknown_root, ctx[@format], ctx.root)
      {response, session, _config} = submit(ctx, fixture, verifier_certificate_trust: policy)
      assert_invalid_request(response, session.id)
      refute_received :policy_called
    end

    test "controllers forward haip false for #{@format} while retaining path and host policy checks", ctx do
      fixture = Fixture.invalid(:embedded_anchor, ctx[@format], ctx.root)
      {response, _session, config} = submit(ctx, fixture, verifier_haip: false)
      assert {:ok, %{"identity" => [result]}} = Verifier.presentation_result(config, response_code(response))
      assert_claims(@format, result)

      {response, session, _config} =
        submit(ctx, fixture, verifier_haip: false, verifier_certificate_trust: {Policy, :reject})

      assert_invalid_request(response, session.id)
      assert_received {:certificate_policy, chain}
      assert chain == fixture.chain

      unknown = Fixture.invalid(:unknown_root, fixture, ctx.root)
      {response, session, _config} = submit(ctx, unknown, verifier_haip: false)
      assert_invalid_request(response, session.id)
    end

    test "controllers require the #{@format} leaf key and certificate chain", ctx do
      wrong_key = %{ctx[@format] | key: JOSE.JWK.generate_key({:ec, "P-256"})}
      {response, session, _config} = submit(ctx, wrong_key)
      assert_invalid_request(response, session.id)

      config = configure(ctx, ctx[@format])
      session = create_request(config, @format)
      params = response_params(ctx, ctx[@format], session, config, omit_chain: true)
      response = post(build_conn(), Config.presentation_response_path(config), params)
      assert_invalid_request(response, session.id)
    end

    test "certificate trust retains #{@format} nonce binding", ctx do
      fixture = ctx[@format]
      config = configure(ctx, fixture)
      session = create_request(config, @format)
      params = response_params(ctx, fixture, %{session | nonce: "wrong-nonce"}, config)
      response = post(build_conn(), Config.presentation_response_path(config), params)
      assert_invalid_request(response, session.id)
    end

    test "without anchors #{@format} still accepts per-request issuer keys and resolvers without certificates", ctx do
      fixture = ctx[@format]
      key = Fixture.public(fixture.key)
      observer = self()
      resolver = fn _issuer -> send(observer, :issuer_resolved) && {:ok, key} end

      config =
        configure(ctx, fixture,
          verifier_trusted_certificates: nil,
          verifier_certificate_trust: {Policy, :reject}
        )

      for trust <- [{:issuer_jwks, key}, {:resolve_issuer, resolver}] do
        session = create_request(config, @format, %{issuer_trust: trust})
        params = response_params(ctx, fixture, session, config, omit_chain: true)
        response = post(build_conn(), Config.presentation_response_path(config), params)
        assert {:ok, %{"identity" => [result]}} = Verifier.presentation_result(config, response_code(response))
        assert_claims(@format, result)
      end

      assert_received :issuer_resolved
      refute_received {:certificate_policy, _chain}
    end

    test "configured #{@format} keys and MFA resolvers work as defaults without anchors", ctx do
      fixture = ctx[@format]
      key = Fixture.public(fixture.key)

      for trust <- [{:issuer_jwks, key}, {:resolve_issuer, {Policy, :resolve, [key, self()]}}] do
        {response, _session, config} =
          submit(ctx, fixture, verifier_trusted_certificates: nil, verifier_issuer_trust: trust)

        assert {:ok, %{"identity" => [result]}} = Verifier.presentation_result(config, response_code(response))
        assert_claims(@format, result)
      end

      assert_received :issuer_resolved
    end

    test "direct verifier API enforces configured #{@format} certificate policy", ctx do
      fixture = ctx[@format]
      config = configure(ctx, fixture, verifier_certificate_trust: {Policy, :reject})
      session = create_request(config, @format)
      params = response_params(ctx, fixture, session, config)
      assert {:error, :invalid_request} = Verifier.complete_presentation_response(config, params)
      assert_received {:certificate_policy, chain}
      assert chain == fixture.chain
      assert {:ok, %{data: %{status: :pending}}} = Store.get(session.id)
    end
  end

  test "controllers refuse an SD-JWT VC leaf naming another issuer", ctx do
    fixture = Fixture.chain(ctx.root, :sd_jwt_vc, issuer: "https://other.example")
    {response, session, _config} = submit(ctx, fixture)
    assert_invalid_request(response, session.id)
  end

  test "request-signing certificates remain separate from credential issuer trust", ctx do
    fixture = ctx.sd_jwt_vc

    config =
      configure(ctx, fixture,
        verifier_client_id_scheme: "x509_san_dns",
        verifier_dns: "verifier.example",
        verifier_x5c: [X509TestCertificate.der()]
      )

    session = create_request(config, :sd_jwt_vc)
    assert {:ok, %{data: %{request_object: jar}}} = Store.get(session.id)
    assert {:ok, %{"x5c" => [encoded]}} = JWS.peek_json(jar, :protected)
    assert Base.decode64!(encoded) == X509TestCertificate.der()
    refute X509TestCertificate.der() in Config.verifier_trusted_certificates(config)

    params = response_params(ctx, fixture, session, config)
    assert {:ok, _body} = Verifier.complete_presentation_response(config, params)
  end

  test "configured anchors refuse per-request issuer keys, resolvers, or alternate anchors", ctx do
    fixture = ctx.sd_jwt_vc
    config = configure(ctx, fixture)
    observer = self()
    resolver = fn _issuer -> send(observer, :resolver_called) && {:ok, Fixture.public(fixture.key)} end

    for trust <- [
          {:issuer_jwks, Fixture.public(fixture.key)},
          {:resolve_issuer, resolver},
          {:trusted_certificates, [Fixture.root().cert]}
        ] do
      attrs = Map.put(request_attrs(:sd_jwt_vc), :issuer_trust, trust)
      assert {:error, :conflicting_issuer_trust} = Verifier.create_presentation_request(config, attrs)
    end

    refute_received :resolver_called
  end

  defp config_options do
    [
      issuer: "https://verifier.example",
      audience: "https://verifier.example",
      keystore: Keystore,
      repo: __MODULE__.Repo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      principal_kinds: [Attesto.PrincipalKind.new("user", "ou_")],
      require_https: false,
      presentation_session_store: Store,
      verifier_client_id: "verifier-client"
    ]
  end

  defp configure(ctx, fixture, options \\ []) do
    options =
      ctx.config_opts
      |> Keyword.put(:verifier_trusted_certificates, fixture.anchors)
      |> Keyword.merge(options)

    config = Config.new(options)
    Application.put_env(:attesto_phoenix, Config, options)
    config
  end

  defp create_request(config, format, extra_attrs \\ %{}) do
    attrs = Map.merge(request_attrs(format), extra_attrs)
    assert {:ok, session} = Verifier.create_presentation_request(config, attrs)
    response = get(build_conn(), URI.parse(session.request_uri).path)
    assert response.status == 200
    assert get_resp_header(response, "content-type") == ["application/oauth-authz-req+jwt"]
    assert {:ok, %{data: %{request_object: jar}}} = Store.get(session.id)
    assert response.resp_body == jar
    signing_key = Keystore.signing_pem() |> JOSE.JWK.from_pem() |> Fixture.public()
    assert {:ok, claims} = JWS.verify_strict(jar, JWS.verification_candidates(signing_key), claims_map?: true)
    assert claims["state"] == session.id
    assert claims["nonce"] == session.nonce
    session
  end

  defp request_attrs(format) do
    credential =
      case format do
        :sd_jwt_vc -> %{id: "identity", format: "dc+sd-jwt", meta: %{vct_values: ["identity"]}}
        :mdoc -> %{id: "identity", format: "mso_mdoc", meta: %{doctype_value: Fixture.doc_type()}}
      end

    %{
      dcql_query: PresentationRequest.dcql_query(%{credentials: [credential]}),
      expected_query_ids: ["identity"]
    }
  end

  defp submit(ctx, fixture, options \\ []) do
    config = configure(ctx, fixture, options)
    session = create_request(config, fixture.format)
    params = response_params(ctx, fixture, session, config)
    response = post(build_conn(), Config.presentation_response_path(config), params)
    {response, session, config}
  end

  defp response_params(ctx, fixture, session, config, options \\ []) do
    presentation =
      Fixture.presentation(fixture, ctx.holder, session, Config.presentation_response_endpoint_url(config), options)

    %{"state" => session.id, "vp_token" => JSON.encode!(%{"identity" => [presentation]})}
  end

  defp response_code(response) do
    %{"redirect_uri" => uri} = json_response(response, 200)
    uri |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query() |> Map.fetch!("response_code")
  end

  defp assert_invalid_request(response, session_id, status \\ :pending) do
    assert json_response(response, 400) == %{"error" => "invalid_request"}
    assert get_resp_header(response, "cache-control") == ["no-store"]
    assert {:ok, %{data: %{status: ^status}}} = Store.get(session_id)
  end

  defp assert_claims(:sd_jwt_vc, result) do
    assert result.iss == Fixture.issuer()
    assert result.claims["given_name"] == "Alice"
  end

  defp assert_claims(:mdoc, result) do
    assert result.doc_type == Fixture.doc_type()
    assert result.namespaces[Fixture.namespace()]["given_name"] == "Alice"
  end

  defp restore_env(key, nil), do: Application.delete_env(:attesto_phoenix, key)
  defp restore_env(key, value), do: Application.put_env(:attesto_phoenix, key, value)
end
