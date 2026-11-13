defmodule AttestoPhoenix.DCApiTestRouter do
  @moduledoc false
  use Phoenix.Router
  use AttestoPhoenix.Router

  alias AttestoPhoenix.Plug.PutConfig

  pipeline :presentation do
    plug PutConfig, otp_app: :attesto_phoenix
    plug Plug.Parsers, parsers: [:json, :urlencoded], pass: ["*/*"], json_decoder: JSON
  end

  scope "/" do
    pipe_through :presentation
    attesto_routes(presentation: true)
  end
end

defmodule AttestoPhoenix.Controller.PresentationDCApiTest do
  use AttestoPhoenix.ConnCase, endpoint: AttestoPhoenix.DCApiTestRouter

  alias Attesto.{JWS, PresentationRequest}
  alias Attesto.PresentationSessionStore.ETS, as: Store
  alias AttestoPhoenix.{Config, Verifier, X509TestCertificate}
  alias AttestoPhoenix.DCApiFixture, as: Fixture

  @origin "https://page.example:8443"

  defmodule Keystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem, do: X509TestCertificate.private_key_pem()
    @impl true
    def verification_pems, do: [signing_pem()]
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

    %{issuer: JOSE.JWK.generate_key({:ec, "P-256"}), holder: JOSE.JWK.generate_key({:ec, "P-256"})}
  end

  test "signed DC API request records its origin and mode and exposes browser invocation data", ctx do
    config = configure(ctx)
    session = create(config)
    request = get(build_conn(), URI.parse(session.request_uri).path)
    descriptor = json_response(request, 200)
    assert descriptor == session.dc_api_request
    assert descriptor["protocol"] == "openid4vp-v1-signed"
    assert get_resp_header(request, "cache-control") == ["no-store"]
    assert get_resp_header(request, "pragma") == ["no-cache"]
    jar = descriptor["data"]["request"]
    public = Keystore.signing_pem() |> JOSE.JWK.from_pem() |> Fixture.public()
    assert {:ok, claims} = JWS.verify_strict(jar, JWS.verification_candidates(public), claims_map?: true)
    assert claims["response_mode"] == "dc_api.jwt"
    assert claims["expected_origins"] == [@origin]
    assert claims["client_id"] == "verifier-client"
    assert claims["nonce"] == session.nonce
    assert claims["response_type"] == "vp_token"
    for field <- ["state", "response_uri", "redirect_uri", "request_uri"], do: refute(Map.has_key?(claims, field))
    assert claims["client_metadata"]["encrypted_response_enc_values_supported"] == ["A128GCM", "A256GCM"]
    assert claims["client_metadata"]["vp_formats_supported"]["mso_mdoc"]["issuerauth_alg_values"] == [-7]
    assert {:ok, %{data: data} = entry} = Store.get(session.id)
    assert data.request_object == jar
    assert data.audience == "origin:" <> @origin
    assert :erlang.binary_to_term(:erlang.term_to_binary(entry)) == entry
    refute Map.has_key?(encryption_jwk(session), "d")
    second = create(config)
    refute encryption_jwk(session)["x"] == encryption_jwk(second)["x"]
  end

  for enc <- ["A128GCM", "A256GCM"] do
    @enc enc
    test "#{enc} mdoc response completes without state and is consumed once", ctx do
      config = configure(ctx)
      session = create(config)
      params = encrypted_mdoc(ctx, config, session, [], @enc)
      response = post_data(session, params)
      %{"response_code" => code} = json_response(response, 200)
      assert_invalid(post_data(session, params), session, :completed)
      assert {:ok, %{"identity" => [result]}} = Verifier.presentation_result(config, code)
      assert result.namespaces[Fixture.namespace()]["given_name"] == "Alice"
      assert :error = Verifier.presentation_result(config, code)
    end
  end

  test "another origin fails even when Origin headers and body fields claim that origin", ctx do
    config = configure(ctx)
    session = create(config)
    params = encrypted_mdoc(ctx, config, session, origin: "https://other.example")
    params = Map.merge(params, %{"origin" => "https://other.example", "dc_api_origin" => "https://other.example"})

    response =
      build_conn()
      |> put_req_header("origin", "https://other.example")
      |> put_req_header("x-forwarded-host", "other.example")
      |> put_req_header("content-type", "application/json")
      |> post(URI.parse(session.response_uri).path, JSON.encode!(params))

    assert_invalid(response, session)
    assert post_data(session, encrypted_mdoc(ctx, config, session)).status == 200
  end

  for failure <- [:nonce, :response_key] do
    @failure failure
    test "mdoc refuses wrong #{@failure} binding", ctx do
      config = configure(ctx)
      session = create(config)

      options =
        case @failure do
          :nonce -> [nonce: "wrong-nonce"]
          :response_key -> [binding_jwk: Fixture.public(JOSE.JWK.generate_key({:ec, "P-256"}))]
        end

      assert_invalid(post_data(session, encrypted_mdoc(ctx, config, session, options)), session)
    end
  end

  test "redirect handover cannot complete a DC API session", ctx do
    config = configure(ctx)
    session = create(config)
    assert_invalid(post_data(session, encrypted_mdoc(ctx, config, session, flow: :redirect)), session)
  end

  test "DC API handover cannot complete a redirect session", ctx do
    config = configure(ctx, presentation_response_mode: "direct_post.jwt")
    session = create(config)
    token = mdoc(ctx, config, session, [])

    params = %{
      "response" =>
        Fixture.encrypt(encryption_jwk(session), %{"vp_token" => %{"identity" => [token]}, "state" => session.id})
    }

    response = post(build_conn(), Config.presentation_response_path(config), params)
    assert_invalid(response, session)
  end

  test "transport endpoints reject sessions from the other flow before completion", ctx do
    config = configure(ctx)
    dc = create(config)
    dc_params = encrypted_mdoc(ctx, config, dc)
    assert_invalid(post(build_conn(), Config.presentation_response_path(config), dc_params), dc)
    redirect = create(config, %{response_mode: "direct_post.jwt"})
    token = mdoc(ctx, config, redirect, flow: :redirect)

    params = %{
      "response" =>
        Fixture.encrypt(encryption_jwk(redirect), %{"vp_token" => %{"identity" => [token]}, "state" => redirect.id})
    }

    response = post(build_conn(), Config.presentation_response_path(config) <> "/" <> redirect.id, params)
    assert_invalid(response, redirect)
  end

  test "a DC API override works with the default redirect config", ctx do
    config = configure(ctx, presentation_response_mode: "direct_post")
    session = create(config, %{response_mode: "dc_api.jwt"})
    assert post_data(session, encrypted_mdoc(ctx, config, session)).status == 200
  end

  test "the path session must match the JWE kid and any inner state", ctx do
    config = configure(ctx)
    first = create(config)
    second = create(config)
    assert_invalid(post_data(second, encrypted_mdoc(ctx, config, first)), second)
    token = mdoc(ctx, config, first, [])

    params = %{
      "response" =>
        Fixture.encrypt(encryption_jwk(first), %{"vp_token" => %{"identity" => [token]}, "state" => second.id})
    }

    assert_invalid(post_data(first, params), first)
  end

  test "plaintext, wallet errors, and malformed JWE cannot complete DC API sessions", ctx do
    config = configure(ctx)
    session = create(config)

    for params <- [
          %{"vp_token" => %{}, "state" => session.id},
          %{"error" => "access_denied"},
          %{"response" => "invalid"}
        ] do
      assert_invalid(post_data(session, params), session)
    end
  end

  test "unknown and expired DC API sessions are refused", ctx do
    config = configure(ctx)
    session = create(config)
    params = encrypted_mdoc(ctx, config, session)
    response = post(build_conn(), Config.presentation_response_path(config) <> "/unknown", params)
    assert json_response(response, 400) == %{"error" => "invalid_request"}
    assert {:ok, entry} = Store.get(session.id)
    expired_id = "expired-session"

    expired = %{
      entry
      | id: expired_id,
        expires_at: System.system_time(:second) - 1,
        data: Map.put(entry.data, :state, expired_id)
    }

    :ok = Store.put(expired)
    expired_key = Map.put(encryption_jwk(session), "kid", expired_id)
    token = mdoc(ctx, config, session, [])
    expired_params = %{"response" => Fixture.encrypt(expired_key, %{"vp_token" => %{"identity" => [token]}})}
    response = post(build_conn(), Config.presentation_response_path(config) <> "/" <> expired_id, expired_params)
    assert json_response(response, 400) == %{"error" => "invalid_request"}
    assert get(build_conn(), Config.presentation_request_path(config) <> "/" <> expired_id).status == 404
  end

  test "SD-JWT key binding uses the configured origin even for signed requests", ctx do
    config = configure(ctx)
    session = create(config, %{}, "dc+sd-jwt")

    for audience <- [session.client_id, "origin:https://other.example"] do
      token = Fixture.sd_jwt(ctx.issuer, ctx.holder, session, audience)
      params = %{"response" => Fixture.encrypt(encryption_jwk(session), %{"vp_token" => %{"identity" => [token]}})}
      assert_invalid(post_data(session, params), session)
    end

    token = Fixture.sd_jwt(ctx.issuer, ctx.holder, session, "origin:" <> @origin)
    params = %{"response" => Fixture.encrypt(encryption_jwk(session), %{"vp_token" => %{"identity" => [token]}})}
    assert post_data(session, params).status == 200
  end

  for {alg, curve, cose} <- [{"ES384", "P-384", -35}, {"ES512", "P-521", -36}] do
    @alg alg
    @curve curve
    @cose cose
    test "#{alg} mdoc issuers require explicit configuration in both flows", ctx do
      ctx = %{ctx | issuer: JOSE.JWK.generate_key({:ec, @curve})}

      for mode <- ["dc_api.jwt", "direct_post.jwt"] do
        config = configure(ctx, presentation_response_mode: mode)
        session = create(config)
        assert_invalid(submit_issuer(ctx, config, session, @alg), session)
        config = configure(ctx, presentation_response_mode: mode, verifier_accepted_algs: ["ES256", @alg])
        session = create(config)
        assert {:ok, claims} = request_claims(session)
        assert claims["client_metadata"]["vp_formats_supported"]["mso_mdoc"]["issuerauth_alg_values"] == [-7, @cose]
        assert claims["client_metadata"]["vp_formats_supported"]["mso_mdoc"]["deviceauth_alg_values"] == [-7]
        assert submit_issuer(ctx, config, session, @alg).status == 200
      end
    end
  end

  test "DC API forwards certificate trust, ES384 policy, and rejecting host policy", ctx do
    root = AttestoPhoenix.IssuerCertificateFixture.root()
    fixture = AttestoPhoenix.IssuerCertificateFixture.chain(root, :mdoc, peer: [key: {:namedCurve, {1, 3, 132, 0, 34}}])
    ctx = %{ctx | issuer: fixture.key}
    opts = [verifier_issuer_trust: nil, verifier_trusted_certificates: fixture.anchors]
    config = configure(ctx, opts)
    session = create(config)
    params = encrypted_mdoc(ctx, config, session, alg: "ES384", x5chain: fixture.chain)
    assert_invalid(post_data(session, params), session)

    opts = Keyword.put(opts, :verifier_accepted_algs, ["ES256", "ES384"])
    config = configure(ctx, opts)
    session = create(config)
    assert post_data(session, encrypted_mdoc(ctx, config, session, alg: "ES384", x5chain: fixture.chain)).status == 200

    observer = self()

    policy = fn chain ->
      send(observer, {:chain, chain})
      {:error, :denied}
    end

    config = configure(ctx, Keyword.put(opts, :verifier_certificate_trust, policy))
    session = create(config)

    assert_invalid(
      post_data(session, encrypted_mdoc(ctx, config, session, alg: "ES384", x5chain: fixture.chain)),
      session
    )

    assert_received {:chain, chain}
    assert chain == fixture.chain
  end

  test "DC API signed requests support configured x509_hash client identifiers", ctx do
    certificate = X509TestCertificate.der()
    config = configure(ctx, verifier_client_id_scheme: "x509_hash", verifier_x5c: [certificate])
    session = create(config)
    response = get(build_conn(), URI.parse(session.request_uri).path)
    jar = json_response(response, 200)["data"]["request"]
    assert {:ok, claims} = JWS.peek_json(jar, :payload)
    assert {:ok, header} = JWS.peek_json(jar, :protected)
    assert claims["client_id"] == "x509_hash:" <> Base.url_encode64(:crypto.hash(:sha256, certificate), padding: false)
    assert claims["expected_origins"] == [@origin]
    assert header["x5c"] == [Base.encode64(certificate)]
    assert post_data(session, encrypted_mdoc(ctx, config, session)).status == 200
  end

  test "DC API request overrides cannot supply the origin or enable plaintext", ctx do
    config = configure(ctx)
    session = create(config, %{dc_api_origin: "https://other.example", expected_origins: ["https://other.example"]})
    assert {:ok, claims} = request_claims(session)
    assert claims["expected_origins"] == [@origin]
    query = claims["dcql_query"]

    assert {:error, :invalid_attrs} =
             Verifier.create_presentation_request(config, %{
               dcql_query: query,
               expected_query_ids: ["identity"],
               response_mode: "dc_api"
             })

    config = configure(ctx, presentation_response_mode: "direct_post", verifier_dc_api_origin: nil)

    assert {:error, :dc_api_origin_required} =
             Verifier.create_presentation_request(config, %{
               dcql_query: query,
               expected_query_ids: ["identity"],
               response_mode: "dc_api.jwt",
               dc_api_origin: @origin
             })
  end

  test "DC API retains the session's DCQL constraints", ctx do
    config = configure(ctx)

    query =
      PresentationRequest.dcql_query(%{
        credentials: [
          %{
            id: "identity",
            format: "mso_mdoc",
            meta: %{doctype_value: "another.document.type"}
          }
        ]
      })

    session = create(config, %{dcql_query: query})
    assert_invalid(post_data(session, encrypted_mdoc(ctx, config, session)), session)
  end

  test "DC API uses the shared JWE header and size checks", ctx do
    config = configure(ctx)
    session = create(config)
    %{"response" => valid} = encrypted_mdoc(ctx, config, session)
    [protected | rest] = String.split(valid, ".")
    header = protected |> Base.url_decode64!(padding: false) |> JSON.decode!()

    for change <- [%{"zip" => "DEF"}, %{"alg" => "dir"}, %{"enc" => "A128CBC-HS256"}] do
      protected = header |> Map.merge(change) |> JSON.encode!() |> Base.url_encode64(padding: false)
      assert_invalid(post_data(session, %{"response" => Enum.join([protected | rest], ".")}), session)
    end

    assert_invalid(post_data(session, %{"response" => String.duplicate(".", 100_000)}), session)
  end

  test "concurrent valid DC API submissions complete only once", ctx do
    config = configure(ctx)
    session = create(config)
    params = encrypted_mdoc(ctx, config, session)

    responses =
      1..4
      |> Task.async_stream(fn _ -> post_data(session, params).status end)
      |> Enum.map(fn {:ok, status} -> status end)

    assert Enum.sort(responses) == [200, 400, 400, 400]
  end

  defp configure(ctx, overrides \\ []) do
    options =
      Keyword.merge(
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
          verifier_client_id: "verifier-client",
          verifier_dc_api_origin: @origin,
          presentation_response_mode: "dc_api.jwt",
          verifier_issuer_trust: {:issuer_jwks, Fixture.public(ctx.issuer)}
        ],
        overrides
      )

    config = Config.new(options)
    Application.put_env(:attesto_phoenix, Config, options)
    config
  end

  defp create(config, overrides \\ %{}, format \\ "mso_mdoc") do
    meta = if format == "mso_mdoc", do: %{doctype_value: Fixture.doc_type()}, else: %{vct_values: ["identity"]}
    query = PresentationRequest.dcql_query(%{credentials: [%{id: "identity", format: format, meta: meta}]})

    assert {:ok, session} =
             Verifier.create_presentation_request(
               config,
               Map.merge(%{dcql_query: query, expected_query_ids: ["identity"]}, overrides)
             )

    session
  end

  defp request_claims(session) do
    assert {:ok, %{data: %{request_object: jar}}} = Store.get(session.id)
    JWS.peek_json(jar, :payload)
  end

  defp encryption_jwk(session) do
    {:ok, claims} = request_claims(session)
    hd(claims["client_metadata"]["jwks"]["keys"])
  end

  defp mdoc(ctx, config, session, opts) do
    opts = Keyword.merge([origin: @origin, response_uri: Config.presentation_response_endpoint_url(config)], opts)
    Fixture.mdoc(ctx.issuer, ctx.holder, session, encryption_jwk(session), opts)
  end

  defp encrypted_mdoc(ctx, config, session, opts \\ [], enc \\ "A128GCM") do
    token = mdoc(ctx, config, session, opts)
    %{"response" => Fixture.encrypt(encryption_jwk(session), %{"vp_token" => %{"identity" => [token]}}, enc)}
  end

  defp submit_issuer(ctx, %{presentation_response_mode: "dc_api.jwt"} = config, session, alg),
    do: post_data(session, encrypted_mdoc(ctx, config, session, alg: alg))

  defp submit_issuer(ctx, config, session, alg) do
    token = mdoc(ctx, config, session, flow: :redirect, alg: alg)

    params = %{
      "response" =>
        Fixture.encrypt(encryption_jwk(session), %{"vp_token" => %{"identity" => [token]}, "state" => session.id})
    }

    post(build_conn(), Config.presentation_response_path(config), params)
  end

  defp post_data(session, params) do
    build_conn()
    |> put_req_header("content-type", "application/json")
    |> post(URI.parse(session.response_uri).path, JSON.encode!(params))
  end

  defp assert_invalid(response, session, status \\ :pending) do
    assert json_response(response, 400) == %{"error" => "invalid_request"}
    assert get_resp_header(response, "cache-control") == ["no-store"]
    assert get_resp_header(response, "pragma") == ["no-cache"]
    assert {:ok, %{data: %{status: ^status}}} = Store.get(session.id)
  end

  defp restore_env(key, nil), do: Application.delete_env(:attesto_phoenix, key)
  defp restore_env(key, value), do: Application.put_env(:attesto_phoenix, key, value)
end
