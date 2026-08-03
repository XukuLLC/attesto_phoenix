defmodule AttestoPhoenix.PresentationTestRouter do
  @moduledoc false
  use Phoenix.Router
  use AttestoPhoenix.Router

  pipeline :wallet_protocol do
    plug Plug.Parsers,
      parsers: [:urlencoded, :json],
      pass: ["application/json", "application/x-www-form-urlencoded"],
      json_decoder: JSON
  end

  scope "/" do
    pipe_through :wallet_protocol
    attesto_routes(presentation: true)
  end
end

defmodule AttestoPhoenix.Controller.PresentationControllerTest do
  @moduledoc false

  use AttestoPhoenix.ConnCase, endpoint: AttestoPhoenix.PresentationTestRouter

  alias Attesto.{JWS, PresentationRequest, PresentationSession, SdJwtVc}
  alias Attesto.PresentationSessionStore.ETS, as: Store
  alias AttestoPhoenix.{Config, Verifier}

  @issuer "https://issuer.example"
  @verifier_client_id "verifier-client-1"
  @query_id "identity"

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

  setup do
    start_supervised!(Store)

    {request_pem, request_jwk} = keypair()
    {issuer_pem, issuer_jwk} = keypair()
    {holder_pem, holder_jwk} = keypair()

    Application.put_env(:attesto_phoenix, Keystore, signing_pem: request_pem)

    config_opts = [
      issuer: @issuer,
      audience: @issuer,
      keystore: Keystore,
      repo: __MODULE__.Repo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      require_https: false,
      presentation_session_store: Store,
      verifier_client_id: @verifier_client_id
    ]

    Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)
    Application.put_env(:attesto_phoenix, Config, config_opts)

    now = System.system_time(:second)

    vc =
      SdJwtVc.issue([iss: @issuer, vct: "identity", pem: issuer_pem],
        claims: %{"given_name" => "Alice", "family_name" => "Example"},
        cnf: %{"jwk" => holder_jwk},
        iat: now
      )

    on_exit(fn ->
      Application.delete_env(:attesto_phoenix, Keystore)
      Application.delete_env(:attesto_phoenix, Config)
      Application.delete_env(:attesto_phoenix, :otp_app)
    end)

    %{
      config: Config.new(config_opts),
      holder_pem: holder_pem,
      issuer_jwk: issuer_jwk,
      now: now,
      request_jwk: request_jwk,
      vc: vc
    }
  end

  test "request_uri serves the signed request object", %{conn: conn} = ctx do
    session = create_request(ctx)
    path = URI.parse(session.request_uri).path

    response = get(conn, path)

    assert response.status == 200
    assert response.resp_body == stored_request_object(session.id)
    assert get_resp_header(response, "content-type") == ["application/oauth-authz-req+jwt"]
    assert get_resp_header(response, "cache-control") == ["no-store"]
    assert get_resp_header(response, "pragma") == ["no-cache"]

    candidates = JWS.verification_candidates(ctx.request_jwk)
    assert {:ok, claims} = JWS.verify_strict(response.resp_body, candidates, claims_map?: true)
    assert claims["state"] == session.id
    assert claims["nonce"] == session.nonce
  end

  test "request_uri returns 404 for an unknown id", %{conn: conn, config: config} do
    path = Config.presentation_request_path(config) <> "/unknown"
    response = get(conn, path)

    assert response.status == 404
    assert get_resp_header(response, "cache-control") == ["no-store"]
  end

  test "direct_post verifies a form-encoded vp_token and exposes the host result", %{conn: conn} = ctx do
    session = create_request(ctx)
    vp_token = valid_vp_token(ctx, session.nonce)

    response = post_response(conn, ctx.config, session.id, JSON.encode!(vp_token))

    assert response.status == 200
    assert json_response(response, 200) == %{}
    assert get_resp_header(response, "cache-control") == ["no-store"]

    assert {:ok, %{@query_id => result}} =
             Verifier.presentation_result(ctx.config, session.id)

    assert result.vct == "identity"
    assert result.iss == @issuer
    assert result.claims["given_name"] == "Alice"
  end

  test "direct_post accepts a JSON-object vp_token", %{conn: conn} = ctx do
    session = create_request(ctx)
    vp_token = valid_vp_token(ctx, session.nonce)

    response = post_json_response(conn, ctx.config, session.id, vp_token)

    assert response.status == 200
    assert {:ok, %{@query_id => _result}} = Verifier.presentation_result(ctx.config, session.id)
  end

  test "direct_post.jwt decrypts a real response and exposes the host result", %{conn: conn} = ctx do
    config = configure_response_mode(ctx.config, "direct_post.jwt")
    ctx = %{ctx | config: config}
    session = create_request(ctx)
    vp_token = valid_vp_token(ctx, session.nonce)
    encryption_jwk = advertised_encryption_jwk(session.id, ctx.request_jwk)

    encrypted_response =
      encryption_jwk
      |> JOSE.JWK.from_map()
      |> encrypt_response(JSON.encode!(%{"vp_token" => vp_token, "state" => session.id}))

    response = post_encrypted_response(conn, config, encrypted_response)

    assert response.status == 200
    assert json_response(response, 200) == %{}

    assert {:ok, %{@query_id => result}} = Verifier.presentation_result(config, session.id)
    assert result.claims["given_name"] == "Alice"
  end

  test "direct_post.jwt rejects undecryptable and plaintext responses without completion",
       %{
         conn: conn
       } = ctx do
    config = configure_response_mode(ctx.config, "direct_post.jwt")
    ctx = %{ctx | config: config}
    undecryptable = create_request(ctx)

    encrypted_response =
      post_encrypted_response(conn, config, "not.a.valid.compact.jwe")

    assert_invalid_request(encrypted_response)
    assert_pending(undecryptable.id)

    plaintext = create_request(ctx)

    plaintext_response =
      post_response(
        recycle(conn),
        config,
        plaintext.id,
        JSON.encode!(valid_vp_token(ctx, plaintext.nonce))
      )

    assert_invalid_request(plaintext_response)
    assert_pending(plaintext.id)
  end

  test "wrong nonce and audience return the same public error without completion", %{conn: conn} = ctx do
    wrong_nonce = create_request(ctx)

    nonce_response =
      post_response(
        conn,
        ctx.config,
        wrong_nonce.id,
        JSON.encode!(valid_vp_token(ctx, "wrong-nonce"))
      )

    assert_invalid_request(nonce_response)
    assert_pending(wrong_nonce.id)
    assert :error = Verifier.presentation_result(ctx.config, wrong_nonce.id)

    wrong_audience = create_request(ctx)

    audience_response =
      post_response(
        recycle(conn),
        ctx.config,
        wrong_audience.id,
        JSON.encode!(valid_vp_token(ctx, wrong_audience.nonce, "wrong-audience"))
      )

    assert_invalid_request(audience_response)
    assert_pending(wrong_audience.id)
    assert :error = Verifier.presentation_result(ctx.config, wrong_audience.id)
  end

  test "unknown and expired state return the same public error", %{conn: conn} = ctx do
    unknown = post_response(conn, ctx.config, "unknown", JSON.encode!(%{}))
    assert_invalid_request(unknown)

    {:ok, expired} =
      PresentationSession.create(
        Store,
        %{
          audience: @verifier_client_id,
          expected_query_ids: [@query_id],
          issuer_trust: {:issuer_jwks, ctx.issuer_jwk}
        },
        now: ctx.now - 301,
        ttl: 300
      )

    expired_response =
      post_response(
        recycle(conn),
        ctx.config,
        expired.id,
        JSON.encode!(valid_vp_token(ctx, expired.nonce))
      )

    assert_invalid_request(expired_response)
  end

  test "double submit rejects the second response and preserves the first result", %{conn: conn} = ctx do
    session = create_request(ctx)
    encoded = session |> valid_vp_token_for_session(ctx) |> JSON.encode!()

    assert post_response(conn, ctx.config, session.id, encoded).status == 200
    assert {:ok, first_result} = Verifier.presentation_result(ctx.config, session.id)

    second = post_response(recycle(conn), ctx.config, session.id, encoded)
    assert_invalid_request(second)
    assert {:ok, ^first_result} = Verifier.presentation_result(ctx.config, session.id)
  end

  test "malformed vp_token returns invalid_request without verification details", %{conn: conn} = ctx do
    session = create_request(ctx)
    response = post_response(conn, ctx.config, session.id, "not-json")

    assert_invalid_request(response)
    assert_pending(session.id)
  end

  defp create_request(ctx) do
    assert {:ok, session} =
             Verifier.create_presentation_request(ctx.config, %{
               dcql_query: dcql_query(),
               expected_query_ids: [@query_id],
               issuer_trust: {:issuer_jwks, ctx.issuer_jwk}
             })

    session
  end

  defp dcql_query do
    PresentationRequest.dcql_query(%{
      credentials: [%{id: @query_id, format: "dc+sd-jwt", meta: %{vct_values: ["identity"]}}]
    })
  end

  defp valid_vp_token(ctx, nonce, audience \\ @verifier_client_id) do
    presentation = ctx.vc <> key_binding_jwt(ctx.holder_pem, ctx.vc, nonce, audience, ctx.now)
    %{@query_id => presentation}
  end

  defp valid_vp_token_for_session(session, ctx), do: valid_vp_token(ctx, session.nonce)

  defp key_binding_jwt(holder_pem, presentation, nonce, audience, now) do
    JWS.sign_compact(holder_pem, %{"alg" => "ES256", "typ" => "kb+jwt"}, %{
      "nonce" => nonce,
      "aud" => audience,
      "iat" => now,
      "sd_hash" => hash(presentation)
    })
  end

  defp hash(value), do: :crypto.hash(:sha256, value) |> Base.url_encode64(padding: false)

  defp post_response(conn, config, state, vp_token) do
    post(conn, Config.presentation_response_path(config), %{
      "state" => state,
      "vp_token" => vp_token
    })
  end

  defp post_json_response(conn, config, state, vp_token) do
    body = JSON.encode!(%{"state" => state, "vp_token" => vp_token})

    conn
    |> put_req_header("content-type", "application/json")
    |> post(Config.presentation_response_path(config), body)
  end

  defp post_encrypted_response(conn, config, encrypted_response) do
    post(conn, Config.presentation_response_path(config), %{"response" => encrypted_response})
  end

  defp advertised_encryption_jwk(id, request_jwk) do
    candidates = JWS.verification_candidates(request_jwk)
    assert {:ok, claims} = JWS.verify_strict(stored_request_object(id), candidates, claims_map?: true)
    get_in(claims, ["client_metadata", "jwks", "keys", Access.at(0)])
  end

  defp encrypt_response(recipient_jwk, plaintext) do
    ephemeral_jwk = JOSE.JWK.generate_key({:ec, "P-256"})

    {recipient_jwk, ephemeral_jwk}
    |> JOSE.JWE.block_encrypt(plaintext, %{"alg" => "ECDH-ES", "enc" => "A128GCM"})
    |> JOSE.JWE.compact()
    |> elem(1)
  end

  defp configure_response_mode(config, mode) do
    opts =
      :attesto_phoenix
      |> Application.fetch_env!(Config)
      |> Keyword.put(:presentation_response_mode, mode)

    Application.put_env(:attesto_phoenix, Config, opts)
    %{config | presentation_response_mode: mode}
  end

  defp assert_invalid_request(response) do
    assert response.status == 400
    assert json_response(response, 400) == %{"error" => "invalid_request"}
    assert get_resp_header(response, "cache-control") == ["no-store"]
    assert get_resp_header(response, "pragma") == ["no-cache"]
  end

  defp assert_pending(id) do
    assert {:ok, %{data: data}} = Store.get(id)
    assert data.status == :pending
    refute Map.has_key?(data, :result)
  end

  defp stored_request_object(id) do
    assert {:ok, request_object} = PresentationSession.request_object(Store, id)
    request_object
  end

  defp keypair do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    pem = jwk |> JOSE.JWK.to_pem() |> elem(1)
    {_kty, public} = JOSE.JWK.to_public_map(jwk)
    {pem, public}
  end
end
