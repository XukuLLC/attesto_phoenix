defmodule AttestoPhoenix.RouterPairwiseHtuE2ETest do
  @moduledoc false
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias Attesto.CodeStore.ETS, as: CodeStore
  alias Attesto.DPoP.ReplayCache
  alias Attesto.PKCE
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Plug.PutConfig

  @issuer "https://issuer.example"
  @subject "oc_user-1"
  @verifier "the-quick-brown-fox-jumps-over_the.lazy~dog-0123"
  @salt String.duplicate("s", 32)
  @signing_pem JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_pem() |> elem(1)

  defmodule Keystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem, do: :attesto_phoenix |> Application.fetch_env!(__MODULE__) |> Keyword.fetch!(:signing_pem)

    @impl true
    def verification_pems, do: [signing_pem()]
  end

  defmodule Repo do
    @moduledoc false
  end

  defmodule TestRouter do
    @moduledoc false
    use Phoenix.Router
    use AttestoPhoenix.Router

    pipeline :attesto_phoenix_config do
      plug PutConfig, otp_app: :attesto_phoenix
    end

    scope "/" do
      attesto_routes(pipeline: :attesto_phoenix_config, credential_issuance: true)
    end
  end

  @clients %{
    "client-a1" => %{
      id: "client-a1",
      redirect_uris: ["https://rp-a.example/cb"],
      subject_type: "pairwise"
    },
    "client-a2" => %{
      id: "client-a2",
      redirect_uris: ["https://rp-a.example/callback"],
      subject_type: "pairwise"
    },
    "client-b" => %{
      id: "client-b",
      redirect_uris: ["https://rp-b.example/cb"],
      subject_type: "pairwise"
    },
    "client-mixed" => %{
      id: "client-mixed",
      redirect_uris: ["https://rp-a.example/cb", "https://rp-b.example/cb"],
      subject_type: "pairwise"
    }
  }

  setup do
    Application.put_env(:attesto_phoenix, Keystore, signing_pem: @signing_pem)
    Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)
    start_supervised!(CodeStore)
    start_supervised!({ReplayCache, single_node?: true})
    CodeStore.reset()

    clients = @clients

    Application.put_env(:attesto_phoenix, Config,
      issuer: @issuer,
      audience: @issuer,
      keystore: Keystore,
      principal_kinds: [Attesto.PrincipalKind.new("user", "oc_")],
      scopes_supported: ["openid", "profile"],
      repo: Repo,
      code_store: CodeStore,
      replay_check: &ReplayCache.check_and_record/2,
      require_https: false,
      pairwise_subject_salt: @salt,
      client_subject_type: fn client -> client.subject_type end,
      load_client: fn id ->
        case Map.fetch(clients, id) do
          {:ok, client} -> {:ok, client}
          :error -> {:error, :not_found}
        end
      end,
      client_redirect_uris: fn client -> client.redirect_uris end,
      client_public?: fn _client -> true end,
      verify_client_secret: fn _client, _secret -> false end,
      client_id: fn client -> client.id end,
      build_principal: fn _client, subject, scope ->
        %{kind: "user", sub: subject, scopes: scope, claims: %{}}
      end,
      load_principal: fn sub -> {:ok, %{kind: "user", sub: sub, scopes: ["openid", "profile"], claims: %{}}} end,
      authenticate_resource_owner: fn _conn, _req, _opts -> {:authenticated, %{subject: @subject}} end,
      consent: fn _conn, _req, subject -> {:consented, subject} end,
      build_userinfo_claims: fn subject, _scopes, _requested ->
        send(self(), {:userinfo_host_subject, subject})
        %{"name" => "Alice"}
      end
    )

    on_exit(fn ->
      Application.delete_env(:attesto_phoenix, Keystore)
      Application.delete_env(:attesto_phoenix, Config)
      Application.delete_env(:attesto_phoenix, :otp_app)
    end)

    :ok
  end

  test "drives pairwise sector isolation and DPoP htu pinning across authorize, token, and userinfo routes" do
    dpop_key = JOSE.JWK.generate_key({:ec, "P-256"})
    {sub_a1, _token_a1} = authorize_token_and_userinfo("client-a1", "https://rp-a.example/cb", dpop_key)
    {sub_a2, _token_a2} = authorize_token_and_userinfo("client-a2", "https://rp-a.example/callback", dpop_key)
    {sub_b, token_b} = authorize_token_and_userinfo("client-b", "https://rp-b.example/cb", dpop_key)

    refute sub_a1 == @subject
    assert sub_a1 == sub_a2
    refute sub_a1 == sub_b

    # Spoofed Host header on UserInfo fails when DPoP htu uses the spoofed host,
    # and succeeds when DPoP htu matches the configured UserInfo endpoint URL.
    ath = Base.url_encode64(:crypto.hash(:sha256, token_b), padding: false)

    spoofed =
      :get
      |> conn("/oauth/userinfo")
      |> Map.put(:host, "evil.example")
      |> put_req_header("authorization", "DPoP " <> token_b)
      |> put_req_header("dpop", dpop_proof(dpop_key, "GET", "https://evil.example/oauth/userinfo", ath))
      |> TestRouter.call([])

    assert spoofed.status == 401
    assert get_resp_header(spoofed, "www-authenticate") |> hd() =~ "invalid_dpop_proof"

    valid =
      :get
      |> conn("/oauth/userinfo")
      |> Map.put(:host, "evil.example")
      |> put_req_header("authorization", "DPoP " <> token_b)
      |> put_req_header("dpop", dpop_proof(dpop_key, "GET", @issuer <> "/oauth/userinfo", ath))
      |> TestRouter.call([])

    assert valid.status == 200
    assert JSON.decode!(valid.resp_body) == %{"sub" => sub_b, "name" => "Alice"}
    assert_received {:userinfo_host_subject, @subject}

    # Pairwise client whose redirect_uris span multiple hosts without a single sector is rejected.
    {:ok, challenge} = PKCE.challenge(@verifier)

    bad_auth =
      :get
      |> conn("/oauth/authorize", %{
        "response_type" => "code",
        "client_id" => "client-mixed",
        "redirect_uri" => "https://rp-a.example/cb",
        "scope" => "openid",
        "state" => "s1",
        "nonce" => "n1",
        "code_challenge" => challenge,
        "code_challenge_method" => "S256"
      })
      |> TestRouter.call([])

    assert bad_auth.status == 302
    [location] = get_resp_header(bad_auth, "location")

    case URI.decode_query(URI.parse(location).query) do
      %{"error" => error} ->
        assert error in ["invalid_request", "server_error"]

      %{"code" => mixed_code} ->
        mixed_token =
          :post
          |> conn(
            "/oauth/token",
            URI.encode_query(%{
              "grant_type" => "authorization_code",
              "code" => mixed_code,
              "client_id" => "client-mixed",
              "redirect_uri" => "https://rp-a.example/cb",
              "code_verifier" => @verifier
            })
          )
          |> put_req_header("content-type", "application/x-www-form-urlencoded")
          |> put_req_header("dpop", dpop_proof(dpop_key, "POST", @issuer <> "/oauth/token"))
          |> Plug.Parsers.call(
            Plug.Parsers.init(
              parsers: [:urlencoded],
              body_reader: {AttestoPhoenix.DuplicateParameterGuard, :read_body, []}
            )
          )
          |> TestRouter.call([])

        assert mixed_token.status == 400
    end
  end

  defp authorize_token_and_userinfo(client_id, redirect_uri, dpop_key) do
    {:ok, challenge} = PKCE.challenge(@verifier)

    auth_conn =
      :get
      |> conn("/oauth/authorize", %{
        "response_type" => "code",
        "client_id" => client_id,
        "redirect_uri" => redirect_uri,
        "scope" => "openid profile",
        "state" => "st-1",
        "nonce" => "nc-1",
        "code_challenge" => challenge,
        "code_challenge_method" => "S256"
      })
      |> TestRouter.call([])

    assert auth_conn.status == 302
    [location] = get_resp_header(auth_conn, "location")
    assert %{"code" => code} = URI.decode_query(URI.parse(location).query)
    assert is_binary(code)

    token_params = %{
      "grant_type" => "authorization_code",
      "code" => code,
      "client_id" => client_id,
      "redirect_uri" => redirect_uri,
      "code_verifier" => @verifier
    }

    token_conn =
      :post
      |> conn("/oauth/token", URI.encode_query(token_params))
      |> put_req_header("content-type", "application/x-www-form-urlencoded")
      |> Map.put(:host, "evil.example")
      |> put_req_header("dpop", dpop_proof(dpop_key, "POST", @issuer <> "/oauth/token"))
      |> Plug.Parsers.call(
        Plug.Parsers.init(parsers: [:urlencoded], body_reader: {AttestoPhoenix.DuplicateParameterGuard, :read_body, []})
      )
      |> TestRouter.call([])

    assert token_conn.status == 200
    token_body = JSON.decode!(token_conn.resp_body)
    access_token = token_body["access_token"]
    id_token = token_body["id_token"]

    config = AttestoPhoenix.Config.resolve!() |> AttestoPhoenix.Config.to_attesto_config()
    {:ok, id_claims} = Attesto.JWS.peek_json(id_token, :payload)
    {:ok, at_claims} = Attesto.Token.peek_signed_claims(config, access_token)

    ath = Base.url_encode64(:crypto.hash(:sha256, access_token), padding: false)

    ui_conn =
      :get
      |> conn("/oauth/userinfo")
      |> put_req_header("authorization", "DPoP " <> access_token)
      |> put_req_header("dpop", dpop_proof(dpop_key, "GET", @issuer <> "/oauth/userinfo", ath))
      |> TestRouter.call([])

    assert ui_conn.status == 200
    ui_body = JSON.decode!(ui_conn.resp_body)

    assert id_claims["sub"] == at_claims["sub"]
    assert ui_body["sub"] == id_claims["sub"]
    {ui_body["sub"], access_token}
  end

  defp dpop_proof(dpop_key, htm, htu, ath \\ nil) do
    {_, pub_map} = JOSE.JWK.to_public_map(dpop_key)

    payload =
      %{
        "htm" => htm,
        "htu" => htu,
        "iat" => System.system_time(:second),
        "jti" => Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
      }
      |> then(fn map -> if ath, do: Map.put(map, "ath", ath), else: map end)

    header = %{"alg" => "ES256", "typ" => "dpop+jwt", "jwk" => pub_map}
    {_, compact} = JOSE.JWS.compact(JOSE.JWT.sign(dpop_key, header, payload))
    compact
  end
end
