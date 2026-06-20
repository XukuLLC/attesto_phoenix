defmodule AttestoPhoenix.AuthorizationServer.DcrClientCredentialsTest do
  @moduledoc """
  End-to-end proof that a Dynamic Client Registration (RFC 7591) confidential
  client can drive the `client_credentials` grant (RFC 6749 §4.4) and that the
  minted access token verifies.

  The point of interest is the **subject seam**. DCR issues an *unprefixed*
  `client_id` (RFC 7591 §3.2.1 - the value is whatever the host's
  `:register_client` returns; the library does not impose a namespace prefix on
  it). The `client_credentials` grant uses that bare `client_id` as the
  principal subject (`AttestoPhoenix.AuthorizationServer.Token`:
  `subject = client_id(config, client)`). The mint-time invariant, however, is
  that a principal's `sub` MUST begin with its `Attesto.PrincipalKind`
  `sub_prefix` (`Attesto.Token`: `check_sub/2`, `{:error, :invalid_sub}`
  otherwise) - defense-in-depth so a token's `sub` is unambiguous across kinds.

  The seam that reconciles the two is the host's `:build_principal` callback: it
  - and only it - is responsible for namespacing the returned `:sub` with the
  client kind's `sub_prefix`. No `:client_subject` callback exists and the
  prefix is never relaxed; the host owns the one-line bridge. These tests prove
  the positive path (a prefixing `:build_principal` succeeds) and the negative
  control (a non-prefixing `:build_principal` is rejected at mint as the
  RFC 6749 §5.2 `invalid_request` the seam guarantees).
  """
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias AttestoPhoenix.AuthorizationServer.Token
  alias AttestoPhoenix.AuthorizationServer.Token.Request
  alias AttestoPhoenix.{Config, OAuthError}
  alias AttestoPhoenix.Controller.RegistrationController
  alias AttestoPhoenix.Controller.TokenController

  # A throwaway RSA keypair for the minting/verification paths.
  @signing_pem JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_pem() |> elem(1)

  # The client principal kind. Its `sub_prefix` ("oc_") is the namespace every
  # client subject MUST carry; `:build_principal` is what applies it.
  @sub_prefix "oc_"
  @client_kind Attesto.PrincipalKind.new("client", @sub_prefix, required_claims: [{"client_id", :non_empty_string}])

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

  defmodule StubRepo do
    @moduledoc false
  end

  setup do
    Application.put_env(:attesto_phoenix, __MODULE__.Keystore, signing_pem: @signing_pem)
    on_exit(fn -> Application.delete_env(:attesto_phoenix, __MODULE__.Keystore) end)
    :ok
  end

  # ── DCR registration (RFC 7591) ──────────────────────────────────────────

  @endpoint_path "/oauth/register"

  # A registration-only config: the controller never touches the keystore/repo/
  # auth callbacks, so those carry inert placeholders.
  defp registration_config do
    struct(Config, %{
      issuer: "https://issuer.example",
      audience: "https://issuer.example",
      keystore: :unused,
      repo: :unused,
      load_client: fn _id -> {:error, :not_found} end,
      verify_client_secret: fn _client, _secret -> false end,
      load_principal: fn _subject -> {:error, :not_found} end,
      register_client: fn attrs -> {:ok, attrs} end,
      scopes_supported: ["read", "write"]
    })
  end

  defp post_register(config, metadata) do
    :post
    |> conn(@endpoint_path, metadata)
    |> Map.put(:scheme, :https)
    |> put_req_header("content-type", "application/json")
    |> Map.put(:body_params, metadata)
    |> put_private(:attesto_phoenix_config, config)
    |> RegistrationController.create(%{})
  end

  # Register a confidential client for `client_credentials` and return its
  # *unprefixed* DCR-issued client_id.
  defp register_client_credentials_client do
    conn =
      post_register(registration_config(), %{
        "grant_types" => ["client_credentials"]
      })

    assert conn.status == 201
    client_id = JSON.decode!(conn.resp_body)["client_id"]
    assert is_binary(client_id) and client_id != ""
    client_id
  end

  # Register a confidential client and return BOTH the DCR-issued (unprefixed)
  # client_id and the issued client_secret (RFC 7591 §3.2.1 / RFC 6749 §2.3.1) so
  # the token-endpoint path can authenticate as that client.
  defp register_confidential_client do
    body =
      registration_config()
      |> post_register(%{"grant_types" => ["client_credentials"]})
      |> then(fn conn ->
        assert conn.status == 201
        JSON.decode!(conn.resp_body)
      end)

    {client_id, secret} = {body["client_id"], body["client_secret"]}
    assert is_binary(client_id) and client_id != ""
    assert is_binary(secret) and secret != ""
    {client_id, secret}
  end

  # ── Token config bound to the DCR-issued client_id ───────────────────────

  # `:build_principal` namespaces the subject with the client kind sub_prefix,
  # mirroring the production seam.
  defp ensure_sub(@sub_prefix <> _ = sub), do: sub
  defp ensure_sub(sub), do: @sub_prefix <> to_string(sub)

  # A Token config whose client *is* the DCR-issued one. `:client_id` returns the
  # bare DCR id (the subject the grant uses); `build_principal` is overridable so
  # the negative control can swap in a non-prefixing builder.
  defp token_config(client_id, build_principal) do
    [
      issuer: "https://issuer.example",
      audience: "https://issuer.example",
      keystore: __MODULE__.Keystore,
      repo: StubRepo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _client, _given -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      client_public?: fn _client -> false end,
      client_id: fn _client -> client_id end,
      authorize_scope: fn _client, requested -> {:ok, requested} end,
      principal_kinds: [@client_kind],
      build_principal: build_principal
    ]
    |> Config.new()
  end

  # The production-correct builder: namespaces :sub with the kind sub_prefix.
  defp prefixing_build_principal(client_id) do
    fn _client, subject, scope ->
      %{
        kind: "client",
        sub: ensure_sub(subject),
        scopes: scope,
        claims: %{"client_id" => client_id}
      }
    end
  end

  # A full server config for the token-endpoint path: `:load_client` resolves the
  # DCR-issued id to a confidential client, `:verify_client_secret` checks the
  # issued secret (RFC 6749 §2.3.1), and `:client_id`/`:build_principal` apply the
  # same subject seam. `require_https: false` so the Plug.Test conn is accepted.
  defp controller_token_config(client_id, secret, build_principal) do
    client = %{id: client_id, public?: false, secret: secret}

    opts = [
      issuer: "https://issuer.example",
      audience: "https://issuer.example",
      keystore: __MODULE__.Keystore,
      repo: StubRepo,
      require_https: false,
      load_client: fn id -> if id == client_id, do: {:ok, client}, else: {:error, :not_found} end,
      verify_client_secret: fn
        %{secret: s}, given -> s == given
        _client, _given -> false
      end,
      client_public?: fn c -> Map.get(c, :public?, false) end,
      client_id: fn c -> c.id end,
      authorize_scope: fn _client, requested -> {:ok, requested} end,
      load_principal: fn _ -> {:error, :not_found} end,
      replay_check: fn _key, _ttl -> :ok end,
      principal_kinds: [@client_kind],
      build_principal: build_principal
    ]

    # The token endpoint resolves its config from application env
    # (TokenController.resolve_config/0 -> Config.from_otp_app/2), so install it
    # there for the HTTP path and restore on exit.
    prev_otp = Application.get_env(:attesto_phoenix, :otp_app)
    Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)
    Application.put_env(:attesto_phoenix, Config, opts)

    on_exit(fn ->
      Application.delete_env(:attesto_phoenix, Config)

      if prev_otp,
        do: Application.put_env(:attesto_phoenix, :otp_app, prev_otp),
        else: Application.delete_env(:attesto_phoenix, :otp_app)
    end)

    Config.new(opts)
  end

  defp request(config, client_id, overrides) do
    fields =
      [
        config: config,
        # The host's loaded client; opaque to the grant, which reads the
        # identifier through the `:client_id` callback.
        client: %{id: client_id, public?: false},
        # client_credentials requires a confidential client (RFC 6749 §4.4).
        client_auth_method: :client_secret_basic,
        grant_type: "client_credentials",
        params: %{},
        sender_constraint_input: %{
          dpop_proof: nil,
          mtls_cert_der: nil,
          http_uri: "https://issuer.example/oauth/token",
          http_method: "POST"
        },
        client_ip: "203.0.113.7",
        request_client_id: nil
      ]
      |> Keyword.merge(overrides)

    struct!(Request, fields)
  end

  describe "DCR → client_credentials → verify" do
    test "a DCR-issued confidential client mints a verifiable client_credentials token" do
      client_id = register_client_credentials_client()

      config = token_config(client_id, prefixing_build_principal(client_id))
      request = request(config, client_id, params: %{"scope" => "read write"})

      assert {:ok, response, [_event]} = Token.issue(config, request)
      assert is_binary(response.access_token)
      assert response.token_type == "Bearer"

      # The minted token verifies against the same server config, and the seam
      # holds end to end: the verified subject is the DCR client_id namespaced
      # with the client kind prefix, while `client_id` carries the bare DCR id.
      assert {:ok, claims} =
               Attesto.Token.verify(Config.to_attesto_config(config), response.access_token)

      assert claims["sub"] == @sub_prefix <> client_id
      assert claims["client_id"] == client_id
    end

    # NEGATIVE CONTROL: the seam is real. A `:build_principal` that returns the
    # bare DCR subject (no kind prefix) is rejected at mint - `Attesto.Token`'s
    # `check_sub/2` returns `:invalid_sub`, which the token core renders as the
    # RFC 6749 §5.2 invalid_request the endpoint must emit. This is exactly the
    # failure a host avoids by namespacing :sub, and proves the prefix is load
    # bearing rather than incidental.
    test "a :build_principal that omits the kind prefix is rejected (invalid_request)" do
      client_id = register_client_credentials_client()

      unprefixing_build_principal = fn _client, subject, scope ->
        %{
          kind: "client",
          # The DCR-issued subject WITHOUT the "oc_" namespace prefix.
          sub: subject,
          scopes: scope,
          claims: %{"client_id" => client_id}
        }
      end

      config = token_config(client_id, unprefixing_build_principal)
      request = request(config, client_id, params: %{"scope" => "read"})

      assert {:error, %OAuthError{error: :invalid_request}, [event]} =
               Token.issue(config, request)

      assert event.name == :token_denied
    end
  end

  describe "DCR → token endpoint → client_credentials (full HTTP path)" do
    test "a DCR-registered confidential client authenticates and mints a verifiable token" do
      # Full path: register over HTTP (RFC 7591), then drive the token endpoint
      # exactly as a client would - HTTP Basic client auth (RFC 6749 §2.3.1)
      # through TokenController.create, real `:load_client`/`:verify_client_secret`
      # - not a synthetic in-process client.
      {client_id, secret} = register_confidential_client()
      config = controller_token_config(client_id, secret, prefixing_build_principal(client_id))

      conn =
        :post
        |> conn("/oauth/token", %{"grant_type" => "client_credentials"})
        |> put_req_header("authorization", "Basic " <> Base.encode64("#{client_id}:#{secret}"))
        |> TokenController.create(%{"grant_type" => "client_credentials"})

      assert conn.status == 200
      body = JSON.decode!(conn.resp_body)
      assert is_binary(body["access_token"])
      assert body["token_type"] == "Bearer"

      assert {:ok, claims} =
               Attesto.Token.verify(Config.to_attesto_config(config), body["access_token"])

      # The bare DCR id authenticated the client and is the `client_id` claim,
      # while the subject seam namespaced `sub` with the client kind prefix.
      assert claims["sub"] == @sub_prefix <> client_id
      assert claims["client_id"] == client_id
    end

    test "a wrong client_secret is rejected at the token endpoint (invalid_client)" do
      {client_id, _secret} = register_confidential_client()
      # Installs the server config in application env (the token endpoint resolves
      # it there); the returned struct is unused on this rejection path.
      _config = controller_token_config(client_id, "the-real-secret", prefixing_build_principal(client_id))

      conn =
        :post
        |> conn("/oauth/token", %{"grant_type" => "client_credentials"})
        |> put_req_header("authorization", "Basic " <> Base.encode64("#{client_id}:wrong-secret"))
        |> TokenController.create(%{"grant_type" => "client_credentials"})

      # RFC 6749 §5.2: invalid_client is 400 (or 401 with a challenge).
      assert conn.status in [400, 401]
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_client"
    end
  end
end
