defmodule AttestoPhoenix.Plug.AuthenticateTest do
  @moduledoc false
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias Attesto.DPoP.ReplayCache
  alias Attesto.Test.DPoP
  alias Attesto.Token
  alias AttestoPhoenix.{Config, ProtectedResource}
  alias AttestoPhoenix.Plug.Authenticate
  alias AttestoPhoenix.Plug.RequireScopes
  alias ReqDPoP.Key, as: DPoPKey

  @issuer "https://issuer.example"
  @subject "ou_user-123"
  @signing_pem JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_pem() |> elem(1)

  defmodule CaptureAdapter do
    @moduledoc false

    # Req adapter that hands the outgoing request to the test process instead
    # of opening a connection.
    def run(request) do
      send(request.private.capture_owner, {:request, request})
      {request, %Req.Response{status: 204}}
    end
  end

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

  defmodule CertCallbacks do
    @moduledoc false

    def cert_der(_conn), do: Process.get(:attesto_phoenix_test_cert_der)
  end

  defmodule ResourceMetadataResolver do
    @moduledoc false

    def resolve(conn) do
      "https://pair.example/.well-known/oauth-protected-resource" <> conn.request_path
    end

    def resolve_with_extra(conn, base, resource) do
      base <> conn.request_path <> "/" <> resource
    end
  end

  defmodule RevokedTokenStore do
    @moduledoc false

    def access_token_revoked?(jti) do
      case Process.get({__MODULE__, :result}, :__not_configured__) do
        :__not_configured__ -> jti == Process.get(:attesto_phoenix_revoked_jti)
        result -> result
      end
    end
  end

  defmodule ConfigObservingRevokedTokenStore do
    @moduledoc false

    alias AttestoPhoenix.Config

    def access_token_revoked?(_jti) do
      send(self(), {:protected_resource_config, Config.request_config()})
      false
    end
  end

  defmodule MissingRevocationCallbackStore do
    @moduledoc false
  end

  @user_kind Attesto.PrincipalKind.new("user", "ou_", required_claims: [{"client_id", :non_empty_string}])

  setup do
    Application.put_env(:attesto_phoenix, __MODULE__.Keystore, signing_pem: @signing_pem)
    on_exit(fn -> Application.delete_env(:attesto_phoenix, __MODULE__.Keystore) end)

    config =
      Config.new(
        issuer: @issuer,
        audience: @issuer,
        keystore: __MODULE__.Keystore,
        repo: __MODULE__.Repo,
        load_client: fn _ -> {:error, :not_found} end,
        verify_client_secret: fn _, _ -> false end,
        load_principal: fn subject -> {:ok, %{subject: subject, kind: :user}} end,
        on_event: fn event -> send(self(), {:event, event}) end,
        principal_kinds: [@user_kind],
        require_https: false
      )

    %{config: config}
  end

  test "delegates token verification to core and assigns neutral Phoenix context", %{
    config: config
  } do
    token = mint(config, scope: "openid read:reports")

    conn =
      :get
      |> conn("/reports")
      |> put_req_header("authorization", "Bearer " <> token)
      |> Authenticate.call(Authenticate.init(config: config))

    refute conn.halted
    assert conn.assigns.attesto_claims["sub"] == @subject
    assert conn.assigns.attesto_principal == %{subject: @subject, kind: :user}

    assert conn.assigns.attesto_context == %{
             subject: @subject,
             client_id: "client-1",
             scope: ["openid", "read:reports"],
             claims: conn.assigns.attesto_claims,
             cnf: nil,
             principal: %{subject: @subject, kind: :user}
           }

    assert_receive {:event, %AttestoPhoenix.Event{name: :auth_succeeded, subject: @subject}}
  end

  test "request-private config is authoritative over static plug config", %{config: config} do
    request_config = %{config | audience: "https://request-resource.example"}
    token = mint(request_config, scope: "openid")

    conn =
      :get
      |> conn("/reports")
      |> put_private(:attesto_phoenix_config, request_config)
      |> put_req_header("authorization", "Bearer " <> token)
      |> Authenticate.call(Authenticate.init(config: config))

    refute conn.halted
    assert conn.assigns.attesto_claims["aud"] == "https://request-resource.example"
    assert Config.request_config() == nil
  end

  test "direct protected-resource authentication binds its explicit config", %{config: config} do
    config = %{config | code_store: __MODULE__.ConfigObservingRevokedTokenStore, schema_prefix: "resource_tenant"}
    token = mint(config, scope: "openid")

    conn =
      :get
      |> conn("/reports")
      |> put_req_header("authorization", "Bearer " <> token)

    assert {:ok, _conn, claims} = ProtectedResource.authenticate(conn, config, nil)
    assert claims["sub"] == @subject
    assert_received {:protected_resource_config, ^config}
    assert Config.request_config() == nil
  end

  test "malformed request-private config fails closed instead of using static config", %{config: config} do
    conn =
      :get
      |> conn("/reports")
      |> put_private(:attesto_phoenix_config, %{repo: config.repo})

    assert_raise ArgumentError, ~r/expected conn\.private\[:attesto_phoenix_config\]/, fn ->
      Authenticate.call(conn, Authenticate.init(config: config))
    end

    assert Config.request_config() == nil
  end

  test "resolves principal kinds once per request and preserves the resolved value", %{
    config: config
  } do
    token = mint(config, scope: "openid read:reports")
    parent = self()

    config = %{
      config
      | principal_kinds: fn ->
          send(parent, {:principal_kinds_resolved, @user_kind})
          [@user_kind]
        end
    }

    conn =
      :get
      |> conn("/reports")
      |> put_req_header("authorization", "Bearer " <> token)
      |> Authenticate.call(Authenticate.init(config: config))

    refute conn.halted
    assert conn.assigns.attesto_principal == %{subject: @subject, kind: :user}
    assert_receive {:principal_kinds_resolved, @user_kind}
    refute_receive {:principal_kinds_resolved, _}
  end

  test "requires explicit trust for a resource-audienced access token", %{config: config} do
    resource = "https://resource.example/reports"
    token = mint(config, scope: "read:reports", audience: resource)

    rejected =
      :get
      |> conn("/reports")
      |> put_req_header("authorization", "Bearer " <> token)
      |> Authenticate.call(Authenticate.init(config: config))

    assert rejected.halted
    assert rejected.status == 401
    assert JSON.decode!(rejected.resp_body)["error"] == "invalid_token"
    assert_receive {:event, %AttestoPhoenix.Event{name: :auth_denied, result: :invalid_token}}

    accepted =
      :get
      |> conn("/reports")
      |> put_req_header("authorization", "Bearer " <> token)
      |> Authenticate.call(Authenticate.init(config: config, trusted_audiences: [resource]))

    refute accepted.halted
    assert accepted.assigns.attesto_claims["aud"] == resource
    assert accepted.assigns.attesto_principal == %{subject: @subject, kind: :user}
    assert accepted.assigns.attesto_context.claims == accepted.assigns.attesto_claims
    assert_receive {:event, %AttestoPhoenix.Event{name: :auth_succeeded, subject: @subject}}
  end

  test "rejects a form-body access_token by default", %{config: config} do
    token = mint(config, scope: "openid read:reports")

    conn =
      %{"access_token" => token}
      |> form_post()
      |> Authenticate.call(Authenticate.init(config: config))

    assert conn.halted
    assert conn.status == 401
    assert JSON.decode!(conn.resp_body)["error"] == "invalid_token"
    assert_receive {:event, %AttestoPhoenix.Event{name: :auth_denied, result: :invalid_token}}
  end

  test "accepts a form-body access_token only when the config advertises body", %{config: config} do
    config = %{config | bearer_methods_supported: ["header", "body"]}
    token = mint(config, scope: "openid read:reports")

    conn =
      %{"access_token" => token}
      |> form_post()
      |> Authenticate.call(Authenticate.init(config: config))

    refute conn.halted
    assert conn.assigns.attesto_claims["sub"] == @subject
    assert conn.assigns.attesto_context.scope == ["openid", "read:reports"]
    assert_receive {:event, %AttestoPhoenix.Event{name: :auth_succeeded, subject: @subject}}
  end

  test "a missing principal is rendered as invalid_token without exposing lookup detail", %{
    config: config
  } do
    config = %{config | load_principal: fn _subject -> {:error, :not_found} end}
    token = mint(config, scope: "openid")

    conn =
      :get
      |> conn("/reports")
      |> put_req_header("authorization", "Bearer " <> token)
      |> Authenticate.call(Authenticate.init(config: config))

    assert conn.halted
    assert conn.status == 401
    assert JSON.decode!(conn.resp_body) == %{"error" => "invalid_token"}
    assert ["Bearer " <> _] = get_resp_header(conn, "www-authenticate")
    assert_receive {:event, %AttestoPhoenix.Event{name: :auth_denied, result: :invalid_token}}
  end

  test "an unexpected principal-store result is a sanitized integration failure", %{
    config: config
  } do
    config = %{config | load_principal: fn _subject -> {:error, :store_unavailable} end}
    token = mint(config, scope: "openid")

    assert_raise RuntimeError, ":load_principal callback violated its return contract", fn ->
      :get
      |> conn("/reports")
      |> put_req_header("authorization", "Bearer " <> token)
      |> Authenticate.call(Authenticate.init(config: config))
    end

    refute_received {:event, %AttestoPhoenix.Event{name: :auth_denied}}
  end

  test "rejects an access token revoked after authorization-code reuse", %{config: config} do
    token = mint(config, scope: "openid")
    Process.put(:attesto_phoenix_revoked_jti, peek_claims(config, token)["jti"])
    config = %{config | code_store: __MODULE__.RevokedTokenStore}

    conn =
      :get
      |> conn("/reports")
      |> put_req_header("authorization", "Bearer " <> token)
      |> Authenticate.call(Authenticate.init(config: config))

    assert conn.halted
    assert conn.status == 401
    assert JSON.decode!(conn.resp_body) == %{"error" => "invalid_token"}
    assert ["Bearer " <> _] = get_resp_header(conn, "www-authenticate")
    assert_receive {:event, %AttestoPhoenix.Event{name: :auth_denied, result: :invalid_token}}
  end

  test "rejects malformed revocation-store results at both public boundaries", %{config: config} do
    token = mint(config, scope: "openid")
    claims = peek_claims(config, token)
    config = %{config | code_store: __MODULE__.RevokedTokenStore}

    for invalid <- [:error, {:error, :backend_unavailable}, "sensitive-result-sentinel"] do
      Process.put({RevokedTokenStore, :result}, invalid)

      error =
        assert_raise RuntimeError, "code_store access_token_revoked?/1 must return true or false", fn ->
          ProtectedResource.access_token_revoked?(config, claims)
        end

      refute Exception.message(error) =~ "sensitive-result-sentinel"

      error =
        assert_raise RuntimeError, "code_store access_token_revoked?/1 must return true or false", fn ->
          :get
          |> conn("/reports")
          |> put_req_header("authorization", "Bearer " <> token)
          |> Authenticate.call(Authenticate.init(config: config))
        end

      refute Exception.message(error) =~ "sensitive-result-sentinel"
    end
  end

  test "loads configured code stores before probing their optional revocation callback", %{
    config: config
  } do
    token = mint(config, scope: "openid")
    claims = peek_claims(config, token)

    refute ProtectedResource.access_token_revoked?(
             %{config | code_store: MissingRevocationCallbackStore},
             claims
           )

    for store <- ["not-a-module", AttestoPhoenix.CodeStoreMissing] do
      config = %{config | code_store: store}

      assert_raise RuntimeError, ~r/configured code_store/, fn ->
        ProtectedResource.access_token_revoked?(config, claims)
      end
    end
  end

  test "supports custom assign keys", %{config: config} do
    token = mint(config, scope: "read:reports")

    conn =
      :get
      |> conn("/reports")
      |> put_req_header("authorization", "Bearer " <> token)
      |> Authenticate.call(
        Authenticate.init(
          config: config,
          claims_key: :claims,
          principal_key: :principal,
          context_key: :auth_context
        )
      )

    refute conn.halted
    assert conn.assigns.claims["sub"] == @subject
    assert conn.assigns.principal.subject == @subject
    assert conn.assigns.auth_context.scope == ["read:reports"]
  end

  test "enforces the configured HTTPS boundary before verifying credentials", %{config: config} do
    config = %{config | require_https: true}
    token = mint(config, scope: "openid")

    conn =
      :get
      |> conn("/reports")
      |> put_req_header("authorization", "Bearer " <> token)
      |> Authenticate.call(Authenticate.init(config: config))

    assert conn.halted
    assert conn.status == 401
    assert JSON.decode!(conn.resp_body)["error"] == "invalid_token"

    assert_receive {:event, %AttestoPhoenix.Event{name: :auth_denied, result: :insecure_transport}}
  end

  test "surfaces the configured RFC 9728 resource_metadata pointer on a 401 challenge", %{config: config} do
    url = @issuer <> "/.well-known/oauth-protected-resource"
    config = %{config | resource_metadata: url}

    conn =
      :get
      |> conn("/reports")
      |> Authenticate.call(Authenticate.init(config: config))

    assert conn.halted
    assert conn.status == 401
    [challenge] = get_resp_header(conn, "www-authenticate")
    assert challenge =~ ~s(resource_metadata="#{url}")
  end

  test "selects or omits resource_metadata per protected-resource request", %{config: config} do
    static = @issuer <> "/.well-known/oauth-protected-resource"

    resolver = fn conn ->
      case conn.request_path do
        "/alpha" -> @issuer <> "/.well-known/oauth-protected-resource/alpha"
        "/beta" -> @issuer <> "/.well-known/oauth-protected-resource/beta"
        "/invalid" -> "http://unsafe.example/.well-known/oauth-protected-resource"
        "/invalid-utf8" -> <<"https://api.example/", 0xFF>>
        _ -> nil
      end
    end

    config = %{config | resource_metadata: static, resource_metadata_resolver: resolver}

    for {path, suffix} <- [{"/alpha", "alpha"}, {"/beta", "beta"}] do
      conn =
        :get
        |> conn(path)
        |> Authenticate.call(Authenticate.init(config: config))

      assert conn.status == 401
      [challenge] = get_resp_header(conn, "www-authenticate")

      assert challenge =~
               ~s(resource_metadata="#{@issuer}/.well-known/oauth-protected-resource/#{suffix}")

      refute challenge =~ ~s(resource_metadata="#{static}")
    end

    for path <- ["/unowned", "/invalid", "/invalid-utf8"] do
      unowned =
        :get
        |> conn(path)
        |> Authenticate.call(Authenticate.init(config: config))

      assert unowned.status == 401
      [challenge] = get_resp_header(unowned, "www-authenticate")
      refute challenge =~ "resource_metadata"
    end
  end

  test "invokes MFA metadata resolvers through the challenge path with extra arguments appended", %{config: config} do
    cases = [
      {{__MODULE__.ResourceMetadataResolver, :resolve},
       "https://pair.example/.well-known/oauth-protected-resource/reports"},
      {{__MODULE__.ResourceMetadataResolver, :resolve_with_extra,
        ["https://extra.example/.well-known/oauth-protected-resource", "invoices"]},
       "https://extra.example/.well-known/oauth-protected-resource/reports/invoices"}
    ]

    for {resolver, selected} <- cases do
      response =
        :get
        |> conn("/reports")
        |> Authenticate.call(Authenticate.init(config: %{config | resource_metadata_resolver: resolver}))

      assert response.status == 401
      assert [challenge] = get_resp_header(response, "www-authenticate")
      assert challenge =~ ~s(resource_metadata="#{selected}")
    end
  end

  test "a resolver exception aborts the request instead of rendering an authentication response", %{config: config} do
    config = %{
      config
      | resource_metadata_resolver: fn _conn ->
          raise "resource metadata resolver failed"
        end
    }

    assert_raise RuntimeError, "resource metadata resolver failed", fn ->
      :get
      |> conn("/reports")
      |> Authenticate.call(Authenticate.init(config: config))
    end
  end

  test "explicit plug challenge options win on core, TLS, revocation, and principal failures", %{config: config} do
    resolver_url = "https://resolver.example/.well-known/oauth-protected-resource"
    explicit_url = "https://plug.example/.well-known/oauth-protected-resource"
    token = mint(config, scope: "openid")
    Process.put(:attesto_phoenix_revoked_jti, peek_claims(config, token)["jti"])
    on_exit(fn -> Process.delete(:attesto_phoenix_revoked_jti) end)

    configured_hook = fn _conn, _status, _body ->
      raise "the configured transport hook must lose to the explicit plug option"
    end

    explicit_send_error = fn conn, status, body ->
      conn
      |> put_resp_header("x-explicit-send-error", "true")
      |> send_resp(status, JSON.encode!(body))
      |> halt()
    end

    explicit_www_authenticate = fn conn, challenge ->
      conn
      |> put_resp_header("www-authenticate", challenge)
      |> put_resp_header("x-explicit-www-authenticate", "true")
    end

    explicit_no_store = fn conn -> put_resp_header(conn, "x-explicit-no-store", "true") end

    config = %{
      config
      | resource_metadata_resolver: fn _conn -> resolver_url end,
        send_error: configured_hook,
        www_authenticate: fn _conn, _challenge -> raise "configured WWW hook must not run" end,
        no_store: fn _conn -> raise "configured no-store hook must not run" end
    }

    authenticated =
      :get
      |> conn("/reports")
      |> put_req_header("authorization", "Bearer " <> token)

    cases = [
      {:core, conn(:get, "/reports"), config},
      {:tls, authenticated, %{config | require_https: true}},
      {:revocation, authenticated, %{config | code_store: __MODULE__.RevokedTokenStore}},
      {:principal, authenticated, %{config | load_principal: fn _ -> {:error, :not_found} end}}
    ]

    for {failure, request, case_config} <- cases do
      response =
        Authenticate.call(
          request,
          Authenticate.init(
            config: case_config,
            resource_metadata: explicit_url,
            send_error: explicit_send_error,
            www_authenticate: explicit_www_authenticate,
            no_store: explicit_no_store
          )
        )

      assert response.status == 401, "unexpected status for #{failure} failure"
      assert get_resp_header(response, "x-explicit-send-error") == ["true"]
      assert get_resp_header(response, "x-explicit-www-authenticate") == ["true"]
      assert get_resp_header(response, "x-explicit-no-store") == ["true"]
      assert [challenge] = get_resp_header(response, "www-authenticate")
      assert challenge =~ ~s(resource_metadata="#{explicit_url}")
      refute challenge =~ resolver_url
    end
  end

  test "an explicit nil plug metadata value is authoritative and safely omitted", %{config: config} do
    config = %{
      config
      | resource_metadata_resolver: fn _conn ->
          raise "resolver must not run when the plug explicitly selects nil"
        end
    }

    response =
      :get
      |> conn("/reports")
      |> Authenticate.call(Authenticate.init(config: config, resource_metadata: nil))

    assert [challenge] = get_resp_header(response, "www-authenticate")
    refute challenge =~ "resource_metadata"
  end

  test "init rejects an invalid static per-plug resource_metadata value" do
    for invalid <- [
          "",
          "/relative",
          "not-a-url",
          "http://unsafe.example/metadata",
          "https://api.example/metadata#fragment",
          "https://api.example/%ZZ",
          <<"https://api.example/", 0xFF>>,
          123
        ] do
      assert_raise ArgumentError,
                   ~r/AttestoPhoenix.Plug.Authenticate: :resource_metadata, when set, must be an absolute https URL/,
                   fn ->
                     Authenticate.init(resource_metadata: invalid)
                   end
    end

    assert Authenticate.init(resource_metadata: nil) == [resource_metadata: nil]

    assert Authenticate.init(resource_metadata: "https://api.example/.well-known/oauth-protected-resource") ==
             [resource_metadata: "https://api.example/.well-known/oauth-protected-resource"]
  end

  test "Bearer, DPoP, and mTLS binding failures carry the selected metadata pointer", %{config: config} do
    selected = "https://api.example/.well-known/oauth-protected-resource/reports"
    config = %{config | resource_metadata_resolver: fn _conn -> selected end}

    bearer =
      :get
      |> conn("/reports")
      |> Authenticate.call(Authenticate.init(config: config))

    assert [bearer_challenge = "Bearer " <> _] = get_resp_header(bearer, "www-authenticate")
    assert bearer_challenge =~ ~s(resource_metadata="#{selected}")

    dpop_key = DPoPKey.generate(:es256)
    dpop_token = mint(config, scope: "openid", dpop_jkt: DPoPKey.thumbprint(dpop_key))

    dpop =
      :get
      |> conn("/reports")
      |> put_req_header("authorization", "Bearer " <> dpop_token)
      |> Authenticate.call(Authenticate.init(config: config))

    assert [dpop_challenge = "DPoP " <> _] = get_resp_header(dpop, "www-authenticate")
    assert dpop_challenge =~ ~s(resource_metadata="#{selected}")

    der = self_signed_cert_der()
    {:ok, thumbprint} = Attesto.MTLS.compute_thumbprint(der)
    mtls_token = mint(config, scope: "openid", mtls_cert_thumbprint: thumbprint)
    mtls_config = %{config | mtls_enabled: true, cert_der: fn _conn -> nil end}

    mtls =
      :get
      |> conn("/reports")
      |> put_req_header("authorization", "Bearer " <> mtls_token)
      |> Authenticate.call(Authenticate.init(config: mtls_config))

    assert [mtls_challenge = "Bearer " <> _] = get_resp_header(mtls, "www-authenticate")
    assert mtls_challenge =~ ~s(resource_metadata="#{selected}")
  end

  test "omits the resource_metadata pointer when the Config does not set it", %{config: config} do
    conn =
      :get
      |> conn("/reports")
      |> Authenticate.call(Authenticate.init(config: config))

    assert conn.status == 401
    [challenge] = get_resp_header(conn, "www-authenticate")
    refute challenge =~ "resource_metadata"
  end

  test "uses configured error transport for core verifier failures", %{config: config} do
    config = %{
      config
      | send_error: fn conn, status, body ->
          conn
          |> put_resp_content_type("application/vnd.host-test+json")
          |> send_resp(status, JSON.encode!(%{"error" => body}))
          |> halt()
        end
    }

    conn =
      :get
      |> conn("/reports")
      |> Authenticate.call(Authenticate.init(config: config))

    assert conn.halted
    assert conn.status == 401
    assert JSON.decode!(conn.resp_body)["error"]["error"] == "invalid_token"
    assert ["Bearer " <> _] = get_resp_header(conn, "www-authenticate")
  end

  test "normalizes {module, function} cert_der callbacks before calling core", %{config: config} do
    der = self_signed_cert_der()
    {:ok, thumbprint} = Attesto.MTLS.compute_thumbprint(der)
    Process.put(:attesto_phoenix_test_cert_der, der)

    config = %{
      config
      | mtls_enabled: true,
        cert_der: {__MODULE__.CertCallbacks, :cert_der},
        trusted_proxies: [:loopback]
    }

    token = mint(config, scope: "openid", mtls_cert_thumbprint: thumbprint)

    conn =
      :get
      |> conn("/reports")
      |> put_req_header("authorization", "Bearer " <> token)
      |> Authenticate.call(Authenticate.init(config: config))

    refute conn.halted
    assert conn.assigns.attesto_claims["cnf"]["x5t#S256"] == thumbprint
    assert_receive {:event, %AttestoPhoenix.Event{name: :auth_succeeded, subject: @subject}}
  end

  test "accepts DPoP requests generated by req_dpop", %{config: config} do
    start_supervised!({ReplayCache, []})

    dpop_key = DPoPKey.generate(:es256)
    token = mint(config, scope: "openid read:reports", dpop_jkt: DPoPKey.thumbprint(dpop_key))

    Req.new(base_url: @issuer, adapter: CaptureAdapter)
    |> Req.Request.put_private(:capture_owner, self())
    |> ReqDPoP.attach(key: dpop_key, access_token: token)
    |> Req.get!(url: "/reports", params: [page: "1"])

    assert_receive {:request, req_request}

    conn =
      :get
      |> conn(@issuer <> "/reports?page=1")
      |> put_req_header(
        "authorization",
        req_request |> Req.Request.get_header("authorization") |> List.first()
      )
      |> put_req_header("dpop", req_request |> Req.Request.get_header("dpop") |> List.first())
      |> Authenticate.call(Authenticate.init(config: config))

    refute conn.halted
    assert conn.assigns.attesto_claims["cnf"]["jkt"] == DPoPKey.thumbprint(dpop_key)
    assert conn.assigns.attesto_context.scope == ["openid", "read:reports"]
    assert_receive {:event, %AttestoPhoenix.Event{name: :auth_succeeded, subject: @subject}}
  end

  # Read the audit store inside Plug's synchronous send boundary. These tests
  # cannot pass merely because the event appears after Authenticate.call/2.
  @denial_paths ~w(missing malformed invalid audience mtls_missing mtls_invalid
    mtls_mismatch dpop_missing dpop_invalid dpop_scheme dpop_binding dpop_replay
    dpop_nonce dpop_unconfigured step_up revoked principal tls)a

  for path <- @denial_paths do
    @tag :denial_ordering
    test "records #{path} denial before the 401 is sent", %{config: config} do
      {request, config, opts, error} = denial_request(unquote(path), config)
      audit = :ets.new(:denial_audit, [:set])
      config = %{config | on_event: fn event -> :ets.insert(audit, {event.name, event}) end}

      request =
        register_before_send(request, fn response ->
          assert response.status == 401
          assert [{:auth_denied, event}] = :ets.lookup(audit, :auth_denied)
          assert event.metadata.path == "/reports"
          assert event.metadata.method == "GET"
          assert :ets.lookup(audit, :auth_succeeded) == []
          response
        end)

      response = Authenticate.call(request, Authenticate.init([config: config] ++ opts))
      assert response.halted
      assert {401, _, body} = sent_resp(request)
      assert JSON.decode!(body)["error"] == error
      if unquote(path) == :dpop_nonce, do: assert(get_resp_header(response, "dpop-nonce") == ["audit-nonce"])
    end

    @tag :denial_ordering
    test "surfaces recording failure and refuses #{path}", %{config: config} do
      {request, config, opts, _error} = denial_request(unquote(path), config)
      config = %{config | on_event: fn _event -> {:error, :audit_unavailable} end}

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          response = Authenticate.call(request, Authenticate.init([config: config] ++ opts))
          assert response.status == 401
          assert response.halted
          refute Map.has_key?(response.assigns, :attesto_principal)
        end)

      assert log =~ "event callback reported an error"
    end

    @tag :denial_ordering
    test "a recording exception aborts #{path} before sending", %{config: config} do
      {request, config, opts, _error} = denial_request(unquote(path), config)
      config = %{config | on_event: fn _event -> raise "audit unavailable" end}

      assert_raise RuntimeError, "audit unavailable", fn ->
        Authenticate.call(request, Authenticate.init([config: config] ++ opts))
      end

      assert_raise RuntimeError, ~r/no sent response/, fn -> sent_resp(request) end
      assert Config.request_config() == nil
    end
  end

  defmodule AuditTransport do
    @moduledoc false
    import ExUnit.Assertions
    import Plug.Conn

    def send_error(conn, status, body, marker \\ "pair") do
      assert_received {:event, %AttestoPhoenix.Event{name: :auth_denied}}
      refute_received {:event, %AttestoPhoenix.Event{name: :auth_denied}}

      conn
      |> put_resp_header("x-audit-transport", marker)
      |> send_resp(status, JSON.encode!(%{"wrapped" => body}))
      |> halt()
    end
  end

  @tag :denial_ordering
  test "audits once before all configured and per-plug transport forms", %{config: config} do
    for transport <- [
          &AuditTransport.send_error/3,
          {AuditTransport, :send_error},
          {AuditTransport, :send_error, ["extra"]}
        ],
        placement <- [:config, :plug],
        path <- @denial_paths do
      {request, case_config, opts, error} = denial_request(path, config)

      {case_config, opts} =
        case placement do
          :config ->
            {%{case_config | send_error: transport}, opts}

          :plug ->
            {%{case_config | send_error: fn _, _, _ -> flunk("overridden transport ran") end},
             Keyword.put(opts, :send_error, transport)}
        end

      response = Authenticate.call(request, Authenticate.init([config: case_config] ++ opts))
      assert response.halted
      assert response.status == 401
      assert JSON.decode!(response.resp_body)["wrapped"]["error"] == error
      refute_received {:event, %AttestoPhoenix.Event{name: :auth_denied}}
    end
  end

  for entry <- [:protected_resource, :scope_plug], path <- [:missing, :invalid, :revoked, :tls] do
    @tag :denial_ordering
    test "#{entry} records #{path} rejection before sending", %{config: config} do
      {request, config, _opts, _error} = denial_request(unquote(path), config)
      request = put_private(request, :attesto_phoenix_config, config)

      request =
        register_before_send(request, fn response ->
          assert response.status == 401
          assert_received {:event, %AttestoPhoenix.Event{name: :auth_denied}}
          refute_received {:event, %AttestoPhoenix.Event{name: :auth_denied}}
          response
        end)

      response = alternate_denial(unquote(entry), request, config)
      assert response.halted
      assert response.status == 401
      refute_received {:event, %AttestoPhoenix.Event{name: :auth_denied}}
    end

    @tag :denial_ordering
    test "#{entry} surfaces recording failure for #{path}", %{config: config} do
      {request, config, _opts, _error} = denial_request(unquote(path), config)
      config = %{config | on_event: fn _ -> {:error, :audit_unavailable} end}
      request = put_private(request, :attesto_phoenix_config, config)

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          response = alternate_denial(unquote(entry), request, config)
          assert response.halted
          assert response.status == 401
        end)

      assert log =~ "event callback reported an error"
    end
  end

  defp alternate_denial(:protected_resource, request, config) do
    {:halt, response} = ProtectedResource.authenticate(request, config, nil)
    response
  end

  defp alternate_denial(:scope_plug, request, _config) do
    RequireScopes.call(request, RequireScopes.init("openid"))
  end

  defp denial_request(path, config) when path in [:mtls_missing, :mtls_invalid, :mtls_mismatch] do
    mtls_denial_request(path, conn(:get, @issuer <> "/reports"), config)
  end

  defp denial_request(path, config)
       when path in [
              :dpop_missing,
              :dpop_invalid,
              :dpop_scheme,
              :dpop_binding,
              :dpop_replay,
              :dpop_nonce,
              :dpop_unconfigured
            ] do
    dpop_denial_request(path, conn(:get, @issuer <> "/reports"), config)
  end

  defp denial_request(path, config) do
    token = mint(config, scope: "openid")
    request = conn(:get, @issuer <> "/reports")
    bearer = put_req_header(request, "authorization", "Bearer " <> token)
    invalid = "invalid_token"

    case path do
      :missing ->
        {request, config, [], invalid}

      :malformed ->
        {put_req_header(request, "authorization", "Basic bad"), config, [], invalid}

      :invalid ->
        {put_req_header(request, "authorization", "Bearer bad"), config, [], invalid}

      :audience ->
        {bearer, %{config | audience: "https://other.example"}, [], invalid}

      :tls ->
        {%{bearer | scheme: :http}, %{config | require_https: true}, [], invalid}

      :principal ->
        {bearer, %{config | load_principal: fn _ -> {:error, :not_found} end}, [], invalid}

      :revoked ->
        Process.put(:attesto_phoenix_revoked_jti, peek_claims(config, token)["jti"])
        {bearer, %{config | code_store: __MODULE__.RevokedTokenStore}, [], invalid}

      :step_up ->
        {bearer, config, [step_up: [acr_values: ["phr"]]], "insufficient_user_authentication"}
    end
  end

  defp mtls_denial_request(path, request, config) do
    der = self_signed_cert_der()
    {:ok, thumbprint} = Attesto.MTLS.compute_thumbprint(der)
    token = mint(config, scope: "openid", mtls_cert_thumbprint: thumbprint)

    presented =
      case path do
        :mtls_missing -> nil
        :mtls_invalid -> "invalid DER"
        :mtls_mismatch -> self_signed_cert_der()
      end

    config = %{config | mtls_enabled: true, cert_der: fn _ -> presented end, trusted_proxies: [:loopback]}
    {put_req_header(request, "authorization", "Bearer " <> token), config, [], "invalid_token"}
  end

  defp dpop_denial_request(path, request, config) do
    key = DPoP.generate_key()
    {_, public} = key |> JOSE.JWK.to_public() |> JOSE.JWK.to_map()
    token = mint(config, scope: "openid", dpop_jkt: Attesto.DPoP.compute_jkt(public))
    proof = DPoP.proof(key, "GET", @issuer <> "/reports", access_token: token)
    request = request |> put_req_header("authorization", "DPoP " <> token) |> put_req_header("dpop", proof)
    opts = [replay_check: fn _, _ -> :ok end]

    case path do
      :dpop_missing ->
        {delete_req_header(request, "dpop"), config, opts, "invalid_dpop_proof"}

      :dpop_invalid ->
        {put_req_header(request, "dpop", "bad"), config, opts, "invalid_dpop_proof"}

      :dpop_scheme ->
        {put_req_header(request, "authorization", "Bearer " <> token), config, opts, "invalid_dpop_proof"}

      :dpop_binding ->
        request = request |> delete_req_header("dpop") |> put_req_header("authorization", "Bearer " <> token)
        {request, config, opts, "invalid_token"}

      :dpop_unconfigured ->
        {request, config, [replay_check: nil], "invalid_dpop_proof"}

      :dpop_replay ->
        {request, config, [replay_check: fn _, _ -> {:error, :replay} end], "invalid_dpop_proof"}

      :dpop_nonce ->
        {request, config,
         opts ++ [nonce_check: fn _ -> {:error, :use_dpop_nonce} end, nonce_issue: fn -> "audit-nonce" end],
         "use_dpop_nonce"}
    end
  end

  defp mint(config, opts) do
    attesto_config = Config.to_attesto_config(config, principal_kinds: [@user_kind])

    principal = %{
      kind: "user",
      sub: @subject,
      scopes: String.split(Keyword.fetch!(opts, :scope), " "),
      claims: %{"client_id" => "client-1"}
    }

    mint_opts =
      []
      |> maybe_mint_opt(:audience, Keyword.get(opts, :audience))
      |> maybe_mint_opt(:mtls_cert_thumbprint, Keyword.get(opts, :mtls_cert_thumbprint))
      |> maybe_mint_opt(:dpop_jkt, Keyword.get(opts, :dpop_jkt))

    {:ok, %{access_token: token}} = Token.mint(attesto_config, principal, mint_opts)
    token
  end

  defp maybe_mint_opt(opts, _key, nil), do: opts
  defp maybe_mint_opt(opts, key, value), do: [{key, value} | opts]

  defp self_signed_cert_der do
    %{cert: der} = :public_key.pkix_test_root_cert(~c"CN=attesto-phoenix-plug-test", [])
    der
  end

  defp form_post(params) do
    :post
    |> conn("/reports", params)
    |> put_req_header("content-type", "application/x-www-form-urlencoded")
  end

  defp peek_claims(config, token) do
    attesto_config = Config.to_attesto_config(config, principal_kinds: [@user_kind])
    {:ok, claims} = Token.peek_signed_claims(attesto_config, token)
    claims
  end
end
