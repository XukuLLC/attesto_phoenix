defmodule AttestoPhoenix.Controller.AuthorizeControllerTest do
  @moduledoc """
  Tests for the authorization endpoint (RFC 6749 §3.1, OIDC Core §3.1.2).

  The route is not mounted yet, so the controller action is exercised directly
  against a built `Plug.Conn`. Host policy (client lookup, registered redirect
  URIs, login, consent, code persistence) is supplied through stub callbacks on
  `AttestoPhoenix.Config`, exactly as a real deployment would wire it.
  """
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog
  import Phoenix.ConnTest
  import Plug.Conn

  alias Attesto.AuthorizationCode
  alias Attesto.RequestObject.Policy
  alias AttestoPhoenix.AuthorizationCodePrivateContext, as: PrivateContext
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Controller.AuthorizeController
  alias AttestoPhoenix.Store.PAR.ETS
  alias AttestoPhoenix.Store.PAR.ETS, as: PARStore

  # A PAR store that resolves (fetch) normally but whose single-use claim (take)
  # always loses - simulating a concurrent completion (on another node) that
  # consumed the reference first. Used to exercise the atomic single-use gate in
  # `issue_and_redirect/6` without orchestrating a real race.
  defmodule TakeLosesPARStore do
    @moduledoc false
    @behaviour AttestoPhoenix.PARStore

    @impl true
    defdelegate put(request_uri, params, ttl_seconds), to: ETS

    @impl true
    defdelegate fetch(request_uri), to: ETS

    @impl true
    def take(_request_uri), do: :error
  end

  defmodule TakeFaultsPARStore do
    @moduledoc false
    @behaviour AttestoPhoenix.PARStore

    @impl true
    defdelegate put(request_uri, params, ttl_seconds), to: ETS

    @impl true
    defdelegate fetch(request_uri), to: ETS

    @impl true
    def take(_request_uri), do: {:error, :store_unavailable}
  end

  # A fixed S256 PKCE pair (RFC 7636 §4.2): the challenge is the
  # BASE64URL-no-pad encoding of SHA-256(verifier). Computed inline here (the
  # transform is fixed by the RFC) so the test does not depend on a core helper.
  @code_verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  @code_challenge Base.url_encode64(:crypto.hash(:sha256, @code_verifier), padding: false)
  @redirect_uri "https://client.example.com/callback"
  @client_id "test-client"

  # RFC 8252: an installed native app registering loopback redirect URIs. The
  # registered port is irrelevant under §7.3 - the app binds an ephemeral one at
  # runtime - so it is registered as 0 by convention. Both loopback families are
  # registered, because which one the app can bind depends on the device's
  # networking stack.
  @native_client_id "native-client"
  @native_loopback_uri "http://127.0.0.1:0/cb"
  @native_loopback_uri_v6 "http://[::1]:0/cb"

  # OP-only HMAC key for the login-bound, OP-owned browser-state value
  # (Session Management 1.0 §3.2). Required whenever session management is on.
  @browser_state_secret :crypto.strong_rand_bytes(32)

  # The default browser-state cookie is `__Host-` prefixed so a sibling/parent-
  # domain origin cannot inject or shadow it.
  @browser_state_cookie "__Host-attesto_op_browser_state"

  # The login binding the controller derives from the authenticate stub's
  # subject + auth_time (+ sid): "subject\nauth_time\nsid".
  @established_binding "user-42\n1700000000\n"
  @reauth_binding "user-42\n1700009999\n"

  defmodule TestStore do
    @moduledoc false
    @behaviour Attesto.CodeStore

    def start_link do
      Agent.start_link(fn -> %{} end, name: __MODULE__)
    end

    @impl true
    def put(record) do
      Agent.update(__MODULE__, &Map.put(&1, record.code_hash, record))
      :ok
    end

    @impl true
    def take(code_hash) do
      Agent.get_and_update(__MODULE__, fn state ->
        case Map.fetch(state, code_hash) do
          {:ok, record} -> {{:ok, record}, Map.delete(state, code_hash)}
          :error -> {:error, state}
        end
      end)
    end

    # Test-only peek that does not consume the code.
    def peek(code) do
      Agent.get(__MODULE__, &Map.get(&1, Attesto.Secret.hash(code)))
    end
  end

  setup do
    {:ok, _} = start_supervised(%{id: TestStore, start: {TestStore, :start_link, []}})

    config = base_config()

    Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)
    Application.put_env(:attesto_phoenix, AttestoPhoenix.Config, config)

    on_exit(fn ->
      Application.delete_env(:attesto_phoenix, AttestoPhoenix.Config)
      Application.delete_env(:attesto_phoenix, :otp_app)
    end)

    %{config: config}
  end

  defp base_config(overrides \\ []) do
    Keyword.merge(
      [
        issuer: "https://issuer.example.com",
        audience: "https://issuer.example.com",
        keystore: __MODULE__.TestKeystore,
        repo: __MODULE__.NoRepo,
        load_client: &__MODULE__.load_client/1,
        verify_client_secret: &__MODULE__.verify_secret/2,
        load_principal: &__MODULE__.load_principal/1,
        client_id: &__MODULE__.client_id/1,
        client_redirect_uris: &__MODULE__.client_redirect_uris/1,
        client_native?: &__MODULE__.client_native?/1,
        authenticate_resource_owner: &__MODULE__.authenticate/3,
        consent: &__MODULE__.consent/3,
        code_store: TestStore,
        authorization_code_ttl: 60,
        require_https: true,
        # A real AS configures principal kinds; needed for the derived
        # Attesto.Config when the authorization endpoint signs JARM responses.
        principal_kinds: [Attesto.PrincipalKind.new("user", "usr_")]
      ],
      overrides
    )
  end

  # `:authorization_code_private_context` is only valid alongside a completion
  # callback, so the issuance tests pair it with a pass-through.
  defp passthrough_completion(_context, continuation), do: continuation.()

  defp put_config(overrides) do
    Application.put_env(:attesto_phoenix, AttestoPhoenix.Config, base_config(overrides))
  end

  defp valid_params(extra \\ %{}) do
    Map.merge(
      %{
        "response_type" => "code",
        "client_id" => @client_id,
        "redirect_uri" => @redirect_uri,
        "scope" => "openid profile",
        "state" => "xyz",
        "nonce" => "n-0S6_WzA2Mj",
        "code_challenge" => @code_challenge,
        "code_challenge_method" => "S256"
      },
      extra
    )
  end

  defp call(params, opts \\ []) do
    conn = build_conn() |> Map.put(:scheme, :https) |> with_config()

    conn =
      case Keyword.get(opts, :user_agent) do
        nil -> conn
        user_agent -> put_req_header(conn, "user-agent", user_agent)
      end

    AuthorizeController.authorize(conn, params)
  end

  defp with_config(conn) do
    put_private(
      conn,
      :attesto_phoenix_config,
      Config.new(Application.fetch_env!(:attesto_phoenix, Config))
    )
  end

  defp location(conn) do
    conn |> get_resp_header("location") |> List.first()
  end

  defp location_query(conn) do
    conn
    |> location()
    |> URI.parse()
    |> Map.get(:query)
    |> case do
      nil -> %{}
      query -> URI.decode_query(query)
    end
  end

  # Verify a JARM response JWT the way a client would: strictly, against the
  # authorization server's signing key (TestKeystore is RSA/RS256), returning
  # the claims.
  defp decode_jarm(jwt) do
    jwk = __MODULE__.TestKeystore.signing_pem() |> Attesto.Key.jwk()

    assert {true, %JOSE.JWT{fields: claims}, %JOSE.JWS{}} =
             JOSE.JWT.verify_strict(jwk, ["RS256"], jwt)

    claims
  end

  # ── Valid flow ───────────────────────────────────────────────────────────

  describe "valid authorization request" do
    test "issues a code and 302-redirects to the redirect_uri with code+state" do
      conn = call(valid_params())

      assert conn.status == 302
      query = location_query(conn)

      assert location(conn) =~ @redirect_uri
      assert is_binary(query["code"])
      assert query["state"] == "xyz"
    end

    test "the issued code is redeemable and carries nonce + auth_time/acr/amr claims" do
      conn = call(valid_params())
      code = location_query(conn)["code"]

      # The stored code carries the OIDC claims the token endpoint needs to mint
      # the ID token (OIDC Core §3.1.3.6).
      record = TestStore.peek(code)
      assert record.data.claims["nonce"] == "n-0S6_WzA2Mj"
      assert record.data.claims["auth_time"] == 1_700_000_000
      assert record.data.claims["acr"] == "urn:mace:incommon:iap:silver"
      assert record.data.claims["amr"] == ["pwd"]

      # And it redeems against the same PKCE verifier and redirect_uri.
      assert {:ok, grant} =
               AuthorizationCode.redeem(TestStore, code, %{
                 redirect_uri: @redirect_uri,
                 code_verifier: @code_verifier,
                 client_id: @client_id
               })

      assert grant.subject == "user-42"
      assert grant.scope == ["openid", "profile"]
    end

    test "an absent private-context hook preserves the ordinary stored record" do
      conn = call(valid_params(%{"authorization_code_private_context" => "client-controlled"}))
      code = location_query(conn)["code"]

      record = TestStore.peek(code)
      refute Map.has_key?(record.data.claims, PrivateContext.claims_key())
      refute Map.has_key?(record.data.claims, "authorization_code_private_context")
    end

    test "the host attaches bounded private context from trusted authorization state" do
      test_pid = self()

      put_config(
        authorization_code_completion: &passthrough_completion/2,
        authorization_code_private_context: fn context ->
          send(test_pid, {:private_context_issuance, context})
          %{"security_epoch" => 42}
        end
      )

      conn = call(valid_params(%{"authorization_code_private_context" => "client-controlled"}))
      code = location_query(conn)["code"]
      record = TestStore.peek(code)

      assert_receive {:private_context_issuance,
                      %{client_id: @client_id, subject: "user-42", family_id: family_id} = context}

      # Exactly the authorized identifiers - no request params, no secrets.
      assert map_size(context) == 3
      assert family_id == record.data.family_id

      # Core admits no sibling key beside the nine canonical ones, so the value
      # rides inside claims under the reserved key.
      assert record.data.claims[PrivateContext.claims_key()] == %{"security_epoch" => 42}
      refute Map.has_key?(record.data, :attesto_phoenix_private_context)
      refute Map.has_key?(record.data.claims, "security_epoch")
    end

    test "a private context the claims column cannot round-trip fails before a code is returned" do
      # Atom keys, invalid UTF-8, a float, unencodable terms, and ordinary
      # Elixir structs all fail the portable-JSON-object contract the claims
      # column requires. None may yield a code: the completion callback would
      # demand state that was never stored. Keep the values out of diagnostics.
      for invalid <- [
            %{security_epoch: 42},
            %{"invalid_utf8" => <<255>>},
            %{"ratio" => 1.5},
            %{"nested" => %{"value" => {:not, :json}}},
            %{"payload" => String.duplicate("x", 4_097)},
            Date.utc_today(),
            DateTime.utc_now(),
            Decimal.new("1.25"),
            MapSet.new(["private-value"])
          ] do
        put_config(
          authorization_code_completion: &passthrough_completion/2,
          authorization_code_private_context: fn _context -> invalid end
        )

        log =
          capture_log(fn ->
            conn = call(valid_params())
            query = location_query(conn)

            assert query["error"] == "server_error"
            refute Map.has_key?(query, "code")
            refute inspect(query) =~ inspect(invalid)
          end)

        assert log =~ "authorization code private context rejected"
        refute log =~ "authorization code claims rejected"
        refute log =~ inspect(invalid)
      end
    end

    test "invalid combined code claims are logged as claims rejection" do
      put_config(
        authorization_code_completion: &passthrough_completion/2,
        authorization_code_private_context: fn _context -> %{"security_epoch" => 42} end,
        authenticate_resource_owner: fn _conn, _request, _auth_opts ->
          {:authenticated, %{subject: "user-42", acr: %{invalid: :term}}}
        end
      )

      log =
        capture_log(fn ->
          conn = call(valid_params())
          query = location_query(conn)

          assert query["error"] == "server_error"
          refute Map.has_key?(query, "code")
        end)

      assert log =~
               "authorization code claims rejected after private context insertion: combined claims are not portable"

      refute log =~ "authorization code private context rejected"
    end

    test "the issued code preserves the OIDC claims request object" do
      claims = %{"userinfo" => %{"name" => %{"essential" => true}}}
      conn = call(valid_params(%{"claims" => JSON.encode!(claims)}))
      code = location_query(conn)["code"]

      record = TestStore.peek(code)
      assert record.data.claims["claims"] == claims
    end

    test "preserves an existing query component in the redirect_uri" do
      put_config(client_redirect_uris: fn _ -> ["https://client.example.com/cb?ui=1"] end)

      conn = call(valid_params(%{"redirect_uri" => "https://client.example.com/cb?ui=1"}))

      assert conn.status == 302
      query = location_query(conn)
      assert query["ui"] == "1"
      assert is_binary(query["code"])
    end

    test "omits state when the request carried none" do
      conn = valid_params(%{}) |> Map.delete("state") |> call()

      assert conn.status == 302
      refute Map.has_key?(location_query(conn), "state")
    end

    test "can include RFC 9207 iss in successful authorization responses" do
      put_config(authorization_response_iss: true)

      conn = call(valid_params())

      assert conn.status == 302
      assert location_query(conn)["iss"] == "https://issuer.example.com"
    end
  end

  # ── JARM (FAPI 2.0 Message Signing §5.4) ─────────────────────────────────

  describe "JARM response modes" do
    test "query.jwt returns a single signed response JWT, not plain code/state" do
      conn = call(valid_params(%{"response_mode" => "query.jwt"}))

      assert conn.status == 302
      query = location_query(conn)

      # Only `response` is in the query; code/state/iss ride inside the JWT.
      assert is_binary(query["response"])
      refute Map.has_key?(query, "code")
      refute Map.has_key?(query, "state")

      claims = decode_jarm(query["response"])
      assert claims["iss"] == "https://issuer.example.com"
      assert claims["aud"] == @client_id
      assert is_binary(claims["code"])
      assert claims["state"] == "xyz"
      assert is_integer(claims["exp"])
    end

    test "the `jwt` shorthand resolves to query.jwt for the code flow (JARM §2.3.2)" do
      conn = call(valid_params(%{"response_mode" => "jwt"}))

      assert conn.status == 302
      query = location_query(conn)
      assert is_binary(query["response"])
      assert decode_jarm(query["response"])["code"] |> is_binary()
    end

    test "fragment.jwt delivers the response JWT in the URL fragment" do
      conn = call(valid_params(%{"response_mode" => "fragment.jwt"}))

      assert conn.status == 302
      fragment = conn |> location() |> URI.parse() |> Map.get(:fragment)
      assert %{"response" => jwt} = URI.decode_query(fragment)
      assert decode_jarm(jwt)["code"] |> is_binary()
    end

    test "form_post.jwt renders an auto-submitting HTML form posting the response" do
      conn = call(valid_params(%{"response_mode" => "form_post.jwt"}))

      assert conn.status == 200
      assert get_resp_header(conn, "content-type") == ["text/html; charset=utf-8"]
      assert conn.resp_body =~ ~s(method="post")
      assert conn.resp_body =~ ~s(action="https://client.example.com/callback")
      assert conn.resp_body =~ ~s(name="response")
      assert [_, jwt] = Regex.run(~r/name="response" value="([^"]+)"/, conn.resp_body)
      assert decode_jarm(jwt)["code"] |> is_binary()
    end

    test "a redirectable error is itself returned as a signed JWT under query.jwt" do
      # An invalid scope token is a redirectable invalid_scope; under a JARM mode
      # the error must be returned as a signed response JWT, not plain params.
      conn = call(valid_params(%{"response_mode" => "query.jwt", "scope" => ~s(open"id)}))

      assert conn.status == 302
      query = location_query(conn)
      assert is_binary(query["response"])
      refute Map.has_key?(query, "error")

      claims = decode_jarm(query["response"])
      assert claims["error"] == "invalid_scope"
      assert claims["aud"] == @client_id
      assert claims["state"] == "xyz"
    end
  end

  # ── Client ID Metadata Documents - CIMD (draft-ietf-oauth-client-id-metadata-document-01) ──
  #
  # The authorization endpoint resolves a CIMD `client_id` URL through the
  # configured fetcher + cache instead of the host `:load_client` registry. A
  # STUB fetcher (no socket / no SSRF) serves a canned document, and the
  # per-node `AttestoPhoenix.ClientIdMetadata.Cache.ETS` is the cache; the
  # assertions cover the §11 integration cases - a CIMD `client_id` issues a
  # code, a `redirect_uri` not in the document is rejected, and a non-same-origin
  # `redirect_uri` is rejected when same-origin is enforced.
  describe "CIMD client_id resolution" do
    alias AttestoPhoenix.ClientIdMetadata.Cache.ETS, as: CimdETS

    @cimd_client_id "https://app.example/clients/metadata.json"
    @cimd_redirect_uri "https://app.example/cb"

    defmodule StubFetcher do
      @moduledoc false
      @behaviour AttestoPhoenix.ClientIdMetadata.Fetcher

      def script(url, result) do
        Agent.update(__MODULE__, &Map.put(&1, url, result))
      end

      @impl true
      def fetch(url, _opts) do
        Agent.get(__MODULE__, &Map.fetch!(&1, url))
      end
    end

    setup do
      {:ok, _} =
        start_supervised(%{
          id: StubFetcher,
          start: {Agent, :start_link, [fn -> %{} end, [name: StubFetcher]]}
        })

      :ok
    end

    defp cimd_config(overrides \\ []) do
      Keyword.merge(
        [enabled: true, fetcher: StubFetcher, cache: CimdETS],
        overrides
      )
    end

    defp cimd_doc(extra \\ %{}) do
      Map.merge(
        %{
          "client_id" => @cimd_client_id,
          "redirect_uris" => [@cimd_redirect_uri],
          "token_endpoint_auth_method" => "none",
          "grant_types" => ["authorization_code"],
          "response_types" => ["code"]
        },
        extra
      )
    end

    # A unique CIMD client_id per test so the node-wide ETS cache never carries
    # an entry from one test into another.
    defp unique_cimd_client_id do
      "https://app.example/clients/#{System.unique_integer([:positive])}/metadata.json"
    end

    defp script_doc(client_id, doc) do
      body = JSON.encode!(Map.put(doc, "client_id", client_id))
      StubFetcher.script(client_id, {:ok, %{body: body, cache_control: []}})
    end

    # A CIMD client that is an installed native app. The document shape is the
    # one Claude Code publishes at
    # https://claude.ai/oauth/claude-code-client-metadata: an https client_id,
    # PORTLESS loopback redirect URIs, and `none` auth. The CLI binds an
    # ephemeral port at runtime, so the request URI carries a port the document
    # cannot have declared.
    #
    # Both defaults used to refuse this. Same-origin is unsatisfiable for it by
    # construction (an https client_id can never share an origin with
    # http://127.0.0.1), and CIMD was hardcoded to exact matching, so the
    # ephemeral port failed too.
    test "a native CIMD client completes the flow on an ephemeral loopback port" do
      client_id = unique_cimd_client_id()

      script_doc(
        client_id,
        cimd_doc(%{"redirect_uris" => ["http://localhost/callback", "http://127.0.0.1/callback"]})
      )

      put_config(client_id_metadata: cimd_config())

      # Everything at its default: same-origin required, loopback allowance on.
      conn =
        call(
          valid_params(%{
            "client_id" => client_id,
            "redirect_uri" => "http://127.0.0.1:51353/callback"
          })
        )

      assert conn.status == 302,
             "expected the native CIMD client to be served, got: #{conn.resp_body}"

      assert location(conn) =~ "http://127.0.0.1:51353/callback"
      assert is_binary(location_query(conn)["code"])
    end

    # The exemption is scoped to loopback: an https redirect from a CIMD
    # document is still held to same origin, which is where the check's
    # anti-impersonation value actually lies.
    test "an https redirect from a CIMD document is still held to same origin" do
      client_id = unique_cimd_client_id()
      script_doc(client_id, cimd_doc(%{"redirect_uris" => ["https://elsewhere.example/cb"]}))
      put_config(client_id_metadata: cimd_config())

      conn =
        call(
          valid_params(%{
            "client_id" => client_id,
            "redirect_uri" => "https://elsewhere.example/cb"
          })
        )

      assert conn.status == 400
      assert location(conn) == nil
    end

    # The same-origin check compares ORIGINS, so it is only as good as the
    # agreement between the parser that decides and the browser that navigates.
    # `https://evil.example\@app.example/cb` reads as host `app.example` under
    # RFC 3986 and as `evil.example` under WHATWG, so approving it would send
    # the code off-origin. The document carrying it is refused outright, which
    # keeps the URI out of the registered set the check ever runs against.
    test "a CIMD document declaring a parser-ambiguous redirect URI is refused" do
      client_id = unique_cimd_client_id()
      ambiguous = "https://evil.example\\@#{URI.parse(client_id).host}/cb"

      script_doc(client_id, cimd_doc(%{"redirect_uris" => [ambiguous]}))
      put_config(client_id_metadata: cimd_config())

      conn = call(valid_params(%{"client_id" => client_id, "redirect_uri" => ambiguous}))

      assert conn.status == 400

      assert location(conn) == nil,
             "an ambiguous redirect URI must never become a redirect target"
    end

    # The same-origin requirement gates the redirect URI itself, so it has to be
    # settled before ANY response travels there. A request that fails ordinary
    # validation (here: mandatory PKCE) must not short-circuit ahead of the gate
    # and carry a redirectable error cross-origin.
    test "a validation error does not escape cross-origin ahead of the same-origin check" do
      client_id = unique_cimd_client_id()
      script_doc(client_id, cimd_doc(%{"redirect_uris" => ["https://elsewhere.example/cb"]}))
      put_config(client_id_metadata: cimd_config())

      conn =
        valid_params(%{
          "client_id" => client_id,
          "redirect_uri" => "https://elsewhere.example/cb"
        })
        |> Map.drop(["code_challenge", "code_challenge_method"])
        |> call()

      assert conn.status == 400

      assert location(conn) == nil,
             "an error must not be redirected to a URI the origin check refuses"
    end

    # The converse: when the origin check passes, an ordinary validation failure
    # is still redirectable. The fix orders the gate ahead of the error, it does
    # not turn every error into a direct one.
    test "a validation error for a same-origin redirect stays redirectable" do
      client_id = unique_cimd_client_id()
      same_origin = "https://#{URI.parse(client_id).host}/cb"

      script_doc(client_id, cimd_doc(%{"redirect_uris" => [same_origin]}))
      put_config(client_id_metadata: cimd_config())

      conn =
        valid_params(%{"client_id" => client_id, "redirect_uri" => same_origin})
        |> Map.drop(["code_challenge", "code_challenge_method"])
        |> call()

      assert conn.status == 302
      assert location(conn) =~ same_origin
      assert location_query(conn)["error"] == "invalid_request"
    end

    # §8.3: the literal IP is required. A document declaring only the localhost
    # NAME gets neither the same-origin exemption nor port flexibility.
    test "a localhost-only CIMD document is still refused" do
      client_id = unique_cimd_client_id()
      script_doc(client_id, cimd_doc(%{"redirect_uris" => ["http://localhost/callback"]}))
      put_config(client_id_metadata: cimd_config())

      conn =
        call(
          valid_params(%{
            "client_id" => client_id,
            "redirect_uri" => "http://localhost:51353/callback"
          })
        )

      assert conn.status == 400
      assert location(conn) == nil
    end

    # Claude Code requests the LOCALHOST member of its document, not the IP
    # literal, so the strict default refuses it (the test above). The opt-in
    # has to carry the whole flow: the match (port flexibility for the name),
    # the native signal (a localhost URI counts as declaring loopback), and the
    # same-origin exemption (a localhost redirect is exempt like the literals).
    test "the localhost opt-in serves Claude Code's actual request shape" do
      client_id = unique_cimd_client_id()

      script_doc(
        client_id,
        cimd_doc(%{"redirect_uris" => ["http://localhost/callback", "http://127.0.0.1/callback"]})
      )

      put_config(
        client_id_metadata: cimd_config(),
        native_apps: [loopback_include_localhost: true]
      )

      conn =
        call(
          valid_params(%{
            "client_id" => client_id,
            "redirect_uri" => "http://localhost:3118/callback"
          })
        )

      assert conn.status == 302,
             "expected the localhost loopback flow to be served, got: #{conn.resp_body}"

      assert location(conn) =~ "http://localhost:3118/callback"
      assert is_binary(location_query(conn)["code"])
    end

    test "the localhost opt-in serves a localhost-ONLY document too" do
      client_id = unique_cimd_client_id()
      script_doc(client_id, cimd_doc(%{"redirect_uris" => ["http://localhost/callback"]}))

      put_config(
        client_id_metadata: cimd_config(),
        native_apps: [loopback_include_localhost: true]
      )

      conn =
        call(
          valid_params(%{
            "client_id" => client_id,
            "redirect_uri" => "http://localhost:51353/callback"
          })
        )

      assert conn.status == 302
      assert location(conn) =~ "http://localhost:51353/callback"
    end

    test "the loopback kill switch disables the localhost same-origin exemption" do
      client_id = unique_cimd_client_id()
      redirect_uri = "http://localhost:51353/callback"
      script_doc(client_id, cimd_doc(%{"redirect_uris" => [redirect_uri]}))

      put_config(
        client_id_metadata: cimd_config(),
        native_apps: [loopback_redirect: false, loopback_include_localhost: true]
      )

      conn = call(valid_params(%{"client_id" => client_id, "redirect_uri" => redirect_uri}))

      assert conn.status == 400
      assert location(conn) == nil
    end

    test "the kill switch preserves the exact IP-literal same-origin exemption" do
      client_id = unique_cimd_client_id()
      redirect_uri = "http://127.0.0.1:51353/callback"
      script_doc(client_id, cimd_doc(%{"redirect_uris" => [redirect_uri]}))

      put_config(
        client_id_metadata: cimd_config(),
        native_apps: [loopback_redirect: false, loopback_include_localhost: true]
      )

      conn = call(valid_params(%{"client_id" => client_id, "redirect_uri" => redirect_uri}))

      assert conn.status == 302
      assert location(conn) =~ redirect_uri
      assert is_binary(location_query(conn)["code"])
    end

    # The opt-in widens which hosts count as loopback, nothing else: an https
    # redirect from a CIMD document is still held to same origin, and a
    # lookalike host gets neither port flexibility nor the exemption.
    test "the localhost opt-in does not widen anything but the name" do
      client_id = unique_cimd_client_id()

      script_doc(
        client_id,
        cimd_doc(%{
          "redirect_uris" => [
            "https://elsewhere.example/cb",
            "http://localhost.evil.example/callback"
          ]
        })
      )

      put_config(
        client_id_metadata: cimd_config(),
        native_apps: [loopback_include_localhost: true]
      )

      cross_origin =
        call(
          valid_params(%{
            "client_id" => client_id,
            "redirect_uri" => "https://elsewhere.example/cb"
          })
        )

      assert cross_origin.status == 400

      lookalike =
        call(
          valid_params(%{
            "client_id" => client_id,
            "redirect_uri" => "http://localhost.evil.example:3118/callback"
          })
        )

      assert lookalike.status == 400
    end

    test "resolves a CIMD client_id and issues a code" do
      client_id = unique_cimd_client_id()
      script_doc(client_id, cimd_doc())
      put_config(client_id_metadata: cimd_config())

      conn =
        call(valid_params(%{"client_id" => client_id, "redirect_uri" => @cimd_redirect_uri}))

      assert conn.status == 302
      query = location_query(conn)
      assert location(conn) =~ @cimd_redirect_uri
      assert is_binary(query["code"])

      # The issued code is bound to the CIMD URL as the client_id.
      record = TestStore.peek(query["code"])
      assert record.data.client_id == client_id
    end

    test "rejects a redirect_uri not in the document (direct error)" do
      client_id = unique_cimd_client_id()
      script_doc(client_id, cimd_doc())
      put_config(client_id_metadata: cimd_config())

      conn =
        call(
          valid_params(%{
            "client_id" => client_id,
            "redirect_uri" => "https://app.example/not-registered"
          })
        )

      # Non-redirectable: the supplied redirect_uri is not in the document, so a
      # direct error (never a redirect back to the untrusted URI).
      assert conn.status == 400
      refute get_resp_header(conn, "location") |> Enum.any?(&(&1 =~ "not-registered"))
    end

    test "rejects a non-same-origin redirect_uri when same-origin is enforced" do
      client_id = unique_cimd_client_id()
      # The document registers a redirect_uri on a DIFFERENT origin than the
      # client_id URL. Exact-match passes, but the same-origin tightening
      # (default on) rejects it.
      cross_origin = "https://other.example/cb"
      script_doc(client_id, cimd_doc(%{"redirect_uris" => [cross_origin]}))
      put_config(client_id_metadata: cimd_config(require_same_origin_redirect_uri: true))

      conn =
        call(valid_params(%{"client_id" => client_id, "redirect_uri" => cross_origin}))

      assert conn.status == 400
    end

    test "permits a non-same-origin redirect_uri when same-origin is disabled" do
      client_id = unique_cimd_client_id()
      cross_origin = "https://other.example/cb"
      script_doc(client_id, cimd_doc(%{"redirect_uris" => [cross_origin]}))
      put_config(client_id_metadata: cimd_config(require_same_origin_redirect_uri: false))

      conn =
        call(valid_params(%{"client_id" => client_id, "redirect_uri" => cross_origin}))

      assert conn.status == 302
      assert location(conn) =~ cross_origin
    end

    test "an unresolvable CIMD client_id is a non-redirectable error" do
      client_id = unique_cimd_client_id()
      StubFetcher.script(client_id, {:error, {:status, 404}})
      put_config(client_id_metadata: cimd_config())

      conn =
        call(valid_params(%{"client_id" => client_id, "redirect_uri" => @cimd_redirect_uri}))

      assert conn.status == 400
      assert get_resp_header(conn, "location") == []
    end

    test "an opaque client_id still flows through :load_client when CIMD is enabled" do
      put_config(client_id_metadata: cimd_config())

      # The opaque @client_id is not a URL, so CIMD never applies; the host
      # registry resolves it exactly as before.
      conn = call(valid_params())

      assert conn.status == 302
      assert is_binary(location_query(conn)["code"])
    end

    test "a CIMD client_id is ignored (host registry) when the feature is disabled" do
      client_id = unique_cimd_client_id()
      script_doc(client_id, cimd_doc())
      put_config(client_id_metadata: cimd_config(enabled: false))

      # With CIMD disabled the URL is treated as an opaque client_id; the host
      # registry has no such client, so it is a non-redirectable error.
      conn =
        call(valid_params(%{"client_id" => client_id, "redirect_uri" => @cimd_redirect_uri}))

      assert conn.status == 400
    end
  end

  describe "PAR-required policy" do
    test "rejects direct authorization requests when PAR is required" do
      put_config(
        require_pushed_authorization_requests: true,
        par_store: PARStore
      )

      conn = call(valid_params())

      assert conn.status == 302
      query = location_query(conn)
      assert query["error"] == "invalid_request"
      assert query["state"] == "xyz"
      refute Map.has_key?(query, "code")
    end

    test "accepts authorization requests resolved from a PAR request_uri" do
      request_uri = "urn:ietf:params:oauth:request_uri:test"

      put_config(
        require_pushed_authorization_requests: true,
        par_store: PARStore
      )

      :ok = PARStore.put(request_uri, valid_params(), 60)

      conn = call(%{"client_id" => @client_id, "request_uri" => request_uri})

      assert conn.status == 302
      query = location_query(conn)
      assert is_binary(query["code"])
      assert query["state"] == "xyz"
    end

    test "a raising private-context callback propagates after PAR claims the request_uri" do
      request_uri = "urn:ietf:params:oauth:request_uri:private-context-raise"

      put_config(
        require_pushed_authorization_requests: true,
        par_store: PARStore,
        authorization_code_completion: &passthrough_completion/2,
        authorization_code_private_context: fn _context ->
          raise "injected private-context callback failure"
        end
      )

      :ok = PARStore.put(request_uri, valid_params(), 60)

      assert_raise RuntimeError, "injected private-context callback failure", fn ->
        call(%{"client_id" => @client_id, "request_uri" => request_uri})
      end

      # The PAR reference is claimed before the private-context callback runs;
      # a raised host callback therefore cannot leave it available for retry.
      assert :error = PARStore.fetch(request_uri)
    end

    test "completion consumes the PAR request_uri (RFC 9126 single-use)" do
      request_uri = "urn:ietf:params:oauth:request_uri:single-use"

      put_config(require_pushed_authorization_requests: true, par_store: PARStore)
      :ok = PARStore.put(request_uri, valid_params(), 60)

      conn = call(%{"client_id" => @client_id, "request_uri" => request_uri})

      assert conn.status == 302
      assert is_binary(location_query(conn)["code"])
      # The reference was claimed atomically at completion, so the store no longer
      # holds it - a later presentation resolves nothing.
      assert :error = PARStore.fetch(request_uri)
    end

    test "a lost single-use claim at completion redirects invalid_request_uri and issues no code" do
      request_uri = "urn:ietf:params:oauth:request_uri:race-lost"

      # fetch resolves (the request is validated and consent runs) but the atomic
      # take loses - as if a concurrent completion consumed the reference first.
      put_config(require_pushed_authorization_requests: true, par_store: TakeLosesPARStore)
      :ok = TakeLosesPARStore.put(request_uri, valid_params(), 60)

      conn = call(%{"client_id" => @client_id, "request_uri" => request_uri})

      assert conn.status == 302
      query = location_query(conn)
      refute Map.has_key?(query, "code")
      assert query["error"] == "invalid_request_uri"
    end

    test "an unexpected single-use claim result is a sanitized integration failure" do
      request_uri = "urn:ietf:params:oauth:request_uri:store-fault"

      put_config(require_pushed_authorization_requests: true, par_store: TakeFaultsPARStore)
      :ok = TakeFaultsPARStore.put(request_uri, valid_params(), 60)

      assert_raise RuntimeError, ~r/take\/1 violated its PAR-store return contract/, fn ->
        call(%{"client_id" => @client_id, "request_uri" => request_uri})
      end

      assert {:ok, _params} = TakeFaultsPARStore.fetch(request_uri)
    end

    test "ignores front-channel state outside a resolved PAR request" do
      request_uri = "urn:ietf:params:oauth:request_uri:state-outside-par"

      put_config(
        require_pushed_authorization_requests: true,
        par_store: PARStore
      )

      :ok = PARStore.put(request_uri, valid_params() |> Map.delete("state"), 60)

      conn =
        call(%{
          "client_id" => @client_id,
          "request_uri" => request_uri,
          "state" => "front-channel-state"
        })

      assert conn.status == 302
      query = location_query(conn)
      assert is_binary(query["code"])
      refute Map.has_key?(query, "state")
    end

    test "carries a PAR DPoP thumbprint into the issued authorization code" do
      request_uri = "urn:ietf:params:oauth:request_uri:dpop-bound"
      jkt = Attesto.Secret.hash("par-proof-key")

      put_config(
        require_pushed_authorization_requests: true,
        par_store: PARStore
      )

      :ok = PARStore.put(request_uri, Map.put(valid_params(), "dpop_jkt", jkt), 60)

      conn = call(%{"client_id" => @client_id, "request_uri" => request_uri})

      assert conn.status == 302
      code = location_query(conn)["code"]
      assert TestStore.peek(code).data.dpop_jkt == jkt
    end

    test "preserves a PAR-verified DPoP thumbprint when the pushed request used a signed request object" do
      # Regression guard: PAR stores the proof-verified thumbprint at the TOP
      # LEVEL of the pushed params AND retains the signed `request` JWT. validate/2
      # re-merges the request object (replacing the param map with the object's),
      # so the top-level dpop_jkt is dropped from `request.dpop_jkt` - the
      # controller must read the PAR-verified value directly or the code is minted
      # UNBOUND (the DPoP sender-constraint silently lost).
      request_uri = "urn:ietf:params:oauth:request_uri:par-jar-dpop"
      jkt = Attesto.Secret.hash("par-jar-proof-key")

      request_key = JOSE.JWK.generate_key({:ec, "P-256"})
      {_kty, pub} = JOSE.JWK.to_public_map(request_key)
      client_jwk = Map.merge(pub, %{"kid" => "rk", "alg" => "ES256"})

      put_config(
        require_pushed_authorization_requests: true,
        par_store: PARStore,
        client_jwks: fn _client -> %{"keys" => [client_jwk]} end
      )

      now = System.system_time(:second)

      claims = %{
        "iss" => @client_id,
        "aud" => "https://issuer.example.com",
        "client_id" => @client_id,
        "redirect_uri" => @redirect_uri,
        "response_type" => "code",
        "scope" => "openid",
        "code_challenge" => @code_challenge,
        "code_challenge_method" => "S256",
        "nbf" => now,
        "exp" => now + 300
      }

      header = %{"alg" => "ES256", "kid" => "rk", "typ" => "oauth-authz-req+jwt"}
      {_header, request} = request_key |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()

      # Exactly what par.ex stores: object params re-tagged with "request", plus
      # the proof-verified thumbprint at the top level.
      stored = %{"client_id" => @client_id, "request" => request, "dpop_jkt" => jkt}
      :ok = PARStore.put(request_uri, stored, 60)

      conn = call(%{"client_id" => @client_id, "request_uri" => request_uri})

      assert conn.status == 302
      code = location_query(conn)["code"]
      assert TestStore.peek(code).data.dpop_jkt == jkt
    end

    test "uses the bound client and ignores other front-channel params when the client_id matches" do
      request_uri = "urn:ietf:params:oauth:request_uri:bound-client"

      put_config(
        require_pushed_authorization_requests: true,
        par_store: PARStore
      )

      :ok = PARStore.put(request_uri, valid_params(), 60)

      conn = call(%{"client_id" => @client_id, "request_uri" => request_uri})

      assert conn.status == 302
      code = location_query(conn)["code"]
      assert is_binary(code)
      assert TestStore.peek(code).data.client_id == @client_id
    end

    test "rejects a front-channel client_id that does not match the request_uri's bound client" do
      # RFC 9126 §2.2 / FAPI2SPFinalPAREnsureRequestUriIsBoundToClient: the
      # request_uri is bound to the client that pushed it; a different client
      # replaying the reference (mismatched front-channel client_id) is rejected,
      # non-redirectable (the bound redirect_uri is not trusted for this caller).
      request_uri = "urn:ietf:params:oauth:request_uri:bound-client"

      put_config(
        require_pushed_authorization_requests: true,
        par_store: PARStore
      )

      :ok = PARStore.put(request_uri, valid_params(), 60)

      conn = call(%{"client_id" => "front-channel-client", "request_uri" => request_uri})

      # Non-redirectable direct error: a 400 means no authorization code was issued.
      assert conn.status == 400
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_request"
    end

    test "a PAR request_uri survives re-entry until a code is issued" do
      # FAPI2 / RFC 9126 PAREnsureServerAcceptsReusedRequestUriBeforeAuthenticationCompletion:
      # a login that halts (host redirects to its own login page) issues no code,
      # so the request_uri MUST remain usable for the host's re-entry.
      request_uri = "urn:ietf:params:oauth:request_uri:reentry"

      put_config(
        require_pushed_authorization_requests: true,
        par_store: PARStore,
        authenticate_resource_owner: fn conn, _request, _opts ->
          {:halt, Plug.Conn.send_resp(conn, 200, "login")}
        end
      )

      :ok = PARStore.put(request_uri, valid_params(), 60)

      first = call(%{"client_id" => @client_id, "request_uri" => request_uri})
      second = call(%{"client_id" => @client_id, "request_uri" => request_uri})

      # Both halt at the host login (no code, no error); the reference is untouched.
      assert first.status == 200
      assert second.status == 200
      assert {:ok, _} = PARStore.fetch(request_uri)
    end

    test "a completed PAR flow consumes the request_uri (single-use, RFC 9126 §2.2)" do
      # FAPI2 / RFC 9126 PARAttemptReuseRequestUri: once a code is issued the
      # request_uri is consumed, so replaying it within the TTL is rejected as
      # invalid_request_uri rather than minting a second code.
      request_uri = "urn:ietf:params:oauth:request_uri:single-use"

      put_config(
        require_pushed_authorization_requests: true,
        par_store: PARStore
      )

      :ok = PARStore.put(request_uri, valid_params(), 60)

      first = call(%{"client_id" => @client_id, "request_uri" => request_uri})
      second = call(%{"client_id" => @client_id, "request_uri" => request_uri})

      assert first.status == 302
      assert is_binary(location_query(first)["code"])

      assert second.status == 400
      assert JSON.decode!(second.resp_body)["error"] == "invalid_request_uri"
      assert :error = PARStore.fetch(request_uri)
    end

    test "an unknown/expired PAR request_uri is a direct invalid_request_uri" do
      # RFC 9126 §2.2 / FAPI2SPFinalPARAttemptToUseExpiredRequestUri: a PAR
      # `urn:ietf:params:oauth:request_uri:` reference that is not in the store
      # (expired or never issued) must be rejected as invalid_request_uri, never
      # treated as an absent reference (which would surface the wrong error).
      put_config(require_pushed_authorization_requests: true, par_store: PARStore)

      conn =
        call(%{
          "client_id" => @client_id,
          "request_uri" => "urn:ietf:params:oauth:request_uri:does-not-exist"
        })

      assert conn.status == 400
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_request_uri"
    end

    test "an unknown/expired PAR request_uri renders the invalid_request_uri code in the HTML error page" do
      # A browser (Accept: text/html) hitting an expired request_uri must see the
      # SAME error code as the JSON body. The HTML page previously hardcoded
      # `invalid_request`, which the FAPI2 par-attempt-to-use-expired-request_uri
      # conformance test (reading the rendered page) rejects.
      put_config(require_pushed_authorization_requests: true, par_store: PARStore)

      conn =
        build_conn()
        |> Map.put(:scheme, :https)
        |> with_config()
        |> put_req_header("accept", "text/html")
        |> AuthorizeController.authorize(%{
          "client_id" => @client_id,
          "request_uri" => "urn:ietf:params:oauth:request_uri:does-not-exist"
        })

      assert conn.status == 400
      assert get_resp_header(conn, "content-type") == ["text/html; charset=utf-8"]
      assert conn.resp_body =~ "<code>invalid_request_uri</code>"
      refute conn.resp_body =~ "<code>invalid_request</code>"
    end
  end

  # ── Direct (non-redirectable) errors (OIDC Core §3.1.2.6) ─────────────────

  describe "direct errors (never a redirect)" do
    test "unknown client_id renders a direct 400, not a redirect" do
      conn = call(valid_params(%{"client_id" => "ghost"}))

      assert conn.status == 400
      assert get_resp_header(conn, "location") == []
      assert %{"error" => "invalid_request"} = json_response(conn, 400)
    end

    test "an unexpected client-store result is a sanitized integration failure" do
      put_config(load_client: fn _client_id -> {:error, :store_unavailable} end)

      assert_raise RuntimeError, ":load_client callback violated its return contract", fn ->
        call(valid_params())
      end
    end

    test "missing client_id renders a direct 400" do
      conn = valid_params(%{}) |> Map.delete("client_id") |> call()

      assert conn.status == 400
      assert get_resp_header(conn, "location") == []
    end

    test "unregistered redirect_uri renders a direct 400, not a redirect" do
      conn = call(valid_params(%{"redirect_uri" => "https://evil.example.com/cb"}))

      assert conn.status == 400
      assert get_resp_header(conn, "location") == []
    end

    test "unregistered redirect_uri renders an HTML error page for browser requests" do
      conn =
        build_conn()
        |> Map.put(:scheme, :https)
        |> with_config()
        |> put_req_header("accept", "text/html")
        |> AuthorizeController.authorize(valid_params(%{"redirect_uri" => "https://evil.example.com/cb"}))

      assert conn.status == 400
      assert get_resp_header(conn, "location") == []
      assert get_resp_header(conn, "content-type") == ["text/html; charset=utf-8"]
      assert conn.resp_body =~ "Authorization request error"
      assert conn.resp_body =~ "redirect_uri is not registered for this client"
    end

    test "missing redirect_uri renders a direct 400" do
      conn = valid_params(%{}) |> Map.delete("redirect_uri") |> call()

      assert conn.status == 400
      assert get_resp_header(conn, "location") == []
    end

    test "insecure transport renders a direct 400 when HTTPS is required" do
      conn =
        build_conn()
        |> Map.put(:scheme, :http)
        |> with_config()
        |> AuthorizeController.authorize(valid_params())

      assert conn.status == 400
      assert get_resp_header(conn, "location") == []
    end
  end

  # ── Redirectable errors (RFC 6749 §4.1.2.1) ───────────────────────────────

  describe "redirectable errors (back to the validated redirect_uri)" do
    test "bad response_type redirects with unsupported_response_type + state" do
      conn = call(valid_params(%{"response_type" => "token"}))

      assert conn.status == 302
      query = location_query(conn)
      assert query["error"] == "unsupported_response_type"
      assert query["state"] == "xyz"
      assert location(conn) =~ @redirect_uri
    end

    test "missing PKCE challenge redirects with invalid_request" do
      conn = valid_params(%{}) |> Map.delete("code_challenge") |> call()

      assert conn.status == 302
      assert location_query(conn)["error"] == "invalid_request"
    end

    test "a request object failing the FAPI Message Signing policy is rejected at /authorize" do
      # Guards that the controller threads :request_object_policy into
      # AuthorizationRequest.validate/2: under the FAPI profile this object
      # (no nbf) must be rejected; the default generic policy would accept it.
      request_key = JOSE.JWK.generate_key({:ec, "P-256"})
      {_kty, pub} = JOSE.JWK.to_public_map(request_key)
      client_jwk = Map.merge(pub, %{"kid" => "rk", "alg" => "ES256"})

      put_config(
        client_jwks: fn _client -> %{"keys" => [client_jwk]} end,
        request_object_policy: Policy.fapi_message_signing()
      )

      claims = %{
        "iss" => @client_id,
        "aud" => "https://issuer.example.com",
        "client_id" => @client_id,
        "redirect_uri" => @redirect_uri,
        "response_type" => "code",
        "scope" => "openid",
        "code_challenge" => @code_challenge,
        "code_challenge_method" => "S256"
      }

      header = %{"alg" => "ES256", "kid" => "rk", "typ" => "oauth-authz-req+jwt"}
      {_header, request} = request_key |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()

      conn =
        call(%{"client_id" => @client_id, "redirect_uri" => @redirect_uri, "request" => request})

      assert conn.status == 302
      assert location_query(conn)["error"] == "invalid_request_object"
    end

    test "can include RFC 9207 iss in authorization error responses" do
      put_config(authorization_response_iss: true)

      conn = valid_params(%{}) |> Map.delete("code_challenge") |> call()

      assert conn.status == 302
      query = location_query(conn)
      assert query["error"] == "invalid_request"
      assert query["iss"] == "https://issuer.example.com"
    end

    test "PKCE plain method redirects with invalid_request (no downgrade)" do
      conn = call(valid_params(%{"code_challenge_method" => "plain"}))

      assert conn.status == 302
      assert location_query(conn)["error"] == "invalid_request"
    end

    test "invalid scope token redirects with invalid_scope" do
      conn = call(valid_params(%{"scope" => "openid \"bad\""}))

      assert conn.status == 302
      assert location_query(conn)["error"] == "invalid_scope"
    end

    test "unsupported request_uri redirects with request_uri_not_supported when no PAR store is configured" do
      conn = call(valid_params(%{"request_uri" => "https://client.example.com/request.jwt"}))

      assert conn.status == 302
      query = location_query(conn)
      assert query["error"] == "request_uri_not_supported"
      assert query["state"] == "xyz"
      refute Map.has_key?(query, "code")
    end

    test "no code is issued when a redirectable error fires" do
      conn = call(valid_params(%{"response_type" => "token"}))

      refute Map.has_key?(location_query(conn), "code")
    end
  end

  # ── Login / consent host hooks ────────────────────────────────────────────

  describe "host login/consent hooks" do
    test "an unauthenticated owner has the connection handed to the host (no code)" do
      put_config(
        authenticate_resource_owner: fn conn, _request, _opts ->
          {:halt, conn |> Plug.Conn.put_resp_header("location", "/login") |> Plug.Conn.send_resp(302, "")}
        end
      )

      conn = call(valid_params())

      # Host redirected to its own login page; no authorization code issued.
      assert location(conn) == "/login"
      refute Map.has_key?(location_query(conn), "code")
    end

    test "denied consent redirects with access_denied" do
      put_config(consent: fn _conn, _request, _subject -> {:denied, :user_refused} end)

      conn = call(valid_params())

      assert conn.status == 302
      assert location_query(conn)["error"] == "access_denied"
      assert location_query(conn)["state"] == "xyz"
    end

    test "consent halting hands the connection to the host (no code)" do
      put_config(
        consent: fn conn, _request, _subject ->
          {:halt,
           conn
           |> Plug.Conn.put_resp_header("location", "/consent")
           |> Plug.Conn.send_resp(302, "")}
        end
      )

      conn = call(valid_params())

      assert location(conn) == "/consent"
      refute Map.has_key?(location_query(conn), "code")
    end

    test "missing authenticate_resource_owner callback fails closed with server_error" do
      put_config(authenticate_resource_owner: nil)

      conn = call(valid_params())

      assert conn.status == 302
      assert location_query(conn)["error"] == "server_error"
    end

    test "absent consent callback implicitly grants consent and issues a code" do
      put_config(consent: nil)

      conn = call(valid_params())

      assert conn.status == 302
      assert is_binary(location_query(conn)["code"])
    end

    test "an invalid authenticate_resource_owner result is logged without callback data" do
      put_config(
        authenticate_resource_owner: fn _conn, _request, _opts ->
          {:invalid_callback_result, %{private_value: "authorize-login-private-sentinel"}}
        end
      )

      log =
        capture_log(fn ->
          conn = call(valid_params())

          assert conn.status == 302
          assert location_query(conn)["error"] == "server_error"
        end)

      assert log =~ "authenticate_resource_owner callback returned an invalid result"
      refute log =~ "authorize-login-private-sentinel"
    end

    test "an invalid consent result is logged without callback data" do
      put_config(
        consent: fn _conn, _request, _subject ->
          {:invalid_callback_result, %{private_value: "authorize-consent-private-sentinel"}}
        end
      )

      log =
        capture_log(fn ->
          conn = call(valid_params())

          assert conn.status == 302
          assert location_query(conn)["error"] == "server_error"
        end)

      assert log =~ "consent callback returned an invalid result"
      refute log =~ "authorize-consent-private-sentinel"
    end
  end

  # ── nonce policy (OIDC Core §3.1.2.1) ──────────────────────────────────────

  describe "require_nonce policy" do
    test "an OIDC request without a nonce is rejected when require_nonce is set" do
      put_config(require_nonce: true)

      conn = valid_params(%{}) |> Map.delete("nonce") |> call()

      assert conn.status == 302
      query = location_query(conn)
      assert query["error"] == "invalid_request"
      assert query["state"] == "xyz"
      # The error is redirectable (the redirect_uri is trusted), never a code.
      refute Map.has_key?(query, "code")
    end

    test "an OIDC request with a nonce still succeeds when require_nonce is set" do
      put_config(require_nonce: true)

      conn = call(valid_params())

      assert conn.status == 302
      assert is_binary(location_query(conn)["code"])
    end

    test "a non-OIDC request without a nonce is unaffected by require_nonce" do
      # No `openid` scope => not an OpenID Connect Authentication Request, so the
      # nonce requirement does not apply (RFC 6749 keeps the code at SHOULD).
      put_config(require_nonce: true)

      conn = valid_params(%{"scope" => "profile"}) |> Map.delete("nonce") |> call()

      assert conn.status == 302
      assert is_binary(location_query(conn)["code"])
    end

    test "an OIDC request without a nonce succeeds when require_nonce is unset (default)" do
      conn = valid_params(%{}) |> Map.delete("nonce") |> call()

      assert conn.status == 302
      assert is_binary(location_query(conn)["code"])
    end
  end

  # ── prompt handling (OIDC Core §3.1.2.1 / §3.1.2.6) ────────────────────────

  describe "prompt=none (no interactive UI)" do
    test "the host is told the request is non-interactive" do
      call(valid_params(%{"prompt" => "none"}))

      assert_received {:auth_opts, auth_opts}
      assert auth_opts.interactive == false
      assert auth_opts.prompt == ["none"]
    end

    test "an already-authenticated subject still issues a code under prompt=none" do
      conn = call(valid_params(%{"prompt" => "none"}))

      assert conn.status == 302
      assert is_binary(location_query(conn)["code"])
    end

    test "a host that cannot authenticate silently ({:none}) yields login_required" do
      put_config(authenticate_resource_owner: fn _conn, _request, _opts -> {:none} end)

      conn = call(valid_params(%{"prompt" => "none"}))

      assert conn.status == 302
      query = location_query(conn)
      assert query["error"] == "login_required"
      assert query["state"] == "xyz"
      refute Map.has_key?(query, "code")
    end

    test "a host halt to login UI is converted to login_required under prompt=none" do
      # The host MUST NOT render UI under prompt=none; even if it tries to halt
      # to its login page, the controller reports login_required instead.
      put_config(
        authenticate_resource_owner: fn conn, _request, _opts ->
          {:halt, conn |> Plug.Conn.put_resp_header("location", "/login") |> Plug.Conn.send_resp(302, "")}
        end
      )

      conn = call(valid_params(%{"prompt" => "none"}))

      assert location(conn) =~ @redirect_uri
      assert location_query(conn)["error"] == "login_required"
    end

    test "a consent halt is converted to consent_required under prompt=none" do
      put_config(
        consent: fn conn, _request, _subject ->
          {:halt,
           conn
           |> Plug.Conn.put_resp_header("location", "/consent")
           |> Plug.Conn.send_resp(302, "")}
        end
      )

      conn = call(valid_params(%{"prompt" => "none"}))

      assert location(conn) =~ @redirect_uri
      assert location_query(conn)["error"] == "consent_required"
    end

    test "denied consent is consent_required (not access_denied) under prompt=none" do
      put_config(consent: fn _conn, _request, _subject -> {:denied, :user_refused} end)

      conn = call(valid_params(%{"prompt" => "none"}))

      assert location_query(conn)["error"] == "consent_required"
    end

    test "a host {:error, :interaction_required} is reported by redirect" do
      put_config(
        authenticate_resource_owner: fn _conn, _request, _opts ->
          {:error, :interaction_required}
        end
      )

      conn = call(valid_params(%{"prompt" => "none"}))

      assert location_query(conn)["error"] == "interaction_required"
    end
  end

  describe "prompt=login (force re-authentication)" do
    test "the host is told to force re-auth" do
      call(valid_params(%{"prompt" => "login"}))

      assert_received {:auth_opts, auth_opts}
      assert auth_opts.force_reauth == true
      assert auth_opts.interactive == true
    end

    test "the freshly established auth_time rides into the code claims" do
      conn = call(valid_params(%{"prompt" => "login"}))
      code = location_query(conn)["code"]

      # The stub bumps auth_time when force_reauth is set; that fresh value is
      # what the ID token must reflect (OIDC Core §2).
      record = TestStore.peek(code)
      assert record.data.claims["auth_time"] == 1_700_009_999
    end
  end

  # ── max_age / auth_time (OIDC Core §3.1.2.1) ───────────────────────────────

  describe "max_age" do
    test "max_age is threaded to the host auth callback" do
      call(valid_params(%{"max_age" => "300"}))

      assert_received {:auth_opts, auth_opts}
      assert auth_opts.max_age == 300
    end

    test "an absent max_age is nil in the auth callback opts" do
      call(valid_params())

      assert_received {:auth_opts, auth_opts}
      assert auth_opts.max_age == nil
    end

    test "a max_age that forces re-auth carries the fresh auth_time into the code" do
      # max_age=0 means the existing authentication is always too old; the stub
      # re-authenticates and returns the fresh auth_time, which the issued code
      # must carry so the ID token's auth_time reflects the re-auth.
      conn = call(valid_params(%{"max_age" => "0"}))
      code = location_query(conn)["code"]

      record = TestStore.peek(code)
      assert record.data.claims["auth_time"] == 1_700_009_999
    end
  end

  # ── Session Management (OIDC Session Management 1.0 §2 / §3.2) ─────────────

  describe "session_state" do
    test "a successful response carries session_state and sets the __Host- browser-state cookie" do
      put_config(session_management: [enabled: true, browser_state_secret: @browser_state_secret])

      conn = call(valid_params())
      query = location_query(conn)

      assert is_binary(query["code"])
      session_state = query["session_state"]
      assert is_binary(session_state)
      refute session_state =~ " "

      # The cookie is minted on this response (the login event) under the
      # __Host- name with the attributes __Host- + the cross-site JS-read iframe
      # require: Secure, Path=/, no Domain, SameSite=None, not HttpOnly.
      cookie = conn.resp_cookies[@browser_state_cookie]
      assert %{value: opbs, http_only: false, secure: true, same_site: "None", path: "/"} = cookie
      assert Map.get(cookie, :domain) == nil

      # The value is OP-owned: it verifies under the OP secret for this login.
      assert Attesto.SessionState.browser_state_valid?(
               @browser_state_secret,
               opbs,
               @established_binding
             )

      # And it verifies against the §3.2 recipe over the redirect_uri origin.
      [_hash, salt] = String.split(session_state, ".", parts: 2)

      assert session_state ==
               Attesto.SessionState.compute(@client_id, "https://client.example.com", opbs, salt)
    end

    test "an OP-minted cookie for the same login is reused, not rotated (unchanged)" do
      put_config(session_management: [enabled: true, browser_state_secret: @browser_state_secret])

      # A value THIS OP minted for the established login is reused untouched, so
      # a stable session recomputes `unchanged`.
      opbs = Attesto.SessionState.mint_browser_state(@browser_state_secret, @established_binding)

      conn =
        build_conn()
        |> Map.put(:scheme, :https)
        |> with_config()
        |> put_req_header("cookie", "#{@browser_state_cookie}=#{opbs}")
        |> AuthorizeController.authorize(valid_params())

      session_state = location_query(conn)["session_state"]
      [_hash, salt] = String.split(session_state, ".", parts: 2)

      assert session_state ==
               Attesto.SessionState.compute(@client_id, "https://client.example.com", opbs, salt)

      # No re-mint: the response sets no fresh cookie value.
      refute Map.has_key?(conn.resp_cookies, @browser_state_cookie)
    end

    test "a re-auth with a newer auth_time rotates the browser state (Finding 1: changed)" do
      put_config(session_management: [enabled: true, browser_state_secret: @browser_state_secret])

      # Cookie bound to the ESTABLISHED-login auth_time.
      opbs = Attesto.SessionState.mint_browser_state(@browser_state_secret, @established_binding)

      # max_age=0 forces the stub to re-authenticate and return a NEWER
      # auth_time; the login binding changes, so the OP browser state MUST
      # rotate even though it is the same user agent + subject.
      conn =
        build_conn()
        |> Map.put(:scheme, :https)
        |> with_config()
        |> put_req_header("cookie", "#{@browser_state_cookie}=#{opbs}")
        |> AuthorizeController.authorize(valid_params(%{"max_age" => "0"}))

      fresh = conn.resp_cookies[@browser_state_cookie]
      assert is_binary(fresh.value)
      refute fresh.value == opbs

      assert Attesto.SessionState.browser_state_valid?(
               @browser_state_secret,
               fresh.value,
               @reauth_binding
             )

      # The RP that earlier held a session_state over the OLD value now
      # recomputes `changed`: the response's session_state is over the fresh
      # value, and the old value no longer produces the same hash.
      session_state = location_query(conn)["session_state"]
      [_hash, salt] = String.split(session_state, ".", parts: 2)

      assert session_state ==
               Attesto.SessionState.compute(
                 @client_id,
                 "https://client.example.com",
                 fresh.value,
                 salt
               )

      refute session_state ==
               Attesto.SessionState.compute(@client_id, "https://client.example.com", opbs, salt)
    end

    test "an injected cookie the OP never minted is rejected and rotated (Finding 2)" do
      put_config(session_management: [enabled: true, browser_state_secret: @browser_state_secret])

      # An attacker-known value set by a sibling/parent-domain origin. The OP
      # never minted it, so its MAC cannot verify: it is not trusted.
      conn =
        build_conn()
        |> Map.put(:scheme, :https)
        |> with_config()
        |> put_req_header("cookie", "#{@browser_state_cookie}=attacker-known-value")
        |> AuthorizeController.authorize(valid_params())

      fresh = conn.resp_cookies[@browser_state_cookie]
      assert is_binary(fresh.value)
      refute fresh.value == "attacker-known-value"

      assert Attesto.SessionState.browser_state_valid?(
               @browser_state_secret,
               fresh.value,
               @established_binding
             )

      # The injected value can no longer forge `unchanged`: the response's
      # session_state is over the OP-minted value, not the attacker's.
      session_state = location_query(conn)["session_state"]
      [_hash, salt] = String.split(session_state, ".", parts: 2)

      refute session_state ==
               Attesto.SessionState.compute(
                 @client_id,
                 "https://client.example.com",
                 "attacker-known-value",
                 salt
               )
    end

    test "disabled session management adds no session_state and no cookie" do
      conn = call(valid_params())
      query = location_query(conn)

      assert is_binary(query["code"])
      refute Map.has_key?(query, "session_state")
      refute Map.has_key?(conn.resp_cookies, @browser_state_cookie)
    end
  end

  # ── family_id (OAuth 2.0 Security BCP §4.13 / §4.14) ───────────────────────

  describe "family_id" do
    test "a canonical 16-byte family_id is threaded into the issued code" do
      conn = call(valid_params())
      code = location_query(conn)["code"]

      record = TestStore.peek(code)
      family_id = record.data.family_id

      assert byte_size(family_id) == 22
      assert family_id =~ ~r/\A[A-Za-z0-9_-]{22}\z/
      assert {:ok, decoded} = Base.url_decode64(family_id, padding: false)
      assert byte_size(decoded) == 16
      assert Base.url_encode64(decoded, padding: false) == family_id
    end

    test "each issued code gets a distinct family_id" do
      code1 = call(valid_params()) |> location_query() |> Map.get("code")
      code2 = call(valid_params()) |> location_query() |> Map.get("code")

      family1 = TestStore.peek(code1).data.family_id
      family2 = TestStore.peek(code2).data.family_id

      assert family1 != family2
    end

    test "the family_id survives redemption onto the grant" do
      conn = call(valid_params())
      code = location_query(conn)["code"]
      family_id = TestStore.peek(code).data.family_id

      assert {:ok, grant} =
               AuthorizationCode.redeem(TestStore, code, %{
                 redirect_uri: @redirect_uri,
                 code_verifier: @code_verifier,
                 client_id: @client_id
               })

      assert grant.family_id == family_id
    end
  end

  # ── OID4VCI authorization_details (draft-ietf-oauth-openid4vci §5) ─────────

  describe "OID4VCI authorization_details" do
    @credential_configurations_supported %{
      "UniversityDegreeCredential" => %{format: "vc+sd-jwt"}
    }

    defp authorization_details_json(entries), do: JSON.encode!(entries)

    test "openid_credential authorization_details for a supported configuration id are recorded onto the code" do
      put_config(credential_configurations_supported: @credential_configurations_supported)

      details =
        authorization_details_json([
          %{
            "type" => "openid_credential",
            "credential_configuration_id" => "UniversityDegreeCredential"
          }
        ])

      conn = call(valid_params(%{"authorization_details" => details}))
      code = location_query(conn)["code"]

      record = TestStore.peek(code)
      assert record.data.claims["credential_configuration_ids"] == ["UniversityDegreeCredential"]
    end

    test "an authorization_details entry naming an unconfigured credential id is dropped" do
      put_config(credential_configurations_supported: @credential_configurations_supported)

      details =
        authorization_details_json([
          %{
            "type" => "openid_credential",
            "credential_configuration_id" => "SomeUnofferedCredential"
          }
        ])

      conn = call(valid_params(%{"authorization_details" => details}))
      code = location_query(conn)["code"]

      record = TestStore.peek(code)
      refute Map.has_key?(record.data.claims, "credential_configuration_ids")
    end

    test "authorization_details is ignored entirely when credential issuance is not configured" do
      # base_config/1 configures no :credential_configurations_supported.
      details =
        authorization_details_json([
          %{
            "type" => "openid_credential",
            "credential_configuration_id" => "UniversityDegreeCredential"
          }
        ])

      conn = call(valid_params(%{"authorization_details" => details}))
      code = location_query(conn)["code"]

      record = TestStore.peek(code)
      refute Map.has_key?(record.data.claims, "credential_configuration_ids")
    end

    test "a request with no authorization_details is completely unaffected" do
      put_config(credential_configurations_supported: @credential_configurations_supported)

      conn = call(valid_params())
      code = location_query(conn)["code"]

      record = TestStore.peek(code)
      refute Map.has_key?(record.data.claims, "credential_configuration_ids")
    end

    test "a non-openid_credential authorization_details entry is ignored" do
      put_config(credential_configurations_supported: @credential_configurations_supported)

      details =
        authorization_details_json([
          %{
            "type" => "payment_initiation",
            "credential_configuration_id" => "UniversityDegreeCredential"
          }
        ])

      conn = call(valid_params(%{"authorization_details" => details}))
      code = location_query(conn)["code"]

      record = TestStore.peek(code)
      refute Map.has_key?(record.data.claims, "credential_configuration_ids")
    end
  end

  # ── RFC 8252 native apps (BCP 212) ─────────────────────────────────────────

  describe "loopback interface redirection (RFC 8252 §7.3)" do
    defp native_params(redirect_uri, extra \\ %{}) do
      valid_params(Map.merge(%{"client_id" => @native_client_id, "redirect_uri" => redirect_uri}, extra))
    end

    # RFC 8252 §7.3 is a MUST, so marking the client native is the whole
    # decision - no `native_apps` configuration at all here.
    test "a native client's loopback redirect matches on any port" do
      conn = call(native_params("http://127.0.0.1:51823/cb"))

      assert conn.status == 302
      # The redirect goes to the ephemeral port the app actually bound, not the
      # registered one.
      assert location(conn) =~ "http://127.0.0.1:51823/cb"
      assert is_binary(location_query(conn)["code"])
    end

    test "the server-wide opt-out turns the same request into a direct error" do
      put_config(native_apps: [loopback_redirect: false])

      conn = call(native_params("http://127.0.0.1:51823/cb"))

      assert conn.status == 400
      assert conn.resp_body =~ "redirect_uri is not registered"
      # Non-redirectable: no Location header, so nothing is redirected to an
      # unvalidated URI.
      assert location(conn) == nil
    end

    test "a deployment that marks no client native sees exact matching" do
      put_config(client_native?: fn _client -> false end)

      conn = call(native_params("http://127.0.0.1:51823/cb"))

      assert conn.status == 400
      assert location(conn) == nil
    end

    test "the IPv6 loopback behaves identically" do
      conn = call(native_params("http://[::1]:51823/cb"))

      assert conn.status == 302
      assert location(conn) =~ "http://[::1]:51823/cb"
    end

    # RFC 8252 §8.3: the literal IP is required. Each of these pairs the
    # rejection with a positive control on the SAME configuration, so the test
    # distinguishes "refused because of this specific difference" from "refused
    # because the exception was not active at all".
    test "localhost is refused while the literal IP on the same port succeeds" do
      assert call(native_params("http://localhost:51823/cb")).status == 400
      assert call(native_params("http://localhost:51823/cb")) |> location() == nil

      assert call(native_params("http://127.0.0.1:51823/cb")).status == 302
    end

    test "a differing path is refused while the registered path on a varying port succeeds" do
      assert call(native_params("http://127.0.0.1:51823/other")).status == 400
      assert call(native_params("http://127.0.0.1:51823/other")) |> location() == nil

      assert call(native_params("http://127.0.0.1:51823/cb")).status == 302
    end

    test "a non-native client with the same registration gets no port flexibility" do
      put_config(
        client_redirect_uris: fn _client -> [@native_loopback_uri] end,
        client_native?: fn _client -> false end
      )

      conn = call(native_params("http://127.0.0.1:51823/cb"))

      assert conn.status == 400
      assert location(conn) == nil
    end

    test "an ordinary https client is unaffected by the exception" do
      assert call(valid_params()).status == 302

      conn = call(valid_params(%{"redirect_uri" => "https://client.example.com/other"}))
      assert conn.status == 400
    end
  end

  describe "PKCE for native apps (RFC 8252 §8.1)" do
    # The global flag is relaxed and the clients are classified confidential, so
    # the only thing that can still force PKCE here is being native.
    defp no_pkce_config(overrides \\ []) do
      put_config([require_pkce: false, client_public?: fn _client -> false end] ++ overrides)
    end

    test "a native client without code_challenge is rejected" do
      no_pkce_config()

      conn =
        call(
          Map.drop(native_params(@native_loopback_uri), [
            "code_challenge",
            "code_challenge_method"
          ])
        )

      assert conn.status == 302
      query = location_query(conn)
      assert query["error"] == "invalid_request"
      assert query["error_description"] =~ "code_challenge"
    end

    test "a native client using code_challenge_method=plain is rejected" do
      no_pkce_config()

      conn = call(native_params(@native_loopback_uri, %{"code_challenge_method" => "plain"}))

      assert conn.status == 302
      query = location_query(conn)
      assert query["error"] == "invalid_request"
      assert query["error_description"] =~ "plain"
    end

    test "a non-native client is unaffected by the native PKCE requirement" do
      no_pkce_config()

      conn = call(Map.drop(valid_params(), ["code_challenge", "code_challenge_method"]))

      assert conn.status == 302
      assert is_binary(location_query(conn)["code"])
    end
  end

  describe "embedded user agents (RFC 8252 §8.12)" do
    @webview_user_agent "Mozilla/5.0 (Linux; Android 13; Pixel 7 Build/TQ3A; wv) AppleWebKit/537.36 " <>
                          "(KHTML, like Gecko) Version/4.0 Chrome/119.0.0.0 Mobile Safari/537.36"

    @browser_user_agent "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 " <>
                          "(KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36"

    test "a webview request is served normally while the check is off (the default)" do
      conn = call(valid_params(), user_agent: @webview_user_agent)

      assert conn.status == 302
      assert is_binary(location_query(conn)["code"])
    end

    test "a webview request is refused directly once the host opts in" do
      put_config(native_apps: [reject_embedded_user_agents: true])

      conn = call(valid_params(), user_agent: @webview_user_agent)

      assert conn.status == 400
      assert conn.resp_body =~ "embedded user agent"
      # Refused, not redirected: the flow must not continue inside the webview.
      assert location(conn) == nil
    end

    test "the system browser is served normally with the check on" do
      put_config(native_apps: [reject_embedded_user_agents: true])

      conn = call(valid_params(), user_agent: @browser_user_agent)

      assert conn.status == 302
      assert is_binary(location_query(conn)["code"])
    end

    test "the refusal happens before the client is resolved" do
      put_config(native_apps: [reject_embedded_user_agents: true])

      conn =
        call(valid_params(%{"client_id" => "no-such-client"}), user_agent: @webview_user_agent)

      assert conn.status == 400
      assert conn.resp_body =~ "embedded user agent"
    end
  end

  # ── Stub host callbacks ────────────────────────────────────────────────────

  # The authorization endpoint never mints a token, so the signing key is never
  # exercised here. `AttestoPhoenix.Config` only requires `:keystore` to be
  # present (non-nil); this minimal keystore satisfies that without any
  # committed key material.
  defmodule TestKeystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @pem JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_pem() |> elem(1)

    @impl true
    def signing_pem, do: @pem

    @impl true
    def verification_pems, do: [@pem]
  end

  defmodule NoRepo do
    @moduledoc false
  end

  def load_client(@client_id), do: {:ok, %{id: @client_id}}

  def load_client(@native_client_id), do: {:ok, %{id: @native_client_id, native?: true, public?: true}}

  def load_client(_), do: {:error, :not_found}

  def verify_secret(_, _), do: false

  def load_principal(_), do: {:error, :not_found}

  def client_id(%{id: id}), do: id

  def client_redirect_uris(%{id: @client_id}), do: [@redirect_uri]

  def client_redirect_uris(%{id: @native_client_id}), do: [@native_loopback_uri, @native_loopback_uri_v6]

  def client_redirect_uris(_), do: []

  def client_native?(client), do: Map.get(client, :native?, false)

  # The default stub establishes a fixed subject. It echoes the `auth_opts`
  # the controller threaded in (prompt/force_reauth/interactive/max_age) into
  # the test process so the prompt/max_age tests can assert the controller
  # passed the right directives, and bumps `auth_time` when a re-auth was asked
  # for (prompt=login or a max_age the existing auth_time would violate).
  @established_auth_time 1_700_000_000
  @reauth_auth_time 1_700_009_999

  def authenticate(_conn, _request, auth_opts) do
    send(self(), {:auth_opts, auth_opts})

    auth_time =
      if auth_opts.force_reauth or max_age_violated?(auth_opts.max_age) do
        @reauth_auth_time
      else
        @established_auth_time
      end

    {:authenticated,
     %{
       subject: "user-42",
       auth_time: auth_time,
       acr: "urn:mace:incommon:iap:silver",
       amr: ["pwd"]
     }}
  end

  # The existing authentication is at @established_auth_time; treat a max_age of
  # 0 (or any value the fixed clock in this stub would exceed) as requiring a
  # re-auth. The tests only need the "max_age=0 forces re-auth" case.
  defp max_age_violated?(nil), do: false
  defp max_age_violated?(max_age) when is_integer(max_age), do: max_age == 0

  def consent(_conn, _request, subject), do: {:consented, subject}
end
