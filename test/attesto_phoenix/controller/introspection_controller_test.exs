defmodule AttestoPhoenix.Controller.IntrospectionControllerTest do
  @moduledoc false
  # Installs config into the application env, so not async-safe.
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias Attesto.Token
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Controller.IntrospectionController

  @client_id "rs-1"
  @token_client_id "oauth-client-1"
  @client_secret "s3cr3t"
  @signed_media_type "application/token-introspection+jwt"

  defmodule Keystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @pem JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_pem() |> elem(1)

    @impl true
    def signing_pem, do: @pem
    @impl true
    def verification_pems, do: [@pem]

    def pem, do: @pem
  end

  defmodule Repo do
    @moduledoc false
  end

  # The tokens these tests introspect are access-token JWTs; the refresh path is
  # exercised in Attesto.IntrospectionTest. This stub just answers "unknown" so
  # inactive cases don't fall through to the Ecto store (which needs a database).
  defmodule StubRefreshStore do
    @moduledoc false
    @behaviour Attesto.RefreshStore

    @impl true
    def get(_hash), do: :error
    @impl true
    def insert(_entry), do: :ok
    @impl true
    def consume(_hash, _opts), do: :error
    @impl true
    def remember_successor(_hash, _data, _opts), do: :ok
    @impl true
    def revoke_family(_family_id), do: :ok
  end

  # The raw config opts: from_otp_app/2 reads these from the application env and
  # builds the struct, so the env must hold the keyword list, not a built struct.
  defp config_opts do
    [
      issuer: "https://issuer.test",
      audience: "https://issuer.test",
      keystore: Keystore,
      repo: Repo,
      load_client: fn
        @client_id -> {:ok, %{id: @client_id}}
        @token_client_id -> {:ok, %{id: @token_client_id}}
        _other -> {:error, :not_found}
      end,
      verify_client_secret: fn
        %{id: @client_id}, presented -> presented == @client_secret
        _client, _presented -> false
      end,
      load_principal: fn _subject -> {:error, :not_found} end,
      client_id: fn %{id: id} -> id end,
      principal_kinds: [Attesto.PrincipalKind.new("client", "oc_")],
      refresh_store: StubRefreshStore,
      require_https: false
    ]
  end

  setup do
    Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)
    Application.put_env(:attesto_phoenix, AttestoPhoenix.Config, config_opts())
    on_exit(fn -> Application.delete_env(:attesto_phoenix, AttestoPhoenix.Config) end)
    {:ok, config: Config.new(config_opts())}
  end

  defp access_token(config, opts \\ []) do
    token_client_id = Keyword.get(opts, :client_id, @token_client_id)
    mint_opts = Keyword.delete(opts, :client_id)

    {:ok, %{access_token: jwt}} =
      Token.mint(
        Config.to_attesto_config(config),
        %{
          kind: "client",
          sub: "oc_abc123",
          scopes: ["documents.read"],
          claims: %{"client_id" => token_client_id}
        },
        mint_opts
      )

    jwt
  end

  defp call(params, headers \\ []) do
    base = put_req_header(conn(:post, "/oauth/introspect", params), "authorization", basic_auth())

    headers
    |> Enum.reduce(base, fn {k, v}, c -> put_req_header(c, k, v) end)
    |> IntrospectionController.create(params)
  end

  defp basic_auth, do: "Basic " <> Base.encode64("#{@client_id}:#{@client_secret}")

  describe "create/2 (RFC 7662)" do
    test "an active access token returns the JSON introspection response", %{config: config} do
      conn = call(%{"token" => access_token(config)})

      assert conn.status == 200
      body = JSON.decode!(conn.resp_body)
      assert body["active"] == true
      assert body["scope"] == "documents.read"
      assert body["iss"] == "https://issuer.test"
      assert body["token_type"] == "Bearer"
      assert get_resp_header(conn, "cache-control") == ["no-store"]
    end

    test "an invalid token returns active:false", %{config: _config} do
      conn = call(%{"token" => "not-a-real-token"})

      assert conn.status == 200
      assert JSON.decode!(conn.resp_body) == %{"active" => false}
    end

    test "a static RFC 8707 audience needs no token-client lookup or dynamic policy", %{config: config} do
      resource = "https://resource.example/mcp"
      test_pid = self()

      opts =
        config_opts()
        |> Keyword.put(:load_client, fn
          @client_id ->
            {:ok, %{id: @client_id}}

          @token_client_id ->
            send(test_pid, :token_client_loaded)
            {:ok, %{id: @token_client_id}}

          _other ->
            {:error, :not_found}
        end)
        |> Keyword.put(:resource_indicators,
          allowed_resources: [resource],
          allowed_resources_for: fn _client -> raise "static audience must bypass dynamic policy" end
        )

      Application.put_env(:attesto_phoenix, AttestoPhoenix.Config, opts)

      conn = call(%{"token" => access_token(config, audience: resource)})

      assert conn.status == 200
      body = JSON.decode!(conn.resp_body)
      assert body["active"] == true
      assert body["aud"] == resource
      refute_received :token_client_loaded
    end

    test "an access token for a resource outside the trusted allowlist is inactive", %{
      config: config
    } do
      configured = "https://resource.example/allowed"
      untrusted = "https://resource.example/not-allowed"

      opts =
        Keyword.put(config_opts(), :resource_indicators, allowed_resources: [configured])

      Application.put_env(:attesto_phoenix, AttestoPhoenix.Config, opts)

      conn = call(%{"token" => access_token(config, audience: untrusted)})

      assert conn.status == 200
      assert JSON.decode!(conn.resp_body) == %{"active" => false}
    end

    test "per-client audience trust is derived from the signed token client, not the caller", %{
      config: config
    } do
      resource = "https://resource.example/per-client"

      opts =
        Keyword.put(config_opts(), :resource_indicators,
          allowed_resources_for: fn
            %{id: @token_client_id} -> [resource]
            %{id: @client_id} -> []
          end
        )

      Application.put_env(:attesto_phoenix, AttestoPhoenix.Config, opts)

      conn = call(%{"token" => access_token(config, audience: resource)})

      assert conn.status == 200
      assert JSON.decode!(conn.resp_body)["active"] == true
    end

    test "the introspection caller's own resource policy cannot activate the token", %{
      config: config
    } do
      resource = "https://resource.example/caller-only"

      opts =
        Keyword.put(config_opts(), :resource_indicators,
          allowed_resources_for: fn
            %{id: @client_id} -> [resource]
            %{id: @token_client_id} -> []
          end
        )

      Application.put_env(:attesto_phoenix, AttestoPhoenix.Config, opts)

      conn = call(%{"token" => access_token(config, audience: resource)})

      assert conn.status == 200
      assert JSON.decode!(conn.resp_body) == %{"active" => false}
    end

    test "an unknown original client receives static trust only", %{config: config} do
      resource = "https://resource.example/dynamic-only"

      opts =
        Keyword.put(config_opts(), :resource_indicators, allowed_resources_for: fn _known_client -> [resource] end)

      Application.put_env(:attesto_phoenix, AttestoPhoenix.Config, opts)

      conn =
        call(%{
          "token" => access_token(config, audience: resource, client_id: "deleted-client")
        })

      assert conn.status == 200
      assert JSON.decode!(conn.resp_body) == %{"active" => false}
    end

    test "a missing token is invalid_request (400)", %{config: _config} do
      conn = call(%{})

      assert conn.status == 400
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_request"
    end

    test "failed client authentication is invalid_client", %{config: config} do
      # AttestoPhoenix.ClientAuthentication returns auth failures as invalid_client
      # with status 400 uniformly (the same as the token/PAR endpoints).
      params = %{"token" => access_token(config)}

      conn =
        conn(:post, "/oauth/introspect", params)
        |> put_req_header("authorization", "Basic " <> Base.encode64("#{@client_id}:wrong"))
        |> IntrospectionController.create(params)

      assert conn.status == 400
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_client"
    end
  end

  describe "create/2 :introspection_authorize caller policy (RFC 7662 §4 / RFC 9701 §5)" do
    test "a callback that rejects the caller downgrades to active:false", %{config: config} do
      # Reject every caller: an otherwise-active token must read inactive so a
      # caller not entitled to it learns nothing.
      opts =
        Keyword.put(config_opts(), :introspection_authorize, fn _caller, _response -> false end)

      Application.put_env(:attesto_phoenix, AttestoPhoenix.Config, opts)

      conn = call(%{"token" => access_token(config)})

      assert conn.status == 200
      assert JSON.decode!(conn.resp_body) == %{"active" => false}
    end

    test "the callback receives the authenticated caller and the response", %{config: config} do
      test_pid = self()

      authorize = fn caller, response ->
        send(test_pid, {:authorize, caller, response["aud"]})
        true
      end

      opts = Keyword.put(config_opts(), :introspection_authorize, authorize)
      Application.put_env(:attesto_phoenix, AttestoPhoenix.Config, opts)

      conn = call(%{"token" => access_token(config)})

      assert conn.status == 200
      assert JSON.decode!(conn.resp_body)["active"] == true
      assert_received {:authorize, @client_id, "https://issuer.test"}
    end

    test "the callback is not consulted for an inactive token", %{config: _config} do
      authorize = fn _caller, _response -> raise "should not be called for an inactive token" end
      opts = Keyword.put(config_opts(), :introspection_authorize, authorize)
      Application.put_env(:attesto_phoenix, AttestoPhoenix.Config, opts)

      conn = call(%{"token" => "not-a-real-token"})

      assert conn.status == 200
      assert JSON.decode!(conn.resp_body) == %{"active" => false}
    end
  end

  describe "create/2 signed responses (RFC 9701)" do
    test "Accept: token-introspection+jwt returns a signed JWT response", %{config: config} do
      conn = call(%{"token" => access_token(config)}, [{"accept", @signed_media_type}])

      assert conn.status == 200
      assert get_resp_header(conn, "content-type") == [@signed_media_type]

      claims = decode(conn.resp_body)
      assert claims["iss"] == "https://issuer.test"
      assert claims["aud"] == @client_id
      assert claims["token_introspection"]["active"] == true
      assert claims["token_introspection"]["scope"] == "documents.read"
    end

    test "a signed response for an inactive token wraps active:false", %{config: _config} do
      conn = call(%{"token" => "nope"}, [{"accept", @signed_media_type}])

      assert conn.status == 200
      assert decode(conn.resp_body)["token_introspection"] == %{"active" => false}
    end

    test "signs with the authenticated client_id even when no :client_id callback is configured" do
      # The audience must come from the credentials, not the optional :client_id
      # callback, so a valid config without that callback must not crash.
      opts = Keyword.delete(config_opts(), :client_id)
      Application.put_env(:attesto_phoenix, AttestoPhoenix.Config, opts)
      config = Config.new(opts)

      conn = call(%{"token" => access_token(config)}, [{"accept", @signed_media_type}])

      assert conn.status == 200
      assert decode(conn.resp_body)["aud"] == @client_id
    end

    test "Accept with q=0 on the signed type returns plain JSON (RFC 9110 §12.5.1)", %{
      config: config
    } do
      conn =
        call(%{"token" => access_token(config)}, [
          {"accept", "#{@signed_media_type};q=0, application/json;q=1"}
        ])

      assert conn.status == 200
      assert get_resp_header(conn, "content-type") |> List.first() =~ "application/json"
      assert JSON.decode!(conn.resp_body)["active"] == true
    end
  end

  defp decode(jwt) do
    jwk = Attesto.Key.jwk(Keystore.pem())
    {true, %JOSE.JWT{fields: claims}, %JOSE.JWS{}} = JOSE.JWT.verify_strict(jwk, ["RS256"], jwt)
    claims
  end
end
