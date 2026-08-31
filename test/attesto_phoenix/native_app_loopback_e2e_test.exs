defmodule AttestoPhoenix.NativeAppLoopbackE2ETest do
  @moduledoc false
  # End-to-end RFC 8252 (BCP 212) native-app flow against a LIVE authorization
  # server, driven by a real third-party OAuth client.
  #
  # Every other test of this feature exercises Attesto against itself: the
  # library decides what a loopback redirect URI is and the library checks its
  # own answer. This one closes that loop. A live Bandit server mounts the real
  # `attesto_routes/1` route table, and `openid-client` - the canonical Node
  # OAuth 2.0 / OpenID Connect client, which knows nothing about Attesto -
  # performs the §7.3 dance end to end:
  #
  #   1. the "app" binds an EPHEMERAL loopback port (`port: 0`, kernel-assigned),
  #      which is precisely why §7.3 exists: the port cannot be registered ahead
  #      of time;
  #   2. it builds an authorization request with PKCE (§8.1) and that
  #      runtime-chosen `redirect_uri`;
  #   3. the server matches it against a registration whose port differs,
  #      accepts it, and redirects the code to the port the app really bound;
  #   4. the app redeems the code at the token endpoint authenticating with
  #      `none` (§8.4), and openid-client verifies `state`, the PKCE binding and
  #      the RFC 9207 `iss`.
  #
  # The module self-skips when Node or `openid-client` is unavailable rather
  # than passing without exercising anything.

  use ExUnit.Case, async: false

  alias AttestoPhoenix.Plug.PutConfig

  @moduletag :e2e

  @js_dir Path.expand("../support/js", __DIR__)
  @script Path.join(@js_dir, "rfc8252_client.mjs")

  @issuer "https://issuer.example"
  @native_client_id "native-app"
  @confidential_client_id "server-app"

  # The registration a native app files: a loopback callback whose port is a
  # placeholder, because the real one is chosen at runtime (§7.3).
  @registered_v4 "http://127.0.0.1:0/cb"
  @registered_v6 "http://[::1]:0/cb"

  @signing_pem JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_pem() |> elem(1)

  defmodule Keystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem do
      :attesto_phoenix |> Application.fetch_env!(__MODULE__) |> Keyword.fetch!(:signing_pem)
    end

    @impl true
    def verification_pems, do: [signing_pem()]
  end

  defmodule CodeStore do
    @moduledoc false
    @behaviour Attesto.CodeStore

    def start_link, do: Agent.start_link(fn -> %{} end, name: __MODULE__)

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
  end

  defmodule Router do
    @moduledoc false
    use Phoenix.Router

    import AttestoPhoenix.Router

    scope "/" do
      attesto_routes()
    end
  end

  # The pipeline a host endpoint would normally supply: query params for the
  # `GET /oauth/authorize` front channel, and form/JSON body parsing for the
  # `POST /oauth/token` back channel.
  defmodule Endpoint do
    @moduledoc false
    use Plug.Builder

    plug :fetch_query
    plug Plug.Parsers, parsers: [:urlencoded, :json], pass: ["*/*"], json_decoder: JSON
    plug PutConfig
    plug Router

    def fetch_query(conn, _opts), do: Plug.Conn.fetch_query_params(conn)
  end

  defmodule NoRepo do
    @moduledoc false
  end

  # ── Host callbacks ────────────────────────────────────────────────────────

  def load_client(@native_client_id), do: {:ok, %{id: @native_client_id, native?: true, public?: true}}
  def load_client(@confidential_client_id), do: {:ok, %{id: @confidential_client_id}}
  def load_client(_), do: {:error, :not_found}

  def verify_client_secret(_client, _secret), do: false
  def load_principal(_subject), do: {:error, :not_found}
  def client_id(%{id: id}), do: id
  def client_native?(client), do: Map.get(client, :native?, false)
  def client_public?(client), do: Map.get(client, :public?, false)

  def client_redirect_uris(%{id: @native_client_id}), do: [@registered_v4, @registered_v6]
  def client_redirect_uris(_client), do: ["https://app.example/cb"]

  # No UI: the resource owner is established and consent granted without
  # interaction, so one HTTP hop produces the redirect.
  def authenticate_resource_owner(_conn, _request, _opts) do
    {:authenticated, %{subject: "user-42", auth_time: 1_700_000_000, acr: "urn:test", amr: ["pwd"]}}
  end

  def consent(_conn, _request, subject), do: {:consented, subject}

  def build_principal(_client, subject, scope) do
    %{kind: "user", sub: "usr_" <> to_string(subject), scopes: List.wrap(scope), claims: %{}}
  end

  # Grant exactly what was asked for; scope policy is not what this test is about.
  def authorize_scope(_client, requested), do: {:ok, requested}

  # ── Setup ─────────────────────────────────────────────────────────────────

  # Resolved at compile time so an unavailable toolchain yields a VISIBLE skip
  # rather than a module that quietly asserts nothing.
  cond do
    System.find_executable("node") == nil ->
      @moduletag skip: "RFC 8252 e2e unavailable: node is not on PATH"

    not File.dir?(Path.join(@js_dir, "node_modules/openid-client")) ->
      @moduletag skip:
                   "RFC 8252 e2e unavailable: openid-client not installed " <>
                     "(cd test/support/js && npm install)"

    true ->
      @moduletag node_ready: true
  end

  setup do
    start_server()
  end

  defp start_server do
    Application.put_env(:attesto_phoenix, Keystore, signing_pem: @signing_pem)
    {:ok, _} = start_supervised(%{id: CodeStore, start: {CodeStore, :start_link, []}})

    {:ok, server} =
      Bandit.start_link(plug: Endpoint, port: 0, scheme: :http, startup_log: false)

    {:ok, {_host, port}} = ThousandIsland.listener_info(server)
    base = "http://127.0.0.1:#{port}"

    Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)
    Application.put_env(:attesto_phoenix, AttestoPhoenix.Config, config(base))

    on_exit(fn ->
      Application.delete_env(:attesto_phoenix, AttestoPhoenix.Config)
      Application.delete_env(:attesto_phoenix, Keystore)
    end)

    {:ok, base: base}
  end

  defp config(_base) do
    [
      issuer: @issuer,
      audience: @issuer,
      keystore: Keystore,
      repo: NoRepo,
      load_client: &__MODULE__.load_client/1,
      verify_client_secret: &__MODULE__.verify_client_secret/2,
      load_principal: &__MODULE__.load_principal/1,
      client_id: &__MODULE__.client_id/1,
      client_redirect_uris: &__MODULE__.client_redirect_uris/1,
      client_native?: &__MODULE__.client_native?/1,
      client_public?: &__MODULE__.client_public?/1,
      authenticate_resource_owner: &__MODULE__.authenticate_resource_owner/3,
      consent: &__MODULE__.consent/3,
      build_principal: &__MODULE__.build_principal/3,
      authorize_scope: &__MODULE__.authorize_scope/2,
      principal_kinds: [Attesto.PrincipalKind.new("user", "usr_")],
      code_store: CodeStore,
      authorization_code_ttl: 60,
      # The harness serves plain HTTP on a loopback port.
      require_https: false,
      scopes_supported: ["openid", "profile"]
      # No `native_apps` configuration: RFC 8252 §7.3 follows from the client
      # being marked native, which is the feature under test.
    ]
  end

  # ── Driver ────────────────────────────────────────────────────────────────

  defp run_client(base, overrides) do
    input =
      Map.merge(
        %{
          issuer: @issuer,
          authorization_endpoint: base <> "/oauth/authorize",
          token_endpoint: base <> "/oauth/token",
          par_endpoint: base <> "/oauth/par",
          client_id: @native_client_id,
          scope: "openid"
        },
        overrides
      )

    {out, status} =
      System.cmd("node", [@script, JSON.encode!(input)], cd: @js_dir, stderr_to_stdout: true)

    assert status == 0, "node driver exited #{status}:\n#{out}"
    JSON.decode!(out)
  end

  # ── Tests ─────────────────────────────────────────────────────────────────

  describe "RFC 8252 §7.3 loopback dance with a real third-party client" do
    test "an IPv4 ephemeral loopback port completes the full code exchange", %{base: base} do
      result = run_client(base, %{family: "ipv4"})

      assert result["ok"] == true, "client failed: #{inspect(result)}"

      # The port really was chosen by the kernel at runtime, and is not the one
      # in the registration - which is the entire point of §7.3.
      assert result["bound_port"] > 0
      assert result["redirect_uri"] == "http://127.0.0.1:#{result["bound_port"]}/cb"
      refute result["redirect_uri"] == @registered_v4

      # The code came back on that exact port.
      assert result["redirect_location"] =~ "http://127.0.0.1:#{result["bound_port"]}/cb?"

      # And redeemed, with openid-client having verified state, PKCE and iss.
      assert result["has_access_token"]
      assert result["token_type"] in ["bearer", "Bearer"]
      assert result["iss"] == @issuer
    end

    test "an IPv6 ephemeral loopback port behaves identically", %{base: base} do
      result = run_client(base, %{family: "ipv6"})

      assert result["ok"] == true, "client failed: #{inspect(result)}"
      assert result["redirect_uri"] == "http://[::1]:#{result["bound_port"]}/cb"
      assert result["has_access_token"]
    end

    test "the server-wide opt-out refuses the same client", %{base: base} do
      # Engage the server-wide opt-out; everything else about the request is
      # unchanged. This is the control that proves the successes above are the
      # exception doing work, not a permissive redirect check.
      Application.put_env(
        :attesto_phoenix,
        AttestoPhoenix.Config,
        Keyword.put(config(base), :native_apps, loopback_redirect: false)
      )

      result = run_client(base, %{family: "ipv4"})

      assert result["ok"] == false, "expected the flag to be load-bearing, got: #{inspect(result)}"

      # Specifically the redirect-URI rejection, reported DIRECTLY (no Location
      # header) so the unvalidated URI is never used as a redirect target.
      assert result["error"] =~ "no Location"
      assert result["error"] =~ "redirect_uri is not registered"
    end

    test "a non-native client gets no port flexibility from the same flag", %{base: base} do
      # `server-app` is registered with an https redirect URI and is not marked
      # native, so its loopback request must be refused even with the exception
      # enabled.
      result = run_client(base, %{client_id: @confidential_client_id})

      assert result["ok"] == false, "expected the per-client mark to be load-bearing, got: #{inspect(result)}"
      assert result["error"] =~ "no Location"
      assert result["error"] =~ "redirect_uri is not registered"
    end
  end
end
