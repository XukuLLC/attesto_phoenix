defmodule AttestoPhoenix.SchemaPrefixTest do
  use ExUnit.Case, async: false

  alias AttestoPhoenix.AuthorizationServer.PAR
  alias AttestoPhoenix.AuthorizationServer.PAR.Request
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Store.EctoPARStore

  @host_app :attesto_phoenix_schema_prefix_host

  defmodule Keystore do
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem, do: "prefix-test-pem"

    @impl true
    def verification_pems, do: [signing_pem()]
  end

  defmodule PrefixCaptureRepo do
    def insert(changeset, opts) do
      send(self(), {:insert, opts, changeset})
      {:ok, changeset}
    end

    def one(_query, opts) do
      send(self(), {:one, opts})
      nil
    end

    def delete_all(_query, opts) do
      send(self(), {:delete_all, opts})
      {0, []}
    end
  end

  defmodule RequestCaptureRepo do
    def insert(changeset, opts) do
      send(self(), {:request_insert, opts, changeset})
      {:ok, changeset}
    end

    def one(_query, opts) do
      send(self(), {:request_one, opts})
      nil
    end

    def delete_all(_query, opts) do
      send(self(), {:request_delete_all, opts})
      {0, []}
    end
  end

  setup do
    previous_otp_app = Application.get_env(:attesto_phoenix, :otp_app, :missing)
    previous_library_prefix = Application.get_env(:attesto_phoenix, :table_prefix, :missing)
    previous_library_repo = Application.get_env(:attesto_phoenix, :repo, :missing)
    previous_host_config = Application.get_env(@host_app, Config, :missing)

    on_exit(fn ->
      restore_env(:attesto_phoenix, :otp_app, previous_otp_app)
      restore_env(:attesto_phoenix, :table_prefix, previous_library_prefix)
      restore_env(:attesto_phoenix, :repo, previous_library_repo)
      restore_env(@host_app, Config, previous_host_config)
    end)

    :ok
  end

  test "request config overrides the host fallback and clear restores the fallback" do
    global = config(schema_prefix: "global_prefix")
    request = config(schema_prefix: "request_prefix")

    Application.put_env(@host_app, Config, global)
    Application.put_env(:attesto_phoenix, :otp_app, @host_app)
    assert Config.table_prefix() == "global_prefix"

    Config.with_request_config(request, fn ->
      assert Config.request_config() === request
      assert Config.table_prefix() == "request_prefix"
    end)

    assert Config.request_config() == nil
    assert Config.table_prefix() == "global_prefix"
  end

  test "representative Ecto write, read, and delete use one schema prefix" do
    global = config(schema_prefix: "global_prefix", repo: PrefixCaptureRepo)
    Application.put_env(@host_app, Config, global)
    Application.put_env(:attesto_phoenix, :otp_app, @host_app)

    assert :ok = EctoPARStore.put("urn:example:request", %{"client_id" => "client"}, 60)

    assert_receive {:insert, opts, %Ecto.Changeset{data: %{__meta__: %{prefix: "global_prefix"}}}}
    assert Keyword.get(opts, :prefix) == "global_prefix"

    assert :error = EctoPARStore.fetch("urn:example:request")
    assert_receive {:one, opts}
    assert Keyword.get(opts, :prefix) == "global_prefix"

    assert :error = EctoPARStore.take("urn:example:request")
    assert_receive {:delete_all, opts}
    assert Keyword.get(opts, :prefix) == "global_prefix"
  end

  test "request repo and schema prefix are selected as one scoped pair" do
    global = config(schema_prefix: "global_prefix", repo: PrefixCaptureRepo)
    request = config(schema_prefix: "request_prefix", repo: RequestCaptureRepo)
    Application.put_env(@host_app, Config, global)
    Application.put_env(:attesto_phoenix, :otp_app, @host_app)

    assert Config.ecto_repo!() == PrefixCaptureRepo

    Config.with_request_config(request, fn ->
      assert Config.ecto_repo!() == RequestCaptureRepo
      assert Config.table_prefix() == "request_prefix"
      assert :ok = EctoPARStore.put("urn:example:request", %{"client_id" => "client"}, 60)

      assert_receive {:request_insert, opts, %Ecto.Changeset{data: %{__meta__: %{prefix: "request_prefix"}}}}
      assert Keyword.get(opts, :prefix) == "request_prefix"
    end)

    assert Config.request_config() == nil
    assert Config.ecto_repo!() == PrefixCaptureRepo
    assert Config.table_prefix() == "global_prefix"
  end

  test "direct PAR processing binds its explicit repo and prefix before the Ecto store call" do
    request_config =
      config(
        repo: RequestCaptureRepo,
        schema_prefix: "request_prefix",
        par_store: EctoPARStore,
        client_id: fn client -> Map.get(client, :id) end,
        client_redirect_uris: fn _client -> ["https://client.example/cb"] end
      )

    request = %Request{
      client: %{id: "client"},
      client_id: "client",
      params: %{
        "client_id" => "client",
        "redirect_uri" => "https://client.example/cb",
        "response_type" => "code",
        "scope" => "openid",
        "code_challenge" => "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "code_challenge_method" => "S256"
      },
      dpop_input: %{proofs: [], http_uri: "https://issuer.example/oauth/par", http_method: "POST"}
    }

    assert {:ok, %{request_uri: _}} = PAR.store(request_config, request)
    assert_receive {:request_insert, opts, %Ecto.Changeset{data: %{__meta__: %{prefix: "request_prefix"}}}}
    assert Keyword.get(opts, :prefix) == "request_prefix"
  end

  test "a private request config resolves without retaining process state" do
    request = config(schema_prefix: "request_prefix")
    conn = Plug.Test.conn(:get, "/") |> Plug.Conn.put_private(:attesto_phoenix_config, request)

    assert Config.request_config() == nil
    assert Config.resolve!(conn) === request
  end

  test "bounded conn-free binding restores state even when callback raises" do
    request = config(schema_prefix: "request_prefix")

    assert_raise RuntimeError, "boom", fn ->
      Config.with_request_config(request, fn ->
        assert Config.table_prefix() == "request_prefix"
        raise "boom"
      end)
    end

    assert Config.request_config() == nil
  end

  test "validates a conservative PostgreSQL schema identifier and byte bound" do
    assert config(schema_prefix: nil).schema_prefix == nil
    assert config(schema_prefix: "auth_2026").schema_prefix == "auth_2026"
    assert_raise ArgumentError, ~r/non-empty.*PostgreSQL schema identifier/, fn -> config(schema_prefix: "") end
    assert_raise ArgumentError, ~r/conservative PostgreSQL schema identifier/, fn -> config(schema_prefix: "Auth") end
    assert_raise ArgumentError, ~r/at most 63 bytes/, fn -> config(schema_prefix: String.duplicate("a", 64)) end
    assert_raise ArgumentError, ~r/reserved PostgreSQL system schema/, fn -> config(schema_prefix: "pg_catalog") end

    assert_raise ArgumentError, ~r/reserved PostgreSQL system schema/, fn ->
      config(schema_prefix: "information_schema")
    end
  end

  test "rejects the removed 2.x table-name prefix option" do
    assert_raise ArgumentError, ~r/:table_prefix was removed in 3\.0.*:schema_prefix/, fn ->
      config(table_prefix: "legacy_")
    end
  end

  test "rejects string-key prefix maps instead of defaulting to public" do
    assert_raise ArgumentError, ~r/string key "schema_prefix".*atom key :schema_prefix/, fn ->
      Config.new(%{"schema_prefix" => "tenant_auth"})
    end

    assert_raise ArgumentError, ~r/string key "table_prefix".*legacy 2.x/, fn ->
      Config.new(%{"table_prefix" => "oauth_"})
    end

    assert_raise ArgumentError, ~r/string key "schema_prefix".*atom key :schema_prefix/, fn ->
      Config.new([{"schema_prefix", "tenant_auth"}])
    end
  end

  test "validates manually assembled request config before storing or resolving" do
    valid = config(schema_prefix: "tenant_auth")
    malformed = Map.put(valid, :schema_prefix, "information_schema")

    assert_raise ArgumentError, ~r/reserved PostgreSQL system schema/, fn ->
      Config.with_request_config(malformed, fn -> :ok end)
    end

    conn = Plug.Test.conn(:get, "/") |> Plug.Conn.put_private(:attesto_phoenix_config, malformed)

    assert_raise ArgumentError, ~r/reserved PostgreSQL system schema/, fn ->
      Config.resolve!(conn)
    end
  end

  test "rejects a stale package-level table prefix regardless of its value" do
    config = config(schema_prefix: "oauth")

    for legacy_value <- [nil, "legacy_"] do
      Application.put_env(:attesto_phoenix, :table_prefix, legacy_value)

      assert_raise ArgumentError, ~r/config :attesto_phoenix, :table_prefix was removed in 3\.0.*:schema_prefix/, fn ->
        Config.table_prefix()
      end

      assert_raise ArgumentError, ~r/config :attesto_phoenix, :table_prefix was removed in 3\.0.*:schema_prefix/, fn ->
        Config.new(Map.from_struct(config))
      end

      assert_raise ArgumentError, ~r/config :attesto_phoenix, :table_prefix was removed in 3\.0.*:schema_prefix/, fn ->
        Config.table_prefix(config)
      end

      assert_raise ArgumentError, ~r/config :attesto_phoenix, :table_prefix was removed in 3\.0.*:schema_prefix/, fn ->
        Config.with_request_config(config, fn -> :ok end)
      end

      conn = Plug.Test.conn(:get, "/") |> Plug.Conn.put_private(:attesto_phoenix_config, config)

      assert_raise ArgumentError, ~r/config :attesto_phoenix, :table_prefix was removed in 3\.0.*:schema_prefix/, fn ->
        Config.resolve!(conn)
      end
    end

    Application.delete_env(:attesto_phoenix, :table_prefix)
    stale_config = with_legacy_table_prefix(config)
    # Keep the intentionally stale map dynamic so the compiler does not reject
    # this test call against Config's current struct-only type.
    config_module = Module.concat(["AttestoPhoenix", "Config"])

    assert_raise ArgumentError, ~r/:table_prefix was removed in 3\.0.*:schema_prefix/, fn ->
      config_module.table_prefix(stale_config)
    end

    assert_raise ArgumentError, ~r/:table_prefix was removed in 3\.0.*:schema_prefix/, fn ->
      config_module.schema_prefix(stale_config)
    end
  end

  defp config(overrides) do
    Config.new(
      Keyword.merge(
        [
          issuer: "https://issuer.example",
          audience: "https://api.example",
          keystore: Keystore,
          repo: AttestoPhoenix.TestRepo,
          load_client: fn _ -> {:error, :not_found} end,
          verify_client_secret: fn _, _ -> false end,
          load_principal: fn _ -> {:error, :not_found} end
        ],
        overrides
      )
    )
  end

  @spec with_legacy_table_prefix(Config.t()) :: Config.t()
  defp with_legacy_table_prefix(config), do: Map.put(config, :table_prefix, "legacy_")

  defp restore_env(app, key, :missing), do: Application.delete_env(app, key)
  defp restore_env(app, key, value), do: Application.put_env(app, key, value)
end
