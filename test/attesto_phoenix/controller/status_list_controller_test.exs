defmodule AttestoPhoenix.Controller.StatusListControllerTest do
  @moduledoc false
  use ExUnit.Case, async: false

  import Plug.Test

  alias Attesto.{Key, StatusList, StatusListStore}
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Controller.StatusListController

  @issuer "https://issuer.example"
  @oauth_prefix "/oauth"
  @status_list_path @oauth_prefix <> Config.status_list_tail()
  @list_id "employment-credentials"
  @uri @issuer <> @status_list_path <> "/" <> @list_id

  @signing_pem JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_pem() |> elem(1)

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

  defmodule StatusListRouter do
    @moduledoc false
    use Phoenix.Router
    use AttestoPhoenix.Router

    scope "/" do
      attesto_routes(status_list: true)
    end
  end

  setup do
    Application.put_env(:attesto_phoenix, __MODULE__.Keystore, signing_pem: @signing_pem)

    start_supervised!(StatusListStore.ETS)
    StatusListStore.ETS.reset()

    put_config(
      issuer: @issuer,
      audience: @issuer,
      keystore: __MODULE__.Keystore,
      repo: __MODULE__.Repo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      require_https: false,
      status_list_store: StatusListStore.ETS
    )

    on_exit(fn ->
      Application.delete_env(:attesto_phoenix, __MODULE__.Keystore)
      Application.delete_env(:attesto_phoenix, Config)
      Application.delete_env(:attesto_phoenix, :otp_app)
    end)

    :ok
  end

  test "GETs the convention-derived statuslist path and serves a verifiable Status List Token" do
    {:ok, 0} = StatusListStore.ETS.allocate(@uri)
    {:ok, 1} = StatusListStore.ETS.allocate(@uri)
    {:ok, 2} = StatusListStore.ETS.allocate(@uri)
    :ok = StatusListStore.ETS.set_status(@uri, 1, 1)

    response = StatusListRouter.call(conn(:get, @status_list_path <> "/" <> @list_id), [])

    assert response.status == 200
    assert Plug.Conn.get_resp_header(response, "content-type") == ["application/statuslist+jwt"]
    assert ["public, max-age=" <> _] = Plug.Conn.get_resp_header(response, "cache-control")

    {_kty, jwk} = @signing_pem |> Key.jwk() |> JOSE.JWK.to_public_map()
    jwk = Map.merge(jwk, %{"alg" => "ES256", "kid" => Key.kid(@signing_pem)})

    assert {:ok, verified} = StatusList.verify(response.resp_body, %{"keys" => [jwk]})
    assert verified.sub == @uri
    assert StatusList.status_at(verified.statuses_binary, verified.bits, 0) == 0
    assert StatusList.status_at(verified.statuses_binary, verified.bits, 1) == 1
    assert StatusList.status_at(verified.statuses_binary, verified.bits, 2) == 0
  end

  test "404s for an unknown list id" do
    response = StatusListRouter.call(conn(:get, @status_list_path <> "/never-allocated"), [])

    assert response.status == 404
  end

  test "404s when no status_list_store is configured" do
    config = Application.fetch_env!(:attesto_phoenix, Config)
    put_config(Keyword.delete(config, :status_list_store))

    {:ok, 0} = StatusListStore.ETS.allocate(@uri)
    response = StatusListRouter.call(conn(:get, @status_list_path <> "/" <> @list_id), [])

    assert response.status == 404
  end

  test "uses a custom OAuth path prefix in the status-list subject URI" do
    config = Application.fetch_env!(:attesto_phoenix, Config)
    put_config(Keyword.put(config, :oauth_path_prefix, "/wallet/oauth"))

    uri = @issuer <> "/wallet/oauth/statuslist/" <> @list_id
    {:ok, 0} = StatusListStore.ETS.allocate(uri)

    response = StatusListController.show(conn(:get, "/wallet/oauth/statuslist/" <> @list_id), %{"id" => @list_id})

    assert response.status == 200

    {_kty, jwk} = @signing_pem |> Key.jwk() |> JOSE.JWK.to_public_map()
    jwk = Map.merge(jwk, %{"alg" => "ES256", "kid" => Key.kid(@signing_pem)})

    assert {:ok, verified} = StatusList.verify(response.resp_body, %{"keys" => [jwk]})
    assert verified.sub == uri
  end

  defp put_config(opts) do
    Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)
    Application.put_env(:attesto_phoenix, Config, opts)
  end
end
