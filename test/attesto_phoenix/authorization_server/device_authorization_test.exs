defmodule AttestoPhoenix.AuthorizationServer.DeviceAuthorizationTest do
  @moduledoc false
  # Core device-authorization request processing (RFC 8628 §3.2) over the
  # in-memory Attesto.DeviceCodeStore.ETS reference store.
  use ExUnit.Case, async: false

  alias Attesto.DeviceCode
  alias Attesto.DeviceCodeStore.ETS, as: Store
  alias AttestoPhoenix.AuthorizationServer.DeviceAuthorization
  alias AttestoPhoenix.AuthorizationServer.DeviceAuthorization.Request
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.OAuthError

  defmodule StubKeystore do
    @moduledoc false
  end

  defmodule StubRepo do
    @moduledoc false
  end

  setup do
    start_supervised!(Store)
    Store.reset()
    :ok
  end

  defp config(overrides \\ []) do
    [
      issuer: "https://issuer.example",
      audience: "https://api.example.com",
      keystore: StubKeystore,
      repo: StubRepo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _client, _given -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      client_id: fn client -> Map.get(client, :id) end,
      device_code_store: Store,
      device_authorization: [enabled: true, code_ttl_seconds: 600, poll_interval_seconds: 5]
    ]
    |> Keyword.merge(overrides)
    |> Config.new()
  end

  defp request(client, params, overrides \\ []) do
    struct!(
      %Request{client: client, client_auth_method: :client_secret_basic, params: params, dpop_input: %{}},
      overrides
    )
  end

  test "issues a device code + user code and the RFC 8628 §3.2 body" do
    config = config()
    client = %{id: "cli-1"}

    assert {:ok, response} = DeviceAuthorization.request(config, request(client, %{"scope" => "read"}))

    assert is_binary(response.device_code)
    assert response.user_code =~ ~r/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/
    assert response.verification_uri == "https://issuer.example/oauth/device_verification"
    assert response.verification_uri_complete == response.verification_uri <> "?user_code=" <> response.user_code
    assert response.expires_in == 600
    assert response.interval == 5

    # The code is bound and pollable: pending until approved.
    assert {:error, :authorization_pending} =
             DeviceCode.redeem(Store, response.device_code, %{client_id: "cli-1"}, interval: 0)
  end

  test "binds the requested scope (visible on the verification view)" do
    config = config()
    assert {:ok, response} = DeviceAuthorization.request(config, request(%{id: "cli-1"}, %{"scope" => "read write"}))
    assert {:ok, view} = DeviceCode.lookup(Store, response.user_code)
    assert view.scope == ["read", "write"]
  end

  test "rejects an unserved RFC 8707 resource with invalid_target" do
    config = config()
    params = %{"scope" => "read", "resource" => "https://evil.example/api"}

    assert {:error, %OAuthError{error: :invalid_target}} =
             DeviceAuthorization.request(config, request(%{id: "cli-1"}, params))
  end

  test "binds an allow-listed resource" do
    config = config(resource_indicators: [allowed_resources: ["https://api.example.com/a"]])
    params = %{"resource" => "https://api.example.com/a"}
    assert {:ok, response} = DeviceAuthorization.request(config, request(%{id: "cli-1"}, params))
    assert {:ok, view} = DeviceCode.lookup(Store, response.user_code)
    assert view.resource == ["https://api.example.com/a"]
  end

  test "a public client without a DPoP proof is rejected (security)" do
    config = config()
    req = request(%{id: "cli-pub"}, %{"scope" => "read"}, client_auth_method: :none)
    assert {:error, %OAuthError{error: :invalid_client}} = DeviceAuthorization.request(config, req)
  end

  test "fails server_error when no device_code_store is configured" do
    config = config(device_code_store: nil)

    assert {:error, %OAuthError{error: :server_error}} =
             DeviceAuthorization.request(config, request(%{id: "cli-1"}, %{}))
  end

  test "device_code is in grant_types_supported when enabled" do
    assert "urn:ietf:params:oauth:grant-type:device_code" in Config.grant_types_supported(config())

    refute "urn:ietf:params:oauth:grant-type:device_code" in Config.grant_types_supported(
             config(device_authorization: [enabled: false])
           )
  end
end
