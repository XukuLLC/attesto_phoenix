defmodule AttestoPhoenix.AuthorizationServer.RegistrationTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.Secret
  alias AttestoPhoenix.AuthorizationServer.Registration
  alias AttestoPhoenix.AuthorizationServer.Registration.Request
  alias AttestoPhoenix.{Config, Event, OAuthError}

  defmodule StubKeystore do
    @moduledoc false
  end

  defmodule StubRepo do
    @moduledoc false
  end

  defp build_config(overrides \\ []) do
    test_pid = self()

    base = [
      issuer: "https://issuer.example",
      audience: "https://api.example.com",
      keystore: StubKeystore,
      repo: StubRepo,
      load_client: fn _id -> {:error, :not_found} end,
      verify_client_secret: fn _client, _secret -> false end,
      load_principal: fn _sub -> {:error, :not_found} end,
      registration_enabled: true,
      register_client: fn attrs ->
        send(test_pid, {:registered_attrs, attrs})
        {:ok, attrs}
      end
    ]

    Config.new(Keyword.merge(base, overrides))
  end

  describe "Request.from_params/1" do
    test "extracts top-level protocol fields as typed values and retains the metadata map" do
      raw = %{
        "redirect_uris" => ["https://client.example/cb"],
        "grant_types" => ["authorization_code"],
        "token_endpoint_auth_method" => "client_secret_basic",
        "application_type" => "web",
        "scope" => "openid",
        "client_name" => "Example App"
      }

      assert {:ok, %Request{} = req} = Request.from_params(raw)
      assert req.redirect_uris == ["https://client.example/cb"]
      assert req.grant_types == ["authorization_code"]
      assert req.token_endpoint_auth_method == "client_secret_basic"
      assert req.application_type == "web"
      assert req.scope == "openid"
      assert req.metadata == raw
    end

    test "rejects non-map, struct, and ill-typed top-level inputs with OAuthError" do
      assert {:error, %OAuthError{error: :invalid_client_metadata}} = Request.from_params(nil)
      assert {:error, %OAuthError{error: :invalid_client_metadata}} = Request.from_params("not-a-map")

      assert {:error, %OAuthError{error: :invalid_client_metadata}} =
               Request.from_params(URI.parse("https://client.example"))

      assert {:error, %OAuthError{error: :invalid_client_metadata}} =
               Request.from_params(%{"application_type" => nil})

      assert {:error, %OAuthError{error: :invalid_redirect_uri}} =
               Request.from_params(%{"redirect_uris" => "not-an-array"})
    end
  end

  describe "check_enabled/1" do
    test "returns :ok when registration_enabled is true and register_client is wired" do
      assert Registration.check_enabled(build_config()) == :ok
    end

    test "returns invalid_client_metadata when registration is disabled" do
      config = build_config(registration_enabled: false)

      assert {:error, %OAuthError{error: :invalid_client_metadata, status: 400}} =
               Registration.check_enabled(config)
    end
  end

  describe "register/2" do
    test "registers a valid client from a normalized Request and returns response + event as data" do
      config = build_config(scopes_supported: ["openid", "profile"])

      {:ok, req} =
        Request.from_params(%{
          "redirect_uris" => ["https://client.example/cb"],
          "scope" => "openid",
          "client_name" => "My Client"
        })

      assert {:ok, response, [%Event{name: :client_registered} = event]} =
               Registration.register(config, req)

      assert is_binary(response["client_id"])
      assert is_binary(response["client_secret"])
      assert response["client_secret_expires_at"] == 0
      assert response["redirect_uris"] == ["https://client.example/cb"]
      assert response["scope"] == "openid"
      assert response["client_name"] == "My Client"
      assert event.client_id == response["client_id"]

      assert_received {:registered_attrs, persisted}
      assert persisted["client_secret_hash"] == Secret.hash(response["client_secret"])
      refute Map.has_key?(persisted, "client_secret")
    end

    test "accepts a hand-built %Request{} struct directly without a raw metadata map" do
      config = build_config(scopes_supported: ["openid"])

      req = %Request{
        redirect_uris: ["https://client.example/cb"],
        grant_types: ["authorization_code"],
        token_endpoint_auth_method: "none",
        application_type: "web",
        scope: "openid"
      }

      assert {:ok, response, [%Event{name: :client_registered}]} =
               Registration.register(config, req)

      assert response["redirect_uris"] == ["https://client.example/cb"]
      assert response["token_endpoint_auth_method"] == "none"
      assert response["scope"] == "openid"
      refute Map.has_key?(response, "client_secret")
    end

    test "enforces the enabled gate even when called directly without check_enabled/1" do
      config = build_config(registration_enabled: false)

      assert {:error, %OAuthError{error: :invalid_client_metadata}} =
               Registration.register(config, %{"redirect_uris" => ["https://client.example/cb"]})
    end

    test "refuses redirect_uris carrying reserved OAuth response query parameters" do
      config = build_config()

      assert {:error, %OAuthError{error: :invalid_redirect_uri}} =
               Registration.register(config, %{
                 "redirect_uris" => ["https://client.example/cb?code=prepopulated"]
               })
    end
  end

  describe "unregister/3" do
    test "verifies the registration access token in constant time and invokes unregister_client" do
      token = "reg-access-token-123"
      token_hash = Secret.hash(token)
      test_pid = self()

      config =
        build_config(
          load_client: fn "client-1" -> {:ok, %{id: "client-1", rat_hash: token_hash}} end,
          client_registration_access_token_hash: fn client -> client.rat_hash end,
          unregister_client: fn client ->
            send(test_pid, {:unregistered, client.id})
            :ok
          end
        )

      assert :ok = Registration.unregister(config, "client-1", token)
      assert_received {:unregistered, "client-1"}
    end

    test "returns 401 invalid_token on a wrong or missing bearer token" do
      token_hash = Secret.hash("expected-token")

      config =
        build_config(
          load_client: fn "client-1" -> {:ok, %{id: "client-1", rat_hash: token_hash}} end,
          client_registration_access_token_hash: fn client -> client.rat_hash end,
          unregister_client: fn _client -> :ok end
        )

      assert {:error, %OAuthError{error: :invalid_token, status: 401}} =
               Registration.unregister(config, "client-1", "wrong-token")

      assert {:error, %OAuthError{error: :invalid_token, status: 401}} =
               Registration.unregister(config, "client-1", nil)
    end
  end
end
