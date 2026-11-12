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

  describe "register/2 response_types (RFC 7591 §2)" do
    @redirect %{"redirect_uris" => ["https://client.example/cb"]}

    test "defaults to code for an authorization_code client, stored and returned" do
      config = build_config()

      assert {:ok, response, _events} = Registration.register(config, @redirect)
      assert response["response_types"] == ["code"]
      assert_received {:registered_attrs, %{"response_types" => ["code"]}}
    end

    test "a client with no authorization-endpoint grant has no response type" do
      config = build_config(registration_grant_types: ["client_credentials"])
      metadata = %{"grant_types" => ["client_credentials"], "token_endpoint_auth_method" => "client_secret_basic"}

      assert {:ok, response, _events} = Registration.register(config, metadata)
      refute Map.has_key?(response, "response_types")

      assert {:ok, response, _events} = Registration.register(config, Map.put(metadata, "response_types", []))
      assert response["response_types"] == []
    end

    test "refuses a value the authorization endpoint does not support" do
      config = build_config()

      for response_types <- [["token"], ["code", "id_token"], ["code token"], ["none"]] do
        assert {:error, %OAuthError{error: :invalid_client_metadata, error_description: description}} =
                 Registration.register(config, Map.put(@redirect, "response_types", response_types))

        assert description =~ "unsupported"
      end
    end

    test "refuses response_types that disagree with grant_types" do
      config = build_config(registration_grant_types: ["authorization_code", "client_credentials"])

      # code without the authorization_code grant
      assert {:error, %OAuthError{error: :invalid_client_metadata, error_description: description}} =
               Registration.register(config, %{
                 "grant_types" => ["client_credentials"],
                 "token_endpoint_auth_method" => "client_secret_basic",
                 "response_types" => ["code"]
               })

      assert description =~ "must agree"

      # the authorization_code grant without code
      assert {:error, %OAuthError{error: :invalid_client_metadata}} =
               Registration.register(config, Map.put(@redirect, "response_types", []))
    end

    test "refuses a malformed member" do
      config = build_config()

      for response_types <- ["code", ["code", "code"], [1], [""], %{"0" => "code"}, nil] do
        assert {:error, %OAuthError{error: :invalid_client_metadata}} =
                 Registration.register(config, Map.put(@redirect, "response_types", response_types))
      end
    end
  end

  describe "register/2 response built from the stored client (RFC 7591 §3.2.1)" do
    test "reports what the host stored, with the credentials issued here" do
      config =
        build_config(
          scopes_supported: ["openid", "profile"],
          register_client: fn attrs ->
            # The host narrows the scope and sets a member of its own.
            {:ok, attrs |> Map.put("scope", "openid") |> Map.put("client_name", "Stored Name")}
          end,
          client_registration_metadata: fn stored -> stored end
        )

      assert {:ok, response, _events} =
               Registration.register(config, %{
                 "redirect_uris" => ["https://client.example/cb"],
                 "scope" => "openid profile",
                 "client_name" => "Requested Name"
               })

      assert response["scope"] == "openid"
      assert response["client_name"] == "Stored Name"

      # Issued once, in plaintext, by the library; the store holds only hashes.
      assert is_binary(response["client_id"])
      assert is_binary(response["client_secret"])
      assert response["client_secret_expires_at"] == 0
      assert is_binary(response["registration_access_token"])
      assert response["registration_client_uri"] =~ response["client_id"]
      refute Map.has_key?(response, "client_secret_hash")
      refute Map.has_key?(response, "registration_access_token_hash")
    end

    test "a store cannot replace the issued identifier or credentials" do
      config =
        build_config(
          register_client: fn attrs -> {:ok, attrs} end,
          client_registration_metadata: fn stored ->
            Map.merge(stored, %{"client_id" => "chosen-by-store", "client_secret" => "chosen-by-store"})
          end
        )

      assert {:ok, response, [event]} =
               Registration.register(config, %{"redirect_uris" => ["https://client.example/cb"]})

      assert response["client_id"] == event.client_id
      refute response["client_id"] == "chosen-by-store"
      refute response["client_secret"] == "chosen-by-store"
    end

    test "without :client_registration_metadata, or with a non-map from it, the validated request is reported" do
      for overrides <- [[], [client_registration_metadata: fn _stored -> :not_a_map end]] do
        config = build_config([register_client: fn _attrs -> {:ok, :opaque_host_client} end] ++ overrides)

        assert {:ok, response, _events} =
                 Registration.register(config, %{
                   "redirect_uris" => ["https://client.example/cb"],
                   "client_name" => "Requested Name"
                 })

        assert response["client_name"] == "Requested Name"
        assert response["redirect_uris"] == ["https://client.example/cb"]
      end
    end
  end

  describe "register/2 host refusals (RFC 7591 §3.2.2)" do
    @metadata %{"redirect_uris" => ["https://client.example/cb"]}

    test "a capacity refusal answers 503 with Retry-After" do
      config = build_config(register_client: fn _attrs -> {:error, {:unavailable, 120}} end)

      assert {:error, %OAuthError{error: :temporarily_unavailable, status: 503, headers: [{"retry-after", "120"}]}} =
               Registration.register(config, @metadata)
    end

    test "a 4xx OAuthError from the host is passed through" do
      refusal = OAuthError.new(:access_denied, "registration is closed to this network", status: 403)
      config = build_config(register_client: fn _attrs -> {:error, refusal} end)

      assert {:error, ^refusal} = Registration.register(config, @metadata)
    end

    test "any other refusal stays invalid_client_metadata, and its reason is not sent" do
      import ExUnit.CaptureLog

      for reason <- [
            :constraint_violation,
            "duplicate key value violates unique constraint",
            {:unavailable, -1},
            {:unavailable, "soon"}
          ] do
        config = build_config(register_client: fn _attrs -> {:error, reason} end)

        assert {:error,
                %OAuthError{
                  error: :invalid_client_metadata,
                  status: 400,
                  error_description: "the requested client could not be registered"
                }} = Registration.register(config, @metadata)
      end

      # A host error carrying a 5xx status is not put on the wire.
      server_fault = OAuthError.new(:server_error, "database password is hunter2", status: 500)
      config = build_config(register_client: fn _attrs -> {:error, server_fault} end)

      log =
        capture_log(fn ->
          assert {:error, %OAuthError{error: :invalid_client_metadata, status: 400} = error} =
                   Registration.register(config, @metadata)

          refute error.error_description =~ "hunter2"
        end)

      assert log =~ "only 4xx refusals are passed through"
      refute log =~ "hunter2"
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
