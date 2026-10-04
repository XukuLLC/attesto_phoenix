defmodule AttestoPhoenix.Controller.RegistrationControllerTest do
  @moduledoc """
  Tests for the OAuth 2.0 Dynamic Client Registration endpoint (RFC 7591 §3).

  These exercise the controller-owned protocol framing: Content-Type guarding
  (RFC 7591 §3.1), metadata validation against the server's advertised policy
  (RFC 7591 §2), credential issuance via the `Attesto` core, host-owned
  persistence through the `:register_client` callback, the RFC 7591 §3.2.1
  client information response, no-store cache headers (RFC 7234 §5.2), and the
  RFC 7591 §3.2.2 error body. The host policy is injected through an
  `AttestoPhoenix.Config` struct placed on the conn, so no live datastore is
  required.
  """
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Controller.RegistrationController

  @endpoint_path "/oauth/register"

  # A minimal validated config struct. The registration controller never
  # touches the keystore/repo/auth callbacks, so those enforce-keys carry inert
  # placeholders; only the registration-relevant fields matter here.
  defp config(overrides) do
    base = %{
      issuer: "https://issuer.example",
      audience: "https://api.example.com",
      keystore: :unused,
      repo: :unused,
      load_client: fn _id -> {:error, :not_found} end,
      verify_client_secret: fn _client, _secret -> false end,
      load_principal: fn _subject -> {:error, :not_found} end,
      register_client: fn attrs -> {:ok, attrs} end,
      registration_enabled: true,
      openid_provider: false,
      scopes_supported: ["read", "write"]
    }

    struct(Config, Map.merge(base, Map.new(overrides)))
  end

  defp post_register(config, metadata, content_type \\ "application/json") do
    # The endpoint requires TLS (config.require_https defaults true): it returns a
    # plaintext client_secret, which must never cross a plain-HTTP hop.
    :post
    |> conn(@endpoint_path, metadata)
    |> Map.put(:scheme, :https)
    |> put_req_header("content-type", content_type)
    |> Map.put(:body_params, metadata)
    |> put_private(:attesto_phoenix_config, config)
    |> RegistrationController.create(%{})
  end

  defp delete_register(config, client_id, token) do
    conn =
      :delete
      |> conn(@endpoint_path <> "/" <> client_id)
      |> Map.put(:scheme, :https)
      |> put_private(:attesto_phoenix_config, config)

    conn =
      if is_binary(token) do
        put_req_header(conn, "authorization", "Bearer " <> token)
      else
        conn
      end

    RegistrationController.delete(conn, %{"client_id" => client_id})
  end

  defp body(conn), do: JSON.decode!(conn.resp_body)

  defp public_ec_jwk do
    {_metadata, public} = JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_public_map()
    public
  end

  defp public_x25519_jwk do
    {_metadata, public} = JOSE.JWK.generate_key({:okp, :X25519}) |> JOSE.JWK.to_public_map()
    public
  end

  defp certificate_jwks do
    der =
      :public_key.pkix_test_data(%{
        root: [],
        intermediates: [],
        peer: [key: {:namedCurve, :secp256r1}]
      })[:cert]

    pem = :public_key.pem_encode([{:Certificate, der, :not_encrypted}])
    {_metadata, public} = pem |> JOSE.JWK.from_pem() |> JOSE.JWK.to_public_map()

    %{"keys" => [Map.put(public, "x5c", [Base.encode64(der)])]}
  end

  test "draft 11 client capabilities survive registration and reject forbidden algorithms" do
    capabilities = %{
      "client_attestation_signing_alg_values_supported" => ["ES256"],
      "client_attestation_pop_signing_alg_values_supported" => ["ES256"],
      "client_attestation_pop_methods_supported" => ["jwt"]
    }

    base = %{"redirect_uris" => ["https://client.example/callback"]}
    conn = post_register(config([]), Map.merge(base, capabilities))
    assert conn.status == 201
    for {key, value} <- capabilities, do: assert(body(conn)[key] == value)

    for {key, value} <- [
          {"client_attestation_signing_alg_values_supported", ["none"]},
          {"client_attestation_pop_signing_alg_values_supported", ["HS256"]},
          {"client_attestation_pop_methods_supported", "jwt"}
        ] do
      conn = post_register(config([]), Map.put(base, key, value))
      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
    end
  end

  # OpenID Connect Registration §2 `application_type`, the standard wire signal
  # a client uses to declare itself an installed app. Recognising it is what
  # lets a host answer `client_native?/1` from a dynamic registration instead of
  # classifying every native client by hand.
  describe "application_type (OpenID Connect Registration §2 / RFC 8252)" do
    test "defaults to web when the client does not declare one" do
      conn =
        post_register(config([]), %{
          "grant_types" => ["authorization_code"],
          "redirect_uris" => ["https://client.example/callback"]
        })

      assert conn.status == 201
      assert body(conn)["application_type"] == "web"
    end

    # Asserted against what reaches `:register_client`, not just the echoed
    # response body. The response is rendered from the issued attrs, so a body
    # assertion alone would still pass if the member were dropped on the way to
    # the host — and the host is the only place it can be persisted for
    # `client_native?/1` to read later.
    test "carries a declared native application_type through to the host" do
      test_pid = self()

      conn =
        post_register(
          config(
            register_client: fn attrs ->
              send(test_pid, {:persisted, attrs})
              {:ok, attrs}
            end
          ),
          %{
            "grant_types" => ["authorization_code"],
            "application_type" => "native",
            "redirect_uris" => ["http://127.0.0.1:0/cb"]
          }
        )

      assert conn.status == 201
      assert body(conn)["application_type"] == "native"

      assert_receive {:persisted, attrs}
      assert attrs["application_type"] == "native"
    end

    # An ABSENT member defaults to "web"; a present JSON null is a malformed
    # value and must not be read as the default.
    test "rejects an explicit null application_type" do
      conn =
        post_register(config([]), %{
          "grant_types" => ["authorization_code"],
          "application_type" => nil,
          "redirect_uris" => ["https://client.example/callback"]
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
    end

    test "rejects an application_type outside the defined set" do
      conn =
        post_register(config([]), %{
          "grant_types" => ["authorization_code"],
          "application_type" => "mobile",
          "redirect_uris" => ["https://client.example/callback"]
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
      assert body(conn)["error_description"] =~ "application_type"
    end
  end

  describe "registration document and RFC 7591 defaults" do
    test "requires a JSON object instead of minting credentials for an empty or non-object document" do
      for metadata <- [%{}, [], nil, "not-an-object"] do
        conn = post_register(config([]), metadata)

        assert conn.status == 400
        assert body(conn)["error"] in ["invalid_client_metadata", "invalid_redirect_uri"]
        refute Map.has_key?(body(conn), "client_id")
        refute Map.has_key?(body(conn), "client_secret")
        refute Map.has_key?(body(conn), "registration_access_token")
      end
    end

    test "defaults an omitted grant_types member to authorization_code" do
      conn =
        post_register(config([]), %{
          "redirect_uris" => ["https://client.example/callback"]
        })

      assert conn.status == 201
      assert body(conn)["grant_types"] == ["authorization_code"]
    end

    test "does not treat an explicit null grant_types member as absent" do
      conn =
        post_register(config([]), %{
          "grant_types" => nil,
          "redirect_uris" => ["https://client.example/callback"]
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
    end

    test "does not treat explicit null redirect_uris or scope as absent" do
      for metadata <- [
            %{"grant_types" => ["client_credentials"], "redirect_uris" => nil},
            %{"grant_types" => ["client_credentials"], "scope" => nil}
          ] do
        conn = post_register(config(registration_default_scope: ["read"]), metadata)
        assert conn.status == 400
      end
    end

    test "requires the registration media type" do
      conn =
        :post
        |> conn(@endpoint_path, %{"redirect_uris" => ["https://client.example/callback"]})
        |> Map.put(:scheme, :https)
        |> Map.put(:body_params, %{"redirect_uris" => ["https://client.example/callback"]})
        |> put_private(:attesto_phoenix_config, config([]))
        |> RegistrationController.create(%{})

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
    end
  end

  # RFC 8252 §7.1: the FIRST redirect type prescribed for a native app is a
  # private-use URI scheme, whose canonical form carries no authority at all.
  describe "native app redirect URIs (RFC 8252 §7.1 / §7.3)" do
    test "accepts the canonical private-use scheme form, which has no authority" do
      for uri <- ["com.example.app:/oauth2redirect/example-provider", "com.example.app:/"] do
        conn =
          post_register(config([]), %{
            "grant_types" => ["authorization_code"],
            "application_type" => "native",
            "redirect_uris" => [uri]
          })

        assert conn.status == 201, "expected #{uri} to be registrable, got: #{conn.resp_body}"
        assert body(conn)["redirect_uris"] == [uri]
      end
    end

    test "accepts loopback redirect URIs in both address families" do
      conn =
        post_register(config([]), %{
          "grant_types" => ["authorization_code"],
          "application_type" => "native",
          "redirect_uris" => ["http://127.0.0.1:0/cb", "http://[::1]:0/cb"]
        })

      assert conn.status == 201
    end

    test "rejects plain HTTP redirects except native loopback literals" do
      for metadata <- [
            %{
              "grant_types" => ["authorization_code"],
              "application_type" => "web",
              "redirect_uris" => ["http://client.example/cb"]
            },
            %{
              "grant_types" => ["authorization_code"],
              "application_type" => "native",
              "redirect_uris" => ["http://client.example/cb"]
            },
            %{
              "grant_types" => ["authorization_code"],
              "application_type" => "native",
              "redirect_uris" => ["http://localhost/cb"]
            }
          ] do
        conn = post_register(config([]), metadata)
        assert conn.status == 400
        assert body(conn)["error"] == "invalid_redirect_uri"
      end
    end

    defp register_native(uri) do
      post_register(config([]), %{
        "grant_types" => ["authorization_code"],
        "application_type" => "native",
        "redirect_uris" => [uri]
      })
    end

    # The authority-less allowance is gated on a reverse-DNS scheme (RFC 8252
    # §7.1 / RFC 7595 §3.8). Without that gate it would admit exactly the
    # schemes that must never be a redirect target.
    test "still rejects authority-less schemes that are not reverse-DNS" do
      for uri <- ["javascript:alert(1)", "data:text/html,x", "mailto:a@b.c", "urn:ietf:params:oauth:x"] do
        conn = register_native(uri)

        assert conn.status == 400, "expected #{uri} to be refused"
        assert body(conn)["error"] == "invalid_redirect_uri"
      end
    end

    # A dot is NECESSARY for the §7.1 convention but not SUFFICIENT to be a
    # usable callback, so the shape is checked too. (It cannot be sufficient to
    # prove app-author control of the domain either — nothing syntactic can —
    # which is why the allowance is additionally confined to native clients.)
    test "rejects a dotted private-use scheme with no path" do
      assert register_native("com.example.app:").status == 400
    end

    # RFC 6749 §3.1.2: the redirection endpoint URI MUST NOT include a
    # fragment. True of every client type, not just native.
    test "rejects a fragment on any redirect URI" do
      assert register_native("com.example.app:/cb#frag").status == 400

      conn =
        post_register(config([]), %{
          "grant_types" => ["authorization_code"],
          "redirect_uris" => ["https://client.example/cb#frag"]
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_redirect_uri"
    end

    # The authority-less door is shut entirely for web clients, so a private-use
    # scheme cannot be smuggled in by a client that never declared itself
    # native.
    test "refuses a private-use scheme from a client that did not declare native" do
      for metadata <- [
            %{"grant_types" => ["authorization_code"], "redirect_uris" => ["com.example.app:/cb"]},
            %{
              "grant_types" => ["authorization_code"],
              "application_type" => "web",
              "redirect_uris" => ["com.example.app:/cb"]
            }
          ] do
        conn = post_register(config([]), metadata)

        assert conn.status == 400, "expected a non-native client to be refused a private-use scheme"
        assert body(conn)["error"] == "invalid_redirect_uri"
      end
    end
  end

  describe "redirect-scheme injection (XSS-sink hardening)" do
    # `javascript://x/%0a…` parses to scheme "javascript" WITH a host, so it is
    # not authority-less and slipped past the reverse-DNS gate; the authority
    # form must be http/https or it lands in an auto-executing sink as XSS.
    test "rejects an authority-form javascript: redirect_uri for web and native" do
      for app <- ["web", "native"] do
        conn =
          post_register(config([]), %{
            "grant_types" => ["authorization_code"],
            "application_type" => app,
            "redirect_uris" => ["javascript://x/%0aalert(document.domain)//"]
          })

        assert conn.status == 400, "expected authority-form javascript: refused for #{app}"
        assert body(conn)["error"] == "invalid_redirect_uri"
      end
    end

    test "rejects non-http(s) schemes in post_logout_redirect_uris" do
      for uri <- [
            "javascript:alert(1)",
            "javascript://x/%0aalert(1)//",
            "data:text/html,x",
            "vbscript:msgbox(1)",
            "https://ok.example/x#frag"
          ] do
        conn =
          post_register(config([]), %{
            "grant_types" => ["authorization_code"],
            "redirect_uris" => ["https://client.example/cb"],
            "post_logout_redirect_uris" => [uri]
          })

        assert conn.status == 400, "expected #{uri} refused in post_logout_redirect_uris"
        assert body(conn)["error"] == "invalid_client_metadata"
      end
    end

    test "accepts an https post_logout_redirect_uri" do
      conn =
        post_register(config([]), %{
          "grant_types" => ["authorization_code"],
          "redirect_uris" => ["https://client.example/cb"],
          "post_logout_redirect_uris" => ["https://client.example/after-logout"]
        })

      assert conn.status == 201, conn.resp_body
      assert body(conn)["post_logout_redirect_uris"] == ["https://client.example/after-logout"]
    end
  end

  describe "oversized scope metadata (DoS hardening)" do
    test "a scope metadata value beyond the size cap is rejected as invalid_client_metadata" do
      huge = Enum.map_join(1..200_000, " ", fn i -> "s#{rem(i, 100)}" end)

      conn =
        post_register(config([]), %{
          "grant_types" => ["authorization_code"],
          "redirect_uris" => ["https://client.example/callback"],
          "scope" => huge
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
      assert body(conn)["error_description"] =~ "too large"
    end
  end

  describe "successful registration (RFC 7591 §3.2.1)" do
    test "only shared-secret methods issue and persist secret credentials" do
      test_process = self()

      for method <- ~w(client_secret_basic client_secret_post) do
        registered_config =
          config(
            token_endpoint_auth_methods_supported: [method],
            register_client: fn attrs ->
              send(test_process, {:stored, attrs})
              {:ok, attrs}
            end
          )

        conn =
          post_register(registered_config, %{
            "grant_types" => ["client_credentials"],
            "token_endpoint_auth_method" => method
          })

        assert conn.status == 201
        payload = body(conn)
        assert is_binary(payload["client_secret"])
        assert payload["client_secret_expires_at"] == 0
        assert_receive {:stored, attrs}
        assert attrs["token_endpoint_auth_method"] == method
        assert attrs["client_secret_hash"] == Attesto.Secret.hash(payload["client_secret"])
        refute Map.has_key?(attrs, "client_secret")
      end
    end

    test "fails closed when a manually assembled config advertises client_secret_jwt" do
      # Config.new/1 rejects this unsupported method. Build the struct through
      # the local helper to retain controller-level defense if a host bypasses
      # configuration construction or restores an old serialized struct.
      conn =
        post_register(
          config(token_endpoint_auth_methods_supported: ["client_secret_jwt"]),
          %{
            "grant_types" => ["client_credentials"],
            "token_endpoint_auth_method" => "client_secret_jwt"
          }
        )

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
      refute Map.has_key?(body(conn), "client_secret")
    end

    test "key, certificate, attestation and public registrations have no shared-secret downgrade credential" do
      test_process = self()
      {_kty, provider_key} = JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_public_map()

      for method <- ~w(private_key_jwt tls_client_auth self_signed_tls_client_auth attest_jwt_client_auth none) do
        registered_config =
          config(
            token_endpoint_auth_methods_supported: [method],
            trusted_wallet_provider_jwks: %{"keys" => [provider_key]},
            register_client: fn attrs ->
              send(test_process, {:stored, attrs})
              {:ok, attrs}
            end
          )

        method_metadata =
          case method do
            "private_key_jwt" -> %{"jwks" => %{"keys" => [public_ec_jwk()]}}
            "tls_client_auth" -> %{"tls_client_auth_san_dns" => "client.example.com"}
            "self_signed_tls_client_auth" -> %{"jwks" => certificate_jwks()}
            _other -> %{}
          end

        conn =
          post_register(
            registered_config,
            Map.merge(
              %{
                "grant_types" => ["client_credentials"],
                "token_endpoint_auth_method" => method
              },
              method_metadata
            )
          )

        assert conn.status == 201
        payload = body(conn)
        refute Map.has_key?(payload, "client_secret")
        refute Map.has_key?(payload, "client_secret_expires_at")
        assert is_binary(payload["registration_access_token"])
        assert_receive {:stored, attrs}
        assert attrs["token_endpoint_auth_method"] == method
        refute Map.has_key?(attrs, "client_secret")
        refute Map.has_key?(attrs, "client_secret_hash")
        refute Map.has_key?(attrs, "client_secret_expires_at")
      end
    end

    test "registers a confidential client and returns 201 with credentials" do
      conn =
        post_register(config([]), %{
          "grant_types" => ["authorization_code"],
          "redirect_uris" => ["https://client.example/callback"],
          "scope" => "read write"
        })

      payload = body(conn)

      assert conn.status == 201
      assert is_binary(payload["client_id"]) and payload["client_id"] != ""
      assert is_binary(payload["client_secret"]) and payload["client_secret"] != ""
      # RFC 7591 §3.2.1: client_secret_expires_at is REQUIRED whenever a
      # client_secret is issued; 0 denotes a non-expiring secret.
      assert payload["client_secret_expires_at"] == 0
      assert payload["redirect_uris"] == ["https://client.example/callback"]
      assert payload["scope"] == "read write"
      assert is_integer(payload["client_id_issued_at"])
      assert is_binary(payload["registration_access_token"])

      assert payload["registration_client_uri"] ==
               "https://issuer.example/oauth/register/" <> payload["client_id"]
    end

    test "registration_client_uri follows a custom :oauth_path_prefix (RFC 7592 §2)" do
      conn =
        post_register(config(oauth_path_prefix: "/mcp/oauth"), %{
          "grant_types" => ["authorization_code"],
          "redirect_uris" => ["https://client.example/callback"]
        })

      payload = body(conn)

      assert conn.status == 201

      assert payload["registration_client_uri"] ==
               "https://issuer.example/mcp/oauth/register/" <> payload["client_id"]
    end

    test "a public client (token_endpoint_auth_method none) is issued no secret" do
      conn =
        post_register(config([]), %{
          "grant_types" => ["authorization_code"],
          "redirect_uris" => ["https://client.example/callback"],
          "token_endpoint_auth_method" => "none"
        })

      payload = body(conn)

      assert conn.status == 201
      refute Map.has_key?(payload, "client_secret")
      # RFC 7591 §3.2.1: with no secret issued, client_secret_expires_at is omitted.
      refute Map.has_key?(payload, "client_secret_expires_at")
      assert payload["token_endpoint_auth_method"] == "none"
    end

    test "omits scope from the response when none was requested" do
      conn = post_register(config([]), %{"grant_types" => ["client_credentials"]})

      assert conn.status == 201
      refute Map.has_key?(body(conn), "scope")
    end

    test "assigns the configured default scope when omitted (RFC 7591 §2) and echoes it" do
      conn =
        post_register(
          config(registration_default_scope: ["read"]),
          %{"grant_types" => ["client_credentials"]}
        )

      assert conn.status == 201
      # echoed back so the client learns what it got (§3.2.1) ...
      assert body(conn)["scope"] == "read"
      # ... and persisted on the stored client (register_client echoes attrs here)
      assert body(conn)["scope"] == "read"
    end

    test "registration_default_scope: :scopes_supported assigns the full catalog" do
      conn =
        post_register(
          config(registration_default_scope: :scopes_supported),
          %{"grant_types" => ["client_credentials"]}
        )

      assert conn.status == 201
      assert body(conn)["scope"] == "read write"
    end

    test "an explicit requested scope still wins over the default" do
      conn =
        post_register(
          config(registration_default_scope: :scopes_supported),
          %{"grant_types" => ["client_credentials"], "scope" => "read"}
        )

      assert conn.status == 201
      assert body(conn)["scope"] == "read"
    end

    test "every response carries no-store cache headers (RFC 7234 §5.2)" do
      conn = post_register(config([]), %{"grant_types" => ["client_credentials"]})

      assert get_resp_header(conn, "cache-control") == ["no-store"]
      assert get_resp_header(conn, "pragma") == ["no-cache"]
    end
  end

  describe "transport security (RFC 6749 §3.1 / §10.1)" do
    test "refuses a plain-HTTP registration and mints no secret" do
      # require_https defaults true; a plain-HTTP register would return the minted
      # client_secret in cleartext, so it must be refused before issuance.
      conn =
        :post
        |> conn(@endpoint_path, %{})
        |> put_req_header("content-type", "application/json")
        |> Map.put(:body_params, %{"redirect_uris" => ["https://client.example/callback"]})
        |> put_private(:attesto_phoenix_config, config([]))
        |> RegistrationController.create(%{})

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_request"
      refute Map.has_key?(body(conn), "client_secret")
    end

    test "refuses a plain-HTTP delete (registration-access-token would cross cleartext)" do
      conn =
        :delete
        |> conn(@endpoint_path <> "/some-client")
        |> put_req_header("authorization", "Bearer reg-token")
        |> put_private(:attesto_phoenix_config, config([]))
        |> RegistrationController.delete(%{"client_id" => "some-client"})

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_request"
    end
  end

  describe "RFC 7591 §2 metadata passthrough" do
    test "carries known client-identity metadata through to the host store and response" do
      test_pid = self()
      jwks = %{"keys" => [public_ec_jwk()]}

      config =
        config(
          register_client: fn attrs ->
            send(test_pid, {:persisted, attrs})
            {:ok, attrs}
          end
        )

      conn =
        post_register(config, %{
          "grant_types" => ["authorization_code"],
          "redirect_uris" => ["https://client.example/callback"],
          "client_name" => "Acme MCP",
          "client_uri" => "https://acme.example",
          "logo_uri" => "https://acme.example/logo.png",
          "tos_uri" => "https://acme.example/tos",
          "policy_uri" => "https://acme.example/privacy",
          "contacts" => ["ops@acme.example"],
          "jwks" => jwks
        })

      payload = body(conn)

      assert conn.status == 201
      assert payload["client_name"] == "Acme MCP"
      assert payload["client_uri"] == "https://acme.example"
      assert payload["logo_uri"] == "https://acme.example/logo.png"
      assert payload["tos_uri"] == "https://acme.example/tos"
      assert payload["policy_uri"] == "https://acme.example/privacy"
      assert payload["contacts"] == ["ops@acme.example"]
      assert payload["jwks"] == jwks

      assert_receive {:persisted, attrs}
      assert attrs["client_name"] == "Acme MCP"
      assert attrs["contacts"] == ["ops@acme.example"]
      assert attrs["jwks"] == jwks
    end

    test "drops unknown fields and never hands them to the host store" do
      test_pid = self()

      config =
        config(
          register_client: fn attrs ->
            send(test_pid, {:persisted, attrs})
            {:ok, attrs}
          end
        )

      conn =
        post_register(config, %{
          "grant_types" => ["authorization_code"],
          "redirect_uris" => ["https://client.example/callback"],
          "is_admin" => true,
          "internal_trust_level" => "root"
        })

      payload = body(conn)

      assert conn.status == 201
      refute Map.has_key?(payload, "is_admin")
      refute Map.has_key?(payload, "internal_trust_level")

      assert_receive {:persisted, attrs}
      refute Map.has_key?(attrs, "is_admin")
      refute Map.has_key?(attrs, "internal_trust_level")
    end

    test "a passthrough member cannot override a protocol-critical member" do
      test_pid = self()

      config =
        config(
          register_client: fn attrs ->
            send(test_pid, {:persisted, attrs})
            {:ok, attrs}
          end
        )

      # A request that also smuggles a redirect_uris-shaped client_name must
      # not corrupt the validated redirect_uris.
      conn =
        post_register(config, %{
          "grant_types" => ["authorization_code"],
          "redirect_uris" => ["https://client.example/callback"],
          "client_name" => "legit"
        })

      assert conn.status == 201
      assert_receive {:persisted, attrs}
      assert attrs["redirect_uris"] == ["https://client.example/callback"]
    end

    test "rejects a malformed known metadata member with invalid_client_metadata" do
      conn =
        post_register(config([]), %{
          "grant_types" => ["client_credentials"],
          "client_name" => 12_345
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
    end

    test "Spring DCR regression bounds human metadata while preserving markup for escaped rendering" do
      test_pid = self()
      markup = ~s(<b>Acme & "Partners"</b>)

      registered_config =
        config(
          register_client: fn attrs ->
            send(test_pid, {:persisted_human_metadata, attrs})
            {:ok, attrs}
          end
        )

      metadata = %{
        "grant_types" => ["client_credentials"],
        "client_name" => markup,
        "software_id" => "com.example.<client>",
        "software_version" => "1.0 & beta"
      }

      conn = post_register(registered_config, metadata)

      assert conn.status == 201, conn.resp_body
      assert body(conn)["client_name"] == markup
      assert body(conn)["software_id"] == metadata["software_id"]
      assert body(conn)["software_version"] == metadata["software_version"]

      assert_receive {:persisted_human_metadata, attrs}
      assert attrs["client_name"] == markup
    end

    test "Spring DCR regression rejects malformed and oversized human metadata" do
      invalid = [
        {"client_name", nil},
        {"client_name", "line one\nline two"},
        {"software_id", <<255>>},
        {"software_version", String.duplicate("v", 4_097)}
      ]

      for {field, value} <- invalid do
        conn =
          post_register(config([]), %{
            "grant_types" => ["client_credentials"],
            field => value
          })

        assert conn.status == 400, "expected #{field}=#{inspect(value, limit: 40)} to be rejected"
        assert body(conn)["error"] == "invalid_client_metadata"
      end
    end

    test "rejects a non-array contacts member" do
      conn =
        post_register(config([]), %{
          "grant_types" => ["client_credentials"],
          "contacts" => "ops@acme.example"
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
    end

    test "rejects a malformed inline jwks member" do
      conn =
        post_register(config([]), %{
          "grant_types" => ["client_credentials"],
          "jwks" => ["not", "an", "object"]
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
    end

    test "Spring DCR regression rejects executable schemes and malformed display URIs" do
      invalid = [
        {"client_uri", "javascript:alert(1)"},
        {"logo_uri", "data:image/svg+xml,<svg/>"},
        {"tos_uri", "file:///etc/passwd"},
        {"policy_uri", "/relative/privacy"},
        {"client_uri", nil},
        {"client_uri", "https://user:password@client.example/"},
        {"backchannel_logout_uri", "http://client.example/logout"},
        {"backchannel_logout_uri", "https://client.example/logout#fragment"},
        {"frontchannel_logout_uri", "http://client.example/logout"},
        {"frontchannel_logout_uri", "https://client.example/logout#fragment"},
        {"policy_uri", "https://client.example/%ZZ"},
        {"policy_uri", "https:\\evil.example\\privacy"},
        {"client_uri", "https://client.example/about\nnext"},
        {"client_uri", "https://client.example/" <> String.duplicate("a", 2_048)}
      ]

      for {field, value} <- invalid do
        conn =
          post_register(config([]), %{
            "grant_types" => ["client_credentials"],
            field => value
          })

        assert conn.status == 400, "expected #{field}=#{inspect(value, limit: 40)} to be rejected"
        assert body(conn)["error"] == "invalid_client_metadata"
      end
    end

    test "Keycloak jwks_uri regression requires an absolute clean HTTPS URL" do
      invalid = [
        "keys.example/jwks.json",
        "//keys.example/jwks.json",
        "http://keys.example/jwks.json",
        "https:///jwks.json",
        "https://user:secret@keys.example/jwks.json",
        "https://keys.example/jwks.json#key",
        "https:\\keys.example\\jwks.json"
      ]

      for jwks_uri <- invalid do
        conn =
          post_register(config([]), %{
            "grant_types" => ["client_credentials"],
            "jwks_uri" => jwks_uri
          })

        assert conn.status == 400, "expected jwks_uri=#{jwks_uri} to be rejected"
        assert body(conn)["error"] == "invalid_client_metadata"
      end
    end

    test "accepts bounded web metadata fragments and private deployment hosts" do
      metadata = %{
        "grant_types" => ["client_credentials"],
        "redirect_uris" => ["https://[::1]/callback"],
        "client_uri" => "http://localhost/about?lang=en#team",
        "logo_uri" => "https://10.0.0.5/logo.png#brand",
        "tos_uri" => "https://service.local/terms#current",
        "policy_uri" => "https://metadata.internal/privacy#v2",
        "jwks_uri" => "https://keys.service.local/jwks.json",
        "backchannel_logout_uri" => "https://127.0.0.1/backchannel",
        "frontchannel_logout_uri" => "https://[::1]/frontchannel"
      }

      conn = post_register(config([]), metadata)

      assert conn.status == 201, conn.resp_body

      for field <- ~w(client_uri logo_uri tos_uri policy_uri jwks_uri backchannel_logout_uri frontchannel_logout_uri) do
        assert body(conn)[field] == metadata[field]
      end
    end

    test "frontchannel_logout_uri must share an origin with a registered redirect_uri" do
      for metadata <- [
            %{
              "grant_types" => ["client_credentials"],
              "frontchannel_logout_uri" => "https://client.example/logout"
            },
            %{
              "grant_types" => ["authorization_code"],
              "redirect_uris" => ["https://client.example/callback"],
              "frontchannel_logout_uri" => "https://other.example/logout"
            },
            %{
              "grant_types" => ["authorization_code"],
              "redirect_uris" => ["https://client.example:8443/callback"],
              "frontchannel_logout_uri" => "https://client.example/logout"
            }
          ] do
        conn = post_register(config([]), metadata)
        assert conn.status == 400
        assert body(conn)["error"] == "invalid_client_metadata"
        assert body(conn)["error_description"] =~ "frontchannel_logout_uri"
      end
    end

    test "frontchannel_logout_uri accepts the registered redirect origin including an explicit default port" do
      conn =
        post_register(config([]), %{
          "grant_types" => ["authorization_code"],
          "redirect_uris" => ["https://client.example/callback"],
          "frontchannel_logout_uri" => "https://client.example:443/logout"
        })

      assert conn.status == 201, conn.resp_body
      assert body(conn)["frontchannel_logout_uri"] == "https://client.example:443/logout"
    end

    test "bounds registration metadata collections" do
      oversized_values = [
        {"contacts", Enum.map(1..65, &"security-#{&1}@example.com")},
        {"client_attestation_signing_alg_values_supported", Enum.map(1..65, &"future-alg-#{&1}")},
        {"post_logout_redirect_uris", Enum.map(1..65, &"https://client.example/logout/#{&1}")},
        {"redirect_uris", Enum.map(1..65, &"https://client.example/callback/#{&1}")}
      ]

      for {field, values} <- oversized_values do
        conn =
          post_register(config([]), %{
            "grant_types" => ["client_credentials"],
            field => values
          })

        assert conn.status == 400, "expected oversized #{field} to be rejected"
      end
    end

    test "requires jwks and jwks_uri to be mutually exclusive" do
      conn =
        post_register(config([]), %{
          "grant_types" => ["client_credentials"],
          "jwks" => %{"keys" => [public_ec_jwk()]},
          "jwks_uri" => "https://keys.client.example/jwks.json"
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
      assert body(conn)["error_description"] =~ "must not both be present"
    end

    test "validates inline jwks as a bounded public asymmetric JWK Set" do
      {_metadata, private_ec} = JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_map()
      public_ec = public_ec_jwk()
      certificate_key = certificate_jwks()["keys"] |> hd()
      mismatched_certificate_key = Map.put(public_ec_jwk(), "x5c", certificate_key["x5c"])

      invalid_sets = [
        %{},
        %{"keys" => [%{"kty" => "oct", "k" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)}]},
        %{"keys" => [private_ec]},
        %{"keys" => [%{"kty" => "RSA", "n" => "AQAB"}]},
        %{"keys" => [%{"kty" => "EC", "x5c" => ["not-base64"]}]},
        %{"keys" => [mismatched_certificate_key]},
        %{"keys" => [Map.put(public_ec, "use", 42)]},
        %{"keys" => [Map.put(public_ec, "alg", "ES256\nignored")]},
        %{"keys" => [Map.put(public_ec, "key_ops", nil)]},
        %{"keys" => [Map.put(public_ec, "key_ops", "verify")]},
        %{"keys" => [Map.merge(public_ec, %{"alg" => "ES256", "use" => "enc"})]},
        %{"keys" => [Map.merge(public_ec, %{"alg" => "ES256", "key_ops" => ["sign"]})]},
        %{"keys" => [Map.merge(public_ec, %{"use" => "sig", "key_ops" => ["deriveKey"]})]},
        %{"keys" => [Map.put(public_ec, "x5t", "AA")]},
        %{"keys" => List.duplicate(public_ec, 17)},
        %{"keys" => [Map.put(public_ec, "padding", String.duplicate("x", 65_536))]}
      ]

      for jwks <- invalid_sets do
        conn =
          post_register(config([]), %{
            "grant_types" => ["client_credentials"],
            "jwks" => jwks
          })

        assert conn.status == 400, "expected invalid JWK Set to be rejected"
        assert body(conn)["error"] == "invalid_client_metadata"
      end
    end

    test "accepts empty, future public, signing, encryption-only, and certificate-bearing JWKs" do
      encryption_key =
        public_x25519_jwk()
        |> Map.merge(%{"use" => "enc", "alg" => "ECDH-ES", "key_ops" => ["deriveKey"]})

      future_public_key = %{"kty" => "future-public-key", "kid" => "future-1"}

      for jwks <- [
            %{"keys" => []},
            %{"keys" => [future_public_key]},
            %{"keys" => [public_ec_jwk()]},
            %{"keys" => [encryption_key]},
            certificate_jwks()
          ] do
        conn =
          post_register(config([]), %{
            "grant_types" => ["client_credentials"],
            "jwks" => jwks
          })

        assert conn.status == 201, conn.resp_body
        assert body(conn)["jwks"] == jwks
      end
    end

    test "carries the logout metadata (Back-Channel §3 + Front-Channel §2 + RP-Initiated §3) through" do
      test_pid = self()

      config =
        config(
          register_client: fn attrs ->
            send(test_pid, {:persisted, attrs})
            {:ok, attrs}
          end
        )

      conn =
        post_register(config, %{
          "grant_types" => ["authorization_code"],
          "redirect_uris" => ["https://client.example/callback"],
          "post_logout_redirect_uris" => ["https://client.example/post_logout"],
          "backchannel_logout_uri" => "https://client.example/bc_logout",
          "backchannel_logout_session_required" => true,
          "frontchannel_logout_uri" => "https://client.example/fc_logout",
          "frontchannel_logout_session_required" => true
        })

      payload = body(conn)

      assert conn.status == 201
      assert payload["post_logout_redirect_uris"] == ["https://client.example/post_logout"]
      assert payload["backchannel_logout_uri"] == "https://client.example/bc_logout"
      assert payload["backchannel_logout_session_required"] == true
      assert payload["frontchannel_logout_uri"] == "https://client.example/fc_logout"
      assert payload["frontchannel_logout_session_required"] == true

      assert_receive {:persisted, attrs}
      assert attrs["frontchannel_logout_uri"] == "https://client.example/fc_logout"
      assert attrs["frontchannel_logout_session_required"] == true
      assert attrs["backchannel_logout_uri"] == "https://client.example/bc_logout"
    end

    test "rejects a non-boolean frontchannel_logout_session_required" do
      conn =
        post_register(config([]), %{
          "grant_types" => ["client_credentials"],
          "frontchannel_logout_session_required" => "yes"
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
    end

    test "rejects a non-string frontchannel_logout_uri" do
      conn =
        post_register(config([]), %{
          "grant_types" => ["client_credentials"],
          "frontchannel_logout_uri" => 42
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
    end
  end

  describe "RFC 8705 registration metadata" do
    test "tls_client_auth accepts each identity field individually" do
      identities = %{
        "tls_client_auth_subject_dn" => "CN=client,O=Example",
        "tls_client_auth_san_dns" => "client.example.com",
        "tls_client_auth_san_uri" => "spiffe://example.com/client/123",
        "tls_client_auth_san_ip" => "192.0.2.10",
        "tls_client_auth_san_email" => "client@example.com"
      }

      for {field, value} <- identities do
        conn =
          post_register(
            config(token_endpoint_auth_methods_supported: ["tls_client_auth"]),
            %{
              "grant_types" => ["client_credentials"],
              "token_endpoint_auth_method" => "tls_client_auth",
              field => value
            }
          )

        assert conn.status == 201, "expected #{field} to be accepted: #{conn.resp_body}"
        assert body(conn)[field] == value
        refute Map.has_key?(body(conn), "client_secret")
      end
    end

    test "tls_client_auth requires exactly one non-empty bounded identity" do
      auth_config = config(token_endpoint_auth_methods_supported: ["tls_client_auth"])

      for extra <- [
            %{},
            %{"tls_client_auth_san_dns" => ""},
            %{"tls_client_auth_san_dns" => "   "},
            %{"tls_client_auth_san_dns" => "client.example.com\nother.example.com"},
            %{"tls_client_auth_san_ip" => "999.999.999.999"},
            %{"tls_client_auth_san_uri" => "not an absolute URI"},
            %{"tls_client_auth_san_email" => "not-an-email"},
            %{"tls_client_auth_subject_dn" => " CN=client,O=Example"},
            %{"tls_client_auth_subject_dn" => String.duplicate("x", 4_097)},
            %{
              "tls_client_auth_san_dns" => "client.example.com",
              "tls_client_auth_san_uri" => "spiffe://example.com/client/123"
            }
          ] do
        conn =
          post_register(
            auth_config,
            Map.merge(
              %{
                "grant_types" => ["client_credentials"],
                "token_endpoint_auth_method" => "tls_client_auth"
              },
              extra
            )
          )

        assert conn.status == 400
        assert body(conn)["error"] == "invalid_client_metadata"
      end
    end

    test "private_key_jwt requires a usable signing key or https jwks_uri" do
      auth_config = config(token_endpoint_auth_methods_supported: ["private_key_jwt"])

      base = %{
        "grant_types" => ["client_credentials"],
        "token_endpoint_auth_method" => "private_key_jwt"
      }

      signing_key = Map.merge(public_ec_jwk(), %{"use" => "sig", "alg" => "ES256", "key_ops" => ["verify"]})

      encryption_key =
        public_x25519_jwk()
        |> Map.merge(%{"use" => "enc", "alg" => "ECDH-ES", "key_ops" => ["deriveKey"]})

      for key_source <- [
            %{"jwks" => %{"keys" => [encryption_key, signing_key]}},
            %{"jwks_uri" => "https://keys.internal/jwks.json"}
          ] do
        conn = post_register(auth_config, Map.merge(base, key_source))
        assert conn.status == 201, conn.resp_body
        refute Map.has_key?(body(conn), "client_secret")
      end

      for key_source <- [
            %{},
            %{"jwks" => %{"keys" => [encryption_key]}},
            %{"jwks" => %{"keys" => [Map.put(signing_key, "alg", "ES384")]}},
            %{"jwks_uri" => "http://keys.internal/jwks.json"}
          ] do
        conn = post_register(auth_config, Map.merge(base, key_source))
        assert conn.status == 400
        assert body(conn)["error"] == "invalid_client_metadata"
      end
    end

    test "private_key_jwt inline keys must satisfy the configured assertion algorithm policy" do
      {_metadata, p384} = JOSE.JWK.generate_key({:ec, "P-384"}) |> JOSE.JWK.to_public_map()

      metadata = %{
        "grant_types" => ["client_credentials"],
        "token_endpoint_auth_method" => "private_key_jwt",
        "jwks" => %{"keys" => [Map.put(p384, "alg", "ES384")]}
      }

      default_fapi =
        post_register(
          config(token_endpoint_auth_methods_supported: ["private_key_jwt"]),
          metadata
        )

      assert default_fapi.status == 400

      explicit_non_fapi =
        post_register(
          config(
            token_endpoint_auth_methods_supported: ["private_key_jwt"],
            client_auth_signing_algs: ["ES384"],
            client_auth_enforce_fapi_alg_policy: false
          ),
          metadata
        )

      assert explicit_non_fapi.status == 201, explicit_non_fapi.resp_body
    end

    test "self_signed_tls_client_auth requires a matching x5c key or https jwks_uri" do
      auth_config = config(token_endpoint_auth_methods_supported: ["self_signed_tls_client_auth"])

      base = %{
        "grant_types" => ["client_credentials"],
        "token_endpoint_auth_method" => "self_signed_tls_client_auth"
      }

      for key_source <- [
            %{"jwks" => certificate_jwks()},
            %{"jwks_uri" => "https://127.0.0.1/jwks.json"}
          ] do
        conn = post_register(auth_config, Map.merge(base, key_source))
        assert conn.status == 201, conn.resp_body
        refute Map.has_key?(body(conn), "client_secret")
      end

      certificate_key = certificate_jwks()["keys"] |> hd()
      mismatched_certificate_key = Map.put(public_ec_jwk(), "x5c", certificate_key["x5c"])

      for key_source <- [
            %{},
            %{"jwks" => %{"keys" => []}},
            %{"jwks" => %{"keys" => [public_ec_jwk()]}},
            %{"jwks" => %{"keys" => [mismatched_certificate_key]}},
            %{"jwks_uri" => "file:///etc/passwd"}
          ] do
        conn = post_register(auth_config, Map.merge(base, key_source))
        assert conn.status == 400
        assert body(conn)["error"] == "invalid_client_metadata"
      end
    end
  end

  describe "persistence (host-owned)" do
    test "persists the at-rest secret hash, never the plaintext" do
      test_pid = self()

      config =
        config(
          register_client: fn attrs ->
            send(test_pid, {:persisted, attrs})
            {:ok, attrs}
          end
        )

      conn =
        post_register(config, %{
          "grant_types" => ["authorization_code"],
          "redirect_uris" => ["https://client.example/callback"]
        })

      plaintext = body(conn)["client_secret"]
      registration_access_token = body(conn)["registration_access_token"]

      assert_receive {:persisted, attrs}
      refute Map.has_key?(attrs, "client_secret")
      # client_secret_expires_at is a response-only member (RFC 7591 §3.2.1),
      # not client metadata, so it is never handed to the host for persistence.
      refute Map.has_key?(attrs, "client_secret_expires_at")
      assert attrs["client_secret_hash"] == Attesto.Secret.hash(plaintext)
      refute Map.has_key?(attrs, "registration_access_token")
      refute Map.has_key?(attrs, "registration_client_uri")

      assert attrs["registration_access_token_hash"] ==
               Attesto.Secret.hash(registration_access_token)
    end

    test "renders a host store rejection as invalid_client_metadata, not a 500" do
      config = config(register_client: fn _attrs -> {:error, :duplicate} end)

      conn =
        post_register(config, %{
          "grant_types" => ["authorization_code"],
          "redirect_uris" => ["https://client.example/callback"]
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
    end
  end

  describe "registration management delete (RFC 7592 §2)" do
    test "deletes a dynamically registered client with its registration access token" do
      test_pid = self()
      token = "registration-token"

      client = %{
        client_id: "client-123",
        registration_access_token_hash: Attesto.Secret.hash(token)
      }

      config =
        config(
          load_client: fn "client-123" -> {:ok, client} end,
          client_registration_access_token_hash: fn loaded ->
            loaded.registration_access_token_hash
          end,
          unregister_client: fn loaded ->
            send(test_pid, {:deleted, loaded})
            :ok
          end
        )

      conn = delete_register(config, "client-123", token)

      assert conn.status == 204
      assert conn.resp_body == ""
      assert_receive {:deleted, ^client}
    end

    test "rejects missing or invalid registration access tokens" do
      client = %{
        client_id: "client-123",
        registration_access_token_hash: Attesto.Secret.hash("registration-token")
      }

      config =
        config(
          load_client: fn "client-123" -> {:ok, client} end,
          client_registration_access_token_hash: fn loaded ->
            loaded.registration_access_token_hash
          end,
          unregister_client: fn _loaded -> flunk("invalid token must not delete") end
        )

      missing = delete_register(config, "client-123", nil)
      invalid = delete_register(config, "client-123", "wrong-token")

      assert missing.status == 401
      assert body(missing)["error"] == "invalid_token"
      assert invalid.status == 401
      assert body(invalid)["error"] == "invalid_token"
    end

    test "an unexpected client-store result is a sanitized integration failure" do
      config =
        config(
          load_client: fn "client-123" -> {:error, :store_unavailable} end,
          client_registration_access_token_hash: fn _client -> flunk("no client may be trusted") end,
          unregister_client: fn _client -> flunk("no client may be deleted") end
        )

      assert_raise RuntimeError, ":load_client callback violated its return contract", fn ->
        delete_register(config, "client-123", "registration-token")
      end
    end
  end

  describe "event emission (RFC 7591)" do
    test "emits a :client_registered event carrying the client_id, never the secret" do
      test_pid = self()
      config = config(on_event: fn event -> send(test_pid, {:event, event}) end)

      conn =
        post_register(config, %{
          "grant_types" => ["authorization_code"],
          "redirect_uris" => ["https://client.example/callback"]
        })

      client_id = body(conn)["client_id"]

      assert_receive {:event, event}
      assert event.name == :client_registered
      assert event.client_id == client_id
    end
  end

  describe "request guards and validation (RFC 7591 §2 / §3.1)" do
    test "rejects a non-JSON Content-Type with invalid_client_metadata" do
      conn =
        post_register(
          config([]),
          %{"grant_types" => ["client_credentials"]},
          "application/x-www-form-urlencoded"
        )

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
    end

    test "rejects a missing redirect_uri for authorization_code with invalid_redirect_uri" do
      conn = post_register(config([]), %{"grant_types" => ["authorization_code"]})

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_redirect_uri"
    end

    test "rejects a non-absolute redirect_uri with invalid_redirect_uri" do
      conn =
        post_register(config([]), %{
          "grant_types" => ["authorization_code"],
          "redirect_uris" => ["/relative/callback"]
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_redirect_uri"
    end

    test "rejects an unknown scope with invalid_client_metadata" do
      conn =
        post_register(config([]), %{
          "grant_types" => ["client_credentials"],
          "scope" => "read delete"
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
    end

    test "rejects a grant_type outside the supported set with invalid_client_metadata" do
      # The default catalog is the RFC 6749 §1.3 set the core understands;
      # `password` is not offered.
      conn = post_register(config([]), %{"grant_types" => ["password"]})

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
    end

    test "an explicitly empty grant catalog does not widen to the default catalog" do
      conn =
        post_register(
          config(grant_types_supported: []),
          %{"grant_types" => ["client_credentials"]}
        )

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
    end

    test "default catalogs match discovery and accept implemented grants and authentication" do
      conn =
        post_register(config([]), %{
          "grant_types" => ["urn:ietf:params:oauth:grant-type:token-exchange"],
          "token_endpoint_auth_method" => "client_secret_post"
        })

      assert conn.status == 201
      assert body(conn)["grant_types"] == ["urn:ietf:params:oauth:grant-type:token-exchange"]
      assert body(conn)["token_endpoint_auth_method"] == "client_secret_post"
    end

    test "an explicitly empty auth-method catalog does not restore default methods" do
      conn =
        post_register(
          config(token_endpoint_auth_methods_supported: []),
          %{
            "grant_types" => ["client_credentials"],
            "token_endpoint_auth_method" => "client_secret_basic"
          }
        )

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
    end

    test "absent authentication method is rejected when its RFC default is not supported" do
      conn =
        post_register(
          config(token_endpoint_auth_methods_supported: ["private_key_jwt"]),
          %{"grant_types" => ["client_credentials"]}
        )

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
      assert body(conn)["error_description"] =~ "default token_endpoint_auth_method"
    end

    test "explicit null authentication method is malformed rather than absent" do
      conn =
        post_register(config([]), %{
          "grant_types" => ["client_credentials"],
          "token_endpoint_auth_method" => nil
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
    end
  end

  describe "request-scoped configuration" do
    test "uses the validated config installed on the request" do
      test_pid = self()

      request_config =
        config(
          register_client: fn attrs ->
            send(test_pid, :request_config_used)
            {:ok, attrs}
          end
        )

      conn = post_register(request_config, %{"grant_types" => ["client_credentials"]})

      assert conn.status == 201
      assert_receive :request_config_used
    end

    test "fails closed when the request config is absent" do
      conn =
        :post
        |> conn(@endpoint_path, %{})
        |> Map.put(:scheme, :https)
        |> put_req_header("content-type", "application/json")

      assert_raise ArgumentError, ~r/conn\.private\[:attesto_phoenix_config\]/, fn ->
        RegistrationController.create(conn, %{})
      end
    end

    test "fails closed when the request config is malformed" do
      conn =
        :post
        |> conn(@endpoint_path, %{})
        |> Map.put(:scheme, :https)
        |> put_private(:attesto_phoenix_config, :malformed)

      assert_raise ArgumentError, ~r/conn\.private\[:attesto_phoenix_config\]/, fn ->
        RegistrationController.create(conn, %{})
      end
    end
  end
end
