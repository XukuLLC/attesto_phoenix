defmodule AttestoPhoenix.AuthorizationServer.RequestPolicyTest do
  use ExUnit.Case, async: true

  alias AttestoPhoenix.AuthorizationServer.RequestPolicy
  alias AttestoPhoenix.ClientIdMetadata.Client, as: CIMDClient
  alias AttestoPhoenix.Config

  # Clients classified through the config callbacks below.
  @public %{id: "public-1", public?: true}
  @dpop %{id: "dpop-1"}
  @mtls %{id: "mtls-1"}
  @confidential %{id: "conf-1"}

  # RFC 8252: a native app the host marks public, and one it (contradictorily)
  # marks confidential - both are exercised, because §8.1 PKCE follows from
  # "native" alone.
  @native_public %{id: "native-1", public?: true, native?: true}
  @native_confidential %{id: "native-2", native?: true}

  defmodule StubKeystore do
    @moduledoc false
  end

  defmodule StubRepo do
    @moduledoc false
  end

  defp required_fields do
    [
      issuer: "https://issuer.example",
      audience: "https://api.example.com",
      keystore: StubKeystore,
      repo: StubRepo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _client, _given -> false end,
      load_principal: fn _ -> {:error, :not_found} end
    ]
  end

  defp config(overrides) do
    fields =
      required_fields()
      |> Keyword.merge(
        client_public?: fn client -> Map.get(client, :public?, false) == true end,
        client_native?: fn client -> Map.get(client, :native?, false) == true end,
        client_requires_dpop?: fn client -> Map.get(client, :id) == "dpop-1" end,
        client_requires_mtls?: fn client -> Map.get(client, :id) == "mtls-1" end
      )
      |> Keyword.merge(overrides)

    struct!(Config, fields)
  end

  describe "require_pkce?/2" do
    test "a public client always requires PKCE, even with the global flag relaxed" do
      assert RequestPolicy.require_pkce?(config(require_pkce: false), @public)
    end

    test "a DPoP sender-constrained (FAPI) client requires PKCE despite confidential auth" do
      # FAPI 2.0 §5.3.1.2: PKCE is mandatory for the FAPI client even though it
      # authenticates with private_key_jwt and the host relaxed :require_pkce for
      # Basic-profile compatibility.
      assert RequestPolicy.require_pkce?(config(require_pkce: false), @dpop)
    end

    test "an mTLS sender-constrained client requires PKCE despite the relaxed flag" do
      assert RequestPolicy.require_pkce?(config(require_pkce: false), @mtls)
    end

    test "a plain confidential client follows the global flag (relaxed -> no PKCE)" do
      # The OpenID Connect Basic profile drives a no-PKCE confidential flow; the
      # relaxation must still reach it so that profile can run.
      refute RequestPolicy.require_pkce?(config(require_pkce: false), @confidential)
    end

    test "a plain confidential client requires PKCE when the global flag is set" do
      assert RequestPolicy.require_pkce?(config(require_pkce: true), @confidential)
    end

    # RFC 8252 §8.1: a native app MUST use PKCE. The requirement follows from
    # the client being native, not from any config flag.
    test "a native client requires PKCE regardless of the global flag" do
      assert RequestPolicy.require_pkce?(config(require_pkce: false), @native_public)
      assert RequestPolicy.require_pkce?(config(require_pkce: false), @native_confidential)
    end
  end

  describe "client_native?/2 (RFC 8252)" do
    test "reads the host's :client_native? callback" do
      assert RequestPolicy.client_native?(config([]), @native_public)
      refute RequestPolicy.client_native?(config([]), @confidential)
    end

    # Unlike client_public?/2 this must NOT default to true: "native" gates a
    # relaxation, so an unclassified client gets the unmodified RFC 6749 rules.
    test "an unclassified client is not native when the callback is absent" do
      refute RequestPolicy.client_native?(config(client_native?: nil), @native_public)
    end

    test "a CIMD client is never native" do
      refute RequestPolicy.client_native?(config([]), %CIMDClient{metadata: %{}})
    end
  end

  # The host's client value is opaque by contract, so a host may represent a
  # client as a tuple. Marking a resolved CIMD client with a tagged tuple would
  # have made `{:cimd, _}` a shape a host could return by coincidence and have
  # every CIMD relaxation applied to it - including `client_public?/2`, which is
  # what decides a client authenticates with no secret. Only the struct counts.
  describe "a host client is never mistaken for a CIMD client" do
    @host_tuple {:cimd, %{"redirect_uris" => ["http://127.0.0.1/callback"]}}

    # The default fixture callbacks reach into the client with `Map.get/3`, so
    # they cannot take an opaque tuple. A host that represents clients as tuples
    # supplies callbacks that can read them; these stand in for those.
    defp host_config(overrides \\ []) do
      config(
        Keyword.merge(
          [
            client_public?: fn _client -> false end,
            client_native?: fn _client -> false end,
            client_requires_dpop?: fn _client -> false end,
            client_requires_mtls?: fn _client -> false end
          ],
          overrides
        )
      )
    end

    test "a tuple shaped like the old CIMD marker is not public" do
      refute RequestPolicy.client_public?(host_config(), @host_tuple)
    end

    test "a tuple shaped like the old CIMD marker does not force PKCE on CIMD grounds" do
      refute RequestPolicy.require_pkce?(host_config(require_pkce: false), @host_tuple)
    end

    test "a tuple shaped like the old CIMD marker takes its redirect URIs from the host" do
      registered = ["https://host-registered.example/cb"]

      assert RequestPolicy.registered_redirect_uris(
               host_config(client_redirect_uris: fn _client -> registered end),
               @host_tuple
             ) == registered
    end

    test "a tuple shaped like the old CIMD marker gets no loopback port allowance" do
      assert RequestPolicy.redirect_uri_matching(host_config(), @host_tuple) == :exact
    end

    test "the struct still receives every CIMD decision" do
      cimd = %CIMDClient{metadata: %{"redirect_uris" => ["http://127.0.0.1/callback"]}}

      assert RequestPolicy.client_public?(config([]), cimd)
      assert RequestPolicy.require_pkce?(config(require_pkce: false), cimd)
      assert RequestPolicy.registered_redirect_uris(config([]), cimd) == ["http://127.0.0.1/callback"]
      assert RequestPolicy.redirect_uri_matching(config([]), cimd) == :exact_allow_loopback_port
    end
  end

  describe "redirect_uri_matching/2 (RFC 8252 §7.3)" do
    # RFC 8252 §7.3 states the port allowance as a MUST, so marking the client
    # native is the whole decision - no second server-wide opt-in.
    test "a native client gets the loopback exception with no further configuration" do
      assert RequestPolicy.redirect_uri_matching(config([]), @native_public) == :exact_allow_loopback_port
      assert RequestPolicy.redirect_uri_matching(config([]), @native_confidential) == :exact_allow_loopback_port
    end

    # The profile stays off for an unconfigured deployment because
    # `:client_native?` defaults to false, not because of any flag.
    test "a client the host has not marked native stays exact" do
      assert RequestPolicy.redirect_uri_matching(config([]), @confidential) == :exact
      assert RequestPolicy.redirect_uri_matching(config([]), @public) == :exact

      # Control on the same config: the exception IS available, just not to them.
      assert RequestPolicy.redirect_uri_matching(config([]), @native_public) == :exact_allow_loopback_port
    end

    test "an unclassified deployment sees exact matching everywhere" do
      config = config(client_native?: nil)

      assert RequestPolicy.redirect_uri_matching(config, @native_public) == :exact
      assert RequestPolicy.redirect_uri_matching(config, @confidential) == :exact
    end

    # The remaining flag is an escape hatch, not a gate: it can only ever
    # REMOVE the exception. Paired with the unset case on the same client, so
    # the assertion cannot be satisfied by an implementation that simply never
    # grants the exception.
    test "the server-wide opt-out forbids the exception even for a native client" do
      assert RequestPolicy.redirect_uri_matching(config(native_apps: [loopback_redirect: false]), @native_public) ==
               :exact

      assert RequestPolicy.redirect_uri_matching(config([]), @native_public) == :exact_allow_loopback_port
    end

    test "setting the opt-out to true is a no-op, since that is the default" do
      assert RequestPolicy.redirect_uri_matching(config(native_apps: [loopback_redirect: true]), @native_public) ==
               :exact_allow_loopback_port
    end

    # A CIMD client has no `:client_native?` callback to consult, so the
    # document's own declared redirect URIs are the native signal. This is the
    # shape of a real published document (Claude Code's), which declares
    # portless loopback URIs and binds an ephemeral port at runtime.
    test "a CIMD client declaring a loopback redirect URI gets the exception" do
      cimd = %CIMDClient{metadata: %{"redirect_uris" => ["http://localhost/callback", "http://127.0.0.1/callback"]}}

      assert RequestPolicy.redirect_uri_matching(config([]), cimd) == :exact_allow_loopback_port
    end

    test "a CIMD client declaring only web redirect URIs does not" do
      cimd = %CIMDClient{metadata: %{"redirect_uris" => ["https://app.example/cb"]}}

      assert RequestPolicy.redirect_uri_matching(config([]), cimd) == :exact
    end

    # §8.3: the literal IP is required, so a document declaring only the
    # `localhost` NAME gets no port flexibility.
    test "a CIMD client declaring only localhost does not" do
      cimd = %CIMDClient{metadata: %{"redirect_uris" => ["http://localhost/callback"]}}

      assert RequestPolicy.redirect_uri_matching(config([]), cimd) == :exact
    end

    test "a malformed or empty CIMD document does not" do
      assert RequestPolicy.redirect_uri_matching(config([]), %CIMDClient{metadata: %{}}) == :exact
      assert RequestPolicy.redirect_uri_matching(config([]), %CIMDClient{metadata: %{"redirect_uris" => []}}) == :exact
    end

    test "the server-wide opt-out still forbids the exception for a CIMD client" do
      cimd = %CIMDClient{metadata: %{"redirect_uris" => ["http://127.0.0.1/callback"]}}

      assert RequestPolicy.redirect_uri_matching(config(native_apps: [loopback_redirect: false]), cimd) == :exact
    end

    # Both resolved modes must be ones the core actually implements, and they
    # must be DIFFERENT - an implementation that collapsed to a single mode
    # would satisfy "is a valid mode" while silently disabling the feature.
    test "the two resolved modes are distinct and both accepted by Attesto.RedirectURI" do
      config = config([])

      native = RequestPolicy.redirect_uri_matching(config, @native_public)
      other = RequestPolicy.redirect_uri_matching(config, @confidential)

      assert native != other
      assert native in Attesto.RedirectURI.matching_modes()
      assert other in Attesto.RedirectURI.matching_modes()
    end
  end

  describe "validate/4" do
    @code_challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

    defp params(redirect_uri) do
      %{
        "response_type" => "code",
        "client_id" => "native-1",
        "redirect_uri" => redirect_uri,
        "code_challenge" => @code_challenge,
        "code_challenge_method" => "S256"
      }
    end

    defp native_config(native_apps) do
      config(
        native_apps: native_apps,
        client_redirect_uris: fn _client -> ["http://127.0.0.1:0/cb"] end
      )
    end

    test "threads the loopback exception into Attesto.AuthorizationRequest" do
      config = native_config(loopback_redirect: true)

      assert {:ok, request} = RequestPolicy.validate(config, @native_public, params("http://127.0.0.1:51823/cb"))
      assert request.redirect_uri == "http://127.0.0.1:51823/cb"
    end

    test "rejects the same request with the exception off" do
      config = native_config(loopback_redirect: false)

      assert {:error, {:direct, :redirect_uri_not_registered}} =
               RequestPolicy.validate(config, @native_public, params("http://127.0.0.1:51823/cb"))
    end

    test "rejects the same request for a non-native client" do
      config = native_config(loopback_redirect: true)

      assert {:error, {:direct, :redirect_uri_not_registered}} =
               RequestPolicy.validate(config, @confidential, params("http://127.0.0.1:51823/cb"))
    end

    # RFC 8252 §8.1 must not be evadable by moving the parameters inside a
    # signed request object (RFC 9101). `Attesto.AuthorizationRequest` merges the
    # object BEFORE the redirectable checks, so the PKCE requirement applies to
    # the object's contents; this pins that for a native client specifically.
    test "the native PKCE requirement applies to a signed request object's contents" do
      {request, jwk} = unsigned_request_object_for("http://127.0.0.1:51823/cb")

      config =
        config(
          native_apps: [loopback_redirect: true],
          require_pkce: false,
          client_public?: fn _client -> false end,
          client_redirect_uris: fn _client -> ["http://127.0.0.1:0/cb"] end
        )

      outer = %{"client_id" => "native-1", "request" => request}

      # The object carries no code_challenge, so the request is rejected -
      # redirectably, since the loopback redirect_uri inside it was matched.
      assert {:error, {:redirect, error}} =
               RequestPolicy.validate(config, @native_public, outer,
                 request_object_jwks: %{"keys" => [jwk]},
                 request_object_audience: "https://issuer.example"
               )

      assert error.error == "invalid_request"
      assert error.error_description =~ "code_challenge"
    end
  end

  # A signed request object carrying a complete authorization request EXCEPT
  # PKCE, returned with the public JWK that verifies it.
  defp unsigned_request_object_for(redirect_uri) do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, public_map} = JOSE.JWK.to_public_map(jwk)
    client_jwk = Map.merge(public_map, %{"kid" => "native-key-1", "alg" => "ES256"})

    claims = %{
      "iss" => "native-1",
      "aud" => "https://issuer.example",
      "response_type" => "code",
      "client_id" => "native-1",
      "redirect_uri" => redirect_uri
    }

    {_, request} =
      jwk
      |> JOSE.JWT.sign(%{"alg" => "ES256", "kid" => "native-key-1"}, claims)
      |> JOSE.JWS.compact()

    {request, client_jwk}
  end
end
