defmodule AttestoPhoenix.AuthorizationServer.RequestPolicyTest do
  use ExUnit.Case, async: true

  alias AttestoPhoenix.AuthorizationServer.RequestPolicy
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
      refute RequestPolicy.client_native?(config([]), {:cimd, %{}})
    end
  end

  describe "redirect_uri_matching/2 (RFC 8252 §7.3)" do
    test "is exact by default" do
      assert RequestPolicy.redirect_uri_matching(config([]), @native_public) == :exact
      assert RequestPolicy.redirect_uri_matching(config([]), @confidential) == :exact
    end

    test "a native client gets the loopback exception once the host enables it" do
      config = config(native_apps: [loopback_redirect: true])

      assert RequestPolicy.redirect_uri_matching(config, @native_public) == :exact_allow_loopback_port
      assert RequestPolicy.redirect_uri_matching(config, @native_confidential) == :exact_allow_loopback_port
    end

    # Both gates are required: the flag alone must not widen matching for a
    # client the host never marked native.
    test "a non-native client stays exact even with the flag on" do
      config = config(native_apps: [loopback_redirect: true])

      assert RequestPolicy.redirect_uri_matching(config, @confidential) == :exact
      assert RequestPolicy.redirect_uri_matching(config, @public) == :exact
    end

    test "a native client stays exact while the flag is off" do
      config = config(native_apps: [loopback_redirect: false])

      assert RequestPolicy.redirect_uri_matching(config, @native_public) == :exact
    end

    test "a CIMD client stays exact even with the flag on" do
      config = config(native_apps: [loopback_redirect: true])

      assert RequestPolicy.redirect_uri_matching(config, {:cimd, %{}}) == :exact
    end

    test "the resolved mode is one Attesto.RedirectURI accepts" do
      config = config(native_apps: [loopback_redirect: true])

      assert RequestPolicy.redirect_uri_matching(config, @native_public) in Attesto.RedirectURI.matching_modes()
      assert RequestPolicy.redirect_uri_matching(config, @confidential) in Attesto.RedirectURI.matching_modes()
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
  end
end
