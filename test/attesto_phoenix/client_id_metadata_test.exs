defmodule AttestoPhoenix.ClientIdMetadataTest do
  use ExUnit.Case, async: true

  alias AttestoPhoenix.ClientIdMetadata
  alias AttestoPhoenix.ClientIdMetadata.FlowControl
  alias AttestoPhoenix.ClientIdMetadata.HostPolicy
  alias AttestoPhoenix.Support.TestKeystore
  alias AttestoPhoenix.Support.TestRepo

  describe "CIMD hostname policy" do
    test "compares lowercase IDNA names after removing one DNS root dot" do
      for host <- ["BÜCHER.Example", "bücher.example.", "XN--BCHER-KVA.EXAMPLE."] do
        assert {:ok, "xn--bcher-kva.example"} = HostPolicy.canonicalize(host)
        assert {:error, :blocked_host} = HostPolicy.check(host, blocked_hosts: ["Bücher.Example."])
        assert :ok = HostPolicy.check(host, allowed_hosts: ["xn--bcher-kva.example"])
      end

      assert {:error, :blocked_host} =
               HostPolicy.check("sub.bücher.example", allowed_hosts: ["BÜCHER.Example."])
    end

    test "rejects invalid or repeated root dots rather than deleting every dot" do
      for host <- ["app.example..", "app..example", ".", "", "*.example", "bad_host.example", nil] do
        assert {:error, :invalid_host} = HostPolicy.canonicalize(host)
        assert {:error, :blocked_host} = HostPolicy.check(host, [])
      end

      assert {:error, :blocked_host} = HostPolicy.check("app.example", blocked_hosts: ["bad_host.example"])
      assert {:error, :blocked_host} = HostPolicy.check("app.example", blocked_hosts: nil)
    end

    test "canonicalizes IP literals without exempting them from host policy" do
      assert {:ok, "2001:db8::1"} = HostPolicy.canonicalize("2001:DB8:0:0:0:0:0:1")

      assert {:error, :blocked_host} =
               HostPolicy.check("2001:DB8:0:0:0:0:0:1", blocked_hosts: ["2001:db8::1"])

      assert {:error, :blocked_host} = HostPolicy.check("127.0.0.1", blocked_hosts: ["127.0.0.1"])
    end
  end

  describe "scopes/1" do
    test "splits a space-delimited RFC 7591 scope member into a list" do
      assert ClientIdMetadata.scopes(%{"scope" => "openid email offline_access"}) ==
               ["openid", "email", "offline_access"]
    end

    test "is an empty list when the document omits scope (an empty declared set)" do
      # The ChatGPT MCP connector's document carries no `scope` member; this is
      # the case the host_client guard turns into an empty set rather than a
      # missing key.
      assert ClientIdMetadata.scopes(%{"client_id" => "https://app.example/c.json"}) == []
    end

    test "is an empty list for a blank or whitespace-only scope member" do
      assert ClientIdMetadata.scopes(%{"scope" => ""}) == []
      assert ClientIdMetadata.scopes(%{"scope" => "   "}) == []
    end

    test "ignores a non-string scope member rather than raising" do
      assert ClientIdMetadata.scopes(%{"scope" => ["openid"]}) == []
    end
  end

  describe "same_origin_redirect_uri?/2" do
    @client_id "https://app.example/client.json"

    test "accepts a redirect URI sharing scheme, host, and port" do
      assert ClientIdMetadata.same_origin_redirect_uri?(@client_id, "https://app.example/cb")
      assert ClientIdMetadata.same_origin_redirect_uri?(@client_id, "https://app.example:443/cb")
      assert ClientIdMetadata.same_origin_redirect_uri?(@client_id, "https://app.example/deep/cb?a=1")
    end

    test "refuses a different scheme, host, or port" do
      refute ClientIdMetadata.same_origin_redirect_uri?(@client_id, "http://app.example/cb")
      refute ClientIdMetadata.same_origin_redirect_uri?(@client_id, "https://other.example/cb")
      refute ClientIdMetadata.same_origin_redirect_uri?(@client_id, "https://app.example:8443/cb")
      refute ClientIdMetadata.same_origin_redirect_uri?(@client_id, "https://sub.app.example/cb")
    end

    # The predicate answers an ORIGIN question, but the browser - not
    # `URI.parse/1` - decides where the response lands. A URI the two read
    # differently has no single origin to compare, so it is refused rather than
    # resolved by whichever parser happens to be asked.
    test "refuses a URI whose host depends on which parser reads it" do
      # RFC 3986 reads the host as `app.example`; a browser navigates to
      # `evil.example`. Approving it would deliver the code off-origin.
      assert URI.parse("https://evil.example\\@app.example/cb").host == "app.example"
      refute ClientIdMetadata.same_origin_redirect_uri?(@client_id, "https://evil.example\\@app.example/cb")

      refute ClientIdMetadata.same_origin_redirect_uri?(@client_id, "https://evil.example@app.example/cb")
      refute ClientIdMetadata.same_origin_redirect_uri?(@client_id, "https://evil.example\t@app.example/cb")
    end

    test "refuses an ambiguous client_id as readily as an ambiguous redirect_uri" do
      refute ClientIdMetadata.same_origin_redirect_uri?(
               "https://evil.example\\@app.example/client.json",
               "https://app.example/cb"
             )
    end

    test "refuses a relative or unparseable redirect_uri" do
      refute ClientIdMetadata.same_origin_redirect_uri?(@client_id, "/cb")
      refute ClientIdMetadata.same_origin_redirect_uri?(@client_id, "")
      refute ClientIdMetadata.same_origin_redirect_uri?(@client_id, nil)
    end

    test "refuses a redirect_uri or client_id with a fragment or malformed/out-of-range port" do
      for bad <- [
            "https://app.example/cb#frag",
            "https://app.example/cb#",
            "https://app.example:443xyz/cb",
            "https://app.example:99999/cb",
            "https://app.example:/cb",
            "https://app.example:0/cb"
          ] do
        refute ClientIdMetadata.same_origin_redirect_uri?(@client_id, bad),
               "expected redirect_uri #{inspect(bad)} to be rejected"

        refute ClientIdMetadata.same_origin_redirect_uri?(bad, "https://app.example/cb"),
               "expected client_id #{inspect(bad)} to be rejected"
      end
    end
  end

  describe "loopback_redirect_uri?/2" do
    test "the IP literals are loopback under both modes" do
      for mode <- [:exact_allow_loopback_port, :exact_allow_loopback_port_including_localhost] do
        assert ClientIdMetadata.loopback_redirect_uri?("http://127.0.0.1/cb", mode)
        assert ClientIdMetadata.loopback_redirect_uri?("http://[::1]:8080/cb", mode)
      end
    end

    test "the localhost name is loopback only under the widened mode" do
      refute ClientIdMetadata.loopback_redirect_uri?("http://localhost/cb", :exact_allow_loopback_port)
      refute ClientIdMetadata.loopback_redirect_uri?("http://localhost:3118/cb", :exact_allow_loopback_port)

      assert ClientIdMetadata.loopback_redirect_uri?(
               "http://localhost/cb",
               :exact_allow_loopback_port_including_localhost
             )

      assert ClientIdMetadata.loopback_redirect_uri?(
               "http://localhost:3118/cb",
               :exact_allow_loopback_port_including_localhost
             )
    end

    # The widened mode admits the bare name and nothing near it: the anchored
    # authority the core matcher enforces must reach through the probe.
    test "lookalike hosts and non-http schemes stay outside the widened mode" do
      for uri <- [
            "http://localhost.evil.example/cb",
            "http://sub.localhost/cb",
            "http://evil-localhost/cb",
            "https://localhost/cb",
            "http://127.0.0.2/cb"
          ] do
        refute ClientIdMetadata.loopback_redirect_uri?(uri, :exact_allow_loopback_port_including_localhost),
               "expected #{uri} not to count as loopback"
      end
    end

    test "the default mode is the strict one" do
      assert ClientIdMetadata.loopback_redirect_uri?("http://127.0.0.1/cb")
      refute ClientIdMetadata.loopback_redirect_uri?("http://localhost/cb")
    end
  end

  describe "auth_methods/1 and supported_by_server?/2" do
    alias AttestoPhoenix.Config

    defp server_config(overrides) do
      Keyword.merge(
        [
          issuer: "https://issuer.example",
          audience: "https://api.example.com",
          keystore: TestKeystore,
          repo: TestRepo,
          load_client: fn _ -> {:error, :not_found} end,
          verify_client_secret: fn _, _ -> false end,
          load_principal: fn _ -> {:error, :not_found} end,
          client_id_metadata: [enabled: true]
        ],
        overrides
      )
      |> Config.new()
    end

    test "auth_methods/1 prefers token_endpoint_auth_methods_supported and defaults to none" do
      assert ClientIdMetadata.auth_methods(%{
               "token_endpoint_auth_methods_supported" => ["none", "private_key_jwt"],
               "token_endpoint_auth_method" => "none"
             }) == ["none", "private_key_jwt"]

      assert ClientIdMetadata.auth_methods(%{"token_endpoint_auth_method" => "private_key_jwt"}) ==
               ["private_key_jwt"]

      assert ClientIdMetadata.auth_methods(%{}) == ["none"]
    end

    test "supported_by_server?/2 checks auth methods, grant_types, and response_types intersections" do
      config = server_config(token_endpoint_auth_methods_supported: ["none", "private_key_jwt"])

      assert ClientIdMetadata.supported_by_server?(
               %{
                 "token_endpoint_auth_methods_supported" => ["private_key_jwt"],
                 "grant_types" => ["authorization_code"],
                 "response_types" => ["code"]
               },
               config
             )

      refute ClientIdMetadata.supported_by_server?(
               %{"grant_types" => ["urn:example:unsupported_grant"]},
               config
             )

      refute ClientIdMetadata.supported_by_server?(
               %{"response_types" => ["token"]},
               config
             )

      assert ClientIdMetadata.supported_by_server?(
               %{"token_endpoint_auth_method" => "none"},
               config
             )
    end
  end

  describe "prefetch_logo/3 (draft-03 §10.9)" do
    alias AttestoPhoenix.Config

    setup do
      fc = start_supervised!({FlowControl, []})
      resolver = fn _host, family -> if family == :inet, do: {:ok, [{93, 184, 216, 34}]}, else: {:ok, []} end

      config =
        Config.new(
          issuer: "https://issuer.example",
          audience: "https://api.example.com",
          keystore: TestKeystore,
          repo: TestRepo,
          load_client: fn _ -> {:error, :not_found} end,
          verify_client_secret: fn _, _ -> false end,
          load_principal: fn _ -> {:error, :not_found} end,
          client_id_metadata: [enabled: true, flow_control_server: fc]
        )

      {:ok, config: config, resolver: resolver}
    end

    defp logo_plug(status, content_type, body) do
      fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type(content_type)
        |> Plug.Conn.send_resp(status, body)
      end
    end

    test "accepts valid PNG, JPEG, GIF, and WebP logos matching content-type and magic bytes", %{
      config: config,
      resolver: resolver
    } do
      samples = [
        {"image/png", <<137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13>>},
        {"image/jpeg", <<0xFF, 0xD8, 0xFF, 0xE0, 0, 16, "JFIF">>},
        {"image/gif", <<"GIF89a", 1, 0, 1, 0>>},
        {"image/webp", <<"RIFF", 12, 0, 0, 0, "WEBP", "VP8 ">>}
      ]

      for {mime, bytes} <- samples do
        url = "https://app.example/logo/#{System.unique_integer([:positive])}"

        assert {:ok, %{body: ^bytes, content_type: ^mime}} =
                 ClientIdMetadata.prefetch_logo(url, config,
                   resolver: resolver,
                   req_options: [plug: logo_plug(200, mime, bytes)]
                 )
      end
    end

    test "rejects SVG and spoofed Content-Type payloads", %{config: config, resolver: resolver} do
      svg_url = "https://app.example/logo/#{System.unique_integer([:positive])}.svg"

      assert {:error, :bad_content_type} =
               ClientIdMetadata.prefetch_logo(svg_url, config,
                 resolver: resolver,
                 req_options: [plug: logo_plug(200, "image/svg+xml", "<svg/>")]
               )

      spoof_url = "https://app.example/logo/#{System.unique_integer([:positive])}.png"

      assert {:error, :invalid_image} =
               ClientIdMetadata.prefetch_logo(spoof_url, config,
                 resolver: resolver,
                 req_options: [plug: logo_plug(200, "image/png", "<html>not a png</html>")]
               )
    end

    test "rejects SSRF loopback IPs and oversized logos", %{config: config, resolver: resolver} do
      ssrf_resolver = fn _host, family -> if family == :inet, do: {:ok, [{127, 0, 0, 1}]}, else: {:ok, []} end
      url = "https://app.example/logo/#{System.unique_integer([:positive])}.png"

      assert {:error, {:blocked_ip, {127, 0, 0, 1}}} =
               ClientIdMetadata.prefetch_logo(url, config, resolver: ssrf_resolver)

      assert {:error, :too_large} =
               ClientIdMetadata.prefetch_logo(url, config,
                 resolver: resolver,
                 max_logo_bytes: 8,
                 req_options: [plug: logo_plug(200, "image/png", <<137, 80, 78, 71, 13, 10, 26, 10, 0, 0>>)]
               )
    end
  end
end
