defmodule AttestoPhoenix.ClientIdMetadataTest do
  use ExUnit.Case, async: true

  alias AttestoPhoenix.ClientIdMetadata

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
end
