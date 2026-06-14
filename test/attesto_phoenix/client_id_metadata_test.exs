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
end
