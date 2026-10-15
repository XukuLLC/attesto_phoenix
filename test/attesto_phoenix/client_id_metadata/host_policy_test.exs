defmodule AttestoPhoenix.ClientIdMetadata.HostPolicyTest do
  use ExUnit.Case, async: true

  alias AttestoPhoenix.ClientIdMetadata.HostPolicy

  test "Unicode aliases and ASCII names share one canonical host policy" do
    for {alias_host, canonical} <- [
          {"BÜCHER.example.", "xn--bcher-kva.example"},
          {"Ⅷ.example", "viii.example"},
          {"ᴬ.example", "a.example"},
          {"K.example", "k.example"},
          {"𝕃ocalhost", "localhost"},
          {"ⓁⓄⒸⒶⓁⒽⓄⓈⓉ", "localhost"},
          {"example。", "example"}
        ] do
      assert HostPolicy.canonicalize(alias_host) == {:ok, canonical}
      assert HostPolicy.canonicalize(canonical) == {:ok, canonical}
      assert HostPolicy.check(alias_host, blocked_hosts: [canonical]) == {:error, :blocked_host}
      assert HostPolicy.check(canonical, blocked_hosts: [alias_host]) == {:error, :blocked_host}
      assert HostPolicy.check(canonical, allowed_hosts: [alias_host]) == :ok
    end
  end

  test "invalid labels and malformed IDNA fail closed" do
    for host <- [
          "",
          ".example",
          "。example",
          "．example",
          "｡example",
          "\u00AD.example",
          "example..",
          "example。｡",
          "a..example",
          "xn--.example",
          "a_b.example",
          "-label.example",
          "label-.example",
          "ab\u200Dcd.example",
          "\u0301label.example",
          String.duplicate("a", 64) <> ".example",
          Enum.join(List.duplicate(String.duplicate("a", 63), 5), ".")
        ] do
      assert HostPolicy.canonicalize(host) == {:error, :invalid_host}
      assert HostPolicy.check(host, []) == {:error, :blocked_host}
      assert HostPolicy.check("valid.example", blocked_hosts: [host]) == {:error, :blocked_host}
    end
  end

  test "screens special-use literal addresses without requiring the optional HTTP client" do
    for host <- [
          "127.0.0.1",
          "10.0.0.1",
          "169.254.169.254",
          "::1",
          "::ffff:127.0.0.1",
          "64:ff9b:1::1"
        ] do
      assert HostPolicy.special_use_literal?(host), "expected #{host} to be special-use"
    end

    refute HostPolicy.special_use_literal?("93.184.216.34")
    refute HostPolicy.special_use_literal?("2001:4860:4860::8888")
    refute HostPolicy.special_use_literal?("example.com")
  end

  test "blocks the entire local-use NAT64 prefix regardless of the embedding layout" do
    for ip <- [
          {0x0064, 0xFF9B, 0x0001, 0, 0, 0, 0, 1},
          {0x0064, 0xFF9B, 0x0001, 0x1234, 0x5678, 0x9ABC, 0xDEF0, 0x1111},
          {0x0064, 0xFF9B, 0x0001, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF}
        ] do
      assert HostPolicy.special_use_ip?(ip)
    end
  end

  test "formats HTTP authorities with non-default ports and bracketed IPv6" do
    assert HostPolicy.authority(URI.parse("https://app.example/path")) == "app.example"
    assert HostPolicy.authority(URI.parse("https://app.example:8443/path")) == "app.example:8443"
    assert HostPolicy.authority(URI.parse("https://[2001:db8::1]:8443/path")) == "[2001:db8::1]:8443"
  end
end
