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
end
