defmodule AttestoPhoenix.SSRFGuardTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias AttestoPhoenix.SSRFGuard

  defp resolver(ips, family \\ :inet) do
    fn _host, fam -> if fam == family, do: {:ok, ips}, else: {:ok, []} end
  end

  @url "https://rp.example/backchannel"

  test "pins a public IP: url rewritten to the checked address, host preserved" do
    assert {:ok, %{url: url, host: "rp.example", authority: "rp.example"}} =
             SSRFGuard.screen(@url, resolver: resolver([{93, 184, 216, 34}]))

    # The socket targets the checked IP; SNI/cert/Host are carried on the host
    # separately by the caller (connect_options[:hostname] + Host header).
    assert url == "https://93.184.216.34/backchannel"
  end

  test "preserves a non-default port in the Host authority (not just the host)" do
    assert {:ok, %{url: url, host: "rp.example", authority: "rp.example:8443"}} =
             SSRFGuard.screen("https://rp.example:8443/logout", resolver: resolver([{93, 184, 216, 34}]))

    assert url == "https://93.184.216.34:8443/logout"
  end

  test "brackets a pinned IPv6 address in the URL" do
    assert {:ok, %{url: url}} =
             SSRFGuard.screen(@url,
               resolver: resolver([{0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25C8, 0x1946}], :inet6)
             )

    assert url == "https://[2606:2800:220:1:248:1893:25c8:1946]/backchannel"
  end

  test "blocks the newly-added IPv6 special-purpose ranges (benchmarking, SRv6, discard, doc)" do
    for ip <- [
          {0x2001, 0x0002, 0, 0, 0, 0, 0, 1},
          {0x5F00, 0, 0, 0, 0, 0, 0, 1},
          {0x0100, 0, 0, 0, 0, 0, 0, 1},
          {0x3FFF, 0, 0, 0, 0, 0, 0, 1}
        ] do
      assert {:error, {:blocked_ip, _}} = SSRFGuard.screen(@url, resolver: resolver([ip], :inet6)),
             "expected #{inspect(ip)} to be blocked"
    end
  end

  test "blocks link-local / cloud-metadata, private, and loopback addresses" do
    for ip <- [{169, 254, 169, 254}, {10, 1, 2, 3}, {127, 0, 0, 1}, {0, 0, 0, 0}, {100, 100, 0, 1}] do
      assert {:error, {:blocked_ip, ^ip}} = SSRFGuard.screen(@url, resolver: resolver([ip])),
             "expected #{inspect(ip)} to be blocked"
    end
  end

  test "blocks an internal IPv6 address (and its IPv4-mapped form)" do
    assert {:error, {:blocked_ip, _}} = SSRFGuard.screen(@url, resolver: resolver([{0, 0, 0, 0, 0, 0, 0, 1}], :inet6))
    mapped = {0, 0, 0, 0, 0, 0xFFFF, 0xA01, 0x0203}
    assert {:error, {:blocked_ip, _}} = SSRFGuard.screen(@url, resolver: resolver([mapped], :inet6))
  end

  test "a mixed answer with any internal address is rejected" do
    resolver = fn _host, fam ->
      case fam do
        :inet -> {:ok, [{93, 184, 216, 34}]}
        :inet6 -> {:ok, [{0, 0, 0, 0, 0, 0, 0, 1}]}
      end
    end

    assert {:error, {:blocked_ip, _}} = SSRFGuard.screen(@url, resolver: resolver)
  end

  test "rejects non-https and unresolvable hosts" do
    assert {:error, :insecure_or_hostless_url} =
             SSRFGuard.screen("http://rp.example/cb", resolver: resolver([{93, 184, 216, 34}]))

    assert {:error, :unresolvable} =
             SSRFGuard.screen(@url, resolver: fn _host, _fam -> {:ok, []} end)
  end

  test "allow_loopback permits http + loopback but nothing else" do
    assert {:ok, %{url: "http://127.0.0.1/cb"}} =
             SSRFGuard.screen("http://local.test/cb", resolver: resolver([{127, 0, 0, 1}]), allow_loopback: true)

    # IPv4-mapped loopback is also exempted under the escape hatch.
    assert {:ok, _} =
             SSRFGuard.screen("http://local.test/cb",
               resolver: resolver([{0, 0, 0, 0, 0, 0xFFFF, 0x7F00, 0x0001}], :inet6),
               allow_loopback: true
             )

    # Other special-use ranges stay blocked even with the escape hatch on.
    assert {:error, {:blocked_ip, {169, 254, 169, 254}}} =
             SSRFGuard.screen(@url, resolver: resolver([{169, 254, 169, 254}]), allow_loopback: true)
  end

  test "a truthy non-boolean cannot enable the loopback exception" do
    for invalid <- ["false", 1, {:error, :unavailable}] do
      assert_raise ArgumentError, ~r/:allow_loopback must be true or false/, fn ->
        SSRFGuard.screen("http://local.test/cb",
          resolver: resolver([{127, 0, 0, 1}]),
          allow_loopback: invalid
        )
      end
    end
  end
end
