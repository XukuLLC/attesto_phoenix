defmodule AttestoPhoenix.PinnedHTTPTest do
  use ExUnit.Case, async: false

  alias AttestoPhoenix.PinnedHTTP
  alias AttestoPhoenix.TestHTTPServer

  test "uses a one-shot pinned connection without consuming caller messages" do
    server = TestHTTPServer.open()

    TestHTTPServer.expect_once(server, "GET", "/document", fn conn ->
      assert Plug.Conn.get_req_header(conn, "host") == ["client.example"]
      Process.sleep(50)
      Plug.Conn.resp(conn, 200, "document")
    end)

    send(self(), :before_request)
    Process.send_after(self(), :during_request, 10)

    assert {:ok, %{status: 200, body: "document"}} =
             PinnedHTTP.request(
               :get,
               "http://127.0.0.1:#{server.port}/document",
               "client.example",
               [{"host", "client.example"}],
               "",
               1_000,
               64
             )

    assert_receive :before_request
    assert_receive :during_request
  end

  test "enforces a total request deadline" do
    server = TestHTTPServer.open()

    TestHTTPServer.expect_once(server, "GET", "/slow", fn conn ->
      Process.sleep(500)
      Plug.Conn.resp(conn, 200, "late")
    end)

    assert {:error, :request_timeout} =
             PinnedHTTP.request(
               :get,
               "http://127.0.0.1:#{server.port}/slow",
               "client.example",
               [{"host", "client.example"}],
               "",
               200,
               64
             )
  end

  test "dials a target whose screened address is IPv6 only" do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, :inet6, ip: {0, 0, 0, 0, 0, 0, 0, 1}, active: false, reuseaddr: true])

    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, port} = :inet.port(listener)
    test_pid = self()

    spawn_link(fn ->
      {:ok, socket} = :gen_tcp.accept(listener, 2_000)
      {:ok, request} = :gen_tcp.recv(socket, 0, 2_000)
      send(test_pid, {:request, request})
      :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
      :gen_tcp.close(socket)
    end)

    resolver = fn
      _host, :inet -> {:error, :nxdomain}
      _host, :inet6 -> {:ok, [{0, 0, 0, 0, 0, 0, 0, 1}]}
    end

    assert {:ok, screened} =
             AttestoPhoenix.SSRFGuard.screen("http://v6only.example:#{port}/doc",
               resolver: resolver,
               allow_loopback: true
             )

    assert screened.url == "http://[::1]:#{port}/doc"

    assert {:ok, %{status: 200, body: "ok"}} =
             PinnedHTTP.request(:get, screened.url, screened.host, [{"host", screened.authority}], "", 2_000, 64)

    assert_receive {:request, request}
    assert request =~ "host: v6only.example:#{port}"
  end

  test "stops collecting an oversized response" do
    server = TestHTTPServer.open()

    TestHTTPServer.expect_once(server, "GET", "/large", fn conn ->
      Plug.Conn.resp(conn, 200, "too large")
    end)

    assert {:error, :too_large} =
             PinnedHTTP.request(
               :get,
               "http://127.0.0.1:#{server.port}/large",
               "client.example",
               [{"host", "client.example"}],
               "",
               1_000,
               3
             )
  end
end
