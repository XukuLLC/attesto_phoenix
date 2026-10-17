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
