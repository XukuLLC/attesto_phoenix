defmodule AttestoPhoenix.DuplicateParameterGuardTest do
  use ExUnit.Case, async: true

  import Plug.Conn

  alias AttestoPhoenix.DuplicateParameterGuard
  alias Plug.Conn.WrapperError
  alias Plug.Parsers.RequestTooLargeError

  defmodule ProbeController do
    use AttestoPhoenix.Controller, formats: [:json]

    def show(conn, _params), do: Plug.Conn.send_resp(conn, 204, "")
  end

  defmodule ChunkedReader do
    @moduledoc false

    def put_chunks(conn, chunks), do: Plug.Conn.put_private(conn, __MODULE__, chunks)

    def read_body(conn, _opts) do
      case Map.fetch!(conn.private, __MODULE__) do
        [last] -> {:ok, last, drop_chunks(conn)}
        [chunk | rest] -> {:more, chunk, Plug.Conn.put_private(conn, __MODULE__, rest)}
      end
    end

    defp drop_chunks(conn) do
      %{conn | private: Map.delete(conn.private, __MODULE__)}
    end
  end

  defp parse_form(conn, body_reader \\ {DuplicateParameterGuard, :read_body, []}) do
    opts =
      Plug.Parsers.init(
        parsers: [:urlencoded],
        pass: ["*/*"],
        body_reader: body_reader
      )

    Plug.Parsers.call(conn, opts)
  end

  defp parse_json(conn, body_reader \\ {DuplicateParameterGuard, :read_body, []}) do
    opts =
      Plug.Parsers.init(
        parsers: [:json],
        pass: ["*/*"],
        json_decoder: JSON,
        body_reader: body_reader
      )

    Plug.Parsers.call(conn, opts)
  end

  test "controller dispatch rejects duplicate query parameters before map collapse" do
    conn =
      Plug.Test.conn(
        :get,
        "/oauth/authorize?client_id=first&client%5Fid=second&response_type=code"
      )
      |> fetch_query_params()

    error = assert_raise WrapperError, fn -> ProbeController.call(conn, :show) end
    assert %Plug.BadRequestError{message: "request contains an ambiguous parameter"} = error.reason
  end

  test "configured body reader rejects duplicate form parameters before map conversion" do
    conn =
      Plug.Test.conn(
        :post,
        "/oauth/token",
        "grant_type=authorization_code&code=first&co%64e=second"
      )
      |> put_req_header("content-type", "application/x-www-form-urlencoded")
      |> parse_form()

    # Endpoint parsing still succeeds so the body reader does not alter other
    # host routes. Attesto controller dispatch consumes and enforces the marker.
    assert {:error, {:duplicate_parameter, "code"}, cleaned} =
             DuplicateParameterGuard.validate_and_forget(conn)

    refute Map.has_key?(cleaned.private, :attesto_phoenix_duplicate_parameter_analysis)
  end

  test "rejects ambiguity across query and body parameter sources" do
    conn =
      Plug.Test.conn(:post, "/oauth/token?client_id=query-client", "client_id=body-client")
      |> put_req_header("content-type", "application/x-www-form-urlencoded; charset=utf-8")
      |> parse_form()

    assert {:error, {:duplicate_parameter, "client_id"}, _cleaned} =
             DuplicateParameterGuard.validate_and_forget(conn)
  end

  test "configured body reader rejects duplicate JSON object names" do
    conn =
      Plug.Test.conn(
        :post,
        "/oauth/register",
        ~s({"redirect_uris":["https://client.example/cb"],"metadata":{"name":"first","name":"second"}})
      )
      |> put_req_header("content-type", "application/json")

    parsed = parse_json(conn)

    assert {:error, {:duplicate_parameter, "name"}, _cleaned} =
             DuplicateParameterGuard.validate_and_forget(parsed)
  end

  test "detects duplicate form names split across body-reader chunks" do
    reader = {ChunkedReader, :read_body, []}

    conn =
      Plug.Test.conn(:post, "/oauth/token", "")
      |> put_req_header("content-type", "application/x-www-form-urlencoded")
      |> ChunkedReader.put_chunks(["code=first&", "co%64e=second"])

    assert {:more, "code=first&", conn} = DuplicateParameterGuard.read_body(conn, [], reader)
    assert {:ok, "co%64e=second", conn} = DuplicateParameterGuard.read_body(conn, [], reader)

    assert {:error, {:duplicate_parameter, "code"}, cleaned} =
             DuplicateParameterGuard.validate_and_forget(conn)

    refute Map.has_key?(cleaned.private, :attesto_phoenix_duplicate_parameter_chunks)
  end

  test "detects duplicate JSON names split across body-reader chunks" do
    reader = {ChunkedReader, :read_body, []}

    conn =
      Plug.Test.conn(:post, "/oauth/register", "")
      |> put_req_header("content-type", "application/json")
      |> ChunkedReader.put_chunks([~s({"metadata":{"name":"first",), ~s("name":"second"}})])

    assert {:more, ~s({"metadata":{"name":"first",), conn} =
             DuplicateParameterGuard.read_body(conn, [], reader)

    assert {:ok, ~s("name":"second"}}), conn} =
             DuplicateParameterGuard.read_body(conn, [], reader)

    assert {:error, {:duplicate_parameter, "name"}, cleaned} =
             DuplicateParameterGuard.validate_and_forget(conn)

    refute Map.has_key?(cleaned.private, :attesto_phoenix_duplicate_parameter_chunks)
  end

  test "preserves :more so Plug.Parsers enforces its request length" do
    reader = {DuplicateParameterGuard, :read_body, [{ChunkedReader, :read_body, []}]}

    conn =
      Plug.Test.conn(:post, "/oauth/token", "")
      |> put_req_header("content-type", "application/x-www-form-urlencoded")
      |> ChunkedReader.put_chunks(["code=first&", "code=second"])

    assert_raise RequestTooLargeError, fn -> parse_form(conn, reader) end
  end

  test "keeps the first completed form analysis if the body is read again" do
    body = "client_id=first&client_id=second"

    conn =
      Plug.Test.conn(:post, "/oauth/token", body)
      |> put_req_header("content-type", "application/x-www-form-urlencoded")

    assert {:ok, ^body, conn} = DuplicateParameterGuard.read_body(conn, [])
    assert {:ok, "", conn} = DuplicateParameterGuard.read_body(conn, [])

    assert {:error, {:duplicate_parameter, "client_id"}, _cleaned} =
             DuplicateParameterGuard.validate_and_forget(conn)
  end

  test "forgets incomplete raw chunks before controller dispatch" do
    reader = {ChunkedReader, :read_body, []}

    conn =
      Plug.Test.conn(:post, "/oauth/token", "")
      |> put_req_header("content-type", "application/x-www-form-urlencoded")
      |> ChunkedReader.put_chunks(["code=first&", "code=second"])

    assert {:more, "code=first&", conn} = DuplicateParameterGuard.read_body(conn, [], reader)
    assert Map.has_key?(conn.private, :attesto_phoenix_duplicate_parameter_chunks)

    assert {:ok, cleaned} = DuplicateParameterGuard.validate_and_forget(conn)
    refute Map.has_key?(cleaned.private, :attesto_phoenix_duplicate_parameter_chunks)
  end

  test "bounds retained chunks by the configured body length" do
    reader = {ChunkedReader, :read_body, []}

    conn =
      Plug.Test.conn(:post, "/oauth/token", "")
      |> put_req_header("content-type", "application/x-www-form-urlencoded")
      |> ChunkedReader.put_chunks(["client_id=", "first"])

    assert {:more, "client_id=", conn} =
             DuplicateParameterGuard.read_body(conn, [length: 10], reader)

    assert {:ok, "first", conn} =
             DuplicateParameterGuard.read_body(conn, [length: 10], reader)

    assert {:error, :body_too_large, cleaned} =
             DuplicateParameterGuard.validate_and_forget(conn)

    refute Map.has_key?(cleaned.private, :attesto_phoenix_duplicate_parameter_chunks)
  end

  test "uses the initial content type for a body completed across reads" do
    reader = {ChunkedReader, :read_body, []}

    conn =
      Plug.Test.conn(:post, "/oauth/token", "")
      |> put_req_header("content-type", "application/x-www-form-urlencoded")
      |> ChunkedReader.put_chunks(["code=first&", "code=second"])

    assert {:more, "code=first&", conn} = DuplicateParameterGuard.read_body(conn, [], reader)
    conn = delete_req_header(conn, "content-type")
    assert {:ok, "code=second", conn} = DuplicateParameterGuard.read_body(conn, [], reader)

    assert {:error, {:duplicate_parameter, "code"}, _cleaned} =
             DuplicateParameterGuard.validate_and_forget(conn)
  end

  test "treats nested-name syntax as the same top-level scalar parameter" do
    conn =
      Plug.Test.conn(:get, "/oauth/authorize?state=first&state%5B%5D=second")
      |> fetch_query_params()

    assert {:error, {:duplicate_parameter, "state"}, _cleaned} =
             DuplicateParameterGuard.validate_and_forget(conn)
  end

  test "preserves RFC 8707 repeated resource indicators instead of collapsing them" do
    a = "https://a.example/api"
    b = "https://b.example/api"

    body =
      URI.encode_query([
        {"grant_type", "client_credentials"},
        {"resource", a},
        {"resource", b}
      ])

    conn =
      Plug.Test.conn(:post, "/oauth/token", body)
      |> put_req_header("content-type", "application/x-www-form-urlencoded")
      |> parse_form()

    assert {:ok, guarded} = DuplicateParameterGuard.validate_and_forget(conn)
    assert guarded.body_params["resource"] == [a, b]
    assert guarded.params["resource"] == [a, b]
    refute Map.has_key?(guarded.private, :attesto_phoenix_duplicate_parameter_analysis)
  end

  test "keeps distinct scalar parameters unchanged" do
    conn =
      Plug.Test.conn(:post, "/oauth/token?trace=one", "grant_type=client_credentials&scope=read")
      |> put_req_header("content-type", "application/x-www-form-urlencoded")
      |> parse_form()

    assert {:ok, guarded} = DuplicateParameterGuard.validate_and_forget(conn)
    assert guarded.params["grant_type"] == "client_credentials"
    assert guarded.params["scope"] == "read"
    assert guarded.params["trace"] == "one"
  end
end
