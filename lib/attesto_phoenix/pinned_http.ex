if Code.ensure_loaded?(Mint.HTTP) do
  defmodule AttestoPhoenix.PinnedHTTP do
    @moduledoc false

    @type response :: %{status: non_neg_integer(), headers: [{binary(), binary()}], body: binary()}

    @spec request(
            atom(),
            String.t(),
            String.t(),
            [{binary(), binary()}],
            binary(),
            pos_integer(),
            non_neg_integer() | :discard
          ) ::
            {:ok, response()} | {:error, term()}
    def request(method, pinned_url, hostname, headers, body, timeout_ms, body_limit) when method in [:get, :post] do
      if valid_request?(pinned_url, hostname, headers, body, timeout_ms, body_limit) do
        task =
          Task.async(fn ->
            do_request(method, pinned_url, hostname, headers, body, timeout_ms, body_limit)
          end)

        await_request(task, timeout_ms)
      else
        {:error, :invalid_request}
      end
    end

    # Mint owns its socket through messages delivered to the process which
    # opened the connection. Isolating that process also means an outbound
    # request can neither consume nor reorder messages in its caller's mailbox.
    # Task.yield/2 supplies the outer wall-clock deadline, covering DNS/connect,
    # request transmission, and response receipt together.
    defp await_request(task, timeout_ms) do
      case Task.yield(task, timeout_ms) do
        {:ok, result} ->
          result

        {:exit, reason} ->
          {:error, reason}

        nil ->
          _ = Task.shutdown(task, :brutal_kill)
          {:error, :request_timeout}
      end
    end

    defp do_request(method, pinned_url, hostname, headers, body, timeout_ms, body_limit) do
      started_at = System.monotonic_time(:millisecond)

      with {:ok, uri} <- parse_url(pinned_url),
           {:ok, conn} <- connect(uri, hostname, timeout_ms),
           {:ok, conn, request_ref} <-
             Mint.HTTP.request(conn, method |> Atom.to_string() |> String.upcase(), request_target(uri), headers, body) do
        receive_response(
          conn,
          request_ref,
          started_at,
          timeout_ms,
          body_limit,
          %{status: nil, headers: [], body: ""}
        )
      else
        {:error, reason} -> {:error, reason}
        {:error, conn, reason} -> close_with_error(conn, reason)
      end
    rescue
      exception -> {:error, exception}
    catch
      kind, reason -> {:error, {kind, reason}}
    end

    defp valid_request?(pinned_url, hostname, headers, body, timeout_ms, body_limit) do
      is_binary(pinned_url) and is_binary(hostname) and is_list(headers) and is_binary(body) and
        is_integer(timeout_ms) and timeout_ms > 0 and valid_body_limit?(body_limit)
    end

    defp valid_body_limit?(:discard), do: true
    defp valid_body_limit?(limit), do: is_integer(limit) and limit >= 0

    defp parse_url(url) do
      case URI.new(url) do
        {:ok, %URI{scheme: scheme, host: host, port: port} = uri}
        when scheme in ["http", "https"] and is_binary(host) and host != "" and is_integer(port) ->
          {:ok, uri}

        _ ->
          {:error, :invalid_url}
      end
    end

    defp connect(%URI{scheme: scheme, host: address, port: port}, hostname, timeout_ms) do
      Mint.HTTP.connect(String.to_existing_atom(scheme), address, port,
        hostname: hostname,
        protocols: [:http1],
        transport_opts: [timeout: timeout_ms, send_timeout: timeout_ms]
      )
    end

    defp request_target(%URI{path: path, query: query}) do
      target = if path in [nil, ""], do: "/", else: path
      if is_binary(query), do: target <> "?" <> query, else: target
    end

    defp receive_response(conn, request_ref, started_at, timeout_ms, body_limit, response) do
      remaining = timeout_ms - (System.monotonic_time(:millisecond) - started_at)

      if remaining <= 0 do
        close_with_error(conn, :request_timeout)
      else
        socket = Mint.HTTP.get_socket(conn)

        receive do
          {tag, ^socket, _payload} = message when tag in [:tcp, :ssl, :tcp_error, :ssl_error] ->
            handle_message(conn, message, request_ref, started_at, timeout_ms, body_limit, response)

          {tag, ^socket} = message when tag in [:tcp_closed, :ssl_closed] ->
            handle_message(conn, message, request_ref, started_at, timeout_ms, body_limit, response)
        after
          remaining -> close_with_error(conn, :request_timeout)
        end
      end
    end

    defp handle_message(conn, message, request_ref, started_at, timeout_ms, body_limit, response) do
      case Mint.HTTP.stream(conn, message) do
        {:ok, next_conn, events} ->
          case fold_events(events, request_ref, body_limit, response) do
            {:cont, next_response} ->
              receive_response(next_conn, request_ref, started_at, timeout_ms, body_limit, next_response)

            {:done, completed} ->
              _ = Mint.HTTP.close(next_conn)
              {:ok, completed}

            {:error, reason} ->
              close_with_error(next_conn, reason)
          end

        {:error, next_conn, reason, _events} ->
          close_with_error(next_conn, reason)
      end
    end

    defp fold_events(events, request_ref, body_limit, response) do
      Enum.reduce_while(events, {:cont, response}, fn
        {:status, ^request_ref, status}, {:cont, acc} ->
          {:cont, {:cont, %{acc | status: status}}}

        {:headers, ^request_ref, headers}, {:cont, acc} ->
          {:cont, {:cont, %{acc | headers: acc.headers ++ headers}}}

        {:data, ^request_ref, _data}, {:cont, acc} when body_limit == :discard ->
          {:cont, {:cont, acc}}

        {:data, ^request_ref, data}, {:cont, acc} ->
          body = acc.body <> data

          if byte_size(body) > body_limit do
            {:halt, {:error, :too_large}}
          else
            {:cont, {:cont, %{acc | body: body}}}
          end

        {:done, ^request_ref}, {:cont, acc} ->
          {:halt, {:done, acc}}

        _other, current ->
          {:cont, current}
      end)
    end

    defp close_with_error(conn, reason) do
      _ = Mint.HTTP.close(conn)
      {:error, reason}
    end
  end
end
