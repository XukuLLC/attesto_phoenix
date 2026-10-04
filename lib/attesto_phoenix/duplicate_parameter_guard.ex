defmodule AttestoPhoenix.DuplicateParameterGuard do
  @moduledoc """
  Preserves and validates OAuth request parameters before Phoenix collapses them.

  The raw query string remains available on `Plug.Conn`, so Attesto's protocol
  controllers reject repeated query names automatically.
  URL-encoded and JSON bodies are different: `Plug.Parsers` converts them to a
  map before router dispatch, losing repeated names. Configure this module as
  the endpoint's body reader so the controller can inspect the original bytes:

      plug Plug.Parsers,
        parsers: [:urlencoded, :multipart, :json],
        pass: ["*/*"],
        json_decoder: Phoenix.json_library(),
        body_reader: {AttestoPhoenix.DuplicateParameterGuard, :read_body, []}

  The reader examines the bytes before `Plug.Parsers` collapses them and returns
  every `:more` result unchanged so Plug can enforce its request limit. If
  another caller continues reading, the reader retains chunks up to the
  configured `:length` so names split across a boundary cannot bypass
  validation. It then keeps only the analysis until controller dispatch;
  `validate_and_forget/1` removes that metadata before the action runs.

  RFC 8707 deliberately permits more than one `resource` parameter. Those
  values in URL-encoded input are preserved as a list and passed to Attesto's
  resource-indicator validation. Every other repeated top-level form name is
  rejected. JSON object names must be unique at every nesting level. Bracketed
  form names are compared by their top-level root, so
  `client_id=a&client_id[]=b` cannot evade the check.

  If the host already uses a custom body reader, pass its MFA as the sole extra
  argument:

      body_reader: {
        AttestoPhoenix.DuplicateParameterGuard,
        :read_body,
        [{MyApp.BodyReader, :read_body, []}]
      }
  """

  alias Plug.Conn
  alias Plug.Conn.Unfetched

  @body_analysis_key :attesto_phoenix_duplicate_parameter_analysis
  @body_chunks_key :attesto_phoenix_duplicate_parameter_chunks
  @default_body_length 8_000_000
  @repeatable_roots MapSet.new(["resource"])

  @type reason ::
          {:duplicate_parameter, String.t()}
          | :body_too_large
          | :invalid_parameter_encoding

  @doc """
  A `Plug.Parsers` body reader that checks ambiguity before map conversion.

  It otherwise has the same return contract and read limits as
  `Plug.Conn.read_body/2` (or the optional underlying reader MFA).
  """
  @spec read_body(Conn.t(), keyword()) :: tuple()
  def read_body(%Conn{} = conn, opts), do: read_body(conn, opts, {Conn, :read_body, []})

  @spec read_body(Conn.t(), keyword(), {module(), atom(), list()}) :: tuple()
  def read_body(%Conn{} = conn, opts, {module, function, arguments})
      when is_atom(module) and is_atom(function) and is_list(arguments) do
    format = body_format(conn)

    module
    |> apply(function, [conn, opts | arguments])
    |> cache_body_chunk(format, opts)
  end

  @doc false
  @spec validate_and_forget(Conn.t()) :: {:ok, Conn.t()} | {:error, reason(), Conn.t()}
  def validate_and_forget(%Conn{} = conn) do
    {body_analysis, private} = Map.pop(conn.private, @body_analysis_key)
    private = Map.delete(private, @body_chunks_key)
    conn = %{conn | private: private}

    with :ok <- body_analysis_valid(body_analysis),
         {:ok, query_pairs} <- decode_pairs(conn.query_string),
         {:ok, body_pairs} <- body_pairs(conn, body_analysis),
         :ok <- reject_scalar_duplicates(query_pairs ++ body_pairs) do
      {:ok, preserve_repeatable_parameters(conn, query_pairs, body_pairs)}
    else
      {:error, reason} -> {:error, reason, conn}
    end
  end

  defp cache_body_chunk({:more, body, %Conn{} = conn}, format, opts) when is_binary(body) do
    conn = cache_incomplete_body(conn, format, body, opts)

    {:more, body, conn}
  end

  defp cache_body_chunk({:ok, body, %Conn{} = conn}, format, _opts) when is_binary(body) do
    {cached_body, private} = Map.pop(conn.private, @body_chunks_key)
    conn = %{conn | private: private}

    conn =
      if Map.has_key?(conn.private, @body_analysis_key) do
        conn
      else
        cached_body
        |> finish_body(format, body)
        |> cache_body_analysis(conn)
      end

    {:ok, body, conn}
  end

  defp cache_body_chunk(other, _format, _opts), do: other

  defp cache_incomplete_body(conn, format, body, opts) do
    cond do
      Map.has_key?(conn.private, @body_analysis_key) ->
        %{conn | private: Map.delete(conn.private, @body_chunks_key)}

      cached_body = conn.private[@body_chunks_key] ->
        %{conn | private: Map.put(conn.private, @body_chunks_key, append_chunk(cached_body, body))}

      analyzable_format?(format) ->
        cached_body = new_cached_body(format, body, opts)
        %{conn | private: Map.put(conn.private, @body_chunks_key, cached_body)}

      true ->
        conn
    end
  end

  defp new_cached_body(format, body, opts) do
    limit = body_length_limit(opts)

    if byte_size(body) <= limit do
      {:chunks, format, byte_size(body), limit, [body]}
    else
      {:too_large, format}
    end
  end

  defp append_chunk({:too_large, format}, _body), do: {:too_large, format}

  defp append_chunk({:chunks, format, size, limit, chunks}, body) do
    new_size = size + byte_size(body)

    if new_size <= limit do
      {:chunks, format, new_size, limit, [body | chunks]}
    else
      {:too_large, format}
    end
  end

  defp finish_body({:too_large, _format}, _current_format, _body), do: {:error, :body_too_large}

  defp finish_body({:chunks, format, size, limit, chunks}, _current_format, body) do
    if size + byte_size(body) <= limit do
      complete_body = IO.iodata_to_binary(Enum.reverse([body | chunks]))
      inspect_body(format, complete_body)
    else
      {:error, :body_too_large}
    end
  end

  defp finish_body(nil, format, body), do: inspect_body(format, body)

  defp cache_body_analysis({:ok, nil}, conn), do: conn

  defp cache_body_analysis({:ok, analysis}, conn) do
    %{conn | private: Map.put(conn.private, @body_analysis_key, analysis)}
  end

  defp cache_body_analysis({:error, reason}, conn) do
    # The endpoint body reader also runs for host application routes. Keep
    # only an error marker here; Attesto's controller dispatch enforces it,
    # while unrelated controllers retain their existing form semantics.
    analysis = %{error: reason}
    %{conn | private: Map.put(conn.private, @body_analysis_key, analysis)}
  end

  defp body_length_limit(opts) do
    case Keyword.get(opts, :length, @default_body_length) do
      limit when is_integer(limit) and limit >= 0 -> limit
      _invalid -> @default_body_length
    end
  end

  defp inspect_body(:urlencoded, body), do: inspect_urlencoded_body(body)
  defp inspect_body(:json, body), do: reject_json_duplicates(body)
  defp inspect_body(nil, _body), do: {:ok, nil}

  defp inspect_urlencoded_body(body) do
    body
    |> URI.query_decoder()
    |> Enum.reduce_while(
      {:ok, MapSet.new(), MapSet.new(), []},
      fn {encoded_key, value}, {:ok, keys, scalar_keys, resources} ->
        key = parameter_root(encoded_key)
        keys = MapSet.put(keys, key)

        cond do
          MapSet.member?(@repeatable_roots, key) ->
            {:cont, {:ok, keys, scalar_keys, [value | resources]}}

          MapSet.member?(scalar_keys, key) ->
            {:halt, {:error, {:duplicate_parameter, key}}}

          true ->
            {:cont, {:ok, keys, MapSet.put(scalar_keys, key), resources}}
        end
      end
    )
    |> case do
      {:ok, keys, _scalar_keys, resources} ->
        {:ok, %{format: :urlencoded, keys: keys, resources: Enum.reverse(resources)}}

      {:error, _reason} = error ->
        error
    end
  rescue
    ArgumentError -> {:error, :invalid_parameter_encoding}
  end

  defp body_pairs(_conn, %{format: :urlencoded, keys: keys, resources: resources}) do
    pairs =
      Enum.map(keys, fn
        "resource" -> %{key: "resource", value: resources}
        key -> %{key: key, value: nil}
      end)

    {:ok, pairs}
  end

  defp body_pairs(conn, nil) do
    if urlencoded?(conn) do
      {:ok, pairs_from_parsed_form(conn.body_params)}
    else
      {:ok, pairs_from_parsed_body(conn.body_params)}
    end
  end

  defp body_pairs(conn, _unknown_analysis) do
    if urlencoded?(conn) do
      {:ok, pairs_from_parsed_form(conn.body_params)}
    else
      {:ok, pairs_from_parsed_body(conn.body_params)}
    end
  end

  defp body_analysis_valid(%{error: reason}), do: {:error, reason}
  defp body_analysis_valid(_analysis), do: :ok

  defp decode_pairs(nil), do: {:ok, []}

  defp decode_pairs(encoded) when is_binary(encoded) do
    pairs =
      encoded
      |> URI.query_decoder()
      |> Enum.map(fn {key, value} -> %{key: parameter_root(key), value: value} end)

    {:ok, pairs}
  rescue
    ArgumentError -> {:error, :invalid_parameter_encoding}
  end

  defp pairs_from_parsed_body(%Unfetched{}), do: []

  defp pairs_from_parsed_body(params) when is_map(params) do
    Enum.flat_map(params, fn
      {key, value} when is_binary(key) ->
        [%{key: parameter_root(key), value: value}]

      _other ->
        []
    end)
  end

  defp pairs_from_parsed_body(_params), do: []

  defp pairs_from_parsed_form(%Unfetched{}), do: []

  defp pairs_from_parsed_form(params) when is_map(params) do
    Enum.flat_map(params, fn
      {"resource", values} when is_list(values) ->
        [%{key: "resource", value: values}]

      {key, values} when is_binary(key) and is_list(values) ->
        # Without the body-reader integration, Plug's bracket syntax is the one
        # case that still exposes multiplicity. Count its members so a scalar
        # protocol parameter cannot bypass the guard by becoming a list.
        case values do
          [] -> [%{key: parameter_root(key), value: values}]
          _ -> Enum.map(values, &%{key: parameter_root(key), value: &1})
        end

      {key, value} when is_binary(key) ->
        [%{key: parameter_root(key), value: value}]

      _other ->
        []
    end)
  end

  defp pairs_from_parsed_form(_params), do: []

  defp reject_json_duplicates(body) do
    decoders = [
      array_start: fn _old_acc -> nil end,
      array_push: &merge_json_duplicate/2,
      array_finish: fn duplicate, old_acc -> {duplicate, old_acc} end,
      object_start: fn _old_acc -> {MapSet.new(), nil} end,
      object_push: &inspect_json_object_member/3,
      object_finish: fn {_keys, duplicate}, old_acc -> {duplicate, old_acc} end,
      float: fn _encoded -> nil end,
      integer: fn _encoded -> nil end
    ]

    case JSON.decode(body, nil, decoders) do
      {{:duplicate_parameter, _key} = reason, nil, ""} ->
        {:error, reason}

      {_decoded, nil, ""} ->
        {:ok, nil}

      # Leave ordinary JSON syntax errors to the configured Plug decoder. This
      # reader is responsible only for ambiguity, and a host may use a decoder
      # with options that differ from Elixir's built-in JSON module.
      {:error, _reason} ->
        {:ok, nil}

      _other ->
        {:ok, nil}
    end
  rescue
    ArgumentError -> {:ok, nil}
  end

  defp inspect_json_object_member(_key, _value, {keys, duplicate}) when not is_nil(duplicate) do
    {keys, duplicate}
  end

  defp inspect_json_object_member(key, value, {keys, nil}) do
    cond do
      MapSet.member?(keys, key) ->
        {keys, {:duplicate_parameter, key}}

      match?({:duplicate_parameter, _key}, value) ->
        {keys, value}

      true ->
        {MapSet.put(keys, key), nil}
    end
  end

  defp merge_json_duplicate(_value, {:duplicate_parameter, _key} = duplicate), do: duplicate
  defp merge_json_duplicate({:duplicate_parameter, _key} = duplicate, nil), do: duplicate
  defp merge_json_duplicate(_value, nil), do: nil

  defp reject_scalar_duplicates(pairs) do
    pairs
    |> Enum.reduce_while(MapSet.new(), fn %{key: key}, seen ->
      cond do
        MapSet.member?(@repeatable_roots, key) ->
          {:cont, seen}

        MapSet.member?(seen, key) ->
          {:halt, {:error, {:duplicate_parameter, key}}}

        true ->
          {:cont, MapSet.put(seen, key)}
      end
    end)
    |> case do
      {:error, _reason} = error -> error
      %MapSet{} -> :ok
    end
  end

  defp preserve_repeatable_parameters(conn, query_pairs, body_pairs) do
    query_resources = resource_values(query_pairs)
    body_resources = resource_values(body_pairs)
    resources = query_resources ++ body_resources

    conn
    |> put_param_values(:query_params, query_resources)
    |> put_param_values(:body_params, body_resources)
    |> put_param_values(:params, resources)
  end

  defp resource_values(pairs) do
    Enum.flat_map(pairs, fn
      %{key: "resource", value: values} when is_list(values) -> values
      %{key: "resource", value: value} -> [value]
      _other -> []
    end)
  end

  defp put_param_values(conn, _field, []), do: conn

  defp put_param_values(conn, field, values) do
    case Map.fetch!(conn, field) do
      %Unfetched{} -> conn
      params when is_map(params) -> Map.put(conn, field, Map.put(params, "resource", scalar_or_list(values)))
    end
  end

  defp scalar_or_list([value]), do: value
  defp scalar_or_list(values), do: values

  defp parameter_root(key) do
    case :binary.match(key, "[") do
      {position, _length} -> binary_part(key, 0, position)
      :nomatch -> key
    end
  end

  defp urlencoded?(conn), do: body_format(conn) == :urlencoded

  defp analyzable_format?(format), do: format in [:urlencoded, :json]

  defp body_format(conn) do
    conn
    |> media_type()
    |> case do
      "application/x-www-form-urlencoded" -> :urlencoded
      "application/json" -> :json
      value when is_binary(value) -> if String.ends_with?(value, "+json"), do: :json
      nil -> nil
    end
  end

  defp media_type(conn) do
    conn
    |> Conn.get_req_header("content-type")
    |> List.first()
    |> case do
      nil ->
        nil

      value ->
        value
        |> String.split(";", parts: 2)
        |> hd()
        |> String.trim()
        |> String.downcase()
    end
  end
end
