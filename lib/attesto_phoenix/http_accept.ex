defmodule AttestoPhoenix.HTTPAccept do
  @moduledoc false

  alias Plug.Conn.Utils

  @qvalue ~r/\A(?:0(?:\.[0-9]{0,3})?|1(?:\.0{0,3})?)\z/

  @spec accepts?([binary()], binary()) :: boolean()
  def accepts?(headers, expected_media_type) when is_list(headers) and is_binary(expected_media_type) do
    case Utils.media_type(expected_media_type) do
      {:ok, expected_type, expected_subtype, %{}} ->
        Enum.any?(headers, &header_accepts?(&1, expected_type, expected_subtype))

      _invalid ->
        false
    end
  end

  def accepts?(_headers, _expected_media_type), do: false

  defp header_accepts?(header, expected_type, expected_subtype) when is_binary(header) do
    case split_quoted(header, ?,) do
      {:ok, ranges} ->
        Enum.any?(ranges, &range_accepts?(&1, expected_type, expected_subtype))

      :error ->
        false
    end
  rescue
    _error -> false
  catch
    _kind, _reason -> false
  end

  defp header_accepts?(_header, _expected_type, _expected_subtype), do: false

  defp range_accepts?(range, expected_type, expected_subtype) do
    case parse_range(range) do
      {:ok, ^expected_type, ^expected_subtype, quality} when quality > 0.0 -> true
      _other -> false
    end
  end

  defp parse_range(range) do
    with {:ok, [media_type | params]} <- split_quoted(range, ?;),
         media_type when media_type != "" <- String.trim(media_type),
         {:ok, type, subtype, %{}} <- Utils.media_type(media_type),
         {:ok, quality} <- quality(params) do
      {:ok, type, subtype, quality}
    else
      _invalid -> :error
    end
  end

  defp quality(params) do
    params
    |> Enum.reduce_while({:ok, 1.0, false}, &reduce_quality/2)
    |> quality_result()
  end

  defp reduce_quality(raw_param, {:ok, quality, seen_q?}) do
    raw_param
    |> String.trim()
    |> reduce_quality_parameter(quality, seen_q?)
  end

  defp reduce_quality_parameter("", _quality, _seen_q?), do: {:halt, :error}

  defp reduce_quality_parameter(param, quality, seen_q?) do
    cond do
      q_parameter?(param) -> reduce_q_parameter(param, seen_q?)
      seen_q? -> continue_if_valid(param, quality, seen_q?, &valid_accept_extension?/1)
      true -> continue_if_valid(param, quality, seen_q?, &valid_parameter?/1)
    end
  end

  defp reduce_q_parameter(_param, true), do: {:halt, :error}

  defp reduce_q_parameter(param, false) do
    case parse_q_parameter(param) do
      {:ok, parsed} -> {:cont, {:ok, parsed, true}}
      :error -> {:halt, :error}
    end
  end

  defp continue_if_valid(param, quality, seen_q?, validator) do
    if validator.(param) do
      {:cont, {:ok, quality, seen_q?}}
    else
      {:halt, :error}
    end
  end

  defp quality_result({:ok, quality, _seen_q?}), do: {:ok, quality}
  defp quality_result(:error), do: :error

  defp q_parameter?(param) do
    param
    |> String.split("=", parts: 2)
    |> List.first()
    |> String.trim()
    |> String.downcase()
    |> Kernel.==("q")
  end

  defp parse_q_parameter(param) do
    with [_name, value] <- String.split(param, "=", parts: 2),
         value = String.trim(value),
         true <- Regex.match?(@qvalue, value),
         {quality, ""} <- Float.parse(normalize_qvalue(value)) do
      {:ok, quality}
    else
      _invalid -> :error
    end
  end

  defp normalize_qvalue(value) do
    if String.ends_with?(value, "."), do: value <> "0", else: value
  end

  defp valid_parameter?(param), do: map_size(Utils.params(param)) == 1

  defp valid_accept_extension?(param) do
    valid_parameter?(param) or valid_token?(param)
  end

  defp valid_token?(value), do: Utils.token(value) not in [false, ""]

  defp split_quoted(value, separator) when is_binary(value) do
    do_split_quoted(value, separator, false, false, <<>>, [])
  end

  defp do_split_quoted(<<>>, _separator, false, false, current, acc), do: {:ok, Enum.reverse([current | acc])}

  defp do_split_quoted(<<>>, _separator, _quoted?, _escaped?, _current, _acc), do: :error

  defp do_split_quoted(<<char, rest::binary>>, separator, true, true, current, acc),
    do: do_split_quoted(rest, separator, true, false, <<current::binary, char>>, acc)

  defp do_split_quoted(<<?\\, rest::binary>>, separator, true, false, current, acc),
    do: do_split_quoted(rest, separator, true, true, <<current::binary, ?\\>>, acc)

  defp do_split_quoted(<<?\", rest::binary>>, separator, quoted?, false, current, acc),
    do: do_split_quoted(rest, separator, not quoted?, false, <<current::binary, ?\">>, acc)

  defp do_split_quoted(<<separator, rest::binary>>, separator, false, false, current, acc),
    do: do_split_quoted(rest, separator, false, false, <<>>, [current | acc])

  defp do_split_quoted(<<char, rest::binary>>, separator, quoted?, false, current, acc),
    do: do_split_quoted(rest, separator, quoted?, false, <<current::binary, char>>, acc)
end
