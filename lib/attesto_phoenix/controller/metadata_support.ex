defmodule AttestoPhoenix.Controller.MetadataSupport do
  @moduledoc false

  import Plug.Conn, only: [put_resp_header: 3]

  @protocol_config_key :attesto_protocol_config

  @spec protocol_config!(Plug.Conn.t(), module()) :: Attesto.Config.t()
  def protocol_config!(conn, caller) when is_atom(caller) do
    case conn.private do
      %{@protocol_config_key => %Attesto.Config{} = config} ->
        config

      _ ->
        raise "#{inspect(caller)}: no %Attesto.Config{} found in " <>
                "conn.private[#{inspect(@protocol_config_key)}]; wire the host pipeline that assigns it"
    end
  end

  @spec put_public_cache(Plug.Conn.t(), non_neg_integer()) :: Plug.Conn.t()
  def put_public_cache(conn, max_age_seconds) when is_integer(max_age_seconds) and max_age_seconds >= 0 do
    put_resp_header(conn, "cache-control", "public, max-age=#{max_age_seconds}")
  end
end
