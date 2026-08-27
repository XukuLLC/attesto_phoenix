defmodule AttestoPhoenix.Plug.PutConfig do
  @moduledoc """
  Loads the host's validated Attesto configuration into `conn.private`.

  AttestoPhoenix controllers use two immutable configuration values:

    * `%AttestoPhoenix.Config{}` under `:attesto_phoenix_config`
    * the derived `%Attesto.Config{}` under `:attesto_protocol_config`

  Mount this plug in the pipeline passed to `AttestoPhoenix.Router.attesto_routes/1`:

      pipeline :attesto_phoenix_config do
        plug AttestoPhoenix.Plug.PutConfig, otp_app: :my_app
      end

      scope "/" do
        attesto_routes(pipeline: :attesto_phoenix_config)
      end

  The explicit `:otp_app` option is preferred. When it is omitted, the plug
  reads `config :attesto_phoenix, otp_app: :my_app` at request time. Existing
  correctly typed private values are preserved, which lets a host install a
  request-specific configuration earlier in the pipeline. A value of the wrong
  type fails closed instead of being silently replaced.
  """

  @behaviour Plug

  import Plug.Conn, only: [put_private: 3]

  alias AttestoPhoenix.Config

  @host_config_key :attesto_phoenix_config
  @protocol_config_key :attesto_protocol_config

  @type options :: %{otp_app: atom() | :from_application_env}

  @impl Plug
  @spec init(keyword()) :: options()
  def init(opts) when is_list(opts) do
    otp_app = Keyword.get(opts, :otp_app, :from_application_env)

    if otp_app != :from_application_env and not is_atom(otp_app) do
      raise ArgumentError,
            "#{inspect(__MODULE__)} expected :otp_app to be an atom; got #{inspect(otp_app)}"
    end

    %{otp_app: otp_app}
  end

  @impl Plug
  @spec call(Plug.Conn.t(), options()) :: Plug.Conn.t()
  def call(%Plug.Conn{} = conn, %{otp_app: configured_otp_app}) do
    host_config = fetch_or_load_host_config!(conn, configured_otp_app)
    protocol_config = fetch_or_derive_protocol_config!(conn, host_config)

    conn
    |> put_private(@host_config_key, host_config)
    |> put_private(@protocol_config_key, protocol_config)
  end

  defp resolve_otp_app!(:from_application_env) do
    case Application.fetch_env(:attesto_phoenix, :otp_app) do
      {:ok, otp_app} when is_atom(otp_app) ->
        otp_app

      {:ok, other} ->
        raise ArgumentError,
              "#{inspect(__MODULE__)} expected config :attesto_phoenix, :otp_app to be an atom; " <>
                "got #{inspect(other)}"

      :error ->
        raise ArgumentError,
              "#{inspect(__MODULE__)} requires the :otp_app plug option or " <>
                "config :attesto_phoenix, otp_app: :my_app"
    end
  end

  defp resolve_otp_app!(otp_app) when is_atom(otp_app), do: otp_app

  defp fetch_or_load_host_config!(conn, configured_otp_app) do
    case Map.fetch(conn.private, @host_config_key) do
      {:ok, %Config{} = config} ->
        config

      {:ok, other} ->
        raise ArgumentError,
              "#{inspect(__MODULE__)} expected conn.private[#{inspect(@host_config_key)}] " <>
                "to contain %AttestoPhoenix.Config{}; got #{inspect(other)}"

      :error ->
        configured_otp_app
        |> resolve_otp_app!()
        |> Config.from_otp_app()
    end
  end

  defp fetch_or_derive_protocol_config!(conn, host_config) do
    case Map.fetch(conn.private, @protocol_config_key) do
      {:ok, %Attesto.Config{} = config} ->
        config

      {:ok, other} ->
        raise ArgumentError,
              "#{inspect(__MODULE__)} expected conn.private[#{inspect(@protocol_config_key)}] " <>
                "to contain %Attesto.Config{}; got #{inspect(other)}"

      :error ->
        Config.to_attesto_config(host_config)
    end
  end
end
