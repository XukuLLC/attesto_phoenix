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
  request-specific configuration earlier in the pipeline. A preinstalled
  protocol config must exactly match the value derived from that request's host
  config; otherwise the plug fails closed instead of advertising policy that
  the token endpoints do not enforce. A value of the wrong type also fails
  closed instead of being silently replaced. This plug is the reference
  implementation and convenient route helper for installing both private values,
  but hosts may also populate them directly using custom plugs. Library
  controllers and `AttestoPhoenix.Plug.Authenticate` bind the private
  configuration only while their bounded work executes; this plug does not
  retain tenant state in the process dictionary between pipeline and action
  dispatch.
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

      {:ok, _other} ->
        raise ArgumentError,
              "#{inspect(__MODULE__)} expected conn.private[#{inspect(@host_config_key)}] " <>
                "to contain %AttestoPhoenix.Config{}"

      :error ->
        configured_otp_app
        |> resolve_otp_app!()
        |> Config.from_otp_app()
    end
  end

  defp fetch_or_derive_protocol_config!(conn, host_config) do
    derived = Config.to_attesto_config(host_config)

    case Map.fetch(conn.private, @protocol_config_key) do
      {:ok, %Attesto.Config{} = config} ->
        if config === derived do
          config
        else
          raise ArgumentError,
                "#{inspect(__MODULE__)} expected conn.private[#{inspect(@protocol_config_key)}] " <>
                  "to match the protocol config derived from conn.private[#{inspect(@host_config_key)}]"
        end

      {:ok, _other} ->
        raise ArgumentError,
              "#{inspect(__MODULE__)} expected conn.private[#{inspect(@protocol_config_key)}] " <>
                "to contain %Attesto.Config{}"

      :error ->
        derived
    end
  end
end
