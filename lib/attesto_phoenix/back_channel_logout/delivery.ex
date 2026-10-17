defmodule AttestoPhoenix.BackChannelLogout.Delivery do
  @moduledoc false

  alias Attesto.LogoutToken
  alias AttestoPhoenix.Config

  require Logger

  @lease_seconds 60
  @target_timeout_ms 10_000

  @doc false
  @spec lease_seconds() :: pos_integer()
  def lease_seconds, do: @lease_seconds

  @doc false
  @spec start(Config.t(), map(), String.t() | nil, [Attesto.LogoutSessionStore.target()]) :: :ok
  def start(_config, _session, nil, _targets), do: :ok

  def start(config, session, lease_id, targets) when is_binary(lease_id) and is_list(targets) do
    backchannel_targets = Enum.filter(targets, &is_binary(&1.backchannel_logout_uri))
    start_targets(backchannel_targets, config, session, lease_id)
  end

  @doc false
  @spec acknowledge(Config.t(), String.t(), [String.t()]) :: :ok
  def acknowledge(_config, _lease_id, []), do: :ok

  def acknowledge(config, lease_id, delivery_ids) do
    Config.with_request_config(config, fn ->
      Config.logout_session_store(config).acknowledge_targets(lease_id, delivery_ids)
    end)
  rescue
    _exception -> Logger.warning("logout delivery acknowledgement failed; lease will expire for retry")
  catch
    _kind, _reason -> Logger.warning("logout delivery acknowledgement failed; lease will expire for retry")
  end

  @doc false
  @spec release(Config.t(), String.t(), [String.t()]) :: :ok
  def release(_config, _lease_id, []), do: :ok

  def release(config, lease_id, delivery_ids) do
    Config.with_request_config(config, fn ->
      Config.logout_session_store(config).release_targets(lease_id, delivery_ids)
    end)
  rescue
    _exception -> Logger.warning("logout delivery release failed; lease will expire for retry")
  catch
    _kind, _reason -> Logger.warning("logout delivery release failed; lease will expire for retry")
  end

  defp start_targets([], _config, _session, _lease_id), do: :ok

  defp start_targets(targets, config, session, lease_id) do
    task = fn ->
      Config.with_request_config(config, fn ->
        deliver_batch(config, session, lease_id, targets)
      end)
    end

    case start_supervised(task) do
      :ok ->
        :ok

      :error ->
        release(config, lease_id, Enum.map(targets, & &1.delivery_id))
    end
  end

  defp start_supervised(task) do
    case Task.Supervisor.start_child(AttestoPhoenix.DeliverySupervisor, task) do
      {:ok, _pid} -> :ok
      {:error, _reason} -> delivery_start_failed()
    end
  catch
    :exit, _reason -> delivery_start_failed()
  end

  defp delivery_start_failed do
    Logger.warning("back-channel logout delivery could not be started")
    :error
  end

  defp deliver_batch(config, session, lease_id, targets) do
    http = Config.backchannel_logout_http(config)
    attesto_config = Config.to_attesto_config(config)

    results =
      targets
      |> Task.async_stream(
        &deliver(attesto_config, http, session, &1),
        max_concurrency: max(length(targets), 1),
        ordered: true,
        timeout: @target_timeout_ms,
        on_timeout: :kill_task
      )
      |> Enum.to_list()

    {acknowledged, released} = partition_results(targets, results)
    acknowledge(config, lease_id, acknowledged)
    release(config, lease_id, released)
  end

  defp partition_results(targets, results) do
    targets
    |> Enum.zip(results)
    |> Enum.reduce({[], []}, fn
      {target, {:ok, :ok}}, {acked, failed} ->
        {[target.delivery_id | acked], failed}

      {target, _result}, {acked, failed} ->
        {acked, [target.delivery_id | failed]}
    end)
  end

  defp deliver(attesto_config, http, session, target) do
    opts =
      []
      |> put_opt(:sub, Map.get(target, :subject) || Map.get(session, :subject))
      |> put_opt(:sid, target.sid)

    with {:ok, token} <- LogoutToken.mint(attesto_config, target.client_id, opts),
         :ok <- http.post(target.backchannel_logout_uri, token) do
      :ok
    else
      {:error, _reason} -> delivery_failed()
    end
  rescue
    _exception -> delivery_failed()
  catch
    _kind, _reason -> delivery_failed()
  end

  defp delivery_failed do
    Logger.warning("back-channel logout delivery failed")
    :error
  end

  defp put_opt(opts, _key, nil), do: opts
  defp put_opt(opts, _key, ""), do: opts
  defp put_opt(opts, key, value), do: Keyword.put(opts, key, value)
end
