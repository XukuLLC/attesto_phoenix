defmodule AttestoPhoenix.AuthorizationServer.CIBADecision do
  @moduledoc """
  Records an end-user's decision on a pending CIBA authentication request and,
  for a ping-mode request, delivers the §10.2 notification - so a host's
  authentication-device UI does not hand-roll the `approve`→`notify` sequence.

  After the end-user authenticates (or refuses) on their authentication device,
  the host calls `approve/3` or `deny/2` with the `auth_req_id`. Each drives the
  atomic `Attesto.CIBA.approve/4` / `deny/3` core transition, then - when the
  request was registered for `ping` delivery - POSTs the notification to the
  client's registered `backchannel_client_notification_endpoint`
  (`Authorization: Bearer <client_notification_token>`, body
  `{"auth_req_id": ...}`) through the configured `AttestoPhoenix.CIBAPing`
  deliverer. The §10.2 notification fires on approval AND denial; a poll-mode
  request sends none. Delivery is async and best-effort: the tokens are already
  available at the token endpoint, so a client that misses the ping falls back
  to polling.

  The notification endpoint is resolved from the client's registration
  (`AttestoPhoenix.Config.client_ciba_registration/2`, `:client_notification_endpoint`), looked
  up by the `client_id` the core decision returns; a ping request whose client
  has no resolvable endpoint simply sends nothing (logged).
  """

  alias Attesto.CIBA
  alias AttestoPhoenix.{Callback, Config}

  require Logger

  @doc """
  Record a successful authentication + consent for `auth_req_id`, then deliver
  the ping notification when the request is ping-mode. `approval` carries
  `:subject` (required, and it MUST match the issue-time subject), and optionally
  `:acr`, `:scope`, `:claims`, `:auth_time`. Returns the `Attesto.CIBA.approve/4`
  result.
  """
  @spec approve(Config.t(), String.t(), map(), keyword()) ::
          {:ok, CIBA.decision()} | {:error, term()}
  def approve(%Config{} = config, auth_req_id, approval, opts \\ []) do
    with {:ok, decision} <- CIBA.approve(ciba_store(config), auth_req_id, approval, opts) do
      deliver_ping(config, auth_req_id, decision)
      {:ok, decision}
    end
  end

  @doc """
  Record a denial for `auth_req_id` (the user refused or failed authentication),
  then deliver the ping notification when the request is ping-mode. Returns the
  `Attesto.CIBA.deny/3` result.
  """
  @spec deny(Config.t(), String.t(), keyword()) :: {:ok, CIBA.decision()} | {:error, term()}
  def deny(%Config{} = config, auth_req_id, opts \\ []) do
    with {:ok, decision} <- CIBA.deny(ciba_store(config), auth_req_id, opts) do
      deliver_ping(config, auth_req_id, decision)
      {:ok, decision}
    end
  end

  # §10.2: only ping-mode requests are notified, and only when the client has a
  # notification token (poll mode returns nil) and a resolvable endpoint. Async,
  # fire-and-forget: the token is already redeemable at the token endpoint.
  defp deliver_ping(config, auth_req_id, %{delivery_mode: :ping, client_notification_token: token, client_id: client_id})
       when is_binary(token) do
    case notification_endpoint(config, client_id) do
      endpoint when is_binary(endpoint) and endpoint != "" ->
        post_async(Config.ciba_ping_http_client(config), endpoint, token, auth_req_id)

      _ ->
        Logger.warning("CIBA ping: no notification endpoint registered for client #{inspect(client_id)}")
        :ok
    end
  end

  defp deliver_ping(_config, _auth_req_id, _decision), do: :ok

  defp post_async(http, endpoint, token, auth_req_id) do
    Task.start(fn ->
      case http.post(endpoint, token, auth_req_id) do
        :ok -> :ok
        {:error, reason} -> Logger.warning("CIBA ping delivery failed: #{inspect(reason)}")
      end
    end)

    :ok
  end

  # The client's registered `backchannel_client_notification_endpoint`, resolved
  # by loading the client and reading its CIBA registration. The core decision
  # carries only the `client_id`, so the host client is re-loaded here.
  defp notification_endpoint(config, client_id) when is_binary(client_id) do
    case Callback.invoke(Config.load_client_fun(config), [client_id], nil) do
      {:ok, client} ->
        config |> Config.client_ciba_registration(client) |> Map.get(:client_notification_endpoint)

      client when not is_nil(client) ->
        config |> Config.client_ciba_registration(client) |> Map.get(:client_notification_endpoint)

      _ ->
        nil
    end
  end

  defp notification_endpoint(_config, _client_id), do: nil

  defp ciba_store(config) do
    case Config.ciba_store(config) do
      store when is_atom(store) and not is_nil(store) ->
        store

      _ ->
        raise ArgumentError, "AttestoPhoenix CIBA: no :ciba_store configured; set `ciba_store: MyApp.EctoCIBAStore`"
    end
  end
end
