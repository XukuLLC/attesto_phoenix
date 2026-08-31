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
    Config.with_request_config(config, fn ->
      with {:ok, decision} <- CIBA.approve(ciba_store(config), auth_req_id, approval, opts) do
        deliver_ping(config, auth_req_id, decision)
        {:ok, decision}
      end
    end)
  end

  @doc """
  Record a denial for `auth_req_id` (the user refused or failed authentication),
  then deliver the ping notification when the request is ping-mode. Returns the
  `Attesto.CIBA.deny/3` result.
  """
  @spec deny(Config.t(), String.t(), keyword()) :: {:ok, CIBA.decision()} | {:error, term()}
  def deny(%Config{} = config, auth_req_id, opts \\ []) do
    Config.with_request_config(config, fn ->
      with {:ok, decision} <- CIBA.deny(ciba_store(config), auth_req_id, opts) do
        deliver_ping(config, auth_req_id, decision)
        {:ok, decision}
      end
    end)
  end

  # §10.2: only ping-mode requests are notified, and only when the client has a
  # notification token (poll mode returns nil) and a resolvable endpoint. Async,
  # fire-and-forget: the token is already redeemable at the token endpoint.
  defp deliver_ping(config, auth_req_id, %{delivery_mode: :ping, client_notification_token: token} = decision)
       when is_binary(token) do
    client_id = Callback.map_value(decision, :client_id)

    case notification_endpoint(config, client_id) do
      {:ok, endpoint} ->
        post_async(config, Config.ciba_ping_http_client(config), endpoint, token, auth_req_id)

      {:error, :client_lookup_failed} ->
        Logger.warning("CIBA ping: client lookup failed; notification skipped")
        :ok

      {:error, :registration_failed} ->
        Logger.warning("CIBA ping registration failed; notification skipped")
        :ok

      :error ->
        Logger.warning("CIBA ping: no notification endpoint registered; notification skipped")
        :ok
    end
  end

  defp deliver_ping(_config, _auth_req_id, _decision), do: :ok

  defp post_async(config, http, endpoint, token, auth_req_id) do
    Task.start(fn ->
      try do
        Config.with_request_config(config, fn ->
          post_ping(http, endpoint, token, auth_req_id)
        end)
      rescue
        _exception -> ping_delivery_failed()
      catch
        _kind, _value -> ping_delivery_failed()
      end
    end)

    :ok
  end

  defp post_ping(http, endpoint, token, auth_req_id) do
    case http.post(endpoint, token, auth_req_id) do
      :ok -> :ok
      {:error, _reason} -> ping_delivery_failed()
      _unexpected -> ping_delivery_failed()
    end
  end

  defp ping_delivery_failed do
    Logger.warning("CIBA ping delivery failed; notification skipped")
  end

  # The client's registered `backchannel_client_notification_endpoint`, resolved
  # by loading the client and reading its CIBA registration. The core decision
  # carries only the `client_id`, so the host client is re-loaded here.
  defp notification_endpoint(config, client_id) when is_binary(client_id) do
    with {:ok, client} <- load_client_for_ping(config, client_id),
         {:ok, registration} <- registration_for_ping(config, client) do
      endpoint_from_registration(registration)
    else
      {:error, reason} when reason in [:not_found, :revoked] -> :error
      error -> error
    end
  end

  defp notification_endpoint(_config, _client_id), do: :error

  defp endpoint_from_registration(registration) do
    case Map.get(registration, :client_notification_endpoint) do
      endpoint when is_binary(endpoint) and endpoint != "" -> {:ok, endpoint}
      nil -> :error
      _malformed -> {:error, :registration_failed}
    end
  end

  defp registration_for_ping(config, client) do
    {:ok, Config.client_ciba_registration(config, client)}
  rescue
    _exception -> {:error, :registration_failed}
  catch
    _kind, _value -> {:error, :registration_failed}
  end

  # The CIBA decision is already durable before ping delivery begins. A host
  # client-store fault must therefore remain observable without changing that
  # committed decision into a misleading failure response. Keep the diagnostic
  # bounded: callback returns/exceptions may contain storage or credential data.
  defp load_client_for_ping(config, client_id) do
    Config.client_store_load(config, client_id)
  rescue
    _exception -> {:error, :client_lookup_failed}
  catch
    _kind, _value -> {:error, :client_lookup_failed}
  end

  defp ciba_store(config) do
    case Config.ciba_store(config) do
      store when is_atom(store) and not is_nil(store) ->
        store

      _ ->
        raise ArgumentError, "AttestoPhoenix CIBA: no :ciba_store configured; set `ciba_store: MyApp.EctoCIBAStore`"
    end
  end
end
