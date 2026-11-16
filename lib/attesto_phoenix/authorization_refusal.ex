defmodule AttestoPhoenix.AuthorizationRefusal do
  @moduledoc false

  alias AttestoPhoenix.{Callback, Config, Event, RequestContext}

  @errors ~w(invalid_request invalid_authorization_details invalid_request_object request_not_supported request_uri_not_supported registration_not_supported invalid_request_uri invalid_scope invalid_target unauthorized_client unsupported_response_type access_denied login_required consent_required interaction_required account_selection_required server_error temporarily_unavailable)
  @reasons Map.new(@errors, &{&1, String.to_atom(&1)})

  def emit(conn, config, error, reason, candidate \\ nil) do
    {reason, repeated} = reason(reason)
    repeated = Enum.uniq(repeated ++ Map.get(conn.private, :attesto_phoenix_repeated_parameters, [])) |> Enum.sort()
    candidate = candidate || conn.private[:attesto_phoenix_authorization_client_id] || Map.get(conn.params, "client_id")
    client_id = if "client_id" not in repeated, do: registered_client_id(config, candidate)

    Event.emit(config, :authorization_failed, %{
      client_id: client_id,
      result: if(error in @errors, do: error, else: "server_error"),
      metadata: %{
        client_ip: RequestContext.client_ip(conn, config),
        reason: reason,
        repeated_parameters: repeated
      }
    })
  end

  defp reason({:duplicate_parameter, name}), do: {:duplicate_parameter, [name]}
  defp reason(reason) when is_binary(reason), do: {Map.get(@reasons, reason, :server_error), []}
  defp reason(reason) when is_atom(reason), do: {reason, []}
  # A refusal is never turned into a crash by the term that describes it.
  defp reason(_other), do: {:invalid_request, []}

  # Registry lookup only: never resolve a request-supplied metadata URL for
  # audit attribution. Unknown identifiers and registry failures are omitted.
  defp registered_client_id(config, candidate) when is_binary(candidate) and candidate != "" do
    case Callback.invoke(Config.load_client_fun(config), [candidate]) do
      {:ok, _client} -> candidate
      _other -> nil
    end
  rescue
    _error -> nil
  catch
    _kind, _reason -> nil
  end

  defp registered_client_id(_config, _candidate), do: nil
end
