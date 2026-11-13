defmodule AttestoPhoenix.AuthorizationServer.ScopeAuthorization do
  @moduledoc """
  Runs the host's scope policy (RFC 6749 §3.3), as conn-free core.

  The authorization endpoint and every token-endpoint grant decide scope
  through `authorize/4`, so a host writes its policy once and both endpoints
  apply it to the same inputs: the client, the requested scope, and the RFC
  8707 resource indicators the request resolved to.

  The host callback has two forms (see `AttestoPhoenix.ScopePolicy`):

    * `authorize_scope(client, requested_scope, resources)` - preferred when
      the host provides it. It may refuse with `{:error, :invalid_scope}` or
      `{:error, :invalid_target}`.
    * `authorize_scope(client, requested_scope)` - sees no resources, so it
      may refuse only with `{:error, :invalid_scope}`.

  RFC 8707 gives no rule that separates `invalid_target` from `invalid_scope`
  for a refusal about a resource and scope together, so the callback's return
  value says which one applies.
  """

  alias AttestoPhoenix.Callback
  alias AttestoPhoenix.ClientIdMetadata
  alias AttestoPhoenix.Config

  @type refusal :: :invalid_scope | :invalid_target

  @doc """
  Whether a policy result stays within what the client asked for (RFC 6749
  §3.3).

  A policy may narrow the requested scope but may not add to it. When the
  client omitted `scope` (an empty request), RFC 6749 §3.3 lets the server
  "process the request using a pre-defined default value", so any granted
  scope is within the request. Both endpoints use this one rule.
  """
  @spec within_request?([String.t()], [String.t()]) :: boolean()
  def within_request?(_granted, []), do: true
  def within_request?(granted, requested) when is_list(granted) and is_list(requested), do: granted -- requested == []

  @doc """
  Decide the scope to grant `client` for `requested` scope values and the
  resolved `resources`.

  Returns `{:ok, granted}` or `{:error, :invalid_scope | :invalid_target}`.
  Raises `RuntimeError` when the callback returns anything outside its
  contract, including `:invalid_target` from the two-argument form.
  """
  @spec authorize(Config.t(), term(), [String.t()], [String.t()]) :: {:ok, [String.t()]} | {:error, refusal()}
  def authorize(%Config{} = config, client, requested, resources) when is_list(requested) and is_list(resources) do
    {callback, arity} = Config.authorize_scope_callback(config)
    host_client = ClientIdMetadata.host_client(client)

    args =
      case arity do
        3 -> [host_client, requested, resources]
        2 -> [host_client, requested]
      end

    case {Callback.invoke(callback, args), arity} do
      {{:ok, scope}, _arity} when is_list(scope) -> {:ok, scope}
      {{:error, :invalid_scope}, _arity} -> {:error, :invalid_scope}
      {{:error, :invalid_target}, 3} -> {:error, :invalid_target}
      _unexpected -> raise RuntimeError, "AttestoPhoenix.Config :authorize_scope callback violated its return contract"
    end
  end
end
