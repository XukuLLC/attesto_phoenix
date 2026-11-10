defmodule AttestoPhoenix.AuthorizationServer.Revocation do
  @moduledoc """
  OAuth 2.0 Token Revocation (RFC 7009), as conn-free core.

  Validates the required `"token"` parameter, revokes the refresh token and its
  descendant family bound to the authenticated `client_id` via
  `Attesto.Revocation`, and returns the `:token_revoked` audit event as data.

  Only refresh tokens are revocable. A presented access token is handled like
  an unknown token and stays valid until it expires, and access tokens already
  issued from a revoked refresh family are not invalidated. See
  `AttestoPhoenix.Controller.RevocationController` for the reasoning.
  """

  alias Attesto.Revocation
  alias AttestoPhoenix.{Config, Event}
  alias AttestoPhoenix.Store.EctoRefreshStore

  # RFC 7009 §2.1: the form parameter carrying the credential to revoke, and
  # the optional hint about its type (RFC 7009 §2.1).
  @token_param "token"
  @default_refresh_store EctoRefreshStore

  @doc """
  Extract the required `"token"` parameter from `params`.
  """
  @spec fetch_token(map()) :: {:ok, String.t()} | {:error, :invalid_request}
  def fetch_token(params) when is_map(params) do
    case Map.get(params, @token_param) do
      token when is_binary(token) and token != "" ->
        {:ok, token}

      # RFC 7009 §2.1: `token` is REQUIRED.
      _missing ->
        {:error, :invalid_request}
    end
  end

  @doc """
  Revoke `token` (bound to `client_id`) in `store` and return `{:ok, [event]}`.
  """
  @spec revoke(Config.t(), String.t() | nil, String.t(), String.t() | nil, keyword()) ::
          {:ok, [Event.t()]}
  def revoke(%Config{} = config, client_id, token, token_type_hint \\ nil, opts \\ [])
      when is_binary(token) and (is_binary(token_type_hint) or is_nil(token_type_hint)) and is_list(opts) do
    store = Keyword.get(opts, :refresh_store) || refresh_store(config)

    # RFC 7009 §2.1: bind the revocation to the authenticated client so a
    # client cannot revoke another client's tokens. `Attesto.Revocation`
    # returns `:ok` for every accepted revocation request, whether the token
    # was unknown, expired, already revoked, or owned by another client. This
    # prevents the endpoint from becoming a token-existence oracle.
    :ok =
      Revocation.revoke(store, token,
        client_id: client_id,
        issuer: config.issuer
      )

    # Audit/telemetry hook (RFC 7009 leaves auditing to the deployment). The
    # resolved event callback is optional, so a config without one is a silent
    # no-op. The event is emitted only after a successful, authenticated
    # revocation request; its metadata carries the optional `token_type_hint`
    # for context but never the token value.
    event =
      Event.new(:token_revoked,
        client_id: client_id,
        metadata: %{token_type_hint: token_type_hint}
      )

    {:ok, [event]}
  end

  defp refresh_store(%Config{refresh_store: nil}), do: @default_refresh_store
  defp refresh_store(%Config{refresh_store: store}), do: store
end
