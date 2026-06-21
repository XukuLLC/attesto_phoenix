defmodule AttestoPhoenix.Controller.ProtectedResourceController do
  @moduledoc """
  RFC 9728 - OAuth 2.0 Protected Resource Metadata endpoint.

  Serves the protected-resource metadata document at
  `/.well-known/oauth-protected-resource` (RFC 9728 §3) so that a client - or
  an authorization server acting on its behalf - can discover, from the
  resource identifier alone, which authorization server(s) issue tokens for
  this resource, the scopes it recognises, and how it expects bearer tokens to
  be presented. This is the resource-server analogue of the RFC 8414
  authorization-server metadata `DiscoveryController` serves, and the discovery
  half of the RFC 9728 §5.1 `WWW-Authenticate: Bearer ..., resource_metadata`
  challenge `AttestoPhoenix.Plug.Authenticate` emits on a 401: the challenge
  points a client here, and this endpoint answers.

  The document is assembled by `Attesto.ProtectedResourceMetadata.metadata/2`;
  this controller contributes transport concerns only and adds no policy of its
  own. The members are derived from the protocol and host configuration the
  rest of the server already carries:

    * `resource` (RFC 9728 §2, REQUIRED) - the resource identifier, the core
      builder's default: the access-token `audience` a resource server
      validates is exactly its resource identifier.
    * `authorization_servers` - this server's `issuer`. An OAuth deployment
      that is both the authorization server and the protected resource issues
      its own tokens, so the issuer is the authorization server for this
      resource; a client that reads this document then fetches that issuer's
      RFC 8414 metadata to run the flow.
    * `scopes_supported` - the host's `:scopes_supported`, the same list the
      RFC 8414 document advertises, so the two never drift.
    * `bearer_methods_supported` - the host's `:bearer_methods_supported`
      (`AttestoPhoenix.Config`), the RFC 6750 token-presentation methods the
      resource server accepts. Defaults to `["header"]`, matching
      `AttestoPhoenix.Plug.Authenticate`; add `"body"` only when the resource
      server intentionally accepts RFC 6750 §2.2 form-body `access_token`
      credentials.

  The response carries no secrets and is identical for every caller, so it is
  served unauthenticated, and RFC 9728 §3.1 permits caching, so a public,
  cacheable `Cache-Control` header is set.

  ## Wiring

  Like the other metadata endpoints, the host pipeline must place the
  `AttestoPhoenix.Config` under `conn.private[:attesto_phoenix_config]` and the
  derived `Attesto.Config` under `conn.private[:attesto_protocol_config]`. Both
  are required; a missing value raises rather than serving a partial document,
  because a document that omits `authorization_servers` or `resource` would
  misdirect a client.
  """

  use Phoenix.Controller, formats: [:json]

  import Plug.Conn, only: [put_resp_header: 3]

  alias Attesto.ProtectedResourceMetadata
  alias AttestoPhoenix.Config

  # The router pipeline installs the AttestoPhoenix.Config here - the same
  # private key the discovery, token, and revocation endpoints read.
  @config_key :attesto_phoenix_config

  # The derived Attesto.Config (the protocol configuration the core metadata
  # builder reads) is installed here, the same key DiscoveryController reads.
  @protocol_config_key :attesto_protocol_config

  # RFC 9728 §3.1: the metadata document is static for a given resource
  # configuration, so it may be cached by clients and intermediaries. One hour
  # mirrors the RFC 8414 discovery document's cache window.
  @cache_max_age_seconds 3600

  @doc """
  Render the RFC 9728 protected-resource metadata document as JSON.

  Fails closed with `RuntimeError` when either required configuration value is
  absent from `conn.private`, since serving a document that omits required
  members would misdirect clients.
  """
  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, _params) do
    config = fetch_config!(conn)
    protocol_config = fetch_protocol_config!(conn)

    metadata = ProtectedResourceMetadata.metadata(protocol_config, metadata_opts(config))

    conn
    |> put_cache_control()
    |> json(metadata)
  end

  # Source the RFC 9728 §2 host-specific members from the configuration the
  # server already carries, so the protected-resource document never drifts
  # from the authorization-server metadata. nil/empty values are dropped by the
  # core builder.
  defp metadata_opts(%Config{} = config) do
    [
      authorization_servers: [config.issuer],
      scopes_supported: presence(config.scopes_supported),
      # RFC 9728 §2 `bearer_methods_supported`: the RFC 6750 token-presentation
      # methods the resource server accepts, from `AttestoPhoenix.Config`
      # `:bearer_methods_supported` (default `["header"]`, matching
      # `AttestoPhoenix.Plug.Authenticate`).
      bearer_methods_supported: config.bearer_methods_supported
    ]
  end

  defp presence([]), do: nil
  defp presence(list) when is_list(list), do: list

  # Fail closed: a missing config is a wiring error, not a runtime condition to
  # paper over. Raising surfaces the misconfiguration instead of emitting a
  # document that omits required members.
  @spec fetch_config!(Plug.Conn.t()) :: Config.t()
  defp fetch_config!(conn) do
    case conn.private do
      %{@config_key => %Config{} = config} ->
        config

      _ ->
        raise "#{inspect(__MODULE__)}: no %AttestoPhoenix.Config{} found in " <>
                "conn.private[#{inspect(@config_key)}]; wire the host pipeline that assigns it"
    end
  end

  @spec fetch_protocol_config!(Plug.Conn.t()) :: Attesto.Config.t()
  defp fetch_protocol_config!(conn) do
    case conn.private do
      %{@protocol_config_key => %Attesto.Config{} = config} ->
        config

      _ ->
        raise "#{inspect(__MODULE__)}: no %Attesto.Config{} found in " <>
                "conn.private[#{inspect(@protocol_config_key)}]; wire the host pipeline that assigns it"
    end
  end

  @spec put_cache_control(Plug.Conn.t()) :: Plug.Conn.t()
  defp put_cache_control(conn) do
    put_resp_header(conn, "cache-control", "public, max-age=#{@cache_max_age_seconds}")
  end
end
