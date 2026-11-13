defmodule AttestoPhoenix.RouteControls do
  @moduledoc """
  Which optional protocol routes `attesto_routes/1` left unmounted.

  `par: false`, `revocation: false`, `introspection: false`,
  `registration_read: false` and `registration_update: false` are compile-time
  router options, while the metadata documents are built at request time from
  `AttestoPhoenix.Config`. The macro records the omitted routes on the routes
  that need to know (both metadata documents and the authorization endpoint),
  and this module is the one place that reads the record back, so the RFC 8414
  document and the OpenID Provider document cannot disagree about which
  endpoints exist.

  Registration management routes also read this record when constructing
  their `Allow` header (RFC 9110 §10.2.1). Omitting read or update does not
  remove the registration endpoint from discovery.
  """

  alias AttestoPhoenix.{Callback, Config}

  @private_key :attesto_phoenix_omitted_routes
  @controls [:par, :revocation, :introspection, :registration_read, :registration_update]

  # RFC 8414 §2 / RFC 9126 §5: the members that describe each endpoint. A
  # document must not advertise an endpoint the router does not serve.
  @metadata_members %{
    par: ~w(pushed_authorization_request_endpoint),
    revocation: ~w(
      revocation_endpoint
      revocation_endpoint_auth_methods_supported
      revocation_endpoint_auth_signing_alg_values_supported
    ),
    registration_read: [],
    registration_update: [],
    introspection: ~w(
      introspection_endpoint
      introspection_endpoint_auth_methods_supported
      introspection_endpoint_auth_signing_alg_values_supported
      introspection_signing_alg_values_supported
    )
  }

  @type control :: :par | :revocation | :introspection | :registration_read | :registration_update

  @doc "The route controls this module tracks."
  @spec controls() :: [control()]
  def controls, do: @controls

  @doc "The `conn.private` key the router macro records omitted routes under."
  @spec private_key() :: atom()
  def private_key, do: @private_key

  @doc "The routes the macro that dispatched `conn` left unmounted."
  @spec omitted(Plug.Conn.t()) :: [control()]
  def omitted(%Plug.Conn{private: private}), do: Map.get(private, @private_key, [])

  @doc """
  Remove the metadata members of every omitted route from `metadata`.
  """
  @spec drop_omitted(map(), [control()]) :: map()
  def drop_omitted(metadata, omitted) when is_map(metadata) and is_list(omitted) do
    Map.drop(metadata, Enum.flat_map(omitted, &Map.fetch!(@metadata_members, &1)))
  end

  @doc """
  Raise when the router omits the PAR endpoint while the configuration
  requires pushed authorization requests (RFC 9126 §5).

  No client could complete an authorization request under that combination.
  The router options are compile-time and the configuration is resolved per
  request, so nothing sees both at boot; the check runs on the metadata and
  authorization routes instead.
  """
  @spec check_par!(Plug.Conn.t(), Config.t()) :: :ok
  def check_par!(%Plug.Conn{} = conn, %Config{} = config) do
    if :par in omitted(conn) and Callback.config_flag(config, :require_pushed_authorization_requests) do
      raise ArgumentError,
            "attesto_routes/1 was given par: false, but AttestoPhoenix.Config sets " <>
              "require_pushed_authorization_requests: true. Mount the PAR endpoint or stop requiring it."
    end

    :ok
  end
end
