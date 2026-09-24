defmodule AttestoPhoenix.Plug.RequireScopes do
  @moduledoc """
  Phoenix alias for `Attesto.Plug.RequireScopes`.

  Scope authorization is protocol logic, so the implementation remains in the
  core `attesto` package and uses `Attesto.Scope` grant-form algebra. This
  module exists to give Phoenix routers a stable `AttestoPhoenix.Plug.*` surface
  alongside `AttestoPhoenix.Plug.Authenticate`.

  If reached without verified claims, this plug answers 401. When request-private
  `:attesto_phoenix_config` or an explicit `:config` option (a config struct or
  zero-arity resolver) is available, it completes `:auth_denied` before sending
  that response. Request-private configuration takes precedence. With no config,
  no audit sink is available. Authenticated scope refusals remain 403 and do not
  emit authentication-denial events.

  ## RFC 9728 `resource_metadata` on the 403

  Unlike `AttestoPhoenix.Plug.Authenticate` (which sources the
  `resource_metadata` pointer from `AttestoPhoenix.Config`), this plug is a thin,
  protocol alias that stays usable in a resource-server-only deployment with no
  host config. Its `insufficient_scope` (403) challenge
  therefore omits the pointer unless one is passed explicitly:

      plug AttestoPhoenix.Plug.RequireScopes,
        scopes: ["read:reports"],
        resource_metadata: "https://api.example/.well-known/oauth-protected-resource"

  This is intentional, not a discovery gap: a 403 is only reached *after* the
  request authenticated, so the client already received the pointer on the
  initial unauthenticated 401 from `Authenticate`, and RFC 9728 §5.1 makes the
  `resource_metadata` auth-param OPTIONAL on a challenge.
  """

  @behaviour Plug

  alias Attesto.Plug.RequireScopes, as: CoreRequireScopes
  alias AttestoPhoenix.{Config, DenialAudit}

  @impl Plug
  def init(scope) when is_binary(scope), do: init([scope])

  def init(opts) do
    opts = if Keyword.keyword?(opts), do: opts, else: [scopes: opts]
    config = Keyword.get(opts, :config)
    transport = Keyword.get(opts, :send_error)

    opts
    |> Keyword.put(:send_error, fn conn, status, body ->
      audit_config = if status == 401, do: scope_config(conn, config)
      DenialAudit.send_error(conn, status, body, audit_config, transport)
    end)
    |> CoreRequireScopes.init()
  end

  @impl Plug
  def call(conn, opts), do: CoreRequireScopes.call(conn, opts)

  # Scope authorization remains usable without an authorization-server config.
  # When supplied, request-private config takes precedence over a static option.
  defp scope_config(conn, fallback) do
    if Map.has_key?(conn.private, :attesto_phoenix_config) do
      Config.resolve!(conn)
    else
      case fallback do
        fun when is_function(fun, 0) -> fun.()
        config -> config
      end
    end
  end
end
