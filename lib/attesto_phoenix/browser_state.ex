defmodule AttestoPhoenix.BrowserState do
  @moduledoc """
  The OP browser-state cookie (OpenID Connect Session Management 1.0 §3.2).

  Session Management binds the RP-visible `session_state` value to an opaque
  browser-scoped value at the OP origin — the *OP User Agent state* — so the
  `check_session_iframe` can recompute the hash purely in the browser. The
  spec's constraints shape the cookie exactly:

    * the iframe's JavaScript must read it, so it is **not** `HttpOnly` (§3.2);
    * the iframe is embedded cross-site (in the RP's page), so the cookie is
      `SameSite=None; Secure` or the browser would not send it to — or expose
      it inside — the third-party iframe context;
    * it changes when the End-User's login state at the OP changes: this
      module mints it when an authorization response is issued with none
      present (login) and expires it at the end-session endpoint (logout), so
      a recomputed `session_state` flips to `changed` after logout.

  The cookie name and lifetime come from `AttestoPhoenix.Config`'s
  `session_management: [browser_state_cookie: ..., browser_state_cookie_max_age: ...]`.
  """

  alias Attesto.SessionState
  alias AttestoPhoenix.Config

  @doc """
  Ensure the browser-state cookie exists, minting a fresh value when the
  request carried none. Returns `{conn, value}` with the response cookie set
  (or the existing request value untouched).
  """
  @spec ensure(Plug.Conn.t(), Config.t()) :: {Plug.Conn.t(), String.t()}
  def ensure(conn, %Config{} = config) do
    conn = Plug.Conn.fetch_cookies(conn)

    case current(conn, config) do
      value when is_binary(value) and value != "" ->
        {conn, value}

      _ ->
        value = SessionState.generate_browser_state()
        {put(conn, config, value), value}
    end
  end

  @doc "The request's browser-state cookie value, or `nil`."
  @spec current(Plug.Conn.t(), Config.t()) :: String.t() | nil
  def current(conn, %Config{} = config) do
    conn
    |> Plug.Conn.fetch_cookies()
    |> Map.fetch!(:req_cookies)
    |> Map.get(Config.browser_state_cookie(config))
  end

  @doc """
  Expire the browser-state cookie (logout — §3.2: the OP browser state changes
  when the End-User's login state does). A subsequent `check_session_iframe`
  recomputation hashes over the empty state and yields `changed`.
  """
  @spec expire(Plug.Conn.t(), Config.t()) :: Plug.Conn.t()
  def expire(conn, %Config{} = config) do
    Plug.Conn.delete_resp_cookie(conn, Config.browser_state_cookie(config), cookie_opts(config))
  end

  defp put(conn, config, value) do
    Plug.Conn.put_resp_cookie(
      conn,
      Config.browser_state_cookie(config),
      value,
      [max_age: Config.browser_state_cookie_max_age(config)] ++ cookie_opts(config)
    )
  end

  # §3.2: JavaScript-readable (no HttpOnly) and reachable from the cross-site
  # iframe context (SameSite=None requires Secure). `delete_resp_cookie` must
  # receive the same attributes to address the same cookie.
  defp cookie_opts(_config) do
    [path: "/", http_only: false, secure: true, same_site: "None", sign: false, encrypt: false]
  end
end
