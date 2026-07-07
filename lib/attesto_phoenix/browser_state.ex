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
    * it is a `__Host-`-prefixed cookie: the browser then rejects it unless it
      is `Secure`, `Path=/`, and carries **no** `Domain` attribute, so a
      sibling/parent-domain origin cannot inject or shadow it and logout (which
      expires the host cookie) fully clears it;
    * it changes when the End-User's login state at the OP changes: this
      module mints it when an authorization response is issued (login) and
      expires it at the end-session endpoint (logout), and rotates it whenever
      the login binding changes, so a recomputed `session_state` flips to
      `changed`.

  The value is **OP-owned and login-bound**: it is not a bare random string but
  the integrity-protected `random . login_tag . mac` minted by
  `Attesto.SessionState.mint_browser_state/2`. `ensure/3` only reuses an
  incoming cookie whose MAC verifies under the OP secret *and* whose login tag
  still matches the current authorization's login binding; otherwise it mints a
  fresh value. That defends two things at once: an injected/forged cookie
  cannot forge `unchanged` (its MAC will not verify), and a re-auth / account
  switch rotates the state (its login tag no longer matches) so earlier RP
  `session_state` values become `changed` (Session Management 1.0 §3.2).

  The cookie name and lifetime come from `AttestoPhoenix.Config`'s
  `session_management: [browser_state_cookie: ..., browser_state_cookie_max_age: ...]`;
  the OP secret is `session_management: [browser_state_secret: ...]` (required
  when session management is enabled).
  """

  alias Attesto.SessionState
  alias AttestoPhoenix.Config

  @doc """
  Ensure the OP browser-state cookie exists and is current for `login_binding`.

  Reuses the incoming cookie only when it is a value this OP minted (MAC
  verifies under the configured secret) that is still bound to the current
  login state; otherwise mints a fresh value and sets the response cookie.
  `login_binding` is a stable string derived from the current authorization's
  resolved login identity (subject / auth_time / sid). Returns `{conn, value}`.
  """
  @spec ensure(Plug.Conn.t(), Config.t(), binary()) :: {Plug.Conn.t(), String.t()}
  def ensure(conn, %Config{} = config, login_binding) when is_binary(login_binding) do
    conn = Plug.Conn.fetch_cookies(conn)
    secret = Config.browser_state_secret(config)

    case current(conn, config) do
      value when is_binary(value) and value != "" ->
        if SessionState.browser_state_valid?(secret, value, login_binding) do
          {conn, value}
        else
          mint(conn, config, secret, login_binding)
        end

      _ ->
        mint(conn, config, secret, login_binding)
    end
  end

  defp mint(conn, config, secret, login_binding) do
    value = SessionState.mint_browser_state(secret, login_binding)
    {put(conn, config, value), value}
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
  # iframe context (SameSite=None requires Secure). These attributes also
  # satisfy the `__Host-` cookie prefix (Secure, Path=/, no Domain), which the
  # default cookie name uses so a sibling/parent-domain origin cannot inject or
  # shadow it. `__Host-` does not constrain SameSite, so `SameSite=None` stands.
  # `delete_resp_cookie` must receive the same attributes to address the same
  # cookie.
  defp cookie_opts(_config) do
    [path: "/", http_only: false, secure: true, same_site: "None", sign: false, encrypt: false]
  end
end
