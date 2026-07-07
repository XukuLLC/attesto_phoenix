defmodule AttestoPhoenix.Controller.EndSessionController do
  @moduledoc """
  End-session endpoint (OpenID Connect RP-Initiated Logout 1.0 §2 +
  Back-Channel Logout 1.0 + Front-Channel Logout 1.0).

  Where a Relying Party sends the End-User's browser to log out. This
  controller owns the protocol — it verifies the `id_token_hint`, validates the
  `post_logout_redirect_uri` against the RP's registered set, fans a
  `logout_token` out to every other RP holding the session, renders each
  front-channel RP's `frontchannel_logout_uri` in an iframe, and either
  redirects to the validated return URI or hands off to the host's logged-out
  page — while the host owns the browser session and the HTML through two
  callbacks:

    * `:terminate_session` (REQUIRED when logout is enabled) —
      `(conn, context -> {:ok, conn} | {:ok, conn, session} | {:halt, conn})`.
      Clears the host's browser login session. `context` is `%{subject, sid,
      client_id}` carrying the `id_token_hint`'s values (any may be nil). The
      host is the authority on the session:

        * `{:ok, conn}` — the current session was cleared; run front-channel
          logout only (no back-channel fan-out).
        * `{:ok, conn, %{sid: ..., subject: ...}}` — the current session was
          cleared; fan out a `logout_token` to the RPs of **this**
          host-confirmed session. The fan-out scope comes from here, NOT from
          the request's `id_token_hint`, so a replayed or stolen ID Token cannot
          force-log-out an arbitrary session.
        * `{:halt, conn}` — the host has taken over the response entirely (e.g.
          to render a logout-confirmation step); nothing further runs.

    * `:render_logged_out` (optional) — `(conn, context -> conn)`. Renders the
      "you are now logged out" page when the request asked for no
      `post_logout_redirect_uri`. A minimal 200 is sent when unset.

  ## Host responsibility: session binding + CSRF (REQUIRED)

  RP-Initiated Logout is a state-changing action reachable by GET (the RP
  redirects the browser here). The `id_token_hint` is **not** an authenticator —
  it is signed by the OP and any party that holds a copy (a malicious RP, a
  leaked token) can present it. The library therefore makes the host the session
  authority: `:terminate_session` MUST verify that the request corresponds to
  the **current** OP browser session (its cookie) before clearing it and before
  returning an `{:ok, conn, session}` that drives back-channel fan-out. A host
  that wants an explicit confirmation step returns `{:halt, conn}` and renders
  its own page. The controller additionally requires HTTPS. Without this
  binding, `/end_session` is a logout-CSRF / forced-logout primitive.

  ## Redirect safety

  A `post_logout_redirect_uri` is honored only when it **exactly** matches one
  the client registered (RP-Initiated Logout §2/§3); the RP is identified from
  the verified `id_token_hint`'s `aud` (or the `client_id` parameter). A request
  that names an unregistered URI — or supplies one with no way to identify the
  client — is refused before any session is touched, so the endpoint cannot be
  turned into an open redirector.

  ## Back-Channel Logout (Back-Channel Logout 1.0 §2.5)

  When `:terminate_session` returns a confirmed session, the OP atomically takes
  (enumerates-and-deletes) that session's recorded `(sid|subject)` rows and
  POSTs a signed `logout_token` to each RP's `backchannel_logout_uri` (recorded
  at mint time, see `Attesto.LogoutSessionStore`). The take is atomic so
  concurrent logouts cannot double-deliver. Delivery is best-effort: a slow or
  failing RP is logged, never allowed to stall the user's logout. Requires a
  `:logout_session_store`; without one, only RP-Initiated logout runs.

  ## Front-Channel Logout (Front-Channel Logout 1.0 §3)

  The same atomically-taken rows also drive front-channel logout: for every RP
  in the session that registered a `frontchannel_logout_uri`, a browser caller
  (`Accept: text/html`) gets a logout page embedding each URI in a hidden
  iframe — with `iss` and `sid` query parameters whenever the session's `sid`
  is known (see `Attesto.FrontChannelLogout`) — before the flow completes. When
  the request carried a validated `post_logout_redirect_uri`, the page
  continues there via JavaScript once the iframes have loaded (bounded by a
  short timeout, with a meta-refresh and a visible link as fallbacks) so the
  RP-Initiated redirect still happens; with no return URI the page itself is
  the logged-out page. Front-channel delivery is inherently best-effort (the
  browser loads the iframes); a non-browser caller cannot run iframes, so
  front-channel targets are skipped (logged) and the response is unchanged.

  ## Session Management (Session Management 1.0 §3.2)

  When Session Management is enabled, a completed logout also expires the
  JavaScript-readable OP browser-state cookie, so an RP polling the
  `check_session_iframe` observes `changed`.
  """

  use Phoenix.Controller, formats: [:html, :json]

  alias Attesto.EndSession
  alias Attesto.FrontChannelLogout
  alias Attesto.LogoutToken
  alias AttestoPhoenix.{BrowserState, Callback, Config, RequestContext}

  require Logger

  # Front-Channel Logout 1.0 §3: the logout page waits for the RP iframes to
  # load before continuing to the post-logout redirect. The JS continues as
  # soon as every iframe fired `load`, capped by this timeout so an unreachable
  # RP can never stall the user's logout; the meta-refresh is the no-JS fallback.
  @front_channel_timeout_ms 5_000
  @front_channel_meta_refresh_seconds 7

  @spec end_session(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def end_session(conn, params) do
    config = resolve_config()

    with :ok <- require_enabled(config),
         :ok <- check_https(conn, config),
         {:ok, request} <- parse(config, params),
         {:ok, redirect} <- confirm_redirect(config, request) do
      logout(conn, config, request, redirect)
    else
      {:error, status, body} -> render_error(conn, status, body)
    end
  end

  # ── pipeline steps ───────────────────────────────────────────────────────

  defp require_enabled(config) do
    if Config.logout_enabled?(config), do: :ok, else: {:error, 404, %{error: "not_found"}}
  end

  defp check_https(conn, config) do
    case RequestContext.check_https(conn, config) do
      :ok -> :ok
      {:error, :insecure_transport} -> {:error, 400, error_body("TLS required")}
    end
  end

  defp parse(config, params) do
    case EndSession.parse(Config.to_attesto_config(config), params) do
      {:ok, request} -> {:ok, request}
      {:error, :invalid_id_token_hint} -> {:error, 400, error_body("invalid id_token_hint")}
      {:error, :client_id_mismatch} -> {:error, 400, error_body("client_id does not match id_token_hint")}
    end
  end

  # Load the RP's registered post-logout URIs (empty when the client could not
  # be identified) and validate the requested return URI against them.
  defp confirm_redirect(config, request) do
    registered = registered_post_logout_uris(config, request.client_id)

    case EndSession.confirm_redirect(request, registered) do
      {:ok, target} -> {:ok, target}
      {:error, :invalid_post_logout_redirect_uri} -> {:error, 400, error_body("invalid post_logout_redirect_uri")}
    end
  end

  defp registered_post_logout_uris(_config, nil), do: []

  defp registered_post_logout_uris(config, client_id) do
    case Config.client_store_load(config, client_id) do
      {:ok, client} -> Config.client_post_logout_redirect_uris(config, client)
      _ -> []
    end
  end

  # ── perform the logout ───────────────────────────────────────────────────

  defp logout(conn, config, request, redirect) do
    context = %{subject: request.subject, sid: request.sid, client_id: request.client_id}

    case terminate_session(conn, config, context) do
      {:error, status, body} ->
        render_error(conn, status, body)

      {:halt, conn} ->
        conn

      {:ok, conn, session} ->
        # The fan-out scope is the host-confirmed session, NOT the request's
        # id_token_hint — a replayed token cannot force-log-out another session.
        # The rows are taken once (atomically) and drive BOTH notification
        # channels: the back-channel POSTs and the front-channel iframes.
        targets = take_logout_targets(config, session)
        deliver_back_channel(config, session, targets)

        conn
        |> expire_browser_state(config)
        |> finish(config, redirect, context, front_channel_uris(config, targets))
    end
  end

  # Session Management 1.0 §3.2: the OP browser state changes on logout, so an
  # RP polling the check_session_iframe observes `changed`. A no-op unless the
  # host enabled Session Management.
  defp expire_browser_state(conn, config) do
    if Config.session_management_enabled?(config), do: BrowserState.expire(conn, config), else: conn
  end

  # The host is the session authority. A missing callback is fail-closed: a
  # logout endpoint that cannot clear the session must NOT report success, fan
  # out, or redirect — that would be a false-success logout.
  defp terminate_session(conn, config, context) do
    case config.terminate_session do
      nil ->
        Logger.error("end_session: no :terminate_session callback configured")
        {:error, 500, %{error: "server_error", error_description: "logout is not fully configured"}}

      callback ->
        case Callback.invoke(callback, [conn, context]) do
          {:halt, halted} -> {:halt, halted}
          {:ok, %Plug.Conn{} = updated, session} when is_map(session) -> {:ok, updated, session}
          {:ok, %Plug.Conn{} = updated} -> {:ok, updated, %{}}
          %Plug.Conn{} = updated -> {:ok, updated, %{}}
          _ -> {:error, 500, %{error: "server_error", error_description: "logout failed"}}
        end
    end
  end

  # With no front-channel RPs to notify, complete exactly as before: redirect
  # to the validated return URI or hand off to the host's logged-out page.
  defp finish(conn, config, redirect, context, []) do
    case redirect do
      target when is_binary(target) ->
        redirect(conn, external: target)

      :no_redirect ->
        case config.render_logged_out do
          nil -> render_logged_out_default(conn)
          callback -> Callback.invoke(callback, [conn, context])
        end
    end
  end

  # Front-Channel Logout 1.0 §3: a browser gets the iframe-rendering logout
  # page (which then continues the RP-Initiated flow itself). A non-browser
  # caller cannot run iframes, so the front-channel targets are skipped —
  # logged, since those RPs will not learn of the logout — and the response is
  # the plain completion.
  defp finish(conn, config, redirect, context, frame_uris) do
    if accepts_html?(conn) do
      render_front_channel_page(conn, redirect, frame_uris)
    else
      Logger.warning("front-channel logout skipped for non-browser caller: #{length(frame_uris)} RP(s) not notified")

      finish(conn, config, redirect, context, [])
    end
  end

  # ── Response rendering (content-negotiated) ──────────────────────────────

  # The end-session endpoint is browser-facing (RP-Initiated Logout §2: the RP
  # redirects the user agent here), so a browser (`Accept: text/html`) gets a
  # human-readable page and any other caller keeps the JSON body — mirroring the
  # authorization endpoint's direct-error handling.
  defp render_error(conn, status, %{error_description: description} = body) do
    if accepts_html?(conn) do
      conn |> put_resp_content_type("text/html") |> send_resp(status, error_html(description))
    else
      conn |> put_status(status) |> json(body)
    end
  end

  defp render_error(conn, status, body) do
    conn |> put_status(status) |> json(body)
  end

  defp render_logged_out_default(conn) do
    if accepts_html?(conn) do
      conn |> put_resp_content_type("text/html") |> send_resp(200, logged_out_html())
    else
      conn |> put_status(200) |> json(%{status: "logged_out"})
    end
  end

  # Front-Channel Logout 1.0 §3: render every front-channel RP's logout URI in
  # a hidden iframe, then complete the RP-Initiated flow. With a validated
  # return URI the page continues there once the iframes have loaded (JS,
  # capped by the timeout above), with a meta-refresh and a
  # visible link as no-JS fallbacks; with no return URI the page itself is the
  # logged-out page. The response is never cached: it is a one-shot
  # notification fan-out.
  defp render_front_channel_page(conn, redirect, frame_uris) do
    conn
    |> put_resp_header("cache-control", "no-store")
    |> put_resp_content_type("text/html")
    |> send_resp(200, front_channel_html(redirect, frame_uris))
  end

  defp front_channel_html(redirect, frame_uris) do
    iframes =
      Enum.map_join(frame_uris, "\n    ", fn uri ->
        ~s(<iframe src="#{esc(uri)}" aria-hidden="true" tabindex="-1"></iframe>)
      end)

    {title, message} =
      case redirect do
        target when is_binary(target) -> {"Signing out…", "Completing sign-out…"}
        :no_redirect -> {"Signed out", "You are now signed out."}
      end

    """
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>#{esc(title)}</title>
        #{meta_refresh(redirect)}
        <style>
          body { margin: 0; min-height: 100vh; display: grid; place-items: center;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: #f7f8fa; color: #1f2933; }
          main { width: min(560px, calc(100vw - 32px)); padding: 32px;
            border: 1px solid #d8dee6; border-radius: 8px; background: white;
            box-shadow: 0 12px 32px rgba(15, 23, 42, 0.08); }
          h1 { margin: 0 0 12px; font-size: 24px; line-height: 1.2; }
          p { margin: 0; line-height: 1.5; }
          iframe { position: absolute; width: 0; height: 0; border: 0; visibility: hidden; }
        </style>
      </head>
      <body#{continue_attribute(redirect)}>
        <main>
          <h1>#{esc(title)}</h1>
          <p>#{esc(message)}</p>
          #{continue_link(redirect)}
        </main>
        #{iframes}
        #{continue_script(redirect)}
      </body>
    </html>
    """
  end

  # The continuation target rides in an HTML-escaped attribute (the browser
  # unescapes it before getAttribute returns), so the URL never lands inside a
  # script string where it could break out.
  defp continue_attribute(redirect) when is_binary(redirect), do: ~s( data-continue="#{esc(redirect)}")
  defp continue_attribute(:no_redirect), do: ""

  defp meta_refresh(redirect) when is_binary(redirect) do
    ~s(<meta http-equiv="refresh" content="#{@front_channel_meta_refresh_seconds};url=#{esc(redirect)}">)
  end

  defp meta_refresh(:no_redirect), do: ""

  defp continue_link(redirect) when is_binary(redirect) do
    ~s(<p><a href="#{esc(redirect)}">Continue</a></p>)
  end

  defp continue_link(:no_redirect), do: ""

  # Continue to the post-logout redirect once every iframe fired `load`, capped
  # by the timeout so an unreachable RP never stalls the user's logout.
  defp continue_script(redirect) when is_binary(redirect) do
    """
    <script>
      (function () {
        var frames = document.querySelectorAll("iframe");
        var remaining = frames.length;
        var continued = false;
        function go() {
          if (continued) { return; }
          continued = true;
          window.location.replace(document.body.getAttribute("data-continue"));
        }
        function loaded() {
          remaining -= 1;
          if (remaining <= 0) { setTimeout(go, 100); }
        }
        for (var i = 0; i < frames.length; i++) {
          frames[i].addEventListener("load", loaded);
        }
        setTimeout(go, #{@front_channel_timeout_ms});
      })();
    </script>
    """
  end

  defp continue_script(:no_redirect), do: ""

  defp accepts_html?(conn) do
    conn
    |> get_req_header("accept")
    |> Enum.any?(fn value -> String.contains?(String.downcase(value), "text/html") end)
  end

  defp error_html(description) do
    page("Logout error", ~s(<code>invalid_request</code>), esc(description))
  end

  defp logged_out_html do
    page("Signed out", "", "You are now signed out.")
  end

  defp page(title, badge, body_html) do
    """
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>#{esc(title)}</title>
        <style>
          body { margin: 0; min-height: 100vh; display: grid; place-items: center;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: #f7f8fa; color: #1f2933; }
          main { width: min(560px, calc(100vw - 32px)); padding: 32px;
            border: 1px solid #d8dee6; border-radius: 8px; background: white;
            box-shadow: 0 12px 32px rgba(15, 23, 42, 0.08); }
          h1 { margin: 0 0 12px; font-size: 24px; line-height: 1.2; }
          p { margin: 0; line-height: 1.5; }
          code { display: inline-block; margin-bottom: 16px; padding: 4px 8px;
            border-radius: 4px; background: #eef2f7; font-size: 14px; }
        </style>
      </head>
      <body>
        <main>
          #{badge}
          <h1>#{esc(title)}</h1>
          <p>#{body_html}</p>
        </main>
      </body>
    </html>
    """
  end

  defp esc(value) do
    value
    |> to_string()
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\"", "&quot;")
    |> String.replace("'", "&#39;")
  end

  # ── Logout fan-out (Back-Channel Logout 1.0 §2.5 + Front-Channel 1.0 §3) ──

  # Atomically take (enumerate-and-delete in one statement) the RP rows of the
  # host-confirmed session, so a session is logged out exactly once even under
  # concurrent end-session calls. `session` is the `%{sid|subject}` the host
  # attested it terminated. Best-effort: a store failure is logged, never
  # allowed to block the user's logout.
  defp take_logout_targets(config, session) do
    store = Config.logout_session_store(config)
    criteria = logout_criteria(session)

    if not is_nil(store) and map_size(criteria) > 0 do
      store.take_targets(criteria)
    else
      []
    end
  rescue
    e ->
      Logger.warning("logout session take failed: #{inspect(e)}")
      []
  end

  # POST a signed logout_token to every back-channel-capable RP in the taken set.
  defp deliver_back_channel(config, session, targets) do
    http = Config.backchannel_logout_http(config)
    attesto_config = Config.to_attesto_config(config)

    targets
    |> Enum.filter(&is_binary(&1.backchannel_logout_uri))
    |> Enum.each(&deliver(attesto_config, http, session, &1))
  rescue
    e -> Logger.warning("back-channel logout fan-out failed: #{inspect(e)}")
  end

  defp deliver(attesto_config, http, session, target) do
    opts =
      []
      |> put_opt(:sub, Map.get(session, :subject))
      |> put_opt(:sid, target.sid)

    with {:ok, token} <- LogoutToken.mint(attesto_config, target.client_id, opts),
         :ok <- http.post(target.backchannel_logout_uri, token) do
      :ok
    else
      {:error, reason} ->
        Logger.warning("back-channel logout to #{target.client_id} failed: #{inspect(reason)}")
        :error
    end
  end

  # The exact iframe URIs the logout page renders: each front-channel-capable
  # RP's registered frontchannel_logout_uri, with iss/sid appended whenever the
  # session's sid is known (Front-Channel Logout 1.0 §2 — both or neither).
  defp front_channel_uris(config, targets) do
    attesto_config = Config.to_attesto_config(config)

    for target <- targets, is_binary(target.frontchannel_logout_uri) do
      FrontChannelLogout.logout_uri(attesto_config, target.frontchannel_logout_uri, target.sid)
    end
  end

  # `:sid` scopes the fan-out to one session; `:subject` (no sid) to all of the
  # subject's sessions. A session map with neither identifies nothing.
  defp logout_criteria(%{sid: sid}) when is_binary(sid) and sid != "", do: %{sid: sid}
  defp logout_criteria(%{subject: sub}) when is_binary(sub) and sub != "", do: %{subject: sub}
  defp logout_criteria(_session), do: %{}

  defp put_opt(opts, _key, nil), do: opts
  defp put_opt(opts, _key, ""), do: opts
  defp put_opt(opts, key, value), do: Keyword.put(opts, key, value)

  defp error_body(description), do: %{error: "invalid_request", error_description: description}

  defp resolve_config do
    otp_app = Application.get_env(:attesto_phoenix, :otp_app)
    Config.from_otp_app(otp_app, Config)
  end
end
