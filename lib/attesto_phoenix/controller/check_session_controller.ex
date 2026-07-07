defmodule AttestoPhoenix.Controller.CheckSessionController do
  @moduledoc """
  The `check_session_iframe` (OpenID Connect Session Management 1.0 §3.3).

  Serves the OP iframe an RP embeds (invisibly) to poll the End-User's login
  state at the OP without network traffic. The RP's own iframe posts
  `client_id + " " + session_state` here (§3.1); this page's script recomputes
  the `session_state` from the message's `client_id`, the **sender's origin**
  (`MessageEvent.origin` — so a message from the wrong origin can never
  compare equal), the current OP browser-state cookie, and the salt carried in
  the received value, then posts back exactly one of (§3.2):

    * `unchanged` — the recomputed value equals the received one;
    * `changed` — it does not (the user logged out, or the state rotated);
    * `error` — the message is syntactically malformed.

  The computation is the mirror image of `Attesto.SessionState.compute/4`
  (lowercase-hex SHA-256 over `client_id <> " " <> origin <> " " <> opbs <>
  " " <> salt`, dot, salt); the hash runs on `crypto.subtle`, which is always
  available here because the page is served from the OP's HTTPS origin. The
  browser-state cookie is the JavaScript-readable cookie maintained by the
  authorization endpoint (set at login) and the end-session endpoint (expired
  at logout) — see `AttestoPhoenix.BrowserState`.

  The page embeds no per-user data (the cookie is read client-side at message
  time), so it is served cacheable like the discovery document. It is mounted
  by `AttestoPhoenix.Router`'s `session_management: true` option and answers
  404 unless the host enabled `session_management: [enabled: true]`, so a
  mounted-but-unconfigured route never advertises a capability that is off.
  """

  use Phoenix.Controller, formats: [:html, :json]

  import Plug.Conn

  alias AttestoPhoenix.Config

  # The page is static for a given configuration; cache like the discovery
  # document (the login-state answer is computed in the browser per message,
  # never baked into the page).
  @cache_max_age_seconds 3600

  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, _params) do
    config = resolve_config()

    if Config.session_management_enabled?(config) do
      conn
      |> put_resp_header("cache-control", "public, max-age=#{@cache_max_age_seconds}")
      |> put_resp_content_type("text/html")
      |> send_resp(200, page_html(Config.browser_state_cookie(config)))
    else
      conn |> put_status(404) |> json(%{error: "not_found"})
    end
  end

  # The §3.2 OP iframe. The cookie name is configuration (not user input) and
  # rides into the script as a JSON string literal, so it cannot break out of
  # the JavaScript context.
  defp page_html(cookie_name) do
    cookie_literal = JSON.encode!(cookie_name)

    """
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <title>OP session check</title>
      </head>
      <body>
        <script>
          (function () {
            var COOKIE = #{cookie_literal};

            function browserState() {
              var prefix = COOKIE + "=";
              var parts = document.cookie ? document.cookie.split("; ") : [];
              for (var i = 0; i < parts.length; i++) {
                if (parts[i].indexOf(prefix) === 0) {
                  return decodeURIComponent(parts[i].substring(prefix.length));
                }
              }
              return "";
            }

            function sha256Hex(text) {
              var bytes = new TextEncoder().encode(text);
              return crypto.subtle.digest("SHA-256", bytes).then(function (digest) {
                var view = new Uint8Array(digest);
                var hex = "";
                for (var i = 0; i < view.length; i++) {
                  hex += view[i].toString(16).padStart(2, "0");
                }
                return hex;
              });
            }

            function reply(event, message) {
              if (event.source) {
                event.source.postMessage(message, event.origin);
              }
            }

            window.addEventListener("message", function (event) {
              var data = event.data;
              if (typeof data !== "string") { return; }

              // Session Management 1.0 section 3.1: "client_id + ' ' + session_state".
              var separator = data.lastIndexOf(" ");
              if (separator < 1 || separator === data.length - 1) {
                reply(event, "error");
                return;
              }

              var clientId = data.substring(0, separator);
              var sessionState = data.substring(separator + 1);
              var dot = sessionState.indexOf(".");
              if (dot < 1 || dot === sessionState.length - 1) {
                reply(event, "error");
                return;
              }

              var salt = sessionState.substring(dot + 1);
              var text = clientId + " " + event.origin + " " + browserState() + " " + salt;

              sha256Hex(text).then(function (hash) {
                reply(event, (hash + "." + salt) === sessionState ? "unchanged" : "changed");
              }).catch(function () {
                reply(event, "error");
              });
            }, false);
          })();
        </script>
      </body>
    </html>
    """
  end

  defp resolve_config do
    otp_app = Application.get_env(:attesto_phoenix, :otp_app)
    Config.from_otp_app(otp_app, Config)
  end
end
