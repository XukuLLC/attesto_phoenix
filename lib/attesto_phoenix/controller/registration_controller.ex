defmodule AttestoPhoenix.Controller.RegistrationController do
  @moduledoc """
  OAuth 2.0 Dynamic Client Registration endpoint (RFC 7591 §3).

  Handles `POST /oauth/register` and, at the client configuration endpoint
  `/oauth/register/:client_id` (RFC 7592 §2), `GET` (read), `PUT` (update) and
  `DELETE`. This
  module owns the HTTP and protocol-framing concerns only: it enforces TLS
  (`require_https`), checks `Content-Type: application/json`, extracts the
  parsed JSON request body or `Bearer` registration access token off the
  `Plug.Conn`, delegates metadata validation, credential minting, and host
  persistence to the conn-free `AttestoPhoenix.AuthorizationServer.Registration`
  core, dispatches the returned `:client_registered` audit event, and renders
  the RFC 7591 §3.2.1 client information response or the RFC 7591 §3.2.2 error
  body.

  ## Disabled by default

  Dynamic registration is an open door: a successful request mints a new client
  from an otherwise unauthenticated POST. The library therefore mounts this
  endpoint only when the host opts in (`AttestoPhoenix.Router`'s
  `:registration` option) AND supplies a `:register_client` callback
  (`AttestoPhoenix.Config` raises at boot otherwise). Any admission control the
  host wants in front of registration - a registration access token
  (RFC 7591 §3), an allowlist, rate limiting - lives in the host pipeline ahead
  of this action; the library does not assume one.

  ## Wire contract

  `POST /oauth/register` with `application/json`: the request body is a JSON
  client-metadata document (RFC 7591 §3.1). Any other Content-Type is rejected
  as `invalid_client_metadata` rather than parsed through an unintended path. A
  metadata document carries nested arrays (`redirect_uris`, `grant_types`) that
  have no canonical form-encoded representation, so no form encoding is offered
  here.

  Recognised metadata members (RFC 7591 §2) include `redirect_uris`,
  `grant_types`, `token_endpoint_auth_method`, and a space-delimited `scope`
  string. The request is validated member by member against the server's policy
  inputs - the scope catalog (`AttestoPhoenix.Config`'s `:scopes_supported`),
  the supported grant types, and the supported token-endpoint auth methods -
  and the first failure is returned.

  An omitted `application_type` uses the host's
  `:registration_default_application_type` profile, which defaults to `"web"`.
  Explicit client values are preserved. Native HTTP loopback registrations
  honor the configured `:native_apps` loopback and `localhost` policies.

  Human-readable client metadata remains untrusted after registration. It is
  stored verbatim after size, UTF-8, and control-character checks; a host
  consent or administration UI must HTML-escape it at the rendering sink.
  Logout callback URIs use an intentional HTTPS-only server profile even where
  an OpenID logout specification permits a confidential deployment to allow
  plain HTTP.

  ## Issued credentials

  `AttestoPhoenix.AuthorizationServer.Registration` mints the `client_id` and
  (for `client_secret_basic` or `client_secret_post`) a high-entropy
  `client_secret` via `Attesto.Secret` (RFC 6749 §2.3.1 high-entropy secret).
  The plaintext secret appears in the RFC 7591 §3.2.1 response exactly once,
  accompanied by the REQUIRED `client_secret_expires_at` (`0`, non-expiring);
  only its one-way hash is handed to the host for persistence, so a leaked
  client store yields no usable secret.

  ## Responses

  Success renders HTTP 201 with the RFC 7591 §3.2.1 client information response
  (the registered metadata plus the synthesised `client_id`, the optional
  `client_secret` with its REQUIRED `client_secret_expires_at`, and
  `client_id_issued_at`). Failure renders the RFC 7591 §3.2.2 error body
  (`{"error": code, "error_description": ...}`) with the RFC 7591 §3.2.2 codes
  `invalid_redirect_uri` and `invalid_client_metadata`. A host store rejection
  surfaces as `invalid_client_metadata` (the request named a client the store
  would not accept) rather than a 500. Both success and error responses carry
  no-store cache headers (RFC 7234 §5.2) because the body can carry a freshly
  minted credential.

  ## Event

  A successful registration emits a `:client_registered` event (RFC 7591)
  through `AttestoPhoenix.Event` carrying the issued `client_id`. The plaintext
  secret is never placed on the event.
  """

  use AttestoPhoenix.Controller, formats: [:json]

  import Plug.Conn

  alias AttestoPhoenix.AuthorizationServer.Registration
  alias AttestoPhoenix.AuthorizationServer.Registration.Request
  alias AttestoPhoenix.{Config, Event, OAuthError}

  # RFC 7591 §3.1: the registration request body is a JSON object.
  @content_type_json "application/json"

  # RFC 7234 §5.2: a credential-bearing response must never be cached.
  # RFC 7591 §3.2.2 / RFC 6750 error codes.
  @error_invalid_client_metadata :invalid_client_metadata
  @error_invalid_token :invalid_token

  @doc """
  Dynamic client registration action (RFC 7591 §3.1).

  Validates the client-metadata document, mints the client's credentials,
  persists via the host callback, and renders either the RFC 7591 §3.2.1
  client information response or an RFC 7591 §3.2.2 error. Every response
  carries no-store cache headers (RFC 7234 §5.2).
  """
  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, _params) do
    config = Config.resolve!(conn)
    conn = OAuthError.no_store(conn, config)

    with :ok <-
           require_https(
             conn,
             config,
             {:error, error(:invalid_request, "the request must be made over TLS")}
           ),
         :ok <- Registration.check_enabled(config),
         :ok <- check_content_type(conn),
         {:ok, request} <- build_request(conn),
         {:ok, response, events} <- Registration.register(config, request) do
      emit_all(config, events)

      conn
      |> put_status(:created)
      |> json(response)
    else
      {:error, %OAuthError{} = err} -> render_error(conn, err)
    end
  end

  @doc """
  Client read action (RFC 7592 §2.1): `GET /oauth/register/:client_id` with the
  registration access token. Renders the client's current registration.

  A host must wire `:client_registration_access_token_hash` and
  `:client_registration_metadata`; absent either, the endpoint fails closed.
  """
  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, %{"client_id" => client_id}) when is_binary(client_id) do
    config = Config.resolve!(conn)
    conn = OAuthError.no_store(conn, config)

    with :ok <- require_management_https(conn, config),
         {:ok, response} <- Registration.read(config, client_id, registration_bearer_token(conn)) do
      json(conn, response)
    else
      {:error, %OAuthError{} = err} -> render_delete_error(conn, err)
    end
  end

  @doc """
  Client update action (RFC 7592 §2.2): `PUT /oauth/register/:client_id` with
  the registration access token and the client's complete new metadata as
  `application/json`. Renders the updated registration.

  A host must wire `:client_registration_access_token_hash`,
  `:client_registration_metadata` and `:update_client`; absent any, the
  endpoint fails closed.
  """
  @spec update(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def update(conn, %{"client_id" => client_id}) when is_binary(client_id) do
    config = Config.resolve!(conn)
    conn = OAuthError.no_store(conn, config)

    with :ok <- require_management_https(conn, config),
         :ok <- check_content_type(conn),
         {:ok, response, events} <-
           Registration.update(config, client_id, registration_bearer_token(conn), Map.get(conn, :body_params)) do
      emit_all(config, events)
      json(conn, response)
    else
      {:error, %OAuthError{} = err} -> render_delete_error(conn, err)
    end
  end

  defp require_management_https(conn, config) do
    require_https(conn, config, {:error, error(:invalid_request, "the request must be made over TLS")})
  end

  @doc """
  Dynamic client registration management delete action (RFC 7592 §2).

  Deletes a previously registered client at its client configuration endpoint
  (RFC 7592 §2.3). A host must wire both
  `:client_registration_access_token_hash` and `:unregister_client`; absent
  either callback, the endpoint fails closed.
  """
  @spec delete(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def delete(conn, %{"client_id" => client_id}) when is_binary(client_id) do
    config = Config.resolve!(conn)
    conn = OAuthError.no_store(conn, config)

    with :ok <-
           require_https(
             conn,
             config,
             {:error, error(:invalid_request, "the request must be made over TLS")}
           ),
         :ok <- Registration.unregister(config, client_id, registration_bearer_token(conn)) do
      send_resp(conn, :no_content, "")
    else
      {:error, %OAuthError{} = err} -> render_delete_error(conn, err)
    end
  end

  # ── Request parsing ──────────────────────────────────────────────────────

  # RFC 7591 §3.1: the metadata document is the JSON request body. Read it from
  # the parsed body only; a query-string copy would leak into proxy logs and is
  # not part of the wire contract.
  defp build_request(%Plug.Conn{} = conn) do
    Request.from_params(Map.get(conn, :body_params))
  end

  defp check_content_type(conn) do
    case get_req_header(conn, "content-type") do
      [] ->
        {:error,
         error(
           @error_invalid_client_metadata,
           "registration requests must be #{@content_type_json} (RFC 7591 §3.1)"
         )}

      [value] ->
        type =
          value
          |> String.split(";", parts: 2)
          |> List.first()
          |> String.trim()
          |> String.downcase()

        if type == @content_type_json do
          :ok
        else
          {:error,
           error(
             @error_invalid_client_metadata,
             "registration requests must be #{@content_type_json} (RFC 7591 §3.1)"
           )}
        end

      _multiple ->
        {:error,
         error(
           @error_invalid_client_metadata,
           "registration requests must contain exactly one Content-Type header"
         )}
    end
  end

  # ── Helpers ──────────────────────────────────────────────────────────────

  defp registration_bearer_token(conn) do
    with [header] <- get_req_header(conn, "authorization"),
         [scheme, token] when token != "" <- String.split(header, " ", parts: 2),
         true <- String.downcase(scheme) == "bearer" do
      token
    else
      _ -> nil
    end
  end

  # ── Rendering (RFC 7591 §3.2.2) ──────────────────────────────────────────

  defp emit_all(config, events) do
    callback = Config.on_event_fun(config)
    Enum.each(events, &Event.dispatch(callback, &1))
  end

  defp render_error(conn, %OAuthError{} = err) do
    OAuthError.render(conn, err, auth_scheme: :none, config: Config.resolve!(conn))
  end

  defp render_delete_error(conn, %OAuthError{error: @error_invalid_token} = err) do
    OAuthError.render(conn, err, auth_scheme: :bearer, config: Config.resolve!(conn))
  end

  defp render_delete_error(conn, %OAuthError{} = err), do: render_error(conn, err)

  defp error(code, description), do: OAuthError.new(code, description, status: 400)
end
