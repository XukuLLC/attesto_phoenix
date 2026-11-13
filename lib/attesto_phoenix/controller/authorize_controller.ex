defmodule AttestoPhoenix.Controller.AuthorizeController do
  @moduledoc """
  OAuth 2.0 / OpenID Connect authorization endpoint (RFC 6749 §3.1,
  OIDC Core §3.1.2).

  Handles `GET /oauth/authorize`, the front-channel browser flow that ends in
  an authorization code (RFC 6749 §4.1). This module owns only the HTTP and
  protocol-framing concerns: it parses and validates the request through
  `Attesto.AuthorizationRequest`, classifies failures by where they may be
  reported (OIDC Core §3.1.2.6), and on success mints a single-use code through
  `Attesto.AuthorizationCode.issue/3` and redirects back to the client. Every
  identity decision - who the resource owner is, and whether they consent - is
  delegated to host callbacks on `AttestoPhoenix.Config`. No login or consent
  UI lives here.

  ## Error disposition (OIDC Core §3.1.2.6, RFC 6749 §4.1.2.1)

  The `client_id` and `redirect_uri` are validated BEFORE anything is rendered
  or redirected. A request whose `client_id` is unknown, or whose
  `redirect_uri` does not exactly match the client's registered set, is
  untrusted: the server MUST NOT redirect back to the supplied URI (that would
  be an open redirect), so it renders a direct error page to the user agent.
  Only once the `client_id`/`redirect_uri` pair is established as trusted is any
  further error (bad `response_type`, `scope`, PKCE, `max_age`) reported by
  redirecting back to the validated `redirect_uri` with an `error` (and
  `error_description`/`state`) query parameter. `Attesto.AuthorizationRequest`
  performs this classification; this controller turns each class into the
  correct HTTP response.

  ## PKCE is mandatory (RFC 7636)

  `Attesto.AuthorizationRequest` requires a valid S256 `code_challenge`; there
  is no PKCE-less path. The challenge is carried into the issued code so the
  token endpoint can verify the matching verifier on redemption.

  ## Resource-owner authentication and consent (host policy)

  Authenticating the end user and obtaining consent are host policy, not
  protocol, so they are delegated to two `AttestoPhoenix.Config` callbacks:

    * `:authenticate_resource_owner` - `(conn, request, auth_opts ->
      {:authenticated, subject} | {:halt, conn} | {:none} | {:error,
      :login_required | :consent_required | :interaction_required})`. Returns
      `{:authenticated, subject}` once a resource owner is established for this
      request, `{:halt, conn}` to take over the connection (e.g. redirect to a
      login page that, after login, re-enters this endpoint with the same
      authorization parameters), `{:none}` when no subject can be established
      without UI, or an `{:error, _}` to explicitly classify why interaction is
      required (OIDC Core §3.1.2.6). The `subject` is a map carrying at least
      `:subject` (the subject identifier, OIDC Core §2 `sub`) and optionally
      `:auth_time`, `:acr`, and `:amr` (OIDC Core §2), plus `:sid` (the host's
      session id, OIDC Back-Channel Logout 1.0 §2.1 — supply it to make the
      session reachable by the end-session endpoint), threaded into the code's
      claims so the token endpoint can mint the ID token.

      For `prompt=login`, `auth_time` must be at or after
      `auth_opts.prompt_login_since` on resume: the first park time for a login
      detour, or the bound already checked before a first park in consent.
      A fresh request permits 60 seconds before request arrival,
      matching the interactive `max_age` allowance. An unusable time is logged
      and returned as `server_error` (OIDC Core §3.1.2.3).

      `auth_opts` is a map carrying the OIDC Core §3.1.2.1 authentication
      directives the host MUST honour: `:prompt` (the parsed `prompt` list),
      `:force_reauth` (`true` for `prompt=login`: reauthenticate even if a
      session exists, returning a fresh `auth_time`), `:interactive` (`false`
      for `prompt=none`: the host MUST NOT render any UI, returning
      `{:authenticated, subject}` only if it can be established silently, else
      `{:none}`), and `:max_age` (when present, the host MUST reauthenticate if
      the existing authentication is older and return the resulting
      `auth_time`). The controller checks the returned `auth_time` against
      `max_age`. Under `prompt=none` an authentication that is too old is
      answered `login_required`. On an interactive request it is a host
      contract violation answered `server_error`, with 60 seconds allowed
      beyond `max_age` for the hop back from the host's login. A missing
      `auth_time` when `max_age` was requested is `server_error` under either
      prompt. Under `prompt=none` the controller converts a `{:halt,
      conn}` or `{:none}` into a `login_required` redirect rather than letting
      any UI run; a `{:halt, conn}` consent screen becomes `consent_required`
      (OIDC Core §3.1.2.6).

    * `:consent` - `(conn, request, subject -> {:consented, subject} |
      {:halt, conn} | {:denied, reason})`. Returns `{:consented, subject}` once
      the resource owner has authorized the request (the returned `subject` may
      carry consent-derived claims), `{:halt, conn}` to take over the
      connection (e.g. render a consent screen that re-enters this endpoint), or
      `{:denied, _reason}` to refuse, which is reported back to the client as
      the RFC 6749 §4.1.2.1 `access_denied` error by redirect. When the host
      does not supply `:consent`, consent is treated as implicitly granted only
      for a client the host explicitly classifies as confidential. Public
      clients require an explicit consent callback before a code can be issued.
      Without `:consent`, a request carrying `prompt=consent` is answered
      `consent_required` by redirect, since the library cannot prompt the
      resource owner itself (OIDC Core §3.1.2.1).

  Both callbacks may hand control back to a host-rendered page; the controller
  only proceeds to mint a code when both yield a subject. The actual login and
  consent UI lives in the host application, never in this library.

  ## Configuration contract

  All host policy is resolved through `AttestoPhoenix.Config`; nothing is
  hardcoded here. This controller reads (see `AttestoPhoenix.Config` for the
  authoritative definitions and defaults):

    * `:load_client` - client lookup and revocation gate (RFC 6749 §2.2). An
      unknown or revoked client is a direct (non-redirectable) error.
    * `:client_redirect_uris` - `(client -> [String.t()])` the client's
      registered redirect URIs, the trusted set the request `redirect_uri` is
      exact-matched against (RFC 6749 §3.1.2.3).
    * `:client_id` - `(client -> String.t())` the client's identifier, carried
      into the issued code.
    * `:authenticate_resource_owner`, `:consent` - the host login/consent hooks
      described above.
    * `:code_store` - the `Attesto.CodeStore` backing the issued code.
    * `:authorization_code_ttl` - the code lifetime, seconds.
    * `:on_event` - the optional audit/telemetry hook (via
      `AttestoPhoenix.Event`).
  """

  use AttestoPhoenix.Controller, formats: [:json]

  import Plug.Conn

  alias Attesto.{AuthorizationCode, AuthorizationRequest, MapParams}
  alias Attesto.JARM
  alias Attesto.ResourceIndicator
  alias Attesto.Secret
  alias Attesto.SessionState
  alias AttestoPhoenix.AuthorizationCodePrivateContext, as: PrivateContext
  alias AttestoPhoenix.AuthorizationServer.Continuation
  alias AttestoPhoenix.AuthorizationServer.RequestPolicy
  alias AttestoPhoenix.AuthorizationServer.ScopeAuthorization
  alias AttestoPhoenix.{BrowserState, Callback, Config, Event, HTTPAccept, RequestContext}
  alias AttestoPhoenix.ClientIdMetadata
  alias AttestoPhoenix.ClientIdMetadata.Client, as: CIMDClient
  alias AttestoPhoenix.Interaction
  alias AttestoPhoenix.OAuthError, as: PhoenixOAuthError
  alias AttestoPhoenix.RouteControls
  alias AttestoPhoenix.Store.PAR.ETS

  require Logger

  # RFC 6749 §4.1.2.1 error codes reported by redirect.
  @error_access_denied "access_denied"
  @error_server_error "server_error"

  # RFC 8707 §2 / RFC 6749 §5.2: a requested `resource` the server does not serve.
  @error_invalid_target "invalid_target"
  @error_invalid_scope "invalid_scope"
  @resumed_private_key :attesto_phoenix_resumed_interaction

  # RFC 9126 §2.3: the PAR `request_uri` is no longer usable. Reported at
  # completion (by redirect, the request is already validated) when the
  # single-use claim is lost - a concurrent completion consumed the reference, or
  # it expired during login/consent.
  @error_invalid_request_uri "invalid_request_uri"

  # OIDC Core §3.1.2.6 error codes reported by redirect when prompt=none cannot
  # be satisfied without interaction.
  @error_login_required "login_required"
  @error_consent_required "consent_required"
  @error_interaction_required "interaction_required"

  # OIDC Core §3.1.2.1: the `prompt` values this controller acts on.
  @prompt_none "none"
  @prompt_login "login"
  @prompt_consent "consent"

  @doc """
  Authorization endpoint action (RFC 6749 §3.1, OIDC Core §3.1.2).

  Validates the request, authenticates and obtains consent from the resource
  owner via host callbacks, issues a single-use authorization code, and
  302-redirects back to the client's `redirect_uri` with `code` (and `state`,
  when present). Failures are dispatched to a direct error page or a redirected
  error per the classification in the moduledoc.
  """
  @spec authorize(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def authorize(conn, params) do
    conn = put_private(conn, :attesto_phoenix_authorization_arrived_at, System.system_time(:second))
    config = Config.resolve!(conn)
    # `par: false` with a configuration that requires PAR cannot serve any
    # request; fail loudly instead of answering each client `invalid_request`.
    :ok = RouteControls.check_par!(conn, config)

    case resume_parked_request(conn, config, params) do
      {:ok, conn, params} ->
        authorize_params(conn, config, params)

      {:error, reason} ->
        emit_failure(conn, config, reason)
        render_direct_error(conn, config, reason)
    end
  end

  # ── Resume (AttestoPhoenix.Interaction) ──────────────────────────────────

  # A request carrying `resume` stands for a request parked earlier with
  # `AttestoPhoenix.Interaction.park/2`. The parked parameters replace the
  # request's and then go through the whole pipeline below as a fresh request
  # would. `resume` alone identifies the request, so any other parameter beside
  # it is refused: it could only be an attempt to alter what was parked.
  defp resume_parked_request(conn, config, %{"resume" => resume_id} = params) do
    with true <- map_size(params) == 1,
         :ok <- RequestContext.check_https(conn, config),
         {:ok, parked} <- Interaction.take(config, conn, resume_id) do
      conn = Plug.Conn.put_private(conn, @resumed_private_key, parked)
      {:ok, conn, Interaction.request_params(conn)}
    else
      false -> {:error, :resume_with_parameters}
      {:error, :insecure_transport} -> {:error, :insecure_transport}
      {:error, :invalid_resume} -> {:error, :invalid_resume}
    end
  end

  defp resume_parked_request(conn, _config, params), do: {:ok, conn, params}

  defp resumed(conn), do: conn.private[@resumed_private_key]

  # The parked request named the client it was validated for. The resumed
  # parameters are the same ones, so this holds unless the stored entry was
  # altered; it is checked rather than assumed.
  defp check_resumed_client(conn, request) do
    case resumed(conn) do
      nil -> :ok
      %{client_id: client_id} when client_id == request.client_id -> :ok
      _mismatch -> {:error, {:direct, :invalid_resume}}
    end
  end

  defp authorize_params(conn, config, params) do
    # Capture the PAR reference before resolution rebinds `params` to the stored
    # set, so it can be consumed once (and only once) a code is issued.
    par_request_uri = params["request_uri"]

    with :ok <- RequestContext.check_https(conn, config),
         :ok <- RequestContext.check_embedded_user_agent(conn, config),
         {:ok, params, par_resolved?} <- resolve_request_uri(config, params),
         {:ok, client} <- load_client(config, params),
         {:ok, request} <- validate_request(config, client, params, par_resolved?),
         :ok <- check_resumed_client(conn, request),
         {:ok, request} <- authorize_scope(config, client, request) do
      conn
      |> stash_par_request_uri(par_request_uri, par_resolved?)
      |> stash_credential_configuration_ids(credential_configuration_ids(config, request))
      |> run_flow(config, client, request, authorize_dpop_jkt(request, params, par_resolved?))
    else
      {:error, :insecure_transport} ->
        # RFC 6749 §3.1 / §10.1: the authorization endpoint requires TLS. The
        # request is untrusted, so this is a direct error, never a redirect.
        render_direct_error(conn, config, :insecure_transport)

      {:error, :embedded_user_agent} ->
        # RFC 8252 §8.12 (opt-in, `native_apps: [reject_embedded_user_agents:
        # true]`): the request appears to come from an in-app webview, whose
        # host application can observe the credentials the user is about to
        # enter. Refused before the client is resolved - the decision depends on
        # nothing but the request - and reported directly: redirecting the flow
        # onward would leave it inside the webview being refused.
        emit_failure(conn, config, :embedded_user_agent)
        render_direct_error(conn, config, :embedded_user_agent)

      {:error, {:direct, reason}} ->
        # OIDC Core §3.1.2.6: bad client_id / redirect_uri is non-redirectable.
        emit_failure(conn, config, reason)
        render_direct_error(conn, config, reason)

      {:error, {:redirect, error}} ->
        # RFC 6749 §4.1.2.1: the client_id/redirect_uri pair is trusted, so the
        # error is reported by redirecting back to the validated redirect_uri.
        emit_failure(conn, config, error.error)
        emit_redirect_error(conn, config, error)

      {:error, {:scope_refused, request, error_code}} ->
        # RFC 6749 §4.1.2.1 `invalid_scope` / RFC 8707 §2 `invalid_target`: the
        # host's scope policy refused a fully validated request.
        emit_failure(conn, config, error_code)
        emit_error(conn, config, request, error_code)
    end
  end

  # ── Scope policy (RFC 6749 §3.3 / §4.1.2.1, RFC 8707 §2) ─────────────────

  # The host's scope policy runs here, on the validated request and before the
  # resource owner is asked to authenticate, with the same arguments the token
  # endpoint will pass. A scope the policy would refuse at redemption is
  # refused now, as a redirectable error that `prompt=none` does not change,
  # and a narrowed scope is what consent sees and the code is bound to. The
  # policy may only narrow: a scope it adds is treated as a refusal.
  defp authorize_scope(config, client, request) do
    case ScopeAuthorization.authorize(config, client, request.scope, request.resource) do
      {:ok, granted} ->
        if ScopeAuthorization.within_request?(granted, request.scope),
          do: {:ok, %{request | scope: granted}},
          else: {:error, {:scope_refused, request, @error_invalid_scope}}

      {:error, :invalid_scope} ->
        {:error, {:scope_refused, request, @error_invalid_scope}}

      {:error, :invalid_target} ->
        {:error, {:scope_refused, request, @error_invalid_target}}
    end
  end

  # ── Client lookup (RFC 6749 §2.2 / OIDC Core §3.1.2.6) ───────────────────

  # The client must be resolved BEFORE validating the request, because its
  # registered redirect-URI set is the trusted set the request `redirect_uri`
  # is matched against. An unknown or revoked client is non-redirectable: the
  # supplied redirect_uri cannot be trusted (OIDC Core §3.1.2.6), so it is
  # reported as a direct error. A request without a usable `client_id` is the
  # same class; `Attesto.AuthorizationRequest` would classify it identically,
  # but it is caught here too so a missing `client_id` never reaches
  # `:load_client`.
  #
  # CIMD (`draft-ietf-oauth-client-id-metadata-document-01`): when the feature
  # is enabled and the presented `client_id` is a CIMD URL, the client is
  # dereferenced from that URL rather than looked up in the host registry. An
  # unresolvable or invalid CIMD `client_id` is the same non-redirectable class
  # as an unknown registry client (the document - and so its trusted
  # redirect_uris - never materialized), so it is reported as a direct error.
  # The resolved CIMD client is wrapped as `%CIMDClient{metadata: metadata}` so the request
  # validation, jwks, and `client_id` helpers read the document directly instead
  # of the host's per-client callbacks.
  defp load_client(config, params) do
    case params["client_id"] do
      client_id when is_binary(client_id) and client_id != "" ->
        if ClientIdMetadata.cimd_client_id?(client_id, config) do
          load_cimd_client(config, client_id)
        else
          load_registered_client(config, client_id)
        end

      _ ->
        {:error, {:direct, :invalid_client_id}}
    end
  end

  defp load_registered_client(config, client_id) do
    case Config.client_store_load(config, client_id) do
      {:ok, client} ->
        {:ok, client}

      {:error, reason} when reason in [:not_found, :revoked] ->
        {:error, {:direct, :invalid_client_id}}
    end
  end

  defp load_cimd_client(config, client_id) do
    case ClientIdMetadata.resolve(client_id, config) do
      {:ok, metadata} -> {:ok, %CIMDClient{metadata: metadata}}
      {:error, _reason} -> {:error, {:direct, :invalid_client_id}}
    end
  end

  # ── Request validation (Attesto.AuthorizationRequest) ────────────────────

  # The registered redirect-URI set is a fact the host supplies via
  # `:client_redirect_uris`; the match check is protocol and is performed by
  # `Attesto.AuthorizationRequest` (RFC 6749 §3.1.2.3). A host that does not
  # supply the callback exposes no registered URIs, so every request is rejected
  # with `{:direct, :redirect_uri_not_registered}` (fail closed) rather than
  # silently trusting the supplied URI. Matching is exact unless the host marked
  # this client native, in which case RFC 8252 §7.3 lets its loopback redirect
  # URI vary in port; `RequestPolicy.redirect_uri_matching/2` owns that
  # decision. An unmatched URI stays non-redirectable under every policy.
  #
  # OIDC Core §3.1.2.1: the `nonce` is OPTIONAL for the code flow by default, but
  # an OpenID Provider MAY require it. When the host sets `:require_nonce`, a
  # request whose scope contains `openid` (an OpenID Connect Authentication
  # Request) must carry a `nonce`; the core rejects a missing one with a
  # redirectable `invalid_request`. A plain OAuth 2.0 request (no `openid` scope)
  # is never subject to the requirement (RFC 6749 keeps the code at SHOULD), so
  # the flag is scoped to OIDC requests via `openid_request?/1`.
  defp validate_request(config, client, params, par_resolved?) do
    with {:ok, request} <- validate_within_origin(config, client, params),
         :ok <- require_par_if_configured(config, request, par_resolved?) do
      {:ok, request}
    end
  end

  # The same-origin requirement gates the redirect URI itself, so it has to be
  # settled before ANY response is allowed to travel to that URI - including an
  # error. Checking it only on the success path would let an ordinary validation
  # failure (a missing `code_challenge`, say) short-circuit ahead of the gate and
  # carry a redirectable error, with the attacker's `state` and the issuer, to a
  # cross-origin URI the gate would have refused. The payload is not a credential
  # and the destination is one the validated document declared, but the control
  # is stated as "responses for this client go to its own origin", and a control
  # that holds only when the request is otherwise perfect does not hold.
  #
  # So the verdict is applied to both outcomes: a failed origin check turns a
  # redirectable error into a direct one, exactly as an unregistered
  # `redirect_uri` already is.
  defp validate_within_origin(config, client, params) do
    validated =
      AuthorizationRequest.validate(
        params,
        RequestPolicy.validation_opts(config, client) ++ RequestPolicy.request_object_opts(config, client)
      )

    case validated do
      {:ok, request} ->
        with :ok <- require_same_origin_redirect_uri(config, client, request.redirect_uri) do
          {:ok, request}
        end

      {:error, {:redirect, error}} = redirectable ->
        # Request-object processing can replace the outer redirect_uri. Apply
        # the origin gate to the validated destination carried by the error,
        # which is the URI the response would actually use.
        with :ok <- require_same_origin_redirect_uri(config, client, error.redirect_uri) do
          redirectable
        end

      {:error, {:direct, _reason}} = direct ->
        direct
    end
  end

  # draft-ietf-oauth-client-id-metadata-document-01 §6.1 (MAY, enforced by
  # default): the request `redirect_uri` must be same-origin (scheme + host +
  # port) with the CIMD `client_id` URL, on top of the exact-match against the
  # document's `redirect_uris` the core already performed. A non-same-origin
  # `redirect_uri` is not a trusted URI for this client, so its failure is
  # non-redirectable - a direct error, like an unregistered redirect_uri. Only
  # applies to CIMD clients; a registered client has no `client_id` URL to be
  # same-origin with.
  #
  # A LOOPBACK redirect URI is exempt, and has to be. A CIMD `client_id` is an
  # `https` URL by definition, so `http://127.0.0.1/cb` can never share its
  # origin - the check is not a policy such a client fails, it is one no
  # installed app can satisfy by construction. Applying it there would deny CIMD
  # to native apps entirely, which is the population the drafts point at CIMD
  # now that dynamic registration is deprecated, and real clients (Claude Code's
  # published document among them) declare exactly these URIs.
  #
  # What is given up is same-origin binding for loopback redirects: any CIMD
  # document may declare one and receive a code on the user's own machine. The
  # check's value is against a document impersonating a better-known client to
  # collect codes at ITS origin, and that value is retained in full for the
  # `https` redirects where such an attack lives. For loopback the attacker must
  # already run code on the device to hold the port, and PKCE is mandatory for
  # every CIMD client regardless.
  defp require_same_origin_redirect_uri(config, %CIMDClient{metadata: metadata}, redirect_uri) do
    same_origin_required? =
      config
      |> Config.client_id_metadata()
      |> Keyword.get(:require_same_origin_redirect_uri, true)

    cond do
      not same_origin_required? ->
        :ok

      # While the port allowance is active, the exemption recognizes the same
      # explicit host set as the matcher. With the kill switch off, retain the
      # pre-existing IP-literal exemption for exact callbacks but do not let the
      # subordinate localhost opt-in affect policy.
      ClientIdMetadata.loopback_redirect_uri?(redirect_uri, same_origin_loopback_matching(config)) ->
        :ok

      ClientIdMetadata.same_origin_redirect_uri?(
        ClientIdMetadata.client_id(metadata),
        redirect_uri
      ) ->
        :ok

      true ->
        {:error, {:direct, :redirect_uri_not_registered}}
    end
  end

  defp require_same_origin_redirect_uri(_config, _client, _redirect_uri), do: :ok

  defp same_origin_loopback_matching(config) do
    if Config.native_app_loopback_redirect?(config) do
      Config.native_app_loopback_matching(config)
    else
      :exact_allow_loopback_port
    end
  end

  defp resolve_request_uri(config, %{"request_uri" => request_uri} = params)
       when is_binary(request_uri) and request_uri != "" do
    cond do
      # Parked requests share the store; their keys are never a `request_uri`.
      Interaction.reserved_key?(request_uri) ->
        {:error, {:direct, :invalid_request_uri}}

      is_nil(par_store(config)) ->
        {:ok, params, false}

      true ->
        case fetch_par_request(par_store(config), request_uri) do
          {:ok, stored} -> resolve_stored_request(params, stored)
          :error -> resolve_missing_request_uri(request_uri, params)
        end
    end
  end

  defp resolve_request_uri(_config, params), do: {:ok, params, false}

  # A `request_uri` the store does not hold.
  #
  # RFC 9126 §2.2: an unknown or EXPIRED PAR `request_uri` (the
  # `urn:ietf:params:oauth:request_uri:` reference this AS issues) is
  # `invalid_request_uri` - it MUST NOT fall through to treating the opaque URN
  # as a by-value parameter (which would surface the wrong error);
  # non-redirectable, since the reference carried no trusted redirect_uri for
  # this caller. An external (non-PAR) reference is left for validation to
  # reject as `request_uri_not_supported` (OpenID Connect Core §6.2), as this AS
  # does not fetch external request objects.
  defp resolve_missing_request_uri(request_uri, params) do
    if par_request_uri?(request_uri) do
      {:error, {:direct, :invalid_request_uri}}
    else
      {:ok, params, false}
    end
  end

  # The `request_uri` reference scheme this AS issues from its PAR endpoint
  # (RFC 9126 §2.2); a store miss on one of these is an expired/unknown PAR
  # reference, distinct from an unsupported external request_uri.
  defp par_request_uri?(request_uri), do: String.starts_with?(request_uri, "urn:ietf:params:oauth:request_uri:")

  # RFC 9126 §2.2: the `request_uri` is bound to the client that pushed it. The
  # stored, verified PAR parameters are authoritative (front-channel parameters
  # outside the pushed request, such as `state`, must not augment the request),
  # but a front-channel `client_id` that disagrees with the bound one is a
  # different client replaying the reference and is rejected (non-redirectable:
  # the bound redirect_uri cannot be trusted for the mismatched caller). An
  # absent front-channel `client_id` defers to the bound one.
  defp resolve_stored_request(params, stored) do
    presented = params["client_id"]

    if is_binary(presented) and presented != "" and presented != stored["client_id"] do
      {:error, {:direct, :request_uri_client_mismatch}}
    else
      {:ok, stored, true}
    end
  end

  defp fetch_par_request(store, request_uri) do
    cond do
      function_exported?(store, :fetch, 1) -> store.fetch(request_uri)
      function_exported?(store, :take, 1) -> store.take(request_uri)
      true -> :error
    end
  end

  defp require_par_if_configured(config, request, false) do
    if Callback.config_flag(config, :require_pushed_authorization_requests) do
      {:error,
       {:redirect,
        %{
          redirect_uri: request.redirect_uri,
          error: "invalid_request",
          state: request.state
        }}}
    else
      :ok
    end
  end

  defp require_par_if_configured(_config, _request, true), do: :ok

  defp par_store(config), do: config_field(config, :par_store, ETS)

  # The per-request validation policy (registered redirect URIs, PKCE, nonce) is
  # resolved by the conn-free `AttestoPhoenix.AuthorizationServer.RequestPolicy`,
  # shared with the PAR endpoint so both validate an authorization request the
  # same way (RFC 9126 §2.1).

  # ── Authenticate, consent, issue (RFC 6749 §4.1.1 / OIDC Core §3.1.2.3) ───

  # The request is now trusted: the client exists and the redirect_uri is
  # registered. From here every further error is reported by redirecting back
  # to the validated redirect_uri (RFC 6749 §4.1.2.1).
  #
  # OIDC Core §3.1.2.1 / §3.1.2.6: `prompt` constrains how the resource owner is
  # established. `prompt=none` means the OP MUST NOT display any authentication
  # or consent UI: if it cannot reuse an already-established session it MUST
  # return one of `login_required` / `consent_required` / `interaction_required`
  # by redirect (never render). `prompt=login` means the OP MUST reauthenticate
  # the resource owner even if a session exists. Both intents are passed to the
  # host's authentication hook as `auth_opts`; the host owns the session, the
  # controller owns the protocol disposition.
  defp run_flow(conn, config, client, request, dpop_jkt) do
    prompt_none? = @prompt_none in request.prompt

    case authenticate_resource_owner(conn, config, request) do
      {:authenticated, subject} ->
        run_authenticated(conn, config, client, request, subject, prompt_none?, dpop_jkt)

      {:none} ->
        # OIDC Core §3.1.2.6: the host has no already-authenticated subject it
        # can return without UI. Under `prompt=none` that is `login_required`
        # (never a UI render); otherwise the host should have halted to its
        # login page, so a bare `{:none}` here is a host/config fault.
        if prompt_none? do
          emit_failure(conn, config, @error_login_required)
          emit_error(conn, config, request, @error_login_required)
        else
          Logger.error("authenticate_resource_owner returned {:none} without prompt=none")
          emit_error(conn, config, request, @error_server_error)
        end

      {:halt, halted_conn} ->
        # The host took over the connection (e.g. a redirect to a login page
        # that re-enters this endpoint after authentication). Under
        # `prompt=none` that is forbidden: the host MUST NOT show UI, so a halt
        # is converted to the `login_required` redirect instead of letting the
        # host's interactive page run (OIDC Core §3.1.2.6). A conformant host
        # honours `auth_opts.interactive == false` and returns `{:none}` rather
        # than halting; the conversion here is the defensive backstop, built on
        # the ORIGINAL `conn` (never the host's, which may already have a body
        # under a buggy host) so the redirect is always well-formed.
        if prompt_none? do
          emit_failure(conn, config, @error_login_required)
          emit_error(conn, config, request, @error_login_required)
        else
          halted_conn
        end

      {:error, reason}
      when reason in [:login_required, :consent_required, :interaction_required] ->
        # OIDC Core §3.1.2.6: the host explicitly classifies why it cannot
        # establish the resource owner without interaction. This is the only
        # path that surfaces `interaction_required` (the catch-all when the
        # blocker is neither specifically login nor consent), and it is reported
        # by redirect like the prompt=none conversions above.
        error_code = interaction_error_code(reason)
        emit_failure(conn, config, error_code)
        emit_error(conn, config, request, error_code)

      _other ->
        # A callback that returns no known shape is a host/config fault, not a
        # client error. Fail closed with the §4.1.2.1 server_error rather than
        # crash, and do not issue a code.
        Logger.error("authenticate_resource_owner callback returned an invalid result")
        emit_error(conn, config, request, @error_server_error)
    end
  end

  defp run_authenticated(conn, config, client, request, subject, prompt_none?, dpop_jkt) do
    case with :ok <- check_authentication_age(conn, request, subject, prompt_none?),
              do: check_prompt_login(conn, request, subject) do
      {:ok, conn} ->
        run_consent(conn, config, client, request, subject, prompt_none?, dpop_jkt)

      {:error, error_code} ->
        emit_failure(conn, config, error_code)
        emit_error(conn, config, request, error_code)
    end
  end

  # OIDC Core §3.1.2.1: when the request carries `max_age`, the authentication
  # the host returned must be no older than that, and must carry an `auth_time`
  # (the ID Token MUST include it). The rule itself is
  # `Attesto.AuthorizationRequest.check_auth_time/4`; this maps its result to the
  # response.
  #
  #   * `prompt=none`: the host could not have re-authenticated, so the check is
  #     exact and an authentication that is too old is `login_required`
  #     (§3.1.2.6).
  #   * Otherwise the host was told to re-authenticate (`auth_opts.max_age`) and
  #     returned an authentication that is still too old. That is a host
  #     contract violation, not something the client can fix: `server_error`.
  #     A host that did re-authenticate comes back to this endpoint a moment
  #     after the login completed, so the interactive check allows
  #     `Interaction.reauthentication_allowance_seconds/0` beyond `max_age`; without it
  #     `max_age=0` could never be satisfied.
  #     A resumed request has the time it was parked, so that interval is
  #     replaced by `Interaction.max_age_allowance/3`: an authentication made
  #     after the park satisfies `max_age`, an earlier one is checked exactly.
  #   * A missing or malformed `auth_time` is a host fault under either prompt.
  defp check_authentication_age(conn, request, subject, prompt_none?) do
    auth_time = Map.get(subject, :auth_time)
    now = System.system_time(:second)

    allowance =
      case resumed(conn) do
        _any when prompt_none? -> 0
        nil -> Interaction.reauthentication_allowance_seconds()
        %{parked_at: parked_at} -> Interaction.max_age_allowance(parked_at, auth_time, now)
      end

    case AuthorizationRequest.check_auth_time(request, auth_time, now, allowance: allowance) do
      :ok ->
        :ok

      {:error, :max_age_exceeded} when prompt_none? ->
        {:error, @error_login_required}

      {:error, reason} ->
        Logger.error("max_age was requested but the host returned an unusable authentication: #{reason}")
        {:error, @error_server_error}
    end
  end

  defp check_prompt_login(conn, request, subject) do
    {since, allowance} =
      case resumed(conn) do
        %{prompt_login_since: since} -> {since, 0}
        nil -> {conn.private.attesto_phoenix_authorization_arrived_at, Interaction.reauthentication_allowance_seconds()}
      end

    case AuthorizationRequest.check_prompt_login(request, Map.get(subject, :auth_time), since,
           now: System.system_time(:second),
           allowance: allowance
         ) do
      :ok ->
        # Only consent receives this connection after the check has passed.
        # A login detour parks before this point and must use the park time.
        conn =
          if @prompt_login in request.prompt,
            do: put_private(conn, :attesto_phoenix_prompt_login_since, since - allowance),
            else: conn

        {:ok, conn}

      {:error, reason} ->
        Logger.error("prompt=login was requested but the host returned an unusable authentication: #{reason}")
        {:error, @error_server_error}
    end
  end

  # OIDC Core §3.1.2.6: map the host's interaction-blocked reason to its error
  # code. Reported by redirect to the (already trusted) redirect_uri.
  defp interaction_error_code(:login_required), do: @error_login_required
  defp interaction_error_code(:consent_required), do: @error_consent_required
  defp interaction_error_code(:interaction_required), do: @error_interaction_required

  defp run_consent(conn, config, client, request, subject, prompt_none?, dpop_jkt) do
    case consent(conn, config, client, request, subject) do
      {:consented, subject} ->
        issue_and_redirect(conn, config, client, request, subject, dpop_jkt)

      {:halt, halted_conn} ->
        # OIDC Core §3.1.2.6: a consent screen is interactive UI, forbidden
        # under `prompt=none`; convert the halt to `consent_required`, built on
        # the ORIGINAL `conn` (never the host's halted one, which may already
        # carry a body) so the redirect is always well-formed.
        if prompt_none? do
          emit_failure(conn, config, @error_consent_required)
          emit_error(conn, config, request, @error_consent_required)
        else
          halted_conn
        end

      {:denied, _reason} ->
        # RFC 6749 §4.1.2.1: the resource owner refused. Report access_denied
        # by redirect (the redirect_uri is already trusted). Under prompt=none
        # the equivalent disposition is consent_required (OIDC Core §3.1.2.6):
        # consent could not be obtained without interaction.
        emit_denied(conn, config, request.client_id)

        error_code = if prompt_none?, do: @error_consent_required, else: @error_access_denied
        emit_error(conn, config, request, error_code)

      reason when reason in [:consent_prompt_unavailable, :missing_public_client_consent] ->
        run_without_consent_callback(conn, config, request, reason, prompt_none?)

      _other ->
        Logger.error("consent callback returned an invalid result")
        emit_error(conn, config, request, @error_server_error)
    end
  end

  # No :consent callback is configured and implicit consent does not apply.
  defp run_without_consent_callback(conn, config, request, :consent_prompt_unavailable, _prompt_none?) do
    # OIDC Core §3.1.2.1: `prompt=consent` asks the OP to prompt for consent,
    # and an OP that cannot obtain it MUST return an error, typically
    # consent_required. Without a :consent callback there is no consent step
    # to run.
    emit_failure(conn, config, @error_consent_required)
    emit_error(conn, config, request, @error_consent_required)
  end

  defp run_without_consent_callback(conn, config, request, :missing_public_client_consent, prompt_none?) do
    # RFC 8252 §8.6: a public client's identity cannot be established from
    # its client_id alone, so a remembered or implicit approval can be
    # claimed by an impersonating app. A host that serves public clients
    # must make an explicit consent decision for each authorization request.
    # Under prompt=none the protocol response is consent_required; on an
    # interactive request, absence of the callback is a host configuration
    # error because this library does not render consent UI itself.
    emit_failure(conn, config, @error_consent_required)

    if prompt_none? do
      emit_error(conn, config, request, @error_consent_required)
    else
      Logger.error("public-client authorization requires an explicit :consent callback")
      emit_error(conn, config, request, @error_server_error)
    end
  end

  # RFC 6749 §4.1.2 / OIDC Core §3.1.3.1: mint a single-use code bound to the
  # validated request and carry the OIDC `nonce` and the authentication context
  # (`auth_time`, `acr`, `amr`) into the code's claims so the token endpoint can
  # mint the ID token from the code alone (OIDC Core §2, §3.1.3.6). A fresh
  # per-code `family_id` is generated and threaded into the code (and onto the
  # redeemed grant) so the token endpoint can link any refresh token it issues
  # to a revocation family for code-reuse / refresh-reuse revocation
  # (OAuth 2.0 Security BCP §4.13, §4.14). On success, redirect back to the
  # client with `code` (and `state`).
  defp issue_and_redirect(conn, config, client, request, subject, dpop_jkt) do
    case authorize_request_resource(config, client, request) do
      :ok ->
        issue_and_redirect_authorized(conn, config, request, subject, dpop_jkt)

      {:error, :invalid_target} ->
        # RFC 8707 §2.2: the client requested a resource this server does not
        # serve. A redirectable error (RFC 6749 §4.1.2.1) since the client is
        # already trusted at this point.
        emit_failure(conn, config, @error_invalid_target)
        emit_error(conn, config, request, @error_invalid_target)
    end
  end

  # RFC 8707 §2.2: every requested resource must be one this server serves for
  # the client (`Config.allowed_resources/2`), else the AS would bind — and the
  # token endpoint later mint — a token audienced to a resource it does not
  # serve. The indicators were syntactically validated (§2.1) when the request
  # was parsed.
  defp authorize_request_resource(config, client, request) do
    case ResourceIndicator.authorize(request.resource, Config.allowed_resources(config, client)) do
      {:ok, _resources} -> :ok
      {:error, :invalid_target} -> {:error, :invalid_target}
    end
  end

  defp issue_and_redirect_authorized(conn, config, request, subject, dpop_jkt) do
    # RFC 9126 §2.2: claim the PAR `request_uri` as the atomic single-use gate
    # BEFORE issuing the code, so two concurrent completions (on any node) cannot
    # each mint a code from one pushed request - exactly one wins the claim.
    case claim_par_request_uri(conn, config) do
      :ok ->
        issue_claimed_request(conn, config, request, subject, dpop_jkt)

      :error ->
        # RFC 9126 §2.2/§2.3: the single-use claim was lost - a concurrent
        # completion already consumed this `request_uri`, or it expired during
        # login/consent - so no second code is minted from it. The request is
        # fully validated here (trusted redirect_uri), so report by redirect like
        # the other completion-phase failures.
        emit_failure(conn, config, @error_invalid_request_uri)
        emit_error(conn, config, request, @error_invalid_request_uri)
    end
  end

  defp issue_claimed_request(conn, config, request, subject, dpop_jkt) do
    # Generated before the private-context callback so the host sees the same
    # family id the code is minted under.
    family_id = generate_family_id()
    subject_id = subject_id(subject)

    case code_claims_with_private_context(config, request, conn, subject, subject_id, family_id) do
      {:ok, claims} ->
        attrs =
          %{
            client_id: request.client_id,
            redirect_uri: request.redirect_uri,
            code_challenge: request.code_challenge,
            code_challenge_method: request.code_challenge_method,
            subject: subject_id,
            scope: request.scope,
            # RFC 8707 §2.2: bind the authorized resource indicator(s) to the
            # code so the token endpoint mints `aud` from what the user actually
            # authorized at this endpoint.
            resource: request.resource,
            family_id: family_id,
            claims: claims
          }
          |> MapParams.put_optional(:dpop_jkt, dpop_jkt)

        mint_code_and_redirect(conn, config, request, subject, attrs)

      {:error, reason} ->
        # The private-context value or the combined code claims cannot
        # round-trip through the claims column. This is a server/config fault on
        # an otherwise valid request, and it must fail closed: issuing a code
        # without the state the completion callback will demand would strand
        # the redemption.
        log_private_context_rejection(reason)
        emit_error(conn, config, request, @error_server_error)
    end
  end

  defp log_private_context_rejection(:invalid_code_claims) do
    Logger.error("authorization code claims rejected after private context insertion: combined claims are not portable")
  end

  defp log_private_context_rejection(:reserved_private_context_claim) do
    Logger.error("authorization code claims rejected: reserved private context key")
  end

  defp log_private_context_rejection(reason) do
    Logger.error("authorization code private context rejected: #{inspect(reason)}")
  end

  defp mint_code_and_redirect(conn, config, request, subject, attrs) do
    case issue_code(config, attrs) do
      {:ok, code} when is_binary(code) ->
        emit_code_issued(conn, config, request.client_id, request.scope)
        emit_success(conn, config, request, subject, code)

      {:error, %PhoenixOAuthError{} = refusal} ->
        # The host's `:authorization_code_issuance` callback refused.
        error_code = issuance_refusal_code(refusal, request)
        emit_failure(conn, config, error_code)
        emit_error(conn, config, request, error_code)

      {:error, reason} ->
        # Issuance failing on a validated request is a server/config fault,
        # not a client error (RFC 6749 §4.1.2.1 server_error). Do not leak
        # detail.
        Logger.error("authorization code issuance failed: #{inspect(reason)}")
        emit_error(conn, config, request, @error_server_error)
    end
  end

  # With no `:authorization_code_issuance` callback the code is issued
  # directly, exactly as before the hook existed. With one, the host runs the
  # issuance through its continuation, inside its own transaction and locks if
  # it wants, so the code is stored atomically with whatever the host checks or
  # writes. The context carries the identifiers the private-context callback
  # saw and that callback's result; never the code.
  defp issue_code(config, attrs) do
    issue = fn -> AuthorizationCode.issue(code_store(config), attrs, ttl: config.authorization_code_ttl) end

    case Config.authorization_code_issuance_fun(config) do
      nil ->
        issue.()

      callback ->
        context = %{
          client_id: attrs.client_id,
          subject: attrs.subject,
          family_id: attrs.family_id,
          private_context: Map.get(attrs.claims, PrivateContext.claims_key())
        }

        Continuation.run(issuance_profile(), &Callback.invoke(callback, &1), context, issue)
    end
  end

  defp issuance_profile do
    %{
      callback: "authorization code issuance callback",
      continuation: "authorization code issuance continuation",
      work: "authorization code issuance",
      not_done: "no code was issued",
      no_success: "no code was returned",
      no_response: "issuance did not succeed and no code was returned",
      after_success:
        "unless the host's transaction rolled back, a code was stored that the client never " <>
          "receives; it expires unredeemed",
      state_key: {__MODULE__, :authorization_code_issuance_continuation},
      succeeded?: &match?({:ok, code} when is_binary(code), &1),
      well_formed?: fn
        {:ok, code} when is_binary(code) -> true
        {:error, _reason} -> true
        _other -> false
      end,
      refusal: {:error, :issuance_callback_contract_violation}
    }
  end

  # RFC 6749 §4.1.2.1 / OIDC Core §3.1.2.6: the errors a host may name when it
  # refuses issuance. `access_denied` and `server_error` (and
  # `temporarily_unavailable`) apply to any request. `login_required` is an
  # answer to `prompt=none` only; on an interactive request the host was able
  # to log the user in, so naming it there is a host fault. Any other code is
  # one this endpoint has no meaning for at this point.
  defp issuance_refusal_code(%PhoenixOAuthError{error: error}, request) do
    cond do
      error in [:access_denied, :server_error, :temporarily_unavailable] ->
        Atom.to_string(error)

      error == :login_required and @prompt_none in request.prompt ->
        @error_login_required

      true ->
        Logger.error(
          "authorization code issuance callback refused with #{inspect(error)}, which does not " <>
            "apply to this request; answered server_error"
        )

        @error_server_error
    end
  end

  # The host's `:authorization_code_private_context` callback (when configured)
  # is given the authorized client, the subject id, the freshly generated
  # family id, the authentication map the host's own callbacks returned, and
  # the validated request's scope and resource list - no raw request
  # parameters, no token secrets. Its result rides with
  # the code inside `:claims` under a reserved namespaced key, because
  # `Attesto.AuthorizationCode` admits no sibling key beside the nine canonical
  # ones.
  defp code_claims_with_private_context(config, request, conn, subject, subject_id, family_id) do
    claims = code_claims(conn, config, request, subject)

    # `code_claims/4` currently builds a closed library-owned key set, so this
    # cannot be reached through a supported host callback. Keep the check at the
    # ownership boundary as defense in depth if host-provided code claims are
    # added later.
    if PrivateContext.reserved?(claims) do
      {:error, :reserved_private_context_claim}
    else
      case Config.authorization_code_private_context_fun(config) do
        nil ->
          {:ok, claims}

        callback ->
          context = %{
            client_id: request.client_id,
            subject: subject_id,
            family_id: family_id,
            authentication: subject,
            scope: request.scope,
            resource: request.resource
          }

          PrivateContext.put(claims, Callback.invoke(callback, [context]))
      end
    end
  end

  # OAuth 2.0 Security BCP §4.13 / §4.14: a fresh, unguessable family identifier
  # generated per issued code. `Attesto.AuthorizationCode` rides it onto the
  # redeemed grant so the token endpoint mints the refresh-token family under
  # this id, and code-reuse detection replays it to revoke the descendant
  # family. Sixteen random bytes match the refresh-family identifiers generated
  # by `Attesto.RefreshToken` and encode to 22 unpadded Base64URL characters.
  defp generate_family_id, do: Secret.generate(16)

  # RFC 9449 §10: the DPoP key thumbprint the issued code is sender-constrained
  # to. Two sources, by path:
  #
  #   * PAR-resolved: the PAR endpoint already verified the presented proof and
  #     stored the thumbprint at the TOP LEVEL of the pushed params (and rejects a
  #     submitted `dpop_jkt` that disagrees with the proof). But `validate/2`
  #     re-merges any pushed `request` object and replaces the params with the
  #     signed object's - dropping that top-level value - so read the
  #     PAR-verified thumbprint straight from the stored params. It is trusted:
  #     PAR put it there after proof verification.
  #
  #   * Direct: read it off the VERIFIED request (`request.dpop_jkt`, sourced from
  #     the effective post-merge params), so a signed request object's value is
  #     authoritative and an unsigned outer-query value is ignored.
  defp authorize_dpop_jkt(request, params, true), do: dpop_jkt_from_params(params) || request.dpop_jkt

  defp authorize_dpop_jkt(request, _params, false), do: request.dpop_jkt

  defp dpop_jkt_from_params(%{"dpop_jkt" => jkt}) when is_binary(jkt) and jkt != "", do: jkt
  defp dpop_jkt_from_params(_params), do: nil

  # OIDC Core §3.1.3.6 / §2: the claims the token endpoint needs to mint the ID
  # token. The request `nonce` (OIDC Core §3.1.2.1) MUST be reflected into the
  # ID token unchanged; the authentication context (`auth_time`, `acr`, `amr`)
  # is whatever the host's authentication/consent callbacks established. When the
  # request carried `max_age` (OIDC Core §3.1.2.1), `auth_time` is REQUIRED in
  # the ID Token, so the host's freshly-established `auth_time` (after any
  # re-authentication it performed to satisfy `max_age`) is carried here;
  # `check_authentication_age/3` has already refused a request whose host
  # returned none.
  # Only the keys the host actually supplied are carried, so the token endpoint
  # can distinguish "absent" from a value. The OIDC `claims` request parameter
  # (OIDC Core §5.5) is carried only when the provider supports it
  # (`:claims_parameter_supported`); otherwise it has no effect on the ID Token
  # or UserInfo response.
  defp code_claims(conn, config, request, subject) do
    auth_time = Map.get(subject, :auth_time)

    %{}
    |> MapParams.put_optional("nonce", request.nonce)
    |> MapParams.put_optional("claims", supported_claims_request(config, request))
    |> MapParams.put_optional("auth_time", auth_time)
    |> MapParams.put_optional("acr", Map.get(subject, :acr))
    |> MapParams.put_optional("amr", Map.get(subject, :amr))
    # OIDC Back-Channel Logout 1.0 §2.1: the host's session id rides into the
    # code's claims so the token endpoint can stamp `sid` on the ID Token and
    # record a back-channel-logout session for the Relying Party.
    |> MapParams.put_optional("sid", Map.get(subject, :sid))
    # OID4VCI (draft-ietf-oauth-openid4vci) §5: the `openid_credential`
    # authorization_details resolved for this request (stashed onto the conn
    # by `authorize/2` via `stash_credential_configuration_ids/2`), so the
    # token endpoint can carry the same `credential_configuration_ids` claim
    # onto the access token that the pre-authorized_code grant uses (see
    # `AttestoPhoenix.AuthorizationServer.Token`'s `@grant_pre_authorized_code`
    # dispatch clause).
    |> MapParams.put_optional(
      "credential_configuration_ids",
      Map.get(conn.private, :attesto_credential_configuration_ids)
    )
    |> MapParams.put_optional(
      "attesto_phoenix.credential_authorization_details_ids",
      Map.get(conn.private, :attesto_credential_authorization_details_ids)
    )
  end

  defp supported_claims_request(%Config{claims_parameter_supported: true}, request), do: request.claims
  defp supported_claims_request(_config, _request), do: nil

  # ── OID4VCI authorization_details (draft-ietf-oauth-openid4vci §5) ───────

  # RFC 9396 §5 `authorization_details`, filtered to `openid_credential`
  # entries (draft-ietf-oauth-openid4vci §5) naming a
  # `credential_configuration_id` this issuer actually offers
  # (`:credential_configurations_supported`). Unconfigured credential
  # issuance, an absent parameter, or a named id this issuer does not offer
  # resolve to `[]`. Structural validation is owned by
  # `Attesto.AuthorizationRequest`, so malformed details fail before this
  # policy filter. This is the SAME entitlement claim the pre-authorized_code grant binds, so the
  # credential endpoint's entitlement check
  # (`AttestoPhoenix.Controller.CredentialController.entitled?/2`) works
  # unchanged regardless of which grant produced the token.
  #
  # Consume only the normalized AuthorizationRequest. Direct, JAR, and PAR
  # requests therefore share one source of truth, and a verified Request
  # Object's signed value remains authoritative over unsigned outer input.
  defp credential_configuration_ids(config, %AuthorizationRequest{} = request) do
    supported = Config.credential_configurations_supported(config) || %{}

    from_authorization_details =
      request.authorization_details
      |> Enum.filter(&openid_credential_entry?/1)
      |> Enum.flat_map(&entry_credential_configuration_ids/1)
      |> Enum.filter(&Map.has_key?(supported, &1))

    %{
      ids: Enum.uniq(from_authorization_details ++ credential_configuration_ids_from_scope(supported, request.scope)),
      authorization_details_ids: Enum.uniq(from_authorization_details)
    }
  end

  # OID4VCI §5.1.2 / HAIP §4.1: a requested `scope` matching a credential
  # configuration's advertised `scope` authorizes that configuration - the
  # scope-based alternative to naming it in `authorization_details`. Both feed
  # the SAME `credential_configuration_ids` entitlement claim.
  defp credential_configuration_ids_from_scope(supported, requested) when is_list(requested) do
    for {id, configuration} <- supported,
        scope = configuration_scope(configuration),
        scope in requested,
        do: id
  end

  defp configuration_scope(configuration) when is_map(configuration),
    do: Map.get(configuration, :scope) || Map.get(configuration, "scope")

  defp configuration_scope(_configuration), do: nil

  defp openid_credential_entry?(%{"type" => "openid_credential"}), do: true
  defp openid_credential_entry?(_entry), do: false

  defp entry_credential_configuration_ids(%{"credential_configuration_id" => id}) when is_binary(id) and id != "",
    do: [id]

  defp entry_credential_configuration_ids(_entry), do: []

  # Stash the resolved credential_configuration_ids (only when non-empty) so
  # `issue_and_redirect_authorized/5` can read them without threading a new
  # parameter through the whole authenticate/consent chain — the same idiom
  # `stash_par_request_uri/3` uses for the PAR reference.
  defp stash_credential_configuration_ids(conn, %{ids: []}), do: conn

  defp stash_credential_configuration_ids(conn, %{ids: ids, authorization_details_ids: explicit_ids}) do
    conn
    |> Plug.Conn.put_private(:attesto_credential_configuration_ids, ids)
    |> Plug.Conn.put_private(:attesto_credential_authorization_details_ids, explicit_ids)
  end

  # ── Host callbacks (login / consent) ─────────────────────────────────────

  # The host login hook. Read defensively from the configuration; when a host
  # has not supplied it there is no way to establish a resource owner, so fail
  # closed with a server_error-classed result rather than minting a code for an
  # unauthenticated subject.
  #
  # The callback is invoked with `[conn, request, auth_opts]`, where `auth_opts`
  # is a map carrying the OIDC Core §3.1.2.1 authentication directives the host
  # must honour:
  #
  #   * `:prompt` - the parsed `prompt` list (OIDC Core §3.1.2.1).
  #   * `:force_reauth` - `true` when `prompt=login`: the host MUST
  #     reauthenticate the resource owner even if a session exists, and reflect
  #     a fresh `auth_time` in the returned subject.
  #   * `:max_age` - the request `max_age` (seconds) when present, else `nil`:
  #     the host MUST reauthenticate if the existing authentication is older than
  #     this, and MUST return the resulting `auth_time` (OIDC Core §3.1.2.1).
  #   * `:interactive` - `false` when `prompt=none`: the host MUST NOT render any
  #     UI; it returns `{:authenticated, subject}` only if a subject can be
  #     established silently, else `{:none}`.
  #   * `:resumed` - `true` when the request was parked with
  #     `AttestoPhoenix.Interaction.park/2` and is being resumed.
  #
  # The host returns `{:authenticated, subject}`, `{:halt, conn}` (it took over
  # the connection to render login UI), or `{:none}` (no subject can be
  # established without UI - used under `prompt=none`).
  defp authenticate_resource_owner(conn, config, request) do
    case Config.authenticate_resource_owner_fun(config) do
      nil ->
        Logger.error(":authenticate_resource_owner callback is not configured")

        {:halt, emit_error(conn, config, request, @error_server_error)}

      callback ->
        Callback.invoke(callback, [conn, request, auth_opts(conn, request)])
    end
  end

  # OIDC Core §3.1.2.1: assemble the authentication directives the host hook
  # must honour from the validated request. `prompt=login` forces reauth;
  # `prompt=none` forbids UI; `max_age` bounds the age of an acceptable existing
  # authentication.
  #
  # `:resumed` is `true` when the request was restored from
  # `AttestoPhoenix.Interaction.park/2`: the End-User has been through the
  # host's login or consent step. It does not by itself establish freshness;
  # `:prompt_login_since` is the earliest acceptable authentication on resume.
  defp auth_opts(conn, request) do
    %{
      prompt: request.prompt,
      force_reauth: @prompt_login in request.prompt,
      interactive: @prompt_none not in request.prompt,
      max_age: request.max_age,
      resumed: not is_nil(resumed(conn)),
      parked_at: (resumed(conn) || %{})[:parked_at],
      prompt_login_since: (resumed(conn) || %{})[:prompt_login_since]
    }
  end

  # The host consent hook. A confidential client may retain the historical
  # implicit-consent behavior when the hook is absent, unless the request
  # explicitly asks for a consent prompt (OIDC Core §3.1.2.1 `prompt=consent`).
  # Public clients require an explicit decision on every request: their
  # client_id does not authenticate the calling app, so remembered or automatic
  # approval is vulnerable to client impersonation (RFC 8252 §8.6).
  defp consent(conn, config, client, request, subject) do
    case Config.consent_fun(config) do
      nil ->
        cond do
          RequestPolicy.client_public?(config, client) -> :missing_public_client_consent
          @prompt_consent in request.prompt -> :consent_prompt_unavailable
          true -> {:consented, subject}
        end

      callback ->
        Callback.invoke(callback, [conn, request, subject])
    end
  end

  # OIDC Core §2: the subject identifier (`sub`) the code is issued for. A
  # subject without a usable identifier is a host/config fault; it surfaces as
  # an issuance error from `Attesto.AuthorizationCode.issue/3`
  # (`:invalid_subject`), which is reported as server_error.
  defp subject_id(subject) when is_map(subject), do: Map.get(subject, :subject)
  defp subject_id(_subject), do: nil

  defp code_store(config), do: Callback.config_callback(config, :code_store)

  # ── Redirect responses (RFC 6749 §4.1.2 / §4.1.2.1) ──────────────────────

  # ── Authorization response emission (query or JARM, JARM §2.3 / FAPI 2.0
  # Message Signing §5.4) ──────────────────────────────────────────────────
  #
  # Every authorization response - success or error - flows through
  # emit_response/6, which honours the request's `response_mode`: the RFC 6749
  # default `query`, or a JARM JWT mode that returns the response as a single
  # signed `response` JWT. The JARM audience is the request `client_id`.

  # RFC 6749 §4.1.2: success. The code and (when present) `state` are the
  # response parameters; under JARM `iss` rides inside the JWT (JARM §2.1), under
  # the query mode it is the RFC 9207 `iss` parameter (added in emit_response/6).
  # With Session Management enabled, the OIDC Session Management 1.0 §2
  # `session_state` parameter rides alongside them.
  defp emit_success(conn, config, request, subject, code) do
    # The PAR `request_uri` has already been claimed (consumed) atomically in
    # `issue_and_redirect/6` before the code was issued (RFC 9126 §2.2), so the
    # success response is just the redirect.
    {conn, session_state} = maybe_session_state(conn, config, request, subject)

    emit_response(
      conn,
      config,
      request.redirect_uri,
      request.response_mode,
      request.client_id,
      drop_nil(%{"code" => code, "state" => request.state, "session_state" => session_state})
    )
  end

  # OIDC Session Management 1.0 §2: a successful Authentication Response MUST
  # carry `session_state` when the OP supports session management. The value is
  # computed over the client_id, the redirect_uri's browser origin, and the OP
  # browser-state cookie — minted (or rotated) here bound to this response's
  # login state (§3.2 keys the OP browser state on the End-User login state).
  # Returns the (possibly cookie-setting) conn and the value, or nil when the
  # feature is off or the redirect_uri yields no usable origin (already
  # validated as registered, so that is defensive only).
  defp maybe_session_state(conn, config, request, subject) do
    with true <- Config.session_management_enabled?(config),
         {:ok, origin} <- SessionState.origin(request.redirect_uri) do
      {conn, browser_state} = BrowserState.ensure(conn, config, login_binding(subject))
      {conn, SessionState.compute(request.client_id, origin, browser_state)}
    else
      _ -> {conn, nil}
    end
  end

  # A stable fingerprint of the current authorization's resolved End-User login
  # state, used to rotate the OP browser state when that state changes (§3.2).
  # (subject, auth_time, sid) is exactly what already flows into the ID token,
  # so an account switch (new `sub`), a `prompt=login` / `max_age=0` re-auth
  # (newer `auth_time`), or a new host session (`sid`) each produces a different
  # binding and forces a fresh browser-state value. The binding is HMAC'd into
  # the cookie by `Attesto.SessionState`, so it is never exposed in cleartext.
  defp login_binding(subject) do
    Enum.map_join(
      [subject_id(subject), Map.get(subject, :auth_time), Map.get(subject, :sid)],
      "\n",
      &to_string/1
    )
  end

  # Stash the PAR reference (only when it actually resolved a stored request) so
  # the completion path can claim it; a non-PAR or unresolved request stashes
  # nothing.
  defp stash_par_request_uri(conn, uri, true) when is_binary(uri) and uri != "",
    do: Plug.Conn.put_private(conn, :attesto_par_request_uri, uri)

  defp stash_par_request_uri(conn, _uri, _par_resolved?), do: conn

  # Claim the stashed PAR `request_uri` as the atomic single-use gate, BEFORE the
  # code is issued (RFC 9126 §2.2). It was resolved with a non-consuming `fetch`
  # so the host could establish login/consent and re-enter `/authorize`, but
  # completion consumes it exactly once via the store's atomic `take/1`: the
  # single winner among any concurrent completions (on any node) gets `:ok` and
  # issues a code; the rest get `:error` and issue nothing.
  #
  #   * `:ok` - won the claim, or not a PAR request (nothing to claim), or an
  #     optional-PAR store does not implement `take/1`.
  #   * `:error` - lost the claim: the reference was already consumed by a
  #     concurrent completion, or expired during login/consent.
  defp claim_par_request_uri(conn, config) do
    case conn.private[:attesto_par_request_uri] do
      uri when is_binary(uri) and uri != "" ->
        claim_reference(
          par_store(config),
          uri,
          Callback.config_flag(config, :require_pushed_authorization_requests)
        )

      _ ->
        :ok
    end
  end

  # Consume the reference via the store's atomic `take/1`. A store that does not
  # implement the optional callback can proceed best-effort only when PAR is
  # optional; mandatory PAR fails closed because it cannot enforce single use.
  defp claim_reference(store, uri, required?) do
    if function_exported?(store, :take, 1) do
      case store.take(uri) do
        {:ok, _params} ->
          :ok

        :error ->
          :error

        _invalid ->
          raise RuntimeError, "#{inspect(store)}.take/1 violated its PAR-store return contract"
      end
    else
      if required?, do: :error, else: :ok
    end
  end

  # RFC 6749 §4.1.2.1: error reported once the client/redirect_uri is trusted,
  # where the validated request (and so its response_mode) is known.
  defp emit_error(conn, config, request, error_code) do
    emit_response(
      conn,
      config,
      request.redirect_uri,
      request.response_mode,
      request.client_id,
      drop_nil(%{"error" => error_code, "state" => request.state})
    )
  end

  # RFC 6749 §4.1.2.1: error surfaced from Attesto.AuthorizationRequest as a
  # redirectable failure. The core enriches it with the requested response_mode
  # and the client_id (JARM audience) when the client is trusted; absent those,
  # effective_response_mode/1 falls back to the query encoding.
  defp emit_redirect_error(conn, config, error) do
    emit_response(
      conn,
      config,
      error.redirect_uri,
      Map.get(error, :response_mode),
      Map.get(error, :client_id),
      drop_nil(%{
        "error" => error.error,
        "error_description" => Map.get(error, :error_description),
        "state" => error.state
      })
    )
  end

  defp emit_response(conn, config, redirect_uri, response_mode, client_id, params) do
    case effective_response_mode(response_mode) do
      "query" ->
        do_redirect(conn, redirect_uri, Map.to_list(params) ++ iss_param(config))

      # OAuth 2.0 Form Post Response Mode: the same parameters as `query`
      # (including the RFC 9207 `iss`), delivered in a POST body.
      "form_post" ->
        deliver_form_post(conn, redirect_uri, "form_post", Map.to_list(params) ++ iss_param(config))

      jwt_mode ->
        {:ok, response} =
          JARM.response_jwt(Config.to_attesto_config(config), client_id, params)

        deliver_jarm(conn, redirect_uri, jwt_mode, response)
    end
  end

  # JARM §2.3.2: `jwt` is shorthand for the response_type's default JWT mode,
  # which for the code flow is `query.jwt`. An absent response_mode is the
  # RFC 6749 default, `query`.
  defp effective_response_mode(nil), do: "query"
  defp effective_response_mode("jwt"), do: "query.jwt"
  defp effective_response_mode(mode), do: mode

  # JARM §2.3.1: deliver the signed response JWT per the requested mode.
  defp deliver_jarm(conn, redirect_uri, "query.jwt", response) do
    do_redirect(conn, redirect_uri, [{"response", response}])
  end

  defp deliver_jarm(conn, redirect_uri, "fragment.jwt", response) do
    location = redirect_uri <> "#" <> URI.encode_query([{"response", response}])

    conn
    |> put_resp_header("location", location)
    |> send_resp(:found, "")
  end

  defp deliver_jarm(conn, redirect_uri, "form_post.jwt", response) do
    deliver_form_post(conn, redirect_uri, "form_post.jwt", [{"response", response}])
  end

  # OAuth 2.0 Form Post Response Mode §2: the response parameters are HTML
  # form values the user agent POSTs to the redirect URI; none of them appears
  # in a URL. The page carries the authorization response, so it must not be
  # cached (§4, and RFC 6749 §5.1's rule for responses bearing credentials).
  # One renderer serves the plain mode and its JARM variant.
  defp deliver_form_post(conn, redirect_uri, mode, fields) do
    if web_form_action?(redirect_uri) do
      conn
      |> put_resp_header("cache-control", "no-store")
      |> put_resp_header("pragma", "no-cache")
      |> put_resp_header(
        "content-security-policy",
        "default-src 'none'; script-src 'unsafe-inline'; form-action https: http:; base-uri 'none'; frame-ancestors 'none'"
      )
      |> put_resp_header("content-type", "text/html; charset=utf-8")
      |> send_resp(:ok, form_post_html(redirect_uri, fields))
    else
      send_resp(conn, :bad_request, "invalid redirect_uri for #{mode}")
    end
  end

  defp web_form_action?(redirect_uri) do
    case URI.new(redirect_uri) do
      {:ok, %URI{scheme: scheme, host: host, userinfo: nil}} when scheme in ["https", "http"] ->
        is_binary(host) and host != ""

      _ ->
        false
    end
  rescue
    _ -> false
  end

  # OAuth 2.0 Form Post Response Mode: a minimal auto-submitting form that POSTs
  # the response parameters to the redirect_uri. The action and every name and
  # value are HTML-attribute-escaped; a noscript fallback keeps it usable
  # without scripting.
  defp form_post_html(redirect_uri, fields) do
    action = Plug.HTML.html_escape(redirect_uri)

    inputs =
      Enum.map_join(fields, "\n", fn {name, value} ->
        ~s(<input type="hidden" name="#{Plug.HTML.html_escape(name)}" value="#{Plug.HTML.html_escape(value)}"/>)
      end)

    """
    <!DOCTYPE html>
    <html>
    <head><title>Submitting…</title></head>
    <body onload="document.forms[0].submit()">
    <form method="post" action="#{action}">
    #{inputs}
    <noscript><button type="submit">Continue</button></noscript>
    </form>
    </body>
    </html>
    """
  end

  defp drop_nil(params), do: :maps.filter(fn _key, value -> not is_nil(value) end, params)

  # RFC 9207: the authorization server's issuer identifier as the `iss` response
  # parameter for the query response mode (under JARM it is the JWT `iss` claim).
  defp iss_param(config) do
    if Callback.config_flag(config, :authorization_response_iss),
      do: [{"iss", config.issuer}],
      else: []
  end

  # RFC 6749 §3.1.2: parameters are appended to the redirect_uri's query
  # component, preserving any query already present in the registered URI.
  defp do_redirect(conn, redirect_uri, params) do
    location = append_query(redirect_uri, params)

    conn
    |> put_resp_header("location", location)
    |> send_resp(:found, "")
  end

  defp append_query(uri, params) do
    encoded = URI.encode_query(params)
    parsed = URI.parse(uri)

    new_query =
      case parsed.query do
        nil -> encoded
        existing -> existing <> "&" <> encoded
      end

    URI.to_string(%{parsed | query: new_query})
  end

  # ── Direct (non-redirectable) error page (OIDC Core §3.1.2.6) ─────────────

  # The request is untrusted (bad client_id / redirect_uri / transport), so the
  # error MUST NOT be redirected (open-redirect protection). It is rendered
  # directly to the user agent as a 400 body (OIDC Core §3.1.2.6). The response
  # is content-negotiated on the request's `Accept`: an `Accept: text/html`
  # request gets minimal HTML for a human reviewing it in a browser; other
  # callers keep the JSON body. The body is encoded and sent directly (not
  # through Phoenix content negotiation) so a user agent that arrived without an
  # `Accept` header still receives the error rather than a 406.
  defp render_direct_error(conn, config, reason) do
    description = direct_error_description(Callback.map_value(%{reason: reason}, :reason))
    code = direct_error_code(reason)

    case config.render_authorization_error do
      nil -> render_default_direct_error(conn, code, description)
      callback -> render_host_direct_error(conn, callback, code, description)
    end
  end

  # The host's page for a non-redirectable error (RFC 6749 §4.1.2.1). It is
  # handed the code and the library's own reason text, never a request
  # parameter. A callback that does not send a response is a host fault; the
  # person still has to be told something, so the built-in page is rendered
  # on the conn as it arrived.
  defp render_host_direct_error(conn, callback, code, description) do
    error = PhoenixOAuthError.new(direct_error_atom(code), description, status: 400)

    case Callback.invoke(callback, [conn, error]) do
      %Plug.Conn{state: state} = rendered when state in [:sent, :chunked, :file] ->
        rendered

      _not_a_sent_conn ->
        Logger.error("authorization error render callback did not send a response; rendering the built-in page")
        render_default_direct_error(conn, code, description)
    end
  end

  defp direct_error_atom("invalid_request_uri"), do: :invalid_request_uri
  defp direct_error_atom(_invalid_request), do: :invalid_request

  defp render_default_direct_error(conn, code, description) do
    if HTTPAccept.accepts?(get_req_header(conn, "accept"), "text/html") do
      conn
      |> put_resp_content_type("text/html")
      |> send_resp(:bad_request, direct_error_html(code, description))
    else
      body =
        JSON.encode!(%{
          error: code,
          error_description: description
        })

      conn
      |> put_resp_content_type("application/json")
      |> send_resp(:bad_request, body)
    end
  end

  defp direct_error_html(code, description) do
    escaped_code = Plug.HTML.html_escape(code)
    escaped_description = Plug.HTML.html_escape(description)

    """
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Authorization request error</title>
        <style>
          body {
            margin: 0;
            min-height: 100vh;
            display: grid;
            place-items: center;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: #f7f8fa;
            color: #1f2933;
          }

          main {
            width: min(560px, calc(100vw - 32px));
            padding: 32px;
            border: 1px solid #d8dee6;
            border-radius: 8px;
            background: white;
            box-shadow: 0 12px 32px rgba(15, 23, 42, 0.08);
          }

          h1 {
            margin: 0 0 12px;
            font-size: 24px;
            line-height: 1.2;
          }

          p {
            margin: 0;
            line-height: 1.5;
          }

          code {
            display: inline-block;
            margin-bottom: 16px;
            padding: 4px 8px;
            border-radius: 4px;
            background: #eef2f7;
            font-size: 14px;
          }
        </style>
      </head>
      <body>
        <main>
          <code>#{escaped_code}</code>
          <h1>Authorization request error</h1>
          <p>#{escaped_description}</p>
        </main>
      </body>
    </html>
    """
  end

  defp direct_error_description(:insecure_transport), do: "TLS required"

  # RFC 8252 §8.12: the message names the remedy, because the human seeing it is
  # inside an app that must reopen the flow in the system browser.
  defp direct_error_description(:embedded_user_agent),
    do: "authorization requests from an embedded user agent are not permitted; use the system browser"

  defp direct_error_description(:invalid_client_id), do: "client_id is invalid"
  defp direct_error_description(:missing_redirect_uri), do: "redirect_uri is required"
  defp direct_error_description(:invalid_redirect_uri), do: "redirect_uri is invalid"

  defp direct_error_description(:redirect_uri_not_registered), do: "redirect_uri is not registered for this client"

  defp direct_error_description(:invalid_request_uri), do: "the request_uri is unknown or has expired"

  defp direct_error_description(:invalid_resume),
    do: "the resume reference is unknown, has expired, was already used, or belongs to another browser"

  defp direct_error_description(:resume_with_parameters),
    do: "resume cannot be combined with other authorization request parameters"

  defp direct_error_description(:request_uri_client_mismatch), do: "the request_uri was not issued to this client"

  defp direct_error_description(_), do: "invalid authorization request"

  # The OAuth error code rendered for a non-redirectable failure. RFC 9126 §2.2:
  # an unknown/expired `request_uri` is `invalid_request_uri`; a `request_uri`
  # replayed by a different client is reported as `invalid_request`. Everything
  # else (bad/absent client_id or redirect_uri) is the `invalid_request`
  # catch-all (OIDC Core §3.1.2.6).
  defp direct_error_code(:invalid_request_uri), do: "invalid_request_uri"
  defp direct_error_code(_reason), do: "invalid_request"

  # ── Audit / telemetry ────────────────────────────────────────────────────

  defp emit_code_issued(conn, config, client_id, scope) do
    Event.emit(config, :code_issued, %{
      client_id: client_id,
      scope: Enum.join(List.wrap(scope), " "),
      grant_type: "authorization_code",
      metadata: %{client_ip: RequestContext.client_ip(conn, config)}
    })
  end

  defp emit_denied(conn, config, client_id) do
    Event.emit(config, :authorization_denied, %{
      client_id: client_id,
      metadata: %{client_ip: RequestContext.client_ip(conn, config)}
    })
  end

  defp emit_failure(conn, config, reason) do
    Event.emit(config, :authorization_failed, %{
      result: reason,
      metadata: %{client_ip: RequestContext.client_ip(conn, config)}
    })
  end

  defp config_field(config, key, default) do
    case Map.get(config, key) do
      nil -> default
      value -> value
    end
  end

  # ── Helpers ──────────────────────────────────────────────────────────────
end
