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
      :login_required | :consent_required | :interaction_required |
      :server_error | :temporarily_unavailable})`. Returns
      `{:authenticated, subject}` once a resource owner is established for this
      request, `{:halt, conn}` to take over the connection (e.g. redirect to a
      login page that, after login, re-enters this endpoint with the same
      authorization parameters), `{:none}` when no subject can be established
      without UI, an `{:error, _}` to explicitly classify why interaction is
      required (OIDC Core §3.1.2.6), or `{:error, :server_error}` /
      `{:error, :temporarily_unavailable}` when the host itself failed, for
      example when `AttestoPhoenix.Interaction.park/2` could not store the
      request (RFC 6749 §4.1.2.1). The `subject` is a map carrying at least
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
      {:halt, conn} | {:denied, reason} | {:error, :server_error |
      :temporarily_unavailable})`. Returns `{:consented, subject}` once
      the resource owner has authorized the request (the returned `subject` may
      carry consent-derived claims), `{:halt, conn}` to take over the
      connection (e.g. render a consent screen that re-enters this endpoint),
      `{:denied, _reason}` to refuse, which is reported back to the client as
      the RFC 6749 §4.1.2.1 `access_denied` error by redirect, or
      `{:error, :server_error}` / `{:error, :temporarily_unavailable}` when the
      host itself failed, reported by redirect with that code. When the host
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

  use AttestoPhoenix.Controller, cors: false, formats: [:json]

  import Plug.Conn

  alias Attesto.{Secret, SessionState}
  alias AttestoPhoenix.{AuthorizationRefusal, BrowserState, Callback, Config, Event, LogMetadata, RequestContext}
  alias AttestoPhoenix.AuthorizationServer.{Authorize, RequestPolicy}
  alias AttestoPhoenix.Controller.ErrorRender
  alias AttestoPhoenix.Interaction
  alias AttestoPhoenix.OAuthError, as: PhoenixOAuthError
  alias AttestoPhoenix.RouteControls

  require Logger

  # RFC 6749 §4.1.2.1 error codes reported by redirect.
  @error_access_denied "access_denied"
  @error_server_error "server_error"
  @host_failures [:server_error, :temporarily_unavailable]
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
        render_direct_error(conn, config, reason)
    end
  end

  # ── Resume (AttestoPhoenix.Interaction) ──────────────────────────────────

  # A request carrying `resume` stands for a request parked earlier with
  # `AttestoPhoenix.Interaction.park/2`. The parked parameters replace the
  # request's and then go through the whole pipeline below as a fresh request
  # would. `resume` alone identifies the request (ignoring router path
  # parameters when mounted under a dynamic scope such as `scope "/:tenant"`),
  # so any other query/body parameter beside it is refused.
  defp resume_parked_request(conn, config, %{"resume" => _resume_id} = params) do
    resume_params = effective_resume_params(conn, params)

    with {:resume, resume_id} <- Authorize.resume_params_status(resume_params),
         :ok <- RequestContext.check_https(conn, config),
         {:ok, parked} <- Interaction.take(config, conn, resume_id) do
      conn = Plug.Conn.put_private(conn, @resumed_private_key, parked)
      {:ok, conn, Interaction.request_params(conn)}
    else
      :fresh -> {:ok, conn, params}
      {:error, :resume_with_parameters} -> {:error, :resume_with_parameters}
      {:error, :insecure_transport} -> {:error, :insecure_transport}
      {:error, :invalid_resume} -> {:error, :invalid_resume}
    end
  end

  defp resume_parked_request(conn, _config, params), do: {:ok, conn, params}

  defp effective_resume_params(conn, params) do
    request_params = Interaction.request_params(conn)

    if Map.has_key?(request_params, "resume"),
      do: request_params,
      else: Map.drop(params, Map.keys(conn.path_params))
  end

  defp resumed(conn), do: conn.private[@resumed_private_key]

  defp authorize_params(conn, config, params) do
    conn = put_private(conn, :attesto_phoenix_authorization_client_id, params["client_id"])

    with :ok <- RequestContext.check_https(conn, config),
         :ok <- RequestContext.check_embedded_user_agent(conn, config),
         {:ok, prepared} <- Authorize.prepare_request(config, params, resumed(conn)) do
      conn
      |> stash_par_request_uri(prepared.par_request_uri)
      |> stash_credential_configuration_ids(prepared.credential_configuration_ids)
      |> run_flow(config, prepared.client, prepared.request, prepared.dpop_jkt)
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
        render_direct_error(conn, config, :embedded_user_agent)

      {:error, {:direct, reason}} ->
        # OIDC Core §3.1.2.6: bad client_id / redirect_uri is non-redirectable.
        render_direct_error(conn, config, reason)

      {:error, {:redirect, error}} ->
        # RFC 6749 §4.1.2.1: the client_id/redirect_uri pair is trusted, so the
        # error is reported by redirecting back to the validated redirect_uri.
        emit_redirect_error(conn, config, error)

      {:error, {:scope_refused, request, error_code}} ->
        # RFC 6749 §4.1.2.1 `invalid_scope` / RFC 8707 §2 `invalid_target`: the
        # host's scope policy refused a fully validated request.
        emit_error(conn, config, request, error_code)
    end
  end

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

    if recorded_deny?(conn),
      do: answer_recorded_deny(conn, config, request, prompt_none?),
      else: run_authentication(conn, config, client, request, prompt_none?, dpop_jkt)
  end

  # A Deny recorded with `AttestoPhoenix.Interaction.decide/4` on the resumed
  # entry is answered before authentication. Refusing grants nothing, so it
  # needs no fresh sign-in: a session that went stale against `max_age` while
  # the End-User was on the consent page must not turn their Deny into a login
  # detour that loses it. Only the parking browser, for the parked subject,
  # can record a decision (RFC 6749 §4.1.2.1 `access_denied`; under
  # `prompt=none`, OIDC Core §3.1.2.6 `consent_required`).
  defp recorded_deny?(conn), do: match?(%{consent_decision: "deny"}, resumed(conn))

  defp answer_recorded_deny(conn, config, request, prompt_none?) do
    emit_denied(conn, config, request.client_id)
    emit_error(conn, config, request, if(prompt_none?, do: @error_consent_required, else: @error_access_denied))
  end

  defp run_authentication(conn, config, client, request, prompt_none?, dpop_jkt) do
    case authenticate_resource_owner(conn, config, request) do
      {:authenticated, subject} ->
        run_authenticated(conn, config, client, request, subject, prompt_none?, dpop_jkt)

      {:none} ->
        # OIDC Core §3.1.2.6: the host has no already-authenticated subject it
        # can return without UI. Under `prompt=none` that is `login_required`
        # (never a UI render); otherwise the host should have halted to its
        # login page, so a bare `{:none}` here is a host/config fault.
        if prompt_none? do
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
        emit_error(conn, config, request, error_code)

      {:error, reason} when reason in @host_failures ->
        emit_host_failure(conn, config, request, reason)

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
        case Authorize.authorize_subject_scope(config, client, subject, request) do
          {:ok, request} ->
            conn = stash_credential_configuration_ids(conn, Authorize.credential_configuration_ids(config, request))
            run_consent(conn, config, client, request, subject, prompt_none?, dpop_jkt)

          {:error, reason} ->
            emit_error(conn, config, request, Atom.to_string(reason))
        end

      {:error, error_code} ->
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
    case Authorize.check_authentication_age(request, subject, resumed(conn), prompt_none?) do
      :ok ->
        :ok

      {:error, :max_age_exceeded} when prompt_none? ->
        {:error, @error_login_required}

      {:error, reason} ->
        Logger.error("max_age was requested but the host returned an unusable authentication",
          reason: LogMetadata.term(reason)
        )

        {:error, @error_server_error}
    end
  end

  defp check_prompt_login(conn, request, subject) do
    arrived_at = conn.private.attesto_phoenix_authorization_arrived_at

    case Authorize.check_prompt_login(request, subject, arrived_at, resumed(conn)) do
      {:ok, recorded_since} ->
        conn =
          if @prompt_login in request.prompt,
            do: put_private(conn, :attesto_phoenix_prompt_login_since, recorded_since),
            else: conn

        {:ok, conn}

      {:error, reason} ->
        Logger.error("prompt=login was requested but the host returned an unusable authentication",
          reason: LogMetadata.term(reason)
        )

        {:error, @error_server_error}
    end
  end

  # OIDC Core §3.1.2.6: map the host's interaction-blocked reason to its error
  # code. Reported by redirect to the (already trusted) redirect_uri.
  defp interaction_error_code(:login_required), do: @error_login_required
  defp interaction_error_code(:consent_required), do: @error_consent_required
  defp interaction_error_code(:interaction_required), do: @error_interaction_required

  # RFC 6749 §4.1.2.1: the host's login or consent step failed on its side (a
  # store outage while parking, for instance). The redirect_uri is already
  # trusted, so the client gets the named code by redirect; no host text is
  # sent.
  defp emit_host_failure(conn, config, request, reason) when reason in @host_failures do
    error_code = Atom.to_string(reason)
    emit_error(conn, config, request, error_code)
  end

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

      {:error, reason} when reason in @host_failures ->
        emit_host_failure(conn, config, request, reason)

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
    case Authorize.authorize_request_resource(config, client, request) do
      :ok ->
        issue_and_redirect_authorized(conn, config, request, subject, dpop_jkt)

      {:error, :invalid_target} ->
        # RFC 8707 §2.2: the client requested a resource this server does not
        # serve. A redirectable error (RFC 6749 §4.1.2.1) since the client is
        # already trusted at this point.
        emit_error(conn, config, request, "invalid_target")
    end
  end

  defp issue_and_redirect_authorized(conn, config, request, subject, dpop_jkt) do
    # RFC 9126 §2.2: claim the PAR `request_uri` as the atomic single-use gate
    # BEFORE issuing the code, so two concurrent completions (on any node) cannot
    # each mint a code from one pushed request - exactly one wins the claim.
    case Authorize.claim_par_request_uri(config, conn.private[:attesto_par_request_uri]) do
      :ok ->
        issue_claimed_request(conn, config, request, subject, dpop_jkt)

      :error ->
        # RFC 9126 §2.2/§2.3: the single-use claim was lost - a concurrent
        # completion already consumed this `request_uri`, or it expired during
        # login/consent - so no second code is minted from it. The request is
        # fully validated here (trusted redirect_uri), so report by redirect like
        # the other completion-phase failures.
        emit_error(conn, config, request, @error_invalid_request_uri)
    end
  end

  defp issue_claimed_request(conn, config, request, subject, dpop_jkt) do
    # Generated before the private-context callback so the host sees the same
    # family id the code is minted under.
    family_id = Secret.generate(16)
    subject_id = subject_id(subject)

    credential_context = %{
      ids: Map.get(conn.private, :attesto_credential_configuration_ids),
      authorization_details_ids: Map.get(conn.private, :attesto_credential_authorization_details_ids)
    }

    case Authorize.build_code_claims(config, request, subject, credential_context, subject_id, family_id) do
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
          |> put_optional_dpop_jkt(dpop_jkt)

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

  defp put_optional_dpop_jkt(attrs, jkt) when is_binary(jkt) and jkt != "", do: Map.put(attrs, :dpop_jkt, jkt)

  defp put_optional_dpop_jkt(attrs, _jkt), do: attrs

  defp log_private_context_rejection(:invalid_code_claims) do
    Logger.error("authorization code claims rejected after private context insertion: combined claims are not portable")
  end

  defp log_private_context_rejection(:reserved_private_context_claim) do
    Logger.error("authorization code claims rejected: reserved private context key")
  end

  defp log_private_context_rejection(reason) do
    Logger.error("authorization code private context rejected", reason: LogMetadata.term(reason))
  end

  defp mint_code_and_redirect(conn, config, request, subject, attrs) do
    case Authorize.issue_code(config, attrs) do
      {:ok, code} when is_binary(code) ->
        emit_code_issued(conn, config, request.client_id, request.scope)
        emit_success(conn, config, request, subject, code)

      {:error, %PhoenixOAuthError{} = refusal} ->
        # The host's `:authorization_code_issuance` callback refused.
        error_code = Authorize.issuance_refusal_code(refusal, request)
        emit_error(conn, config, request, error_code)

      {:error, reason} ->
        # Issuance failing on a validated request is a server/config fault,
        # not a client error (RFC 6749 §4.1.2.1 server_error). Do not leak
        # detail.
        Logger.error("authorization code issuance failed", reason: LogMetadata.term(reason))
        emit_error(conn, config, request, @error_server_error)
    end
  end

  # ── OID4VCI authorization_details (OpenID4VCI 1.0, 2025-09-16, §5) ──────

  # Stash the resolved credential_configuration_ids (only when non-empty) so
  # `issue_and_redirect_authorized/5` can read them without threading a new
  # parameter through the whole authenticate/consent chain — the same idiom
  # `stash_par_request_uri/3` uses for the PAR reference.
  defp stash_credential_configuration_ids(conn, %{ids: []}) do
    %{
      conn
      | private:
          Map.drop(conn.private, [:attesto_credential_configuration_ids, :attesto_credential_authorization_details_ids])
    }
  end

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

        # Under prompt=none the caller converts this halt to login_required.
        # Count that final refusal once, preserving the existing response path.
        {:halt, emit_error(conn, config, request, @error_server_error, @prompt_none not in request.prompt)}

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
  defp stash_par_request_uri(conn, uri) when is_binary(uri) and uri != "",
    do: Plug.Conn.put_private(conn, :attesto_par_request_uri, uri)

  defp stash_par_request_uri(conn, _uri), do: conn

  # RFC 6749 §4.1.2.1: error reported once the client/redirect_uri is trusted,
  # where the validated request (and so its response_mode) is known.
  defp emit_error(conn, config, request, error_code, emit_event? \\ true) do
    if emit_event? do
      AuthorizationRefusal.emit(conn, config, error_code, error_code, request.client_id)
    end

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
  # query encoding is used.
  defp emit_redirect_error(conn, config, error) do
    AuthorizationRefusal.emit(conn, config, error.error, error.error, Map.get(error, :client_id))

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
    case Authorize.build_response(config, redirect_uri, response_mode, client_id, params) do
      {:redirect, location} ->
        conn
        |> put_resp_header("location", location)
        |> send_resp(:found, "")

      {:form_post, action_uri, fields} ->
        deliver_form_post(conn, action_uri, fields)

      {:bad_form_post_uri, mode} ->
        send_resp(conn, :bad_request, "invalid redirect_uri for #{mode}")
    end
  end

  # OAuth 2.0 Form Post Response Mode §2: the response parameters are HTML
  # form values the user agent POSTs to the redirect URI; none of them appears
  # in a URL. The page carries the authorization response, so it must not be
  # cached (§4, and RFC 6749 §5.1's rule for responses bearing credentials).
  # One renderer serves the plain mode and its JARM variant.
  defp deliver_form_post(conn, action_uri, fields) do
    conn
    |> put_resp_header("cache-control", "no-store")
    |> put_resp_header("pragma", "no-cache")
    |> put_resp_header(
      "content-security-policy",
      "default-src 'none'; script-src 'unsafe-inline'; form-action https: http:; base-uri 'none'; frame-ancestors 'none'"
    )
    |> put_resp_header("content-type", "text/html; charset=utf-8")
    |> send_resp(:ok, form_post_html(action_uri, fields))
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
    AuthorizationRefusal.emit(conn, config, code, reason)
    status = if reason == :client_metadata_unavailable, do: 503, else: 400

    case config.render_authorization_error do
      nil -> render_default_direct_error(conn, status, code, description)
      callback -> render_host_direct_error(conn, callback, status, code, description)
    end
  end

  # The host's page for a non-redirectable error (RFC 6749 §4.1.2.1). It is
  # handed the code and the library's own reason text, never a request
  # parameter. A callback that does not send a response is a host fault; the
  # person still has to be told something, so the built-in page is rendered
  # on the conn as it arrived.
  defp render_host_direct_error(conn, callback, status, code, description) do
    error = PhoenixOAuthError.new(direct_error_atom(code), description, status: status)

    ErrorRender.invoke_hook(
      conn,
      callback,
      error,
      &render_default_direct_error(&1, status, code, description),
      "authorization error render callback did not send a response; rendering the built-in page"
    )
  end

  defp direct_error_atom("invalid_request_uri"), do: :invalid_request_uri
  defp direct_error_atom("temporarily_unavailable"), do: :temporarily_unavailable
  defp direct_error_atom(_invalid_request), do: :invalid_request

  defp render_default_direct_error(conn, status, code, description) do
    ErrorRender.negotiated(conn, status, direct_error_html(code, description), %{
      error: code,
      error_description: description
    })
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
  defp direct_error_description(:client_metadata_unavailable), do: "client metadata is temporarily unavailable"
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
  defp direct_error_code(:client_metadata_unavailable), do: "temporarily_unavailable"
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
end
