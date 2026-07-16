defmodule AttestoPhoenix.AuthorizationServer.Token do
  @moduledoc """
  Token-endpoint grant processing (RFC 6749 §3.2), as conn-free core.

  This is the single place that turns an authenticated client and a parsed
  token request into either an RFC 6749 §5.1 response body or an
  `AttestoPhoenix.OAuthError`, together with the list of audit events the
  exchange produced. It owns every grant-state and claim-level decision the
  token endpoint takes:

    * the grant dispatch (RFC 6749 §4) across `authorization_code`,
      `refresh_token`, `client_credentials`, and OAuth token exchange
      (RFC 8693);
    * authorization-code redemption and code-reuse family revocation
      (OAuth 2.0 Security BCP §4.13), via `Attesto.AuthorizationCode`;
    * refresh-token rotation and the initial offline-access refresh-token
      issuance gate (RFC 6749 §6 / OIDC Core §11), via `Attesto.RefreshToken`;
    * ID-Token minting with `at_hash`/`c_hash`/`nonce`/`auth_time`
      (OIDC Core §3.1.3.3 / §3.3.2.11), via `Attesto.IDToken`;
    * UserInfo / claims-parameter extra claims (OIDC Core §5.4 / §5.5);
    * scope resolution (RFC 6749 §3.3) and access-token claim assembly, via
      `Attesto.Token`.

  ## North star

  `AttestoPhoenix.Controller.TokenController` parses the request off the
  `Plug.Conn`, authenticates the client (RFC 6749 §2.3), lifts the conn facts
  into a `%Request{}` of plain data, and calls `issue/2`. This module reads only
  data, never touches a conn, and never emits an event: it returns the events as
  data and the controller emits them. Policy is carried on the
  `%AttestoPhoenix.Config{}` the caller passes in (host callbacks, stores, TTLs);
  nothing is hardcoded here.

  ## Return value

  `{:ok, response_map, events}` on success, where `response_map` is the
  RFC 6749 §5.1 body (atom keys) and `events` is a list of
  `%AttestoPhoenix.Event{}` the caller emits. `{:error, %OAuthError{}, events}`
  on failure, where `events` carries the RFC 6749 §5.2 `:token_denied` audit
  event (this module emits no event itself).

  Failures that are a server/config fault rather than a client error (a mint
  failure, a refresh-issuance failure) are surfaced as RFC 6749 §5.2
  `invalid_request` without leaking detail; the underlying reason is logged.
  """

  alias Attesto.{AuthorizationCode, DeviceCode, IDToken, RefreshToken, ResourceIndicator}
  alias AttestoPhoenix.AuthorizationServer.JwtBearer
  alias AttestoPhoenix.AuthorizationServer.SenderConstraint
  alias AttestoPhoenix.AuthorizationServer.Token.Request
  alias AttestoPhoenix.{Callback, ClientIdMetadata, Config, Event, OAuthError, ResourceAudiencePolicy}

  require Logger

  # RFC 6749 §5.2 error codes, held as the atoms `OAuthError.new/3` requires so
  # there is no string round-trip that could raise before the atom exists.
  @error_invalid_request :invalid_request
  @error_invalid_client :invalid_client
  @error_invalid_grant :invalid_grant
  @error_invalid_scope :invalid_scope
  @error_unsupported_grant_type :unsupported_grant_type

  # RFC 8707 §2.1: the error code for a `resource` indicator the server cannot
  # honour (syntactically invalid, or more than one distinct value for a single
  # access token).
  @error_invalid_target :invalid_target

  # RFC 8693 token exchange.
  @grant_token_exchange "urn:ietf:params:oauth:grant-type:token-exchange"
  @subject_token_type_access_token "urn:ietf:params:oauth:token-type:access_token"

  # RFC 7523 §4 / draft-ietf-oauth-identity-assertion-authz-grant-04: the ID-JAG
  # JWT-bearer authorization grant (MCP Enterprise-Managed Authorization).
  @grant_jwt_bearer "urn:ietf:params:oauth:grant-type:jwt-bearer"

  # RFC 8628 §3.4: the device authorization grant token request.
  @grant_device_code "urn:ietf:params:oauth:grant-type:device_code"

  # OpenID Connect CIBA Core 1.0 §10.1: the CIBA grant token request.
  @grant_ciba "urn:openid:params:grant-type:ciba"

  # RFC 8628 §3.5: the polling errors that MUST be rendered with their own error
  # codes (NOT collapsed to invalid_grant) — clients depend on distinguishing
  # authorization_pending / slow_down from a terminal failure.
  @error_authorization_pending :authorization_pending
  @error_slow_down :slow_down
  @error_expired_token :expired_token
  @error_access_denied :access_denied

  # RFC 6749 §4.4 / RFC 8693 §2.1: grants that require a confidential client.
  # client_credentials authenticates the client AS the principal, a token
  # exchange mints fresh authority off a presented token, and the jwt-bearer
  # ID-JAG grant binds the assertion to an authenticated `client_id` (the
  # assertion's `client_id` claim MUST match it); none is safe for a public
  # (`:none`) client that proved possession of no client credential, so all
  # reject the public-client path regardless of any per-client policy.
  # CIBA (CIBA Core §7.1 / FAPI-CIBA §5.2.2) is confidential-clients-only: the
  # backchannel authentication request was made by an authenticated confidential
  # client, and the token request must be by that same client.
  @confidential_only_grants ["client_credentials", @grant_token_exchange, @grant_jwt_bearer, @grant_ciba]

  # OIDC Core §3.1.2.1 / §11: the scope values that trigger ID-Token issuance
  # and initial refresh-token issuance respectively.
  @openid_scope "openid"
  @offline_access_scope "offline_access"

  @typedoc "The RFC 6749 §5.1 token response body (atom keys)."
  @type response :: %{required(atom()) => term()}

  @doc """
  Process a token request, returning the response (or error) and the audit
  events the exchange produced.

  `config` is the validated `%AttestoPhoenix.Config{}` (also carried on the
  `request` for the conn-free helpers); `request` is the
  `AttestoPhoenix.AuthorizationServer.Token.Request` the controller built from
  the request and the conn facts. See the module docs for the return shape.
  This module emits no event itself: the caller emits the returned `events`.

  Direct callers sit at the same trusted post-authentication boundary as the
  controller. They MUST set `request_client_id` only to the identifier proven
  by client authentication; this function deliberately does not reauthenticate
  an already-constructed request. Legacy direct requests that omit the field
  resolve the configured client identifier once for compatibility.
  """
  @spec issue(Config.t(), Request.t()) ::
          {:ok, response(), [Event.t()]} | {:error, OAuthError.t(), [Event.t()]}
  def issue(%Config{} = _config, %Request{} = request) do
    # The controller supplies the exact identifier authenticated at the edge.
    # Preserve compatibility for direct callers that predate that field's
    # authoritative semantics by resolving the host callback once, up front.
    # Every downstream grant, token, ID Token, refresh binding, and event then
    # reads this immutable snapshot instead of re-invoking mutable host policy.
    request = snapshot_client_id(request)

    case run(request) do
      {:ok, response, events} ->
        {:ok, response, events}

      {:error, %OAuthError{} = err} ->
        {:error, err, [denied_event(request, err)]}
    end
  end

  defp run(%Request{} = request) do
    with :ok <- require_supported_grant_type(request),
         :ok <- require_confidential_client(request),
         :ok <- require_registered_grant_type(request) do
      dispatch(request)
    end
  end

  # RFC 6749 §4.4 / RFC 8693: a public client (auth method `:none`) presented no
  # client credential, so it may not run a confidential-only grant. Rejected as
  # invalid_client (RFC 6749 §5.2: client authentication required but absent),
  # independent of the optional per-client `:client_grant_types` policy - the
  # library does not depend on the host wiring that callback to keep a public
  # client out of client_credentials / token-exchange.
  defp require_confidential_client(%Request{grant_type: grant_type, client_auth_method: :none})
       when grant_type in @confidential_only_grants do
    {:error, error(@error_invalid_client, "#{grant_type} requires a confidential client")}
  end

  defp require_confidential_client(%Request{}), do: :ok

  # RFC 8414 §2 / RFC 6749 §5.2: the server gates the token endpoint on the grant
  # types it advertises (`AttestoPhoenix.Config.grant_types_supported/1`). A host
  # that narrows `:grant_types_supported` (e.g. to disable token exchange) has the
  # narrowing ENFORCED here, not merely reflected in discovery - an un-advertised
  # grant is rejected before any per-client check or dispatch. This is the global
  # backstop; `require_registered_grant_type/1` is the per-client restriction.
  defp require_supported_grant_type(%Request{config: config, grant_type: grant_type}) do
    if grant_type in Config.grant_types_supported(config) do
      :ok
    else
      {:error, error(@error_unsupported_grant_type, "unsupported grant_type: #{grant_type}")}
    end
  end

  # RFC 6749 §4: a client may be registered for only a subset of grant types.
  # When the host supplies `:client_grant_types`, a grant the client is not
  # registered for is rejected (RFC 6749 §5.2 unsupported_grant_type); when the
  # callback is unset every grant is allowed (the dispatch's own
  # unsupported-grant clause remains the backstop).
  defp require_registered_grant_type(%Request{} = request) do
    %{config: config, client: client, grant_type: grant_type} = request

    case Callback.invoke(Config.client_grant_types_fun(config), [host_client(client)], nil) do
      grant_types when is_list(grant_types) ->
        if grant_type in grant_types do
          :ok
        else
          {:error, error(@error_unsupported_grant_type, "unsupported grant_type: #{grant_type}")}
        end

      _not_configured ->
        :ok
    end
  end

  # ── Grant dispatch (RFC 6749 §4) ─────────────────────────────────────────

  # RFC 6749 §4.1.3 + RFC 7636: authorization-code grant. Public clients must
  # present PKCE; confidential clients do too by default, unless the host has
  # explicitly relaxed `:require_pkce` for Basic-profile compatibility.
  defp dispatch(%Request{grant_type: "authorization_code"} = request) do
    %{config: config, client: client, params: params} = request

    with {:ok, code} <- require_param(params, "code"),
         {:ok, verifier} <- fetch_code_verifier(config, client, params),
         {:ok, redirect_uri} <- require_param(params, "redirect_uri"),
         {:ok, binding, token_type} <- resolve_sender_constraint(request),
         {:ok, grant} <-
           redeem_code(
             request,
             code,
             verifier,
             redirect_uri,
             SenderConstraint.binding_jkt(binding)
           ),
         {:ok, scope} <- authorize_scope(config, client, grant.scope),
         {:ok, audience} <- resolve_code_resource(grant, params),
         {:ok, response} <-
           mint(
             request,
             grant.subject,
             scope,
             token_type,
             binding,
             access_token_claims(grant),
             # RFC 8707 §2.2: the access token's `aud` is the resource set the
             # user authorized (bound to the code), optionally narrowed by a
             # request-time `resource` — never widened by one. RFC 9470: carry
             # the authentication context (`acr`/`auth_time`) the code recorded
             # at authorize onto the access token for step-up enforcement.
             audience_opts(audience) ++ auth_context_opts(grant.claims)
           ),
         # OIDC Core §3.1.3.3: when the request was an OpenID Connect
         # Authentication Request (granted scope contains `openid`), the token
         # response additionally carries an ID Token.
         {:ok, response} <- maybe_mint_id_token(request, grant, scope, code, response) do
      :ok = record_code_access_token(config, grant, response)
      issued = token_issued_event(request, scope, "authorization_code", token_type, binding)

      # RFC 6749 §4.1.4 / §6: optionally issue an initial refresh token so the
      # client can refresh without re-running the authorization flow. The
      # initial token is minted into the code's `family_id` (OAuth 2.0 Security
      # BCP §4.13) so a later replay of the same code, surfaced as
      # `{:error, {:reuse, meta}}` by `Attesto.AuthorizationCode.redeem/4`,
      # carries the `family_id` needed to revoke this exact descendant family.
      #
      # Only on full success do we finalize the code (record the reuse marker).
      # `redeem/4` claimed and validated the code but deferred that marker, so a
      # failure ANYWHERE above (mint, refresh persistence, a host-callback fault)
      # leaves the code spent-but-unfinalized: the client's retry is a clean
      # `invalid_grant`, never a false reuse that would revoke the family.
      case maybe_issue_refresh_token(request, grant, scope, token_type, binding, response, [issued]) do
        {:ok, response, events} ->
          :ok = AuthorizationCode.finalize(grant_store(config, :code_store), code, grant)
          {:ok, response, events}

        {:error, %OAuthError{}} = error ->
          error
      end
    end
  end

  # RFC 6749 §6 + §10.4: refresh-token rotation with reuse detection.
  defp dispatch(%Request{grant_type: "refresh_token"} = request) do
    %{config: config, client: client, params: params} = request

    with {:ok, presented} <- require_param(params, "refresh_token"),
         requested = parse_requested_scope(params),
         {:ok, resource} <- refresh_requested_resource(params),
         {:ok, binding, token_type} <- resolve_sender_constraint(request),
         {:ok, rotated} <-
           rotate_refresh(
             request,
             presented,
             requested,
             resource,
             SenderConstraint.refresh_binding_jkt(config, client, binding)
           ),
         {:ok, scope} <- authorize_scope(config, client, rotated.context.scope),
         {:ok, response} <-
           mint(
             request,
             rotated.context.subject,
             scope,
             token_type,
             binding,
             %{},
             # RFC 9470: the refresh context carries the ORIGINAL acr/auth_time
             # (never re-stamped on rotation), so the refreshed access token
             # reports the real authentication event.
             audience_opts(rotated.context.resource) ++ context_auth_context_opts(rotated.context)
           ) do
      response = Map.put(response, :refresh_token, rotated.token)
      {:ok, response, [refresh_rotated_event(request, scope, "refresh_token", token_type, binding)]}
    end
  end

  # RFC 6749 §4.4: client-credentials grant. No resource owner is involved, so
  # no refresh token is issued (RFC 6749 §4.4.3).
  defp dispatch(%Request{grant_type: "client_credentials"} = request) do
    %{config: config, client: client, params: params} = request

    with {:ok, binding, token_type} <- resolve_sender_constraint(request),
         subject = token_client_id(request),
         {:ok, scope} <- authorize_scope(config, client, parse_requested_scope(params)),
         {:ok, audience} <- request_resource_audience(config, client, params),
         {:ok, response} <-
           mint(request, subject, scope, token_type, binding, %{}, audience_opts(audience)) do
      {:ok, response, [token_issued_event(request, scope, "client_credentials", token_type, binding)]}
    end
  end

  # RFC 8628 §3.4 / §3.5: device authorization grant. The device polls with its
  # `device_code`; the store's polling state machine returns the user's decision
  # (or the §3.5 pending/slow_down/expired/denied signals, mapped to their exact
  # error codes by `device_grant_error/1`). On approval the bound subject/scope/
  # resource/acr+auth_time mint a token exactly as the authorization-code grant
  # does; a refresh token follows the host `:issue_refresh_token?` gate.
  defp dispatch(%Request{grant_type: @grant_device_code} = request) do
    %{config: config, client: client, params: params} = request

    with {:ok, device_code} <- require_param(params, "device_code"),
         {:ok, binding, token_type} <- resolve_sender_constraint(request),
         {:ok, grant} <- redeem_device_code(request, device_code, SenderConstraint.binding_jkt(binding)),
         {:ok, scope} <- authorize_scope(config, client, grant.scope),
         {:ok, audience} <- resolve_code_resource(grant, params),
         {:ok, response} <-
           mint(
             request,
             grant.subject,
             scope,
             token_type,
             binding,
             %{},
             # RFC 8707 aud from the bound resource set; RFC 9470 acr/auth_time
             # the verification page recorded onto the approved code.
             audience_opts(audience) ++ auth_context_opts(grant.claims)
           ) do
      issued = token_issued_event(request, scope, "device_code", token_type, binding)
      maybe_issue_refresh_token(request, grant, scope, token_type, binding, response, [issued], "device_code")
    end
  end

  # OpenID Connect CIBA Core 1.0 §10.1/§11: the CIBA grant token request. The
  # client polls (or is pinged, then polls) with its `auth_req_id`; the store's
  # state machine returns the user's decision (or the §11 pending/slow_down/
  # expired/denied signals, mapped to their exact error codes by
  # `ciba_grant_error/1`). On approval the bound subject/scope/resource and the
  # authentication context (`acr`/`auth_time`) mint a token exactly as the
  # device grant does, PLUS an ID Token (§10.1: the CIBA token response always
  # carries one - the scope always includes `openid`); a refresh token follows
  # the host `:issue_refresh_token?` gate.
  defp dispatch(%Request{grant_type: @grant_ciba} = request) do
    %{config: config, client: client, params: params} = request

    with {:ok, auth_req_id} <- require_param(params, "auth_req_id"),
         {:ok, binding, token_type} <- resolve_sender_constraint(request),
         {:ok, grant} <- redeem_ciba(request, auth_req_id, SenderConstraint.binding_jkt(binding)),
         {:ok, scope} <- authorize_scope(config, client, grant.scope),
         {:ok, audience} <- resolve_code_resource(grant, params),
         {:ok, response} <-
           mint(
             request,
             grant.subject,
             scope,
             token_type,
             binding,
             %{},
             # RFC 8707 aud from the bound resource set; RFC 9470 acr/auth_time
             # the CIBA approval recorded (on the Grant struct, not in claims).
             audience_opts(audience) ++ ciba_auth_context_opts(grant)
           ),
         # CIBA Core §10.1: the token response carries an ID Token (no nonce -
         # CIBA has none - and no c_hash - there is no authorization code).
         {:ok, response} <- maybe_mint_ciba_id_token(request, grant, scope, response) do
      issued = token_issued_event(request, scope, "ciba", token_type, binding)
      # RFC 9470: fold the Grant's struct-level acr/auth_time into its `claims`
      # so the shared refresh-issuance path (which reads them from `claims`)
      # seeds the refresh family with the real authentication event.
      maybe_issue_refresh_token(
        request,
        ciba_refresh_grant(grant),
        scope,
        token_type,
        binding,
        response,
        [issued],
        "ciba"
      )
    end
  end

  # RFC 8693: exchange a valid Attesto access token for a new, host-authorized
  # access token. The exchanged token MUST NOT carry authority the subject token
  # lacks (§2.1), so a requested scope beyond the subject token's scope is
  # rejected BEFORE the host `:authorize_scope` policy runs - token exchange can
  # only preserve or narrow scope, never broaden it. When no `scope` is requested
  # the subject token's existing scope is carried forward. `:authorize_scope` may
  # then narrow further (client policy), but cannot re-widen past the subject's.
  defp dispatch(%Request{grant_type: @grant_token_exchange} = request) do
    %{config: config, client: client, params: params} = request

    with {:ok, subject_token} <- require_param(params, "subject_token"),
         :ok <- require_subject_token_type(params),
         {:ok, binding, token_type} <- resolve_sender_constraint(request),
         {:ok, claims} <- verify_subject_token(config, subject_token, binding),
         requested = requested_exchange_scope(params, claims),
         :ok <- require_scope_within_subject_token(requested, claims),
         {:ok, scope} <- authorize_scope(config, client, requested),
         {:ok, audience} <- exchange_resource_audience(config, client, params, claims),
         {:ok, response} <- mint_exchanged_token(request, claims, scope, token_type, binding, audience) do
      response = Map.put(response, :issued_token_type, @subject_token_type_access_token)
      {:ok, response, [token_issued_event(request, scope, "token_exchange", token_type, binding)]}
    else
      {:error, %OAuthError{} = err} -> {:error, err}
      {:error, _reason} -> {:error, error(@error_invalid_grant, "subject token is invalid")}
    end
  end

  # RFC 7523 §4 / draft-ietf-oauth-identity-assertion-authz-grant-04: the ID-JAG
  # JWT-bearer authorization grant. The client presents an Identity Assertion JWT
  # (signed by a trusted enterprise IdP, asserting one user for this resource
  # application) in the `assertion` parameter and receives a normal access token.
  # `AttestoPhoenix.AuthorizationServer.JwtBearer` validates the assertion
  # (signature against the trusted issuer's JWKS, claims, `jti` replay) and maps
  # its `client_id` claim to the authenticated client, then resolves the local
  # subject via the host `:resolve_jwt_bearer_subject` callback. The assertion's
  # `scope` claim, when present, is the ceiling on what may be granted (draft
  # §6.1); the host `:authorize_scope` policy narrows from there.
  defp dispatch(%Request{grant_type: @grant_jwt_bearer} = request) do
    %{config: config, client: client, params: params} = request

    with {:ok, %{subject: subject, scope_ceiling: ceiling, claims: _claims}} <-
           jwt_bearer_authorize(config, token_client_id(request), params),
         {:ok, binding, token_type} <- resolve_sender_constraint(request),
         {:ok, audience} <- request_resource_audience(config, client, params),
         requested = jwt_bearer_requested_scope(params, ceiling),
         :ok <- require_scope_within_ceiling(requested, ceiling),
         {:ok, scope} <- authorize_scope(config, client, requested),
         {:ok, response} <-
           mint(request, subject, scope, token_type, binding, %{}, audience_opts(audience)) do
      # RFC 7523 §4 / draft-ietf-oauth-identity-assertion-authz-grant-04: this
      # grant issues NO refresh token. Access is re-derived from a fresh
      # assertion on each request; a refresh token would outlive the enterprise
      # IdP's policy/deprovisioning window, letting a client keep minting access
      # after the IdP has revoked the user's entitlement. The client re-presents
      # a fresh ID-JAG instead of refreshing.
      {:ok, response, [token_issued_event(request, scope, @grant_jwt_bearer, token_type, binding)]}
    end
  end

  # RFC 6749 §5.2.
  defp dispatch(%Request{grant_type: grant_type}) do
    {:error, error(@error_unsupported_grant_type, "unsupported grant_type: #{grant_type}")}
  end

  # Validate the ID-JAG and map the handler's reasons to RFC 6749 §5.2 errors: a
  # missing `assertion` parameter is a malformed request (`invalid_request`);
  # every assertion/trust/replay/subject failure collapses to `invalid_grant`
  # (draft §6.1) so the wire never learns which issuers are trusted or why a
  # subject was denied. The authenticated client's identifier is passed so the
  # handler can enforce the `client_id`-claim binding.
  defp jwt_bearer_authorize(config, authenticated_client_id, params) do
    case JwtBearer.authorize(config, authenticated_client_id, params) do
      {:ok, result} ->
        {:ok, result}

      {:error, :missing_assertion} ->
        {:error, error(@error_invalid_request, "assertion is required")}

      {:error, _reason} ->
        {:error, error(@error_invalid_grant, "the identity assertion is invalid")}
    end
  end

  # When the client requests no scope, default to the assertion's scope ceiling
  # (mirrors token exchange); an absent ceiling leaves the request empty so the
  # host `:authorize_scope` policy alone decides.
  defp jwt_bearer_requested_scope(params, ceiling) do
    case parse_requested_scope(params) do
      [] when is_list(ceiling) -> ceiling
      requested -> requested
    end
  end

  # draft §6.1: the granted scope MUST be within the assertion's `scope` claim
  # when it carries one. The host `:authorize_scope` callback never sees the
  # assertion, so the library enforces the ceiling before delegating. An absent
  # ceiling (`nil`) imposes no bound.
  defp require_scope_within_ceiling(_requested, nil), do: :ok

  defp require_scope_within_ceiling(requested, ceiling) when is_list(ceiling) do
    case requested -- ceiling do
      [] -> :ok
      _exceeded -> {:error, error(@error_invalid_scope, "requested scope exceeds the assertion")}
    end
  end

  # RFC 8707 §2: the request-time `resource` indicator(s) scope the issued access
  # token to the named protected resource(s) by setting its `aud`. Validation
  # (§2.1 absolute-URI syntax) and parsing live in the conn-free core primitive
  # `Attesto.ResourceIndicator`; authorization (§2.2) is against the set of
  # resources this server will mint for `client` (`Config.allowed_resources/2`:
  # the server's own `:audience` plus any configured / per-client allow-listed
  # resources). Returns `{:ok, [resource]}` (possibly `[]` when none was
  # requested - the `config.audience` default), or `invalid_target`.
  #
  # This is the request-time path, used by grants whose resource arrives on the
  # token request (`client_credentials`, token exchange, jwt-bearer). The
  # `authorization_code` and `refresh_token` grants instead mint `aud` from the
  # resource set BOUND to the grant at authorization time.
  defp request_resource_audience(config, client, params) do
    with {:ok, resources} <- validate_resource_param(params) do
      authorize_resources(config, client, resources)
    end
  end

  defp validate_resource_param(params) do
    case ResourceIndicator.validate(Map.get(params, "resource")) do
      {:ok, resources} ->
        {:ok, resources}

      {:error, :invalid_target} ->
        {:error, error(@error_invalid_target, "resource is not a valid absolute-URI indicator (RFC 8707 §2.1)")}
    end
  end

  # RFC 8707 §2.2: a client may only target a resource this server serves for it;
  # any other resource is `invalid_target` so the AS never mints a token for a
  # resource it does not serve (and a client cannot mis-audience a token to a
  # sibling resource it was not granted).
  defp authorize_resources(config, client, resources) do
    case ResourceIndicator.authorize(resources, Config.allowed_resources(config, client)) do
      {:ok, resources} ->
        {:ok, resources}

      {:error, :invalid_target} ->
        {:error, error(@error_invalid_target, "the requested resource is not served by this authorization server")}
    end
  end

  # RFC 8707: a `resource` presented at authorization-code redemption may NARROW
  # the set the code was bound to (a subset the user already authorized) but never
  # widen it — a requested resource outside the bound set is `invalid_target`, and
  # a malformed one is rejected (§2.1). Absent, the full bound set is used.
  defp resolve_code_resource(grant, params) do
    case ResourceIndicator.validate(Map.get(params, "resource")) do
      {:ok, []} ->
        {:ok, grant.resource}

      {:ok, requested} ->
        if Enum.all?(requested, &(&1 in grant.resource)),
          do: {:ok, requested},
          else: {:error, error(@error_invalid_target, "the requested resource is not within the grant")}

      {:error, :invalid_target} ->
        {:error, error(@error_invalid_target, "resource is not a valid absolute-URI indicator (RFC 8707 §2.1)")}
    end
  end

  # The `Attesto.Token.mint/3` opt carrying the RFC 8707 resource audience(s); an
  # empty set adds no opt, so `mint/3` keeps its `config.audience` default.
  defp audience_opts([]), do: []
  defp audience_opts(resources) when is_list(resources), do: [audience: resources]

  # RFC 9470 / OIDC Core §2: the `Attesto.Token.mint/3` opts carrying the
  # authentication context (`acr` / `auth_time`) onto the access token, read from
  # the source map (an authorization code's `claims`, where the authorize
  # controller's code_claims/2 recorded the host-asserted values; string keys).
  # Absent values add no opt, so a flow that never established an auth context
  # (machine grants) mints no acr/auth_time and fails closed against step-up.
  defp auth_context_opts(source) when is_map(source) do
    []
    |> put_optional_kw(:acr, valid_acr(Map.get(source, "acr")))
    |> put_optional_kw(:auth_time, valid_auth_time(Map.get(source, "auth_time")))
  end

  defp auth_context_opts(_source), do: []

  # As above but from a refresh-token context map (atom keys `:acr`/`:auth_time`).
  defp context_auth_context_opts(context) when is_map(context) do
    []
    |> put_optional_kw(:acr, valid_acr(Map.get(context, :acr)))
    |> put_optional_kw(:auth_time, valid_auth_time(Map.get(context, :auth_time)))
  end

  defp valid_acr(acr) when is_binary(acr) and acr != "", do: acr
  defp valid_acr(_acr), do: nil
  defp valid_auth_time(t) when is_integer(t) and t >= 0, do: t
  defp valid_auth_time(_t), do: nil

  # ── Grant-state delegation (Attesto core) ────────────────────────────────

  # PKCE enforcement is challenge-based and belongs to the code, not the request:
  # the authorization/PAR endpoint already requires a `code_challenge`
  # (RequestPolicy.require_pkce?/2) for clients that must use PKCE, so the issued
  # code carries one. `Attesto.AuthorizationCode.redeem/4` then requires a
  # matching `code_verifier` and collapses a missing OR mismatched verifier to
  # `invalid_grant` (RFC 7636 §4.6). So the verifier is passed through optionally
  # rather than short-circuited here as `invalid_request`.
  defp fetch_code_verifier(_config, _client, params) do
    {:ok, optional_param(params, "code_verifier")}
  end

  defp redeem_code(%Request{config: config} = request, code, verifier, redirect_uri, jkt) do
    params =
      %{
        redirect_uri: redirect_uri,
        client_id: token_client_id(request)
      }
      |> put_optional(:code_verifier, verifier)
      |> put_optional(:dpop_jkt, jkt)

    case AuthorizationCode.redeem(grant_store(config, :code_store), code, params) do
      {:ok, grant} ->
        {:ok, grant}

      # OAuth 2.0 Security BCP §4.13 / RFC 6749 §4.1.2: a re-presented,
      # already-redeemed code is the reuse attack signal. Revoke the
      # descendant refresh-token family recorded at the first redemption
      # (`meta.family_id`) before answering - the captured code and any tokens
      # it spawned are now compromised - then fail closed with the generic
      # `invalid_grant` so the replay learns nothing on the wire.
      {:error, {:reuse, meta}} ->
        revoke_reused_family(config, meta)
        revoke_reused_access_tokens(config, meta)
        {:error, grant_error(:invalid_grant)}

      {:error, reason} ->
        {:error, grant_error(reason)}
    end
  end

  # RFC 8628 §3.4/§3.5: poll the device-code store for the authenticated client's
  # `device_code`, carrying the DPoP holder-of-key the token request demonstrated
  # (matched against any pre-bound key). The §3.5 polling signals map to their
  # own wire error codes; only a genuinely bad/unknown code is `invalid_grant`.
  defp redeem_device_code(%Request{config: config} = request, device_code, jkt) do
    store = Config.device_code_store(config)
    interval = config |> Config.device_authorization() |> Keyword.get(:poll_interval_seconds, 5)

    params =
      %{client_id: token_client_id(request)}
      |> put_optional(:dpop_jkt, jkt)

    case DeviceCode.redeem(store, device_code, params, interval: interval) do
      {:ok, grant} -> {:ok, grant}
      {:error, reason} -> {:error, device_grant_error(reason)}
    end
  end

  # RFC 8628 §3.5: render each polling outcome with its OWN error code. The
  # client distinguishes "keep polling" (authorization_pending / slow_down) from
  # a terminal failure (expired_token / access_denied) — collapsing them to
  # invalid_grant would break the polling loop.
  defp device_grant_error(:authorization_pending),
    do: error(@error_authorization_pending, "the authorization request is still pending")

  defp device_grant_error(:slow_down), do: error(@error_slow_down, "polling too frequently; slow down")
  defp device_grant_error(:expired_token), do: error(@error_expired_token, "the device code has expired")
  defp device_grant_error(:access_denied), do: error(@error_access_denied, "the user denied the request")
  defp device_grant_error(_reason), do: error(@error_invalid_grant, "the device code is invalid")

  # CIBA Core §10.1/§11: redeem the authenticated client's `auth_req_id`,
  # carrying the DPoP holder-of-key the token request demonstrated (matched
  # against any key pre-bound at issue). The §11 polling signals map to their
  # own wire error codes; only a bad/unknown/wrong-client request is
  # `invalid_grant`.
  defp redeem_ciba(%Request{config: config} = request, auth_req_id, jkt) do
    store = Config.ciba_store(config)

    params =
      %{client_id: token_client_id(request)}
      |> put_optional(:dpop_jkt, jkt)

    case Attesto.CIBA.redeem(store, auth_req_id, params, []) do
      {:ok, grant} -> {:ok, grant}
      {:error, reason} -> {:error, ciba_grant_error(reason)}
    end
  end

  # CIBA Core §11: render each redemption outcome with its OWN error code so the
  # client distinguishes "keep polling" (authorization_pending / slow_down) from
  # a terminal failure (expired_token / access_denied). A push-mode request
  # redeemed at the token endpoint is `unauthorized_client` (§11); everything
  # else (unknown / wrong-client / wrong-DPoP / consumed) is `invalid_grant`.
  defp ciba_grant_error(:authorization_pending),
    do: error(@error_authorization_pending, "the authentication request is still pending")

  defp ciba_grant_error(:slow_down), do: error(@error_slow_down, "polling too frequently; slow down")
  defp ciba_grant_error(:expired_token), do: error(@error_expired_token, "the authentication request has expired")
  defp ciba_grant_error(:access_denied), do: error(@error_access_denied, "the user denied the request")

  defp ciba_grant_error(:unauthorized_client),
    do: error(:unauthorized_client, "a push-mode request must not be redeemed at the token endpoint")

  defp ciba_grant_error(_reason), do: error(@error_invalid_grant, "the authentication request is invalid")

  # RFC 9470: fold the CIBA Grant's struct-level acr/auth_time into its `claims`
  # so the shared refresh-issuance path (`issue_initial_refresh_token`, which
  # reads them from `claims`) seeds the refresh family with the real
  # authentication event, exactly as the authorization-code grant does.
  defp ciba_refresh_grant(grant) do
    claims =
      grant.claims
      |> put_optional("acr", valid_acr(grant.acr))
      |> put_optional("auth_time", valid_auth_time(grant.auth_time))

    %{grant | claims: claims}
  end

  # RFC 9470 / OIDC Core §2: the CIBA Grant carries the satisfied `acr` and the
  # `auth_time` of the out-of-band authentication as struct fields (not in a
  # claims map like the authorization code), so read them directly onto the
  # access token. Absent values add no opt (fail closed against step-up).
  defp ciba_auth_context_opts(%{acr: acr, auth_time: auth_time}) do
    []
    |> put_optional_kw(:acr, valid_acr(acr))
    |> put_optional_kw(:auth_time, valid_auth_time(auth_time))
  end

  # CIBA Core §10.1: the token response from a CIBA grant always carries an ID
  # Token (the request scope always contains `openid`, CIBA §7.1). It carries
  # `sub`/`acr`/`auth_time` and `at_hash`, but no `nonce` (CIBA has none) and no
  # `c_hash` (there is no authorization code). Gated on `openid` defensively.
  defp maybe_mint_ciba_id_token(%Request{} = request, grant, scope, response) do
    if @openid_scope in scope do
      mint_ciba_id_token(request, grant, scope, response)
    else
      {:ok, response}
    end
  end

  defp mint_ciba_id_token(%Request{config: config, client: client} = request, grant, scope, response) do
    case token_client_id(request) do
      client_id when is_binary(client_id) and client_id != "" ->
        opts =
          [access_token: response.access_token]
          # FAPI-CIBA §5.2.2: `acr` REQUIRED in the ID Token when the client
          # requested `acr_values` (the approval recorded the satisfied value).
          |> put_optional_kw(:acr, valid_acr(grant.acr))
          |> put_optional_kw(:auth_time, valid_auth_time(grant.auth_time))
          |> put_optional_kw(:extra_claims, ciba_id_token_extra_claims(config, client, grant, scope))

        case IDToken.mint(attesto_config(config), grant.subject, client_id, opts) do
          {:ok, id_token} ->
            {:ok, Map.put(response, :id_token, id_token)}

          {:error, reason} ->
            Logger.error("ciba id token mint failed: #{inspect(reason)}")
            {:error, error(@error_invalid_request, "unable to issue token")}
        end

      _ ->
        Logger.error("ciba id token mint failed: missing client_id")
        {:error, error(@error_invalid_request, "unable to issue token")}
    end
  end

  # OIDC Core §5.4/§5.5: host-sourced extra ID Token claims (e.g. `email`),
  # sourced from the `:build_id_token_claims` callback. CIBA carries no OIDC
  # `claims` request parameter, so the requested-claims argument is nil.
  defp ciba_id_token_extra_claims(config, client, grant, scope) do
    case Config.build_id_token_claims_fun(config) do
      nil ->
        nil

      callback ->
        case invoke(callback, [host_client(client), grant.subject, scope, nil]) do
          map when is_map(map) and map_size(map) > 0 -> map
          _ -> nil
        end
    end
  end

  # Revoke the refresh-token family linked to a replayed code (OAuth 2.0
  # Security BCP §4.13.2) through the configured `:refresh_store`. The reuse
  # `meta` carries a `family_id` (not a token), so the family-level
  # `c:Attesto.RefreshStore.revoke_family/1` is the right seam -
  # `Attesto.Revocation` is the per-token entry point and would need a token
  # to look the family up. Reuse detection only fires when a `:code_store`
  # tracks consumption; a deployment that wired no `:refresh_store` has no
  # family to revoke (the grant never minted one), so this is a no-op there,
  # as is an absent/empty `family_id`.
  defp revoke_reused_family(config, meta) do
    if refresh_store = grant_store(config, :refresh_store) do
      case reuse_family_id(meta) do
        family_id when is_binary(family_id) and family_id != "" ->
          :ok = refresh_store.revoke_family(family_id)

        _ ->
          :ok
      end
    end

    :ok
  end

  # The replayed code's first-redemption context is the
  # `Attesto.CodeStore.consumed_meta()` map (always a map per that callback's
  # spec). Read the `:family_id` under both atom and string keys so a store
  # that serialised it either way is honoured; absent it, return nil and the
  # caller treats revocation as a no-op.
  defp reuse_family_id(meta) do
    Map.get(meta, :family_id) || Map.get(meta, "family_id")
  end

  defp revoke_reused_access_tokens(config, meta) do
    store = grant_store(config, :code_store)

    if store && function_exported?(store, :revoke_family_access_tokens, 1) do
      case reuse_family_id(meta) do
        family_id when is_binary(family_id) and family_id != "" ->
          :ok = store.revoke_family_access_tokens(family_id)

        _ ->
          :ok
      end
    end

    :ok
  end

  # The request-time `resource` on a refresh narrows the bound set (the core
  # enforces subset-only). An absent parameter (`{:ok, []}` from the validator)
  # becomes `nil` so the full granted set is kept; a present-but-malformed value
  # is `invalid_target`.
  defp refresh_requested_resource(params) do
    case ResourceIndicator.validate(Map.get(params, "resource")) do
      {:ok, []} ->
        {:ok, nil}

      {:ok, resources} ->
        {:ok, resources}

      {:error, :invalid_target} ->
        {:error, error(@error_invalid_target, "resource is not a valid absolute-URI indicator (RFC 8707 §2.1)")}
    end
  end

  defp rotate_refresh(%Request{config: config} = request, presented, requested, resource, jkt) do
    opts =
      [client_id: token_client_id(request)]
      |> put_optional_kw(:scope, requested)
      # RFC 8707: a present `resource` narrows the bound set (subset-only); absent
      # (`nil`) keeps the full granted set so the refreshed token stays audienced
      # to the resources the original grant authorized.
      |> put_optional_kw(:resource, resource)
      |> put_optional_kw(:dpop_jkt, jkt)
      |> Keyword.put(:rotation_grace_seconds, config.refresh_token_rotation_grace_seconds)

    case RefreshToken.rotate(grant_store(config, :refresh_store), presented, opts) do
      {:ok, rotated} -> {:ok, rotated}
      {:error, reason} -> {:error, grant_error(reason)}
    end
  end

  # ── Initial refresh-token issuance (RFC 6749 §4.1.4 / §6) ────────────────

  # RFC 6749 §6: an authorization-code grant MAY return a refresh token. It
  # is host policy whether to do so, so issuance is gated and only happens
  # when:
  #
  #   * a `:refresh_store` is configured (the persistence the refresh grant
  #     needs), and
  #   * the policy permits it: the host's `:issue_refresh_token?` callback
  #     returns `true` for this `(client, scope)`, OR - when the host does
  #     not supply that callback - the granted scope contains the
  #     `offline_access` scope (OIDC Core §11), the standard signal that the
  #     client asked for offline access.
  #
  # RFC 9449 §8 requires DPoP-bound refresh tokens for public clients. For
  # confidential clients, the refresh token remains bound to the authenticated
  # client_id (RFC 6749 §6 / §10.4) rather than to one DPoP proof key; this
  # lets a confidential client rotate or recover its DPoP key while each newly
  # minted access token is still sender-constrained to the proof presented on
  # that token request. An mTLS-bound request issues no DPoP binding on the
  # refresh token. The plaintext token is added to the RFC 6749 §5.1 body;
  # only its hash is persisted (see `Attesto.RefreshToken`).
  defp maybe_issue_refresh_token(
         request,
         grant,
         scope,
         token_type,
         binding,
         response,
         events,
         grant_type \\ "authorization_code"
       ) do
    %{config: config, client: client} = request

    if refresh_store = grant_store(config, :refresh_store) do
      if issue_refresh_token?(config, client, scope) do
        issue_initial_refresh_token(
          request,
          grant,
          scope,
          {token_type, binding},
          refresh_store,
          response,
          events,
          grant_type
        )
      else
        {:ok, response, events}
      end
    else
      {:ok, response, events}
    end
  end

  defp issue_initial_refresh_token(request, grant, scope, sender, refresh_store, response, events, grant_type) do
    %{config: config, client: client} = request
    {token_type, binding} = sender

    # RFC 8707: carry the code's bound resource set onto the initial refresh
    # token so a refreshed access token stays audienced to the same resources.
    # RFC 9470: seed the original acr/auth_time (from the code's claims) onto the
    # refresh family so refreshes preserve the real authentication event.
    context =
      %{subject: grant.subject, scope: scope, resource: grant.resource}
      |> put_optional(:client_id, token_client_id(request))
      |> put_optional(:acr, valid_acr(Map.get(grant.claims, "acr")))
      |> put_optional(:auth_time, valid_auth_time(Map.get(grant.claims, "auth_time")))
      |> put_optional(:dpop_jkt, SenderConstraint.refresh_binding_jkt(config, client, binding))

    # OAuth 2.0 Security BCP §4.13: mint the initial token into the code's
    # `family_id` so the spent code and its descendant tokens share one
    # family. `Attesto.RefreshToken.issue/3` takes `:family_id` as an option
    # (not in the context map) and starts a fresh family only when it is
    # absent; threading the grant's `family_id` here is what lets a later
    # code-reuse `{:reuse, meta}` revoke this exact family (see
    # `revoke_reused_family/2`). When the code carried no `family_id`,
    # `put_optional_kw/3` drops the option, a fresh family is generated, and
    # reuse detection simply has no family to revoke.
    # `Map.get/2` (not `grant.family_id`) so this path is shared with grants
    # whose struct has no `family_id` (the RFC 8628 device grant): a single-use
    # device code has no code-reuse family to link, so the absent id yields a
    # fresh family — exactly the intended behavior.
    issue_opts =
      [ttl: config.refresh_token_ttl]
      |> put_optional_kw(:family_id, Map.get(grant, :family_id))

    case RefreshToken.issue(refresh_store, context, issue_opts) do
      {:ok, %{token: token}} ->
        response = Map.put(response, :refresh_token, token)
        issued = refresh_issued_event(request, scope, grant_type, token_type, binding)
        {:ok, response, events ++ [issued]}

      {:error, reason} ->
        # Issuance is a server/config fault, not a client error; do not leak
        # detail, and do not hand back an access token whose advertised
        # offline access we then failed to provide.
        Logger.error("refresh token issuance failed: #{inspect(reason)}")
        {:error, error(@error_invalid_request, "unable to issue token")}
    end
  end

  # The issuance gate. Prefer the host's `:issue_refresh_token?` callback;
  # when it is not supplied, fall back to the OIDC `offline_access` scope
  # signal. Read defensively so a host that wires neither simply never gets
  # an initial refresh token (fail-closed: no token rather than a crash).
  defp issue_refresh_token?(config, client, scope) do
    case Callback.config_callback(config, :issue_refresh_token?) do
      nil -> @offline_access_scope in scope
      callback -> invoke(callback, [host_client(client), scope]) == true
    end
  end

  # ── ID Token issuance (OpenID Connect Core §3.1.3.3) ─────────────────────

  # OIDC Core §3.1.3.3: the token response from an OpenID Connect
  # Authentication Request carries an ID Token in addition to the access
  # token. The trigger is the granted scope containing the `openid` scope
  # value (OIDC Core §3.1.2.1); a non-openid authorization-code grant is a
  # plain OAuth 2.0 response (access token only) and is left untouched.
  defp maybe_mint_id_token(%Request{} = request, grant, scope, code, response) do
    if @openid_scope in scope do
      mint_id_token(request, grant, scope, code, response)
    else
      {:ok, response}
    end
  end

  # The ID Token's `aud` is the exact OAuth `client_id` authenticated for this
  # token request (OIDC Core §2). Use the same immutable snapshot as the access
  # token and state redemption so a mutable host callback cannot split one
  # response across two client identities.
  defp mint_id_token(%Request{config: config, client: client} = request, grant, scope, code, response) do
    case token_client_id(request) do
      client_id when is_binary(client_id) and client_id != "" ->
        opts = id_token_opts(config, client, grant, scope, code, response)

        case IDToken.mint(attesto_config(config), grant.subject, client_id, opts) do
          {:ok, id_token} ->
            maybe_record_logout_session(config, client, grant, client_id)
            {:ok, Map.put(response, :id_token, id_token)}

          {:error, reason} ->
            # Minting is a server/config fault, not a client error; do not
            # leak detail, and do not hand back an access token whose OpenID
            # Connect contract (an ID Token) we then failed to satisfy.
            Logger.error("id token mint failed: #{inspect(reason)}")
            {:error, error(@error_invalid_request, "unable to issue token")}
        end

      _ ->
        Logger.error("id token mint failed: missing client_id")
        {:error, error(@error_invalid_request, "unable to issue token")}
    end
  end

  # OIDC Back-Channel Logout 1.0 §2 / Front-Channel Logout 1.0 §3: record that
  # this Relying Party now holds a session for the subject, so the end-session
  # endpoint can later POST it a `logout_token` and/or render its
  # `frontchannel_logout_uri` in an iframe on the logout page. Recorded only
  # when logout is wired (store present), the session carries a `sid`, and the
  # client registered at least one logout URI — a plain (non-logout-capable) RP
  # records nothing. Idempotent on `(sid, client_id)`, so a refresh re-mint
  # refreshes the row rather than duplicating it. Best-effort: a store failure
  # never blocks token issuance (the session is simply not logout-reachable),
  # so it is logged and swallowed.
  defp maybe_record_logout_session(config, client, grant, client_id) do
    with true <- Config.logout_enabled?(config),
         store when not is_nil(store) <- Config.logout_session_store(config),
         sid when is_binary(sid) and sid != "" <- id_token_claim(grant.claims, "sid") do
      bc_uri = Config.client_backchannel_logout_uri(config, host_client(client))
      fc_uri = Config.client_frontchannel_logout_uri(config, host_client(client))

      if is_binary(bc_uri) or is_binary(fc_uri) do
        now = System.system_time(:second)

        store.record(%{
          sid: sid,
          subject: grant.subject,
          client_id: client_id,
          backchannel_logout_uri: bc_uri,
          session_required: Config.client_backchannel_logout_session_required(config, host_client(client)),
          frontchannel_logout_uri: fc_uri,
          frontchannel_session_required:
            Config.client_frontchannel_logout_session_required(config, host_client(client)),
          expires_at: now + Config.logout_session_ttl_seconds(config)
        })
      else
        :ok
      end
    else
      _ -> :ok
    end
  rescue
    e ->
      Logger.warning("logout session record failed: #{inspect(e)}")
      :ok
  end

  # OIDC Core §3.1.3.6 / §3.3.2.11: bind the ID Token to the artifacts of this
  # exchange. The `nonce` from the Authentication Request (OIDC Core §3.1.3.7
  # item 11) and the optional `auth_time`/`acr`/`amr` (OIDC Core §2) ride in
  # the authorization code's `claims`, carried verbatim from the authorization
  # endpoint by `Attesto.AuthorizationCode`. `at_hash` is computed from the
  # access token just minted and `c_hash` from the redeemed code.
  defp id_token_opts(config, client, grant, scope, code, response) do
    # `Attesto.AuthorizationCode` always materialises `:claims` as a map
    # (defaulting to `%{}` at construction), so it is read directly here.
    claims = grant.claims

    [access_token: response.access_token, code: code]
    |> put_optional_kw(:nonce, id_token_claim(claims, "nonce"))
    |> put_optional_kw(:auth_time, id_token_claim(claims, "auth_time"))
    |> put_optional_kw(:acr, id_token_claim(claims, "acr"))
    |> put_optional_kw(:amr, id_token_claim(claims, "amr"))
    # OIDC Back-Channel Logout 1.0 §2.1: stamp the session id the authorization
    # endpoint recorded, so a later logout token can target this session.
    |> put_optional_kw(:sid, id_token_claim(claims, "sid"))
    # OIDC Core §5.4/§5.5: host userinfo / claims-param-requested claims ride
    # in as `Attesto.IDToken.mint/4`'s `:extra_claims`, where the protocol
    # claims stay authoritative (a collision is rejected, never shadowed).
    |> put_optional_kw(:extra_claims, id_token_extra_claims(config, client, grant, scope))
  end

  # OIDC Core §5.4 / §5.5: the additional identity claims an ID Token may
  # carry (e.g. `email`, `name`) are the host's to source - this library knows
  # no user store. The host's `:build_id_token_claims` callback is given the
  # client, the authenticated `subject`, the granted `scope`, and the OIDC
  # `claims` request parameter the authorization endpoint stashed on the code
  # (OIDC Core §5.5, the claims-param-requested claims), and returns a map of
  # extra claims. They ride into `Attesto.IDToken.mint/4` via its `:claims`
  # option, where the standard claims (`iss`/`sub`/`aud`/...) always win, so
  # the host cannot forge protocol claims. Read defensively: a host that wires
  # no callback adds no extra claims (`nil` -> the `:claims` option is dropped
  # by `put_optional_kw/3`), and a callback that does not return a non-empty
  # map is treated the same (fail-closed: no claims rather than a crash or a
  # malformed token).
  defp id_token_extra_claims(config, client, grant, scope) do
    case Config.build_id_token_claims_fun(config) do
      nil ->
        nil

      callback ->
        requested = id_token_claim(grant.claims, "claims")

        case invoke(callback, [host_client(client), grant.subject, scope, requested]) do
          map when is_map(map) and map_size(map) > 0 -> map
          _ -> nil
        end
    end
  end

  # The authorization code's `claims` is an opaque host map; read each OIDC
  # value under both its string and atom key so a host that stashed it either
  # way is honoured, and treat anything absent as `nil` (the option is then
  # simply not passed to `Attesto.IDToken.mint/4`).
  defp id_token_claim(claims, key) do
    Map.get(claims, key) || Map.get(claims, String.to_existing_atom(key))
  rescue
    ArgumentError -> Map.get(claims, key)
  end

  # ── Scope (RFC 6749 §3.3) ────────────────────────────────────────────────

  # RFC 6749 §3.3: the `scope` parameter is a space-delimited, case-sensitive
  # list of scope tokens. Splitting is pure framing; what the resulting list is
  # allowed to grant is decided by the host's `:authorize_scope` callback.
  defp parse_requested_scope(params) do
    case params["scope"] do
      value when is_binary(value) and value != "" -> String.split(value, " ", trim: true)
      _ -> []
    end
  end

  defp require_subject_token_type(params) do
    case params["subject_token_type"] do
      @subject_token_type_access_token -> :ok
      nil -> {:error, error(@error_invalid_request, "subject_token_type is required")}
      _ -> {:error, error(@error_invalid_request, "subject_token_type is unsupported")}
    end
  end

  defp verify_subject_token(config, token, binding) when binding in [nil, :none] do
    Attesto.Token.verify(attesto_config(config), token, subject_token_verify_opts(config))
  end

  defp verify_subject_token(config, token, {:dpop, jkt}) do
    Attesto.Token.verify(attesto_config(config), token, subject_token_verify_opts(config, dpop_jkt: jkt))
  end

  defp verify_subject_token(config, token, {:mtls, thumb}) do
    Attesto.Token.verify(attesto_config(config), token, subject_token_verify_opts(config, mtls_cert_thumbprint: thumb))
  end

  defp subject_token_verify_opts(config, binding_opts \\ []) do
    [expected_typ: "access", trusted_audiences: ResourceAudiencePolicy.resolver(config)] ++ binding_opts
  end

  defp requested_exchange_scope(params, claims) do
    case parse_requested_scope(params) do
      [] -> subject_token_scope(claims)
      scopes -> scopes
    end
  end

  # RFC 8693 §2.1: the issued token's scope must be within the subject token's
  # authorization. The host `:authorize_scope` callback never sees the subject
  # token, so it cannot enforce this - the library must, before delegating. Any
  # requested scope not present in the subject token's scope fails the exchange
  # (`invalid_scope`), so an exchange can only carry forward or narrow scope.
  defp require_scope_within_subject_token(requested, claims) do
    case requested -- subject_token_scope(claims) do
      [] -> :ok
      _exceeded -> {:error, error(@error_invalid_scope, "requested scope exceeds the subject token")}
    end
  end

  # RFC 8693 §2.1 + RFC 8707: token exchange MUST NOT carry authority the
  # subject token lacks. An explicit `resource` is validated and authorized for
  # the exchanger, then ceilinged to the subject token's `aud`. When the request
  # omits `resource`, inherit the full subject audience and re-authorize every
  # member for the exchanger. This mirrors omitted `scope` and refresh behavior
  # and, critically, never lets an absent parameter turn a resource-confined
  # subject token into one for `config.audience`.
  defp exchange_resource_audience(config, client, params, claims) do
    with {:ok, requested} <- validate_resource_param(params),
         effective = if(requested == [], do: List.wrap(Map.get(claims, "aud")), else: requested),
         {:ok, authorized} <- authorize_resources(config, client, effective),
         :ok <- require_resource_within_subject_token(authorized, claims) do
      {:ok, authorized}
    end
  end

  defp require_resource_within_subject_token(requested, claims) do
    subject_aud = List.wrap(Map.get(claims, "aud"))

    if Enum.all?(requested, &(&1 in subject_aud)),
      do: :ok,
      else: {:error, error(@error_invalid_target, "requested resource exceeds the subject token's audience")}
  end

  defp subject_token_scope(claims) do
    claims |> Map.get("scope", "") |> String.split(" ", trim: true)
  end

  # RFC 6749 §3.3: scope resolution is host policy. The documented
  # `:authorize_scope` callback takes the client and the requested scope and
  # returns the granted scope or `{:error, :invalid_scope}` (RFC 6749 §5.2).
  defp authorize_scope(config, client, requested) do
    case invoke(Config.authorize_scope_fun(config), [host_client(client), requested]) do
      {:ok, scope} when is_list(scope) -> {:ok, scope}
      {:error, _reason} -> {:error, error(@error_invalid_scope, "scope not permitted")}
      _ -> {:error, error(@error_invalid_request, "scope policy unavailable")}
    end
  end

  # ── Token minting (Attesto.Token) ────────────────────────────────────────

  # `mint_extra_opts` is appended to the sender-constraint mint opts; today it
  # carries only the RFC 8707 `:audience` override (jwt-bearer grant), so the
  # `aud` of any other grant's token is unaffected.
  defp mint(
         %Request{config: config, client: client} = request,
         subject,
         scope,
         token_type,
         binding,
         extra_claims,
         mint_extra_opts
       ) do
    with {:ok, principal} <- build_principal(config, client, subject, scope),
         principal = merge_principal_claims(principal, extra_claims),
         {:ok, principal} <- put_access_token_client_id(principal, token_client_id(request)),
         {:ok, minted} <-
           Attesto.Token.mint(
             attesto_config(config),
             principal,
             SenderConstraint.mint_opts(binding) ++ mint_extra_opts
           ) do
      {:ok,
       %{
         access_token: minted.access_token,
         token_type: token_type,
         expires_in: minted.expires_in,
         scope: minted.scope
       }}
    else
      {:error, reason} ->
        # A mint failure here is a server/config fault, not a client error;
        # surface it as RFC 6749 §5.2 invalid_request rather than leak detail.
        Logger.error("token mint failed: #{inspect(reason)}")
        {:error, error(@error_invalid_request, "unable to issue token")}
    end
  end

  defp record_code_access_token(config, grant, response) do
    store = grant_store(config, :code_store)

    if store && function_exported?(store, :record_access_token, 3) do
      with family_id when is_binary(family_id) and family_id != "" <- grant.family_id,
           {:ok, %{"jti" => jti, "exp" => exp}} <-
             decode_access_token_claims(response.access_token),
           true <- is_binary(jti) and is_integer(exp) do
        :ok = store.record_access_token(family_id, jti, exp)
      else
        _ -> :ok
      end
    end

    :ok
  end

  defp decode_access_token_claims(token) when is_binary(token) do
    with [_header, payload, _signature] <- String.split(token, ".", parts: 3),
         {:ok, json} <- Base.url_decode64(payload, padding: false),
         {:ok, claims} <- JSON.decode(json) do
      {:ok, claims}
    else
      _ -> :error
    end
  end

  defp mint_exchanged_token(%Request{config: config} = request, claims, scope, token_type, binding, audience) do
    attesto_config = attesto_config(config)
    kind_claim = attesto_config.principal_kind_claim

    with {:ok, authenticated_client_id} <- require_token_client_id(request),
         principal = %{
           kind: Map.get(claims, kind_claim),
           sub: Map.get(claims, "sub"),
           scopes: scope,
           claims:
             claims
             |> exchange_extra_claims(kind_claim)
             |> Map.put("client_id", authenticated_client_id)
         },
         {:ok, minted} <-
           Attesto.Token.mint(
             attesto_config,
             principal,
             SenderConstraint.mint_opts(binding) ++ audience_opts(audience)
           ) do
      {:ok,
       %{
         access_token: minted.access_token,
         token_type: token_type,
         expires_in: minted.expires_in,
         scope: minted.scope
       }}
    else
      {:error, reason} ->
        Logger.error("token exchange mint failed: #{inspect(reason)}")
        {:error, error(@error_invalid_request, "unable to issue token")}
    end
  end

  defp exchange_extra_claims(claims, principal_kind_claim) do
    # `acr` / `auth_time` are reserved: an exchanged (machine-authorized) token
    # must not inherit the subject token's authentication context, which would
    # let token exchange forge a step-up-satisfying token (RFC 9470).
    reserved =
      MapSet.new(~w(iss aud exp iat nbf jti scope sub typ cnf acr auth_time client_id) ++ [principal_kind_claim])

    claims
    |> Enum.reject(fn {key, _value} -> MapSet.member?(reserved, key) end)
    |> Map.new()
  end

  defp build_principal(config, client, subject, scope) do
    case invoke(Config.build_principal_fun(config), [host_client(client), subject, scope]) do
      %{} = principal -> {:ok, principal}
      _ -> {:error, :no_principal_builder}
    end
  end

  # RFC 9068 §2.2: `client_id` identifies the authenticated client to which the
  # access token was issued. It is protocol-owned, not an optional host claim.
  # A matching host value remains compatible; a conflict fails closed rather
  # than signing a token whose resource policy and client identity disagree.
  defp put_access_token_client_id(principal, authenticated_client_id) do
    case Map.get(principal, :claims, %{}) do
      claims when is_map(claims) ->
        reconcile_access_token_client_id(
          principal,
          claims,
          Map.get(claims, "client_id"),
          authenticated_client_id
        )

      _invalid_claims ->
        {:error, :invalid_principal_claims}
    end
  end

  defp reconcile_access_token_client_id(principal, claims, nil, auth_id) when is_binary(auth_id) and auth_id != "" do
    {:ok, Map.put(principal, :claims, Map.put(claims, "client_id", auth_id))}
  end

  defp reconcile_access_token_client_id(principal, _claims, existing, auth_id)
       when is_binary(auth_id) and auth_id != "" and existing == auth_id do
    {:ok, principal}
  end

  defp reconcile_access_token_client_id(_principal, _claims, _existing, auth_id)
       when is_binary(auth_id) and auth_id != "" do
    {:error, :conflicting_client_id}
  end

  # Compatibility for trusted direct `Token.issue/2` callers that did not
  # populate `request_client_id` before 2.0.2. The shipped controller always
  # supplies the authenticated snapshot, so only the legacy direct-call
  # boundary may retain a valid builder claim.
  defp reconcile_access_token_client_id(principal, _claims, existing, _authenticated_client_id)
       when is_binary(existing) and existing != "" do
    {:ok, principal}
  end

  defp reconcile_access_token_client_id(_principal, _claims, _existing, _authenticated_client_id) do
    {:error, :missing_client_id}
  end

  # OIDC Core §5.5: the access token carries the claims request object so the
  # UserInfo endpoint can later shape its response. Only the `claims` object is
  # propagated; authentication-context values like nonce/auth_time stay code/ID
  # token state and are not access-token claims.
  defp access_token_claims(%{claims: claims}) when is_map(claims) do
    case id_token_claim(claims, "claims") do
      requested when is_map(requested) -> %{"claims" => requested}
      _ -> %{}
    end
  end

  defp access_token_claims(_grant), do: %{}

  defp merge_principal_claims(principal, extra_claims) when map_size(extra_claims) == 0, do: principal

  defp merge_principal_claims(principal, extra_claims) do
    claims =
      case Map.get(principal, :claims) do
        claims when is_map(claims) -> Map.merge(claims, extra_claims)
        _ -> extra_claims
      end

    Map.put(principal, :claims, claims)
  end

  # ── Sender-constraint resolution (RFC 9449 / RFC 8705) ───────────────────

  # Delegate to the conn-free `SenderConstraint` core, passing the input the
  # controller lifted off the conn. A required-but-absent DPoP nonce surfaces
  # as a `use_dpop_nonce` error whose `:headers` carry the fresh `DPoP-Nonce`,
  # rendered verbatim by the controller.
  defp resolve_sender_constraint(%Request{} = request) do
    SenderConstraint.resolve(request.config, request.sender_constraint_input, request.client)
  end

  # ── Configuration / protocol-config derivation ───────────────────────────

  # The `Attesto.Config` consumed by `Attesto.Token`. Derived from the same
  # `%AttestoPhoenix.Config{}`; the principal-kind declarations are host policy
  # carried alongside the config and passed through as the protocol `extra`.
  defp attesto_config(config) do
    Config.to_attesto_config(config, principal_kinds_extra(config))
  end

  # Read the field directly: it is declared `[PrincipalKind.t()] | callback() |
  # nil`, so the list branch is reachable. (`config_callback/2` narrows its
  # return to `callback() | nil`, under which the `is_list` guard cannot hold.)
  defp principal_kinds_extra(%Config{principal_kinds: principal_kinds}) do
    case principal_kinds do
      kinds when is_list(kinds) and kinds != [] -> [principal_kinds: kinds]
      callback -> callback |> invoke([]) |> principal_kinds_kw()
    end
  end

  defp principal_kinds_kw(kinds) when is_list(kinds) and kinds != [] do
    [principal_kinds: kinds]
  end

  defp principal_kinds_kw(_other) do
    []
  end

  # ── Configured-callback access ───────────────────────────────────────────

  # Legacy direct `Token.issue/2` callers may not have populated the request
  # snapshot. Resolve their opaque client once for compatibility. Controller
  # requests always arrive with the exact credential-carried identifier, so no
  # callback is invoked after authentication and no later callback change can
  # relabel state, tokens, ID Tokens, or audit events.
  defp client_id(_config, {:cimd, metadata}), do: ClientIdMetadata.client_id(metadata)

  defp client_id(config, client) do
    Callback.invoke(Config.client_id_fun(config), [client], nil)
  end

  defp snapshot_client_id(%Request{request_client_id: client_id} = request)
       when is_binary(client_id) and client_id != "", do: request

  defp snapshot_client_id(%Request{config: config, client: client} = request) do
    %{request | request_client_id: client_id(config, client)}
  end

  defp token_client_id(%Request{} = request) do
    case request.request_client_id do
      client_id when is_binary(client_id) and client_id != "" -> client_id
      _missing -> nil
    end
  end

  defp require_token_client_id(%Request{} = request) do
    case token_client_id(request) do
      client_id when is_binary(client_id) and client_id != "" -> {:ok, client_id}
      _missing -> {:error, :missing_client_id}
    end
  end

  # Host *policy* callbacks (`:authorize_scope`, `:build_principal`,
  # `:build_id_token_claims`, `:issue_refresh_token?`, `:client_grant_types`) are
  # written for the host's own client shape. A CIMD client is handed to them as
  # its bare, string-keyed metadata map (shaped like a `:load_client` result,
  # `draft-ietf-oauth-client-id-metadata-document-01` §7), with the internal
  # `{:cimd, _}` tag stripped, so a CIMD-aware host reads it like any client map.
  # A registered client passes through untouched.
  #
  # One guard: a CIMD document need NOT declare a `scope` member, so the bare map
  # carries no scope key at all - and `:authorize_scope` fires on every token
  # exchange, including the authorization_code grant a CIMD client actually uses.
  # A scope policy written for a registered client reads `client.scopes`, which
  # would `KeyError` on the bare map. Expose the document's *declared* scopes (or
  # an empty set) under the atom `:scopes` key so that callback degrades to an
  # empty set instead of raising; the host still owns what an empty set grants.
  defp host_client({:cimd, metadata}) do
    Map.put(metadata, :scopes, ClientIdMetadata.scopes(metadata))
  end

  defp host_client(client), do: client

  # The `Attesto.CodeStore` / `Attesto.RefreshStore` backing each stateful
  # grant. Resolved from the configuration so the host owns persistence; this
  # module hardcodes no store module.
  defp grant_store(config, key), do: Callback.config_callback(config, key)

  # ── Audit events (returned as data; the controller emits) ────────────────

  defp token_issued_event(request, scope, grant_type, token_type, binding) do
    issued_like_event(request, :token_issued, scope, grant_type, token_type, binding)
  end

  defp refresh_rotated_event(request, scope, grant_type, token_type, binding) do
    issued_like_event(request, :refresh_rotated, scope, grant_type, token_type, binding)
  end

  defp refresh_issued_event(request, scope, grant_type, token_type, binding) do
    issued_like_event(request, :refresh_issued, scope, grant_type, token_type, binding)
  end

  defp issued_like_event(request, name, scope, grant_type, token_type, binding) do
    Event.new(name, %{
      client_id: token_client_id(request),
      scope: Enum.join(List.wrap(scope), " "),
      grant_type: grant_type,
      metadata:
        %{client_ip: request.client_ip}
        |> Map.merge(sender_constraint_metadata(token_type, binding))
    })
  end

  defp sender_constraint_metadata(token_type, :none) do
    %{
      token_type: token_type,
      sender_constraint: :none,
      cnf: nil
    }
  end

  defp sender_constraint_metadata(token_type, {:dpop, jkt}) do
    %{
      token_type: token_type,
      sender_constraint: :dpop,
      cnf: %{"jkt" => jkt}
    }
  end

  defp sender_constraint_metadata(token_type, {:mtls, x5t}) do
    %{
      token_type: token_type,
      sender_constraint: :mtls,
      cnf: %{"x5t#S256" => x5t}
    }
  end

  # RFC 6749 §5.2: the audit event for a denied grant. The error code is the
  # atom `err.error`; it rides as its wire string. The `:scope` and
  # `:grant_type` are the requested values off the request (not a resolved
  # grant), and the `client_id` is the immutable authenticated identifier
  # snapshot used throughout the grant.
  defp denied_event(request, %OAuthError{} = err) do
    code = Atom.to_string(err.error)
    client_id = denial_client_id(request)

    Event.new(:token_denied, %{
      client_id: client_id,
      scope: optional_param(request.params, "scope"),
      grant_type: request.grant_type,
      result: code,
      metadata:
        %{
          client_ip: request.client_ip,
          client_id: client_id,
          reason: err.error,
          error: code,
          error_description: err.error_description,
          http_status: err.status
        }
        |> Map.merge(SenderConstraint.audit_metadata(request.config, request.sender_constraint_input))
        |> Enum.reject(fn {key, value} -> key != :cnf and is_nil(value) end)
        |> Map.new()
    })
  end

  defp denial_client_id(request), do: token_client_id(request)

  # ── Request helpers ──────────────────────────────────────────────────────

  defp require_param(params, key) do
    case params[key] do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, error(@error_invalid_request, "missing #{key}")}
    end
  end

  defp optional_param(params, key) do
    case params[key] do
      value when is_binary(value) and value != "" -> value
      _ -> nil
    end
  end

  defp put_optional(map, _key, nil), do: map
  defp put_optional(map, key, value), do: Map.put(map, key, value)

  defp put_optional_kw(kw, _key, nil), do: kw
  defp put_optional_kw(kw, _key, []), do: kw
  defp put_optional_kw(kw, key, value), do: Keyword.put(kw, key, value)

  # Callback invocation delegates to `AttestoPhoenix.Callback`, except that an
  # absent (`nil`) callback becomes the `:no_callback` sentinel its callers
  # branch on (rather than raising a FunctionClauseError).
  defp invoke(nil, _args), do: :no_callback
  defp invoke(callback, args), do: Callback.invoke(callback, args)

  # ── Errors (RFC 6749 §5.2) ───────────────────────────────────────────────

  # `code` is a compile-time RFC 6749 §5.2 error-code atom (the `@error_*`
  # attributes); it is passed straight to `OAuthError.new/3`, which requires an
  # atom. No string-to-atom resolution, so this can never raise on an unknown
  # code the way `String.to_existing_atom/1` would.
  defp error(code, description), do: OAuthError.new(code, description, status: 400)

  # RFC 6749 §5.2: redemption/rotation failures all map to invalid_grant; the
  # specific internal reason is not exposed to the client. Reuse detection is
  # also invalid_grant on the wire (the family is already revoked in the
  # store), so a captured-token replay learns nothing.
  defp grant_error(:invalid_scope), do: error(@error_invalid_scope, "requested scope exceeds the grant")

  # RFC 8707 §2: a refresh `resource` that is not a subset of the resources the
  # original grant was bound to cannot be honored (narrowing only, never widen).
  defp grant_error(:invalid_target), do: error(@error_invalid_target, "the requested resource is not within the grant")

  defp grant_error(_reason), do: error(@error_invalid_grant, "authorization grant is invalid or expired")
end
