defmodule AttestoPhoenix.Interaction do
  @moduledoc """
  Park an authorization request while the End-User authenticates or grants
  consent, and resume it afterwards.

  When `:authenticate_resource_owner` has to send the End-User to a login page
  (no session, `prompt=login`, or an authentication older than `max_age`), the
  host needs a way back to the same authorization request. `park/2` stores the
  request and returns a `resume_id`; the host redirects to its login page with
  that id and, once the End-User has authenticated, sends the browser to the
  authorization endpoint with `?resume=<resume_id>` and nothing else.

      def authenticate_resource_owner(conn, request, auth_opts) do
        case current_session(conn, auth_opts) do
          {:ok, subject} ->
            {:authenticated, subject}

          :login_needed ->
            case AttestoPhoenix.Interaction.park(conn, request) do
              {:ok, resume_id} -> {:halt, redirect(conn, to: "/login?resume=" <> resume_id)}
              {:error, _reason} -> {:error, :temporarily_unavailable}
            end
        end
      end

  When the store cannot take the request, `park/2` returns `{:error, reason}`.
  Return `{:error, :temporarily_unavailable}` (or `{:error, :server_error}`)
  from either callback: the client receives that RFC 6749 §4.1.2.1 code by
  redirect.

  ## What a resume does

  The authorization endpoint takes the parked request out of the store and
  runs it as it would a fresh request with the same parameters: the client is
  loaded again, the request is validated again, the scope policy runs again.
  Authentication and consent are checked again. The host's
  `:authenticate_resource_owner` then receives `auth_opts.resumed: true`,
  `auth_opts.parked_at` and `auth_opts.prompt_login_since` (Unix seconds).
  When the original request included `prompt=login`, the returned `auth_time`
  must be at or after `prompt_login_since`. An older, missing or invalid time
  is a host contract violation: it is logged and returned as `server_error`.
  The host must supply an authentication satisfying the recorded bound.
  Both host callbacks can use `request_params/1` to read the original
  parameters; `conn.params` still describes the HTTP request containing only
  `resume`.

  ## Recording a consent decision

  From `:consent`, park with the authenticated OIDC `sub` and render the host's
  consent page. On resume, use `consent_decision/3` against the newly validated
  request and authenticated subject:

      def consent(conn, request, subject) do
        case AttestoPhoenix.Interaction.consent_decision(conn, request, subject) do
          :allow ->
            {:consented, subject}

          :deny ->
            {:denied, :user_denied}

          nil ->
            case AttestoPhoenix.Interaction.park(conn, request, subject: subject.subject) do
              {:ok, resume_id} ->
                {:halt, render(conn, :consent, resume_id: resume_id, request: request)}

              {:error, _reason} ->
                {:error, :temporarily_unavailable}
            end
        end
      end

  The page POSTs the resume id and Allow/Deny choice to a host handler with a
  fetched session, the `AttestoPhoenix.Interaction.BrowserBinding` plug and
  `AttestoPhoenix.Plug.PutConfig`, as on the authorization route. Read the
  current authenticated subject from the host session, never from the form:

      def record_consent(conn, %{"resume" => resume_id, "decision" => choice}) do
        subject_id = get_session(conn, :subject)

        decision = case choice do
          "allow" -> :allow
          "deny" -> :deny
          _ -> nil
        end

        if decision in [:allow, :deny] and is_binary(subject_id) do
          case AttestoPhoenix.Interaction.decide(conn, resume_id, decision, subject_id) do
            :ok -> redirect(conn, to: "/oauth/authorize?" <> URI.encode_query(%{"resume" => resume_id}))
            {:error, :invalid_resume} -> send_resp(conn, 400, "Invalid consent request")
          end
        else
          send_resp(conn, 400, "Invalid consent request")
        end
      end

  Use the host's configured authorization path and return with
  `?resume=<resume_id>` only.

  Cross-site request forgery: the resume id in the form is the page's
  synchronizer token. It is random, bound to this browser and subject, held
  server-side on the parked entry, and appears in no URL until the decision is
  recorded, so another site cannot build a valid POST. `decide/4` also refuses
  a request whose `Sec-Fetch-Site` header is present and not `same-origin`, or
  whose `Origin` header names an origin other than the issuer's or the one the
  request reached, before it reads the store. `Origin: null`, which browsers
  send on a same-origin form POST from a page with `Referrer-Policy:
  no-referrer`, names no origin and is not refused on its own. A page rendered from `:consent` is served by the
  authorization route, which cannot run `:protect_from_forgery` because the
  authorization endpoint must accept cross-site POST requests (OIDC Core
  §3.1.2.1); a Plug CSRF token put in that page is not saved to the session,
  so do not require one on this handler. Serve the page and the handler from
  one origin: the issuer's, or the one the browser reached (for example a
  development server on `http://localhost:4000` with an `https://localhost`
  issuer). Behind a TLS-terminating proxy, list it in `:trusted_proxies` so
  the reached origin is computed from its forwarded headers.

  The library ships no POST controller because the session, the subject and
  the page belong to the host. Protect the consent page against clickjacking
  with a Content-Security-Policy `frame-ancestors` directive appropriate for
  the host (for example, `frame-ancestors 'none'`).

  No separate `AttestoPhoenix.ConsentGrant` is needed for this flow. The
  decision lives on the single-use parked entry: its key binds it to the
  browser, `decide/4` and `consent_decision/3` bind it to the subject, and the
  stored consent binding hash binds it to the request. The accessor recomputes
  that hash from the resumed validated request, covering the client, redirect
  URI, effective scope, resource, PKCE challenge and method, claims, DPoP key,
  and authorization details (all `AttestoPhoenix.ConsentGrant.binding/2`
  fields; RFC 6749 §4.1.1, §3.3). Nothing about the decision is in a cookie.
  Two consent pages in one browser have separate entries. Another decision
  before resume replaces the first without extending expiry. Re-parking
  always clears the decision; supply `subject:` again for a new consent page.

  A resume id alone is not approval. A recorded Allow is not acted on by the
  library: the host's `:consent` reads it with `consent_decision/3` and
  chooses whether to consent, deny, or park again, after the controller has
  loaded the client and run validation, scope policy and authentication. A
  recorded Deny is answered `access_denied` as soon as the resumed request is
  validated, before authentication and before `:consent` runs: refusing grants
  nothing, so a session that went stale against `max_age` on the consent page
  does not send the End-User to sign in again only to lose their Deny. A consent halt under `prompt=none`
  still becomes `consent_required` (OIDC Core §3.1.2.1, §3.1.2.6).
  Returning with the original query starts a fresh request, including a new
  `prompt=login` requirement (OIDC Core §3.1.2.1, §3.1.2.3, §3.1.2.4).

  If a fresh `prompt=login` request passes authentication before parking in
  consent, `prompt_login_since` records the bound that check used: request
  arrival minus `reauthentication_allowance_seconds/0`. Resume accepts that
  same bound with no further allowance. A login detour parks before the check
  passes, so its bound is the real park time: `auth_time >= parked_at`.
  Re-parking retains the original parameters, first `parked_at` and first
  `prompt_login_since`, including a login resume parked again for consent.
  `parked_at` remains the real first park time for `max_age_allowance/3`.
  The host can reuse an authentication satisfying `auth_opts.prompt_login_since`
  on resume while honoring `auth_opts.force_reauth`. Never treat
  `auth_opts.resumed` alone as evidence of fresh authentication.

  A parked request can be resumed once. It is bound to the browser that parked
  it through the host's `:interaction_browser_binding` callback
  (`(conn -> binary)`): a value that is stable for one browser and that
  another browser cannot present. Mount `AttestoPhoenix.Interaction.BrowserBinding`
  after `:fetch_session` and before the authorize route, and configure
  `:interaction_browser_binding` as
  `&AttestoPhoenix.Interaction.BrowserBinding.binding/1`.
  Preserve the value through login, including session renewal:
  `Plug.Conn.configure_session(conn, renew: true)` keeps session data;
  `drop: true` discards it. Losing the value makes resume follow the
  wrong-browser refusal path. Only a hash of it is stored. The parked request
  is stored under a key derived from both the resume id and that hash, so a
  resume from a browser whose value differs finds nothing: it is refused and
  leaves the parked request in place for the browser that parked it. A leaked
  resume id alone cannot be used, or used up, from another browser.

  `resume` cannot be combined with any other parameter. An unknown, expired,
  already used or wrong-browser `resume` is answered with a direct error page,
  never a redirect, since nothing about the request can be trusted.

  ## `max_age`

  A request with `max_age` normally allows `reauthentication_allowance_seconds/0`
  beyond `max_age` for the trip back from the login page. On a resumed request
  that interval is replaced by an exact rule: an authentication performed at
  or after the request was parked satisfies `max_age` (the End-User
  re-authenticated for this request);
  one performed before it must still be within `max_age` now. `max_age=0` on a
  resumed request therefore requires an authentication at or after the park.

  ## Upgrading from 4.10

  Return `:auth_time` (Unix seconds) from `:authenticate_resource_owner`.
  Send the browser to login when `auth_opts.force_reauth` is true or the
  existing authentication exceeds `auth_opts.max_age`, and return the new
  authentication time (OIDC Core §3.1.2.1, §3.1.2.3). Use park/resume to
  preserve the request across login and consent; on resume, use the bounds
  above to decide whether the authentication already satisfies this request.

  ## Storage

  Parked requests live in the configured `:par_store`, under a key no pushed
  authorization request can have, for `:interaction_ttl` seconds (default 600,
  at most 3600). The store must implement atomic `take/1`, and atomic
  `replace/2` only when using `decide/4`. The bundled stores expire the rows
  as they do pushed requests (the Ecto store through the
  sweeper), and parked requests count toward the ETS store's
  `:par_max_entries`.
  """

  alias Attesto.AuthorizationRequest
  alias Attesto.Secret
  alias AttestoPhoenix.Callback
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.ConsentGrant
  alias AttestoPhoenix.RequestContext
  # Not a `urn:ietf:params:oauth:request_uri:` reference, so the key space is
  # disjoint from pushed authorization requests held in the same store.
  alias AttestoPhoenix.Store.PAR.ETS
  alias Plug.Conn.Unfetched

  @key_prefix "urn:attesto:interaction:"
  @resume_id_bytes 32
  @resumed_private_key :attesto_phoenix_resumed_interaction
  @reauthentication_allowance_seconds 60

  @type parked :: %{
          params: map(),
          client_id: String.t(),
          parked_at: integer(),
          prompt_login_since: integer(),
          subject: String.t() | nil,
          consent_binding: String.t() | nil,
          consent_decision: String.t() | nil
        }

  @doc """
  Store the authorization request being processed on `conn` and return the
  identifier that resumes it.

  `request` is the validated request the host callback received. Call this
  from `:authenticate_resource_owner` (or `:consent`), where `conn` still
  carries the authorization request's parameters.

  Parking a resumed request preserves its original parameters and first
  `parked_at` and `prompt_login_since`. A first park after a successful fresh
  `prompt=login` check saves its arrival-minus-allowance bound; a park before
  that check uses the park time. Each park issues a new single-use identifier
  bound to the browser; the consumed identifier cannot be reused.

  Pass `subject: subject_id` (a non-empty OIDC `sub`) to bind a subsequent
  `decide/4` call to that subject and this validated request. Re-parking never
  carries over a consent decision, even when the subject is supplied again.

  Raises `ArgumentError` when the configuration cannot park a request: no
  `:interaction_browser_binding`, a `:par_store` without `take/1`, or a
  callback that returns no usable browser value.
  """
  @spec park(Plug.Conn.t(), AuthorizationRequest.t()) :: {:ok, String.t()} | {:error, term()}
  @spec park(Plug.Conn.t(), AuthorizationRequest.t(), keyword()) :: {:ok, String.t()} | {:error, term()}
  def park(%Plug.Conn{} = conn, %AuthorizationRequest{} = request, opts \\ []) do
    config = Config.resolve!(conn)
    store = store!(config)
    binding = browser_binding!(config, conn)
    resume_id = Secret.generate(@resume_id_bytes)
    parked_at = original_parked_at(conn)

    entry =
      %{
        "params" => request_params(conn),
        "client_id" => request.client_id,
        "binding" => binding_hash(binding),
        "parked_at" => parked_at,
        "prompt_login_since" => original_prompt_login_since(conn, parked_at)
      }
      |> bind_subject(request, opts)

    case store.put(parked_key(resume_id, binding), entry, config.interaction_ttl) do
      :ok -> {:ok, resume_id}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Record `:allow` or `:deny` on a live parked request for the current browser
  and authenticated OIDC `subject_id`. A later call replaces the decision.

  Returns `{:error, :invalid_resume}` without changing the entry for a wrong
  browser or subject, an entry parked without `subject:`, or an unknown,
  expired or taken id. Replacement retains the entry's original expiry and
  cannot recreate a taken entry.

  Returns `{:error, :cross_origin}`, before reading the store, when the
  request's `Sec-Fetch-Site` header is present and not `same-origin`, or its
  `Origin` header names an origin other than the issuer's or the one this
  request reached (`Origin: null` is not refused on its own). A browser with no binding value, such as one that
  never parked a request, gets `{:error, :invalid_resume}`.

  Call from the host's browser POST handler, using the current subject from
  its session. Raises `ArgumentError` when `:interaction_browser_binding` is
  not configured or the configured `:par_store` has no `replace/2`.
  """
  @spec decide(Plug.Conn.t(), String.t(), :allow | :deny, String.t()) ::
          :ok | {:error, :invalid_resume | :cross_origin}
  def decide(%Plug.Conn{} = conn, resume_id, decision, subject_id) when decision in [:allow, :deny] do
    config = Config.resolve!(conn)
    store = decision_store!(config)

    if config.interaction_browser_binding == nil,
      do: raise(ArgumentError, "AttestoPhoenix.Interaction: :interaction_browser_binding must be configured")

    if same_origin_request?(conn, config) do
      case browser_binding(config, conn) do
        {:ok, binding} -> record_decision(config, store, binding, resume_id, decision, subject_id)
        :error -> {:error, :invalid_resume}
      end
    else
      {:error, :cross_origin}
    end
  end

  defp record_decision(config, store, binding, resume_id, decision, subject_id) do
    Config.with_request_config(config, fn ->
      with true <- is_binary(resume_id) and resume_id != "",
           true <- is_binary(subject_id) and subject_id != "",
           key = parked_key(resume_id, binding),
           {:ok, %{"subject" => stored_subject} = entry} <- store.fetch(key),
           true <- secure_equal?(stored_subject, subject_id),
           :ok <- store.replace(key, Map.put(entry, "consent_decision", Atom.to_string(decision))) do
        :ok
      else
        _ -> {:error, :invalid_resume}
      end
    end)
  end

  @doc """
  The decision recorded on the resumed request, if it still matches the
  authenticated subject and validated request's consent binding.

  Use inside `:consent`. Returns `nil` for a fresh request, an absent decision,
  or a changed subject or request binding (including the effective scope).
  The host decides whether to consent, deny, or park for consent again. A
  recorded Deny never reaches `:consent`: the controller answers it first.
  """
  @spec consent_decision(Plug.Conn.t(), AuthorizationRequest.t(), map()) :: :allow | :deny | nil
  def consent_decision(%Plug.Conn{} = conn, %AuthorizationRequest{} = request, subject) do
    with %{subject: subject_id} when is_binary(subject_id) and subject_id != "" <- subject,
         %{subject: stored_subject, consent_binding: stored_binding, consent_decision: decision}
         when decision in ["allow", "deny"] <- conn.private[@resumed_private_key],
         true <- secure_equal?(stored_subject, subject_id),
         true <- secure_equal?(stored_binding, consent_binding(request, subject_id)) do
      case decision do
        "allow" -> :allow
        "deny" -> :deny
      end
    else
      _ -> nil
    end
  end

  @doc """
  Take the request parked under `resume_id` for the browser on `conn`.

  Returns `{:ok, parked}` with the original parameters, client id, park and
  login times, and `subject`, `consent_binding`, `consent_decision` (each `nil`
  when absent), or
  `{:error, :invalid_resume}` when the id is unknown, expired or already used,
  the browser value does not match, or the configuration cannot resume. The
  lookup key includes the browser value, so a wrong browser's lookup finds no
  entry and consumes nothing. A found entry is consumed.
  """
  @spec take(Config.t(), Plug.Conn.t(), term()) :: {:ok, parked()} | {:error, :invalid_resume}
  def take(%Config{} = config, %Plug.Conn{} = conn, resume_id) when is_binary(resume_id) and resume_id != "" do
    with {:ok, store} <- store(config),
         {:ok, binding} <- browser_binding(config, conn),
         {:ok, entry} <- store.take(parked_key(resume_id, binding)),
         %{"params" => params, "client_id" => client_id, "binding" => stored, "parked_at" => parked_at}
         when is_map(params) and is_binary(client_id) and is_binary(stored) and is_integer(parked_at) <- entry,
         true <- Plug.Crypto.secure_compare(stored, binding_hash(binding)),
         since when is_integer(since) and since >= 0 <- Map.get(entry, "prompt_login_since", parked_at) do
      {:ok,
       %{
         params: params,
         client_id: client_id,
         parked_at: parked_at,
         prompt_login_since: since,
         subject: Map.get(entry, "subject"),
         consent_binding: Map.get(entry, "consent_binding"),
         consent_decision: Map.get(entry, "consent_decision")
       }}
    else
      _ -> {:error, :invalid_resume}
    end
  end

  def take(%Config{}, %Plug.Conn{}, _resume_id), do: {:error, :invalid_resume}

  @doc false
  # The store key for a parked request: the resume id and the browser binding
  # hash together, so a lookup from another browser misses instead of taking
  # the entry. The resume id is base64url and the hash has a fixed length, so
  # the "." separator is unambiguous.
  @spec parked_key(String.t(), String.t()) :: String.t()
  def parked_key(resume_id, binding) when is_binary(resume_id) and is_binary(binding),
    do: @key_prefix <> Secret.hash(resume_id <> "." <> binding_hash(binding))

  @doc """
  Whether `key` is in the key space parked requests use. The authorization
  endpoint refuses such a value as a `request_uri`.
  """
  @spec reserved_key?(term()) :: boolean()
  def reserved_key?(key) when is_binary(key), do: String.starts_with?(key, @key_prefix)
  def reserved_key?(_key), do: false

  @doc """
  The interval beyond `max_age` a resumed request is allowed, given the
  authentication time the host returned (see "`max_age`" above).

  An authentication at or after `parked_at` gets the time since the park, which
  always satisfies `max_age`; anything else gets zero.
  """
  @spec max_age_allowance(integer(), term(), integer()) :: non_neg_integer()
  def max_age_allowance(parked_at, auth_time, now)
      when is_integer(parked_at) and is_integer(auth_time) and is_integer(now) and auth_time >= parked_at,
      do: max(now - parked_at, 0)

  def max_age_allowance(_parked_at, _auth_time, _now), do: 0

  @doc """
  The authorization parameters used as input to request validation.

  On a resumed request, returns the original parked parameters. Otherwise,
  fetches the query parameters and merges the already parsed body parameters
  over them, excluding router path parameters. An unfetched body contributes
  no parameters; the host pipeline must parse request bodies before dispatch.

  For PAR, returns the front-channel parameters, including `request_uri`,
  rather than the pushed parameters. The controller resolves that reference
  again on each resume and consumes it only on completion (RFC 9126 §2.3).
  Signed Request Objects are likewise left encoded. Use the validated
  `request` argument for protocol fields and policy decisions.

  Available to both `:authenticate_resource_owner` and `:consent`; callers
  need not read private connection fields or the resume-only `conn.params`.
  """
  @spec request_params(Plug.Conn.t()) :: map()
  def request_params(%Plug.Conn{private: %{@resumed_private_key => %{params: params}}}), do: params

  def request_params(%Plug.Conn{} = conn) do
    conn = Plug.Conn.fetch_query_params(conn)

    body =
      case conn.body_params do
        %Unfetched{} -> %{}
        %{} = params -> params
      end

    Map.merge(conn.query_params, body)
  end

  @doc """
  The interactive allowance, in seconds, for a fresh authorization request.

  The controller allows this interval beyond `max_age`, or before request
  arrival for `prompt=login` (OpenID Connect Core §3.1.2.1, §3.1.2.3).
  `prompt=none` gets no allowance. Resumes use the recorded
  `prompt_login_since` for `prompt=login`, with no further allowance, and
  the real `parked_at` for `max_age_allowance/3`.
  Hosts must still perform reauthentication.
  """
  @spec reauthentication_allowance_seconds() :: non_neg_integer()
  def reauthentication_allowance_seconds, do: @reauthentication_allowance_seconds

  defp original_parked_at(%Plug.Conn{private: %{@resumed_private_key => %{parked_at: parked_at}}}), do: parked_at

  defp original_parked_at(%Plug.Conn{}), do: System.system_time(:second)

  defp original_prompt_login_since(
         %Plug.Conn{private: %{@resumed_private_key => %{prompt_login_since: since}}},
         _parked_at
       ), do: since

  defp original_prompt_login_since(%Plug.Conn{} = conn, parked_at),
    do: Map.get(conn.private, :attesto_phoenix_prompt_login_since, parked_at)

  defp store!(config) do
    case store(config) do
      {:ok, store} ->
        store

      :error ->
        raise ArgumentError,
              "AttestoPhoenix.Interaction: :par_store must implement put/3 and atomic take/1 to park a request"
    end
  end

  defp decision_store!(config) do
    store = store!(config)

    if function_exported?(store, :replace, 2) do
      store
    else
      raise ArgumentError,
            "AttestoPhoenix.Interaction: :par_store must implement atomic replace/2 to record a consent decision"
    end
  end

  defp bind_subject(entry, request, opts) do
    case Keyword.fetch(opts, :subject) do
      {:ok, subject} when is_binary(subject) and subject != "" ->
        entry
        |> Map.put("subject", subject)
        |> Map.put("consent_binding", consent_binding(request, subject))

      :error ->
        entry

      _ ->
        raise ArgumentError, "AttestoPhoenix.Interaction: :subject must be a non-empty binary OIDC sub"
    end
  end

  defp consent_binding(request, subject), do: ConsentGrant.binding_hash(ConsentGrant.binding(request, subject))

  defp secure_equal?(left, right) when is_binary(left) and is_binary(right), do: Plug.Crypto.secure_compare(left, right)

  defp secure_equal?(_left, _right), do: false

  # Fetch Metadata and Origin (RFC 6454 §7) as browsers send them on a form
  # POST. Absent headers are allowed; a present one must say same-origin.
  # `Origin: null` carries no origin: browsers send it on a same-origin form
  # POST when the page's Referrer-Policy is `no-referrer` (Fetch, "append a
  # request `Origin` header"), so it defers to `Sec-Fetch-Site` and the resume
  # id, the form's synchronizer token. A named origin must be the issuer's or
  # the origin this request reached (`RequestContext.canonical_url/2`, which
  # honors forwarded headers only from trusted proxies), the same test as
  # Phoenix's `check_origin: :conn`.
  defp same_origin_request?(conn, config) do
    fetch_site = Plug.Conn.get_req_header(conn, "sec-fetch-site")
    origin = Plug.Conn.get_req_header(conn, "origin")

    fetch_site in [[], ["same-origin"]] and allowed_origin?(origin, allowed_origins(conn, config))
  end

  defp allowed_origins(conn, config) do
    [config.issuer, RequestContext.canonical_url(conn, config)]
    |> Enum.map(&origin_of/1)
    |> Enum.reject(&is_nil/1)
  end

  defp allowed_origin?([], _allowed), do: true
  defp allowed_origin?(["null"], _allowed), do: true
  defp allowed_origin?([origin], allowed), do: origin_of(origin) in allowed and origin_of(origin) != nil
  defp allowed_origin?(_origin, _allowed), do: false

  defp origin_of(url) when is_binary(url) do
    case URI.parse(url) do
      %URI{scheme: scheme, host: host, port: port} when is_binary(scheme) and is_binary(host) and host != "" ->
        if String.downcase(scheme) in ["https", "http"],
          do: {String.downcase(scheme), String.downcase(host), port}

      _other ->
        nil
    end
  end

  defp origin_of(_url), do: nil

  defp store(config) do
    store = config.par_store || ETS

    if Code.ensure_loaded?(store) and function_exported?(store, :put, 3) and function_exported?(store, :take, 1),
      do: {:ok, store},
      else: :error
  end

  defp browser_binding!(config, conn) do
    case browser_binding(config, conn) do
      {:ok, binding} ->
        binding

      :error ->
        raise ArgumentError,
              "AttestoPhoenix.Interaction: :interaction_browser_binding must be configured and return a " <>
                "non-empty binary for the current browser"
    end
  end

  defp browser_binding(%Config{interaction_browser_binding: nil}, _conn), do: :error

  defp browser_binding(%Config{interaction_browser_binding: callback}, conn) do
    case Callback.invoke(callback, [conn]) do
      binding when is_binary(binding) and binding != "" -> {:ok, binding}
      _ -> :error
    end
  end

  defp binding_hash(binding), do: Secret.hash(binding)
end
