defmodule AttestoPhoenix.Controller.RegistrationController do
  @moduledoc """
  OAuth 2.0 Dynamic Client Registration endpoint (RFC 7591 §3).

  Handles `POST /oauth/register`. This module owns the HTTP and protocol-framing
  concerns only: it parses the RFC 7591 §2 client-metadata document, validates
  the requested metadata against the server's advertised policy, mints the
  client's credentials through the `Attesto` core, hands the validated,
  issuance-ready attributes to the host's persistence callback, and renders the
  RFC 7591 §3.2.1 client information response or the RFC 7591 §3.2.2 error body.
  It carries no business-domain logic; the client registry is owned entirely by
  the host through the `:register_client` callback resolved from
  `AttestoPhoenix.Config`.

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

  ## Issued credentials

  This controller owns credential generation: it mints the `client_id` and (for
  a confidential client, i.e. any `token_endpoint_auth_method` other than
  `none`) a high-entropy `client_secret` via `Attesto.Secret` (RFC 6749 §2.3.1
  high-entropy secret). The plaintext secret appears in the RFC 7591 §3.2.1
  response exactly once, accompanied by the REQUIRED `client_secret_expires_at`
  (`0`, non-expiring); only its one-way hash is handed to the host for
  persistence, so a leaked client store yields no usable secret.

  ## Responses

  Success renders HTTP 201 with the RFC 7591 §3.2.1 client information response
  (the registered metadata plus the synthesised `client_id`, the optional
  `client_secret` with its REQUIRED `client_secret_expires_at`, and
  `client_id_issued_at`). Failure renders the RFC 7591
  §3.2.2 error body (`{"error": code, "error_description": ...}`) with the
  RFC 7591 §3.2.2 codes `invalid_redirect_uri` and `invalid_client_metadata`.
  A host store rejection surfaces as `invalid_client_metadata` (the request
  named a client the store would not accept) rather than a 500. Both success
  and error responses carry no-store cache headers (RFC 7234 §5.2) because the
  body can carry a freshly minted credential.

  ## Event

  A successful registration emits a `:client_registered` event (RFC 7591)
  through `AttestoPhoenix.Event` carrying the issued `client_id`. The plaintext
  secret is never placed on the event.
  """

  use Phoenix.Controller, formats: [:json]

  import Plug.Conn

  alias Attesto.{Secret, SecureCompare}
  alias AttestoPhoenix.{Callback, Config, Event, OAuthError, RequestContext}

  # RFC 7234 §5.2: a credential-bearing response must never be cached.
  # RFC 7591 §3.1: the registration request body is a JSON object.
  @content_type_json "application/json"

  # RFC 7591 §3.2.2 error codes.
  @error_invalid_redirect_uri :invalid_redirect_uri
  @error_invalid_client_metadata :invalid_client_metadata

  # An 8 KiB (~200 scope) cap on the registration `scope` metadata: registration
  # can be unauthenticated, so an uncapped value is a cheap DoS lever. Far above
  # any real client.
  @max_scope_metadata_bytes 8_192
  @error_invalid_token :invalid_token

  # RFC 7591 §2 / RFC 6749 §2.1: a public client (token_endpoint_auth_method
  # "none") holds no secret; any other method designates a confidential client,
  # which is issued one. Absent the member, the client defaults to confidential
  # (RFC 7591 §2 default is client_secret_basic).
  @auth_method_none "none"
  @default_auth_method "client_secret_basic"

  # RFC 7591 §3.2.1: when a `client_secret` is issued, `client_secret_expires_at`
  # is REQUIRED in the client information response; `0` denotes a secret that
  # does not expire. This server issues non-expiring secrets.
  @client_secret_non_expiring 0

  # RFC 6749 §1.3 / §4: the grant types this server understands, against which a
  # requested `grant_types` member is checked when the host has not narrowed the
  # set via `:grant_types_supported`.
  @default_grant_types_supported ~w(authorization_code refresh_token client_credentials)

  # RFC 7591 §2: a grant type that issues an authorization code (and thus
  # redirects the resource owner back to the client) requires at least one
  # registered redirect URI (RFC 6749 §3.1.2). client_credentials does not.
  @redirect_requiring_grant_types ~w(authorization_code)

  # RFC 7591 §2: human-facing client metadata members carried through to the
  # host store so consent screens keep the client's identity. These are
  # display/identity strings; the controller validates only that each is a
  # string (their trust level is the host's, never the library's).
  # `backchannel_logout_uri` (OpenID Connect Back-Channel Logout 1.0 §3) and
  # `frontchannel_logout_uri` (OpenID Connect Front-Channel Logout 1.0 §2) are
  # registered client URLs, carried through like the other display-string members.
  @display_string_metadata ~w(client_name client_uri logo_uri tos_uri policy_uri
                              jwks_uri software_id software_version software_statement
                              backchannel_logout_uri frontchannel_logout_uri)

  # RFC 7591 §2 `contacts`: an array of strings (e.g. email addresses) carried
  # through to the host store. `post_logout_redirect_uris` (OpenID Connect
  # RP-Initiated Logout 1.0 §3) is the registered set the end-session endpoint
  # exact-matches the request `post_logout_redirect_uri` against.
  @string_array_metadata ~w(contacts post_logout_redirect_uris)

  # RFC 7591 §2 `jwks`: the client's inline public JWK Set. It is carried
  # through to the host store so authorization and token endpoints can verify
  # request objects and private_key_jwt assertions without resolving jwks_uri.
  @map_metadata ~w(jwks)

  # `backchannel_logout_session_required` (OpenID Connect Back-Channel Logout
  # 1.0 §3): whether the client's logout token must carry `sid`.
  # `frontchannel_logout_session_required` (OpenID Connect Front-Channel Logout
  # 1.0 §2): whether the rendered logout URI must carry `iss`/`sid`.
  @boolean_metadata ~w(backchannel_logout_session_required frontchannel_logout_session_required)

  @doc """
  Dynamic client registration action (RFC 7591 §3.1).

  Validates the client-metadata document, mints the client's credentials,
  persists via the host callback, and renders either the RFC 7591 §3.2.1
  client information response or an RFC 7591 §3.2.2 error. Every response
  carries no-store cache headers (RFC 7234 §5.2).
  """
  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, _params) do
    config = config(conn)
    conn = OAuthError.no_store(conn, config)
    metadata = registration_metadata(conn)

    with :ok <- check_https(conn, config),
         :ok <- check_content_type(conn),
         {:ok, validated} <- validate_metadata(metadata, config),
         {:ok, issued} <- issue_client(validated, config),
         {:ok, _stored} <- persist(issued, config) do
      emit_registered(conn, config, issued)

      conn
      |> put_status(:created)
      |> json(client_information_response(issued))
    else
      {:error, %{} = error} -> render_error(conn, error)
    end
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
    config = config(conn)
    conn = OAuthError.no_store(conn, config)

    with :ok <- check_https(conn, config),
         {:ok, token} <- registration_bearer_token(conn),
         {:ok, client} <- Callback.invoke(Config.load_client_fun(config), [client_id]),
         :ok <- verify_registration_access_token(config, client, token),
         :ok <- unregister_client(config, client) do
      send_resp(conn, :no_content, "")
    else
      {:error, %{} = error} -> render_error(conn, error)
      _ -> render_error(conn, invalid_registration_token_error())
    end
  end

  # ── Configuration ────────────────────────────────────────────────────────

  # The per-request config is placed on the conn by the host pipeline (the same
  # mechanism the other authorization-server controllers rely on). It is a
  # validated `AttestoPhoenix.Config` struct read by field; this controller
  # holds no policy of its own.
  defp config(%Plug.Conn{private: %{attesto_phoenix_config: %Config{} = config}}), do: config

  # ── Request parsing ──────────────────────────────────────────────────────

  # RFC 7591 §3.1: the metadata document is the JSON request body. Read it from
  # the parsed body only; a query-string copy would leak into proxy logs and is
  # not part of the wire contract.
  defp registration_metadata(%Plug.Conn{body_params: body}) when is_map(body), do: body
  defp registration_metadata(_conn), do: %{}

  defp check_content_type(conn) do
    case get_req_header(conn, "content-type") do
      [] ->
        # No body parser ran; the empty document fails metadata validation
        # below, not here.
        :ok

      [value | _] ->
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
    end
  end

  # ── Metadata validation (RFC 7591 §2) ────────────────────────────────────

  # Validate each requested metadata member against the server's advertised
  # policy and return the normalised, validated metadata. The first failing
  # check stops validation (RFC 7591 §3.2.2) so the client learns which member
  # was rejected.
  defp validate_metadata(metadata, config) do
    with {:ok, auth_method} <- validate_auth_method(metadata, config),
         {:ok, application_type} <- validate_application_type(metadata),
         {:ok, grant_types} <- validate_grant_types(metadata, config),
         {:ok, redirect_uris} <- validate_redirect_uris(metadata, grant_types, application_type),
         {:ok, scope} <- validate_scope(metadata, config),
         {:ok, passthrough} <- validate_passthrough_metadata(metadata) do
      core = %{
        "token_endpoint_auth_method" => auth_method,
        "application_type" => application_type,
        "grant_types" => grant_types,
        "redirect_uris" => redirect_uris,
        "scope" => scope
      }

      # The known RFC 7591 §2 display/identity members are merged UNDER the
      # protocol-critical members so a request can never override the validated
      # auth method, grants, redirect URIs, or scope through a passthrough key.
      {:ok, Map.merge(passthrough, core)}
    end
  end

  # RFC 7591 §2: validate and carry through the KNOWN client-identity metadata
  # members (client_name, client_uri, logo_uri, contacts, policy_uri, tos_uri,
  # ...) so consent screens keep the client's identity. Only members on the
  # explicit allowlist are passed through; an unknown field is dropped and
  # never promoted to trusted policy. The first malformed known member stops
  # validation with `invalid_client_metadata` (RFC 7591 §3.2.2).
  defp validate_passthrough_metadata(metadata) do
    Enum.reduce_while(passthrough_specs(), {:ok, %{}}, fn {key, kind}, {:ok, acc} ->
      case validate_passthrough_member(metadata, key, kind) do
        :absent -> {:cont, {:ok, acc}}
        {:ok, value} -> {:cont, {:ok, Map.put(acc, key, value)}}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  # The allowlist of known RFC 7591 §2 members carried through, each paired
  # with the shape it must satisfy.
  defp passthrough_specs do
    Enum.map(@display_string_metadata, &{&1, :string}) ++
      Enum.map(@string_array_metadata, &{&1, :string_array}) ++
      Enum.map(@map_metadata, &{&1, :map}) ++
      Enum.map(@boolean_metadata, &{&1, :boolean})
  end

  defp validate_passthrough_member(metadata, key, kind) do
    case Map.get(metadata, key) do
      nil -> :absent
      value -> validate_passthrough_value(key, kind, value)
    end
  end

  defp validate_passthrough_value(_key, :string, value) when is_binary(value), do: {:ok, value}

  defp validate_passthrough_value(key, :string, _value) do
    {:error, error(@error_invalid_client_metadata, "#{key} must be a string (RFC 7591 §2)")}
  end

  defp validate_passthrough_value(_key, :string_array, value) when is_list(value) do
    if Enum.all?(value, &is_binary/1) do
      {:ok, value}
    else
      {:error, error(@error_invalid_client_metadata, "contacts must be an array of strings (RFC 7591 §2)")}
    end
  end

  defp validate_passthrough_value(key, :string_array, _value) do
    {:error, error(@error_invalid_client_metadata, "#{key} must be an array (RFC 7591 §2)")}
  end

  defp validate_passthrough_value(_key, :map, value) when is_map(value), do: {:ok, value}

  defp validate_passthrough_value(key, :map, _value) do
    {:error, error(@error_invalid_client_metadata, "#{key} must be an object (RFC 7591 §2)")}
  end

  defp validate_passthrough_value(_key, :boolean, value) when is_boolean(value), do: {:ok, value}

  defp validate_passthrough_value(key, :boolean, _value) do
    {:error, error(@error_invalid_client_metadata, "#{key} must be a boolean")}
  end

  # RFC 7591 §2 / RFC 6749 §2.3.1: the token-endpoint auth method must be one
  # the server supports. Absent, it defaults to client_secret_basic.
  # OpenID Connect Dynamic Client Registration §2 `application_type`: `"web"`
  # (the default) or `"native"`. It is the standard wire signal a client uses to
  # declare itself an installed app, and it is what lets an authorization server
  # accept the redirect URIs RFC 8252 prescribes - a private-use scheme (§7.1)
  # or a loopback address with a runtime port (§7.3) - instead of rejecting
  # them as it would for a web client.
  #
  # The validated value is carried through to the host's `:register_client`
  # callback in the client metadata, so a host can persist it and answer
  # `AttestoPhoenix.ClientStore.client_native?/1` from it. This endpoint does
  # not itself classify the client: the registered value is a claim by the
  # client, and whether to honour it is the host's decision.
  @application_types ~w(web native)
  @default_application_type "web"

  defp validate_application_type(metadata) do
    # `Map.fetch/2`, not `Map.get/2`: an ABSENT member defaults to `"web"`, but
    # a present JSON `null` is a malformed value and must be rejected, not
    # silently read as the default.
    case Map.fetch(metadata, "application_type") do
      :error ->
        {:ok, @default_application_type}

      {:ok, type} when type in @application_types ->
        {:ok, type}

      {:ok, other} ->
        {:error,
         error(
           @error_invalid_client_metadata,
           "application_type #{inspect(other)} is invalid; expected one of #{inspect(@application_types)}"
         )}
    end
  end

  defp validate_auth_method(metadata, config) do
    supported = token_endpoint_auth_methods_supported(config)

    case Map.get(metadata, "token_endpoint_auth_method") do
      nil ->
        {:ok, @default_auth_method}

      method when is_binary(method) ->
        if method in supported do
          {:ok, method}
        else
          {:error,
           error(
             @error_invalid_client_metadata,
             "token_endpoint_auth_method #{inspect(method)} is not supported"
           )}
        end

      _ ->
        {:error, error(@error_invalid_client_metadata, "token_endpoint_auth_method must be a string")}
    end
  end

  # RFC 7591 §2: every requested grant type must be one the server supports
  # (RFC 6749 §1.3). Absent, the client is registered with no grant types; the
  # host store decides whether that is acceptable.
  defp validate_grant_types(metadata, config) do
    supported = grant_types_supported(config)

    case Map.get(metadata, "grant_types") do
      nil ->
        {:ok, []}

      grant_types when is_list(grant_types) ->
        case Enum.reject(grant_types, &(&1 in supported)) do
          [] ->
            {:ok, grant_types}

          [unsupported | _] ->
            {:error,
             error(
               @error_invalid_client_metadata,
               "grant_type #{inspect(unsupported)} is not supported"
             )}
        end

      _ ->
        {:error, error(@error_invalid_client_metadata, "grant_types must be an array")}
    end
  end

  # RFC 7591 §2 / RFC 6749 §3.1.2: a grant type that redirects the resource
  # owner back to the client requires at least one absolute redirect URI; a
  # malformed or relative URI is rejected as invalid_redirect_uri.
  defp validate_redirect_uris(metadata, grant_types, application_type) do
    redirect_uris = Map.get(metadata, "redirect_uris")
    needs_redirect? = Enum.any?(grant_types, &(&1 in @redirect_requiring_grant_types))

    cond do
      is_nil(redirect_uris) and needs_redirect? ->
        {:error,
         error(
           @error_invalid_redirect_uri,
           "redirect_uris is required for the requested grant_types (RFC 6749 §3.1.2)"
         )}

      is_nil(redirect_uris) ->
        {:ok, []}

      is_list(redirect_uris) ->
        validate_redirect_uri_list(redirect_uris, needs_redirect?, application_type)

      true ->
        {:error, error(@error_invalid_redirect_uri, "redirect_uris must be an array")}
    end
  end

  defp validate_redirect_uri_list([], true, _application_type) do
    {:error,
     error(
       @error_invalid_redirect_uri,
       "redirect_uris must not be empty for the requested grant_types (RFC 6749 §3.1.2)"
     )}
  end

  defp validate_redirect_uri_list(redirect_uris, _needs_redirect?, application_type) do
    case Enum.find(redirect_uris, &(not valid_redirect_uri?(&1, application_type))) do
      nil ->
        {:ok, redirect_uris}

      bad ->
        {:error, error(@error_invalid_redirect_uri, "redirect_uri #{inspect(bad)} is invalid")}
    end
  end

  # RFC 6749 §3.1.2: a redirect URI must be an absolute URI, and MUST NOT
  # include a fragment. "Absolute URI" does NOT require an authority - RFC 3986
  # §4.3 is `scheme ":" hier-part`, where `hier-part` may be a bare absolute
  # path - which matters because the canonical RFC 8252 §7.1 private-use scheme
  # redirect has exactly that shape:
  #
  #     com.example.app:/oauth2redirect/example-provider
  #
  # It is the FIRST redirect type RFC 8252 prescribes for a native app, ahead of
  # loopback (§7.3). Requiring a host rejected it outright, so a native app
  # could be registered with one by hand but never through this endpoint, even
  # though `Attesto.RedirectURI` matches it correctly at the authorization
  # endpoint.
  #
  # The authority-less form is admitted only for a client that declared
  # `application_type: "native"`, and only when its scheme contains a dot and it
  # carries a non-empty absolute path. Those conditions are necessary for the
  # §7.1 convention - the scheme must be a domain name under the app author's
  # control expressed in reverse order (RFC 7595 §3.8) - but they are NOT
  # sufficient to prove that control, and nothing here can be: `com.apple.x:`
  # is as dotted as `com.example.app:`. What they do buy is keeping the
  # authority-less door shut for web clients entirely, and keeping the schemes
  # that must never be a redirect target (`javascript:`, `data:`, `mailto:`)
  # out of it. Ownership, if a deployment needs it enforced, is host policy in
  # front of this endpoint.
  defp valid_redirect_uri?(value, application_type) when is_binary(value) do
    case URI.new(value) do
      {:ok, uri} -> acceptable_redirect_uri?(uri, application_type)
      _ -> false
    end
  end

  defp valid_redirect_uri?(_value, _application_type), do: false

  # RFC 6749 §3.1.2: "The redirection endpoint URI MUST NOT include a fragment
  # component." True of every client type, checked before anything else.
  defp acceptable_redirect_uri?(%URI{fragment: fragment}, _application_type) when not is_nil(fragment), do: false

  # The ordinary form: scheme + authority.
  defp acceptable_redirect_uri?(%URI{scheme: scheme, host: host}, _application_type)
       when is_binary(scheme) and scheme != "" and is_binary(host) and host != "", do: true

  # RFC 8252 §7.1 private-use scheme: no authority, reverse-DNS scheme, and a
  # real path to call back to.
  defp acceptable_redirect_uri?(%URI{scheme: scheme, path: path}, "native")
       when is_binary(scheme) and scheme != "" and is_binary(path) and path != "", do: String.contains?(scheme, ".")

  defp acceptable_redirect_uri?(%URI{}, _application_type), do: false

  # RFC 7591 §2 / RFC 6749 §3.3: the requested scope is a space-delimited
  # string; every requested scope must be in the server's catalog
  # (`:scopes_supported`). Absent, the server MAY assign a default scope
  # (RFC 7591 §2) — `:registration_default_scope`, echoed back in the §3.2.1
  # response so the client learns what it got; with no default configured the
  # client registers with no scope (fail-closed).
  defp validate_scope(metadata, config) do
    case Map.get(metadata, "scope") do
      nil ->
        default_scope(config)

      scope when is_binary(scope) and byte_size(scope) > @max_scope_metadata_bytes ->
        # Registration is unauthenticated when enabled, so an uncapped `scope`
        # is a cheap lever: it was split into a list and every token checked for
        # catalog membership. Reject an absurd value in O(1), before the split.
        {:error, error(@error_invalid_client_metadata, "scope metadata is too large")}

      scope when is_binary(scope) ->
        check_requested_scope(scope, config)

      _ ->
        {:error, error(@error_invalid_client_metadata, "scope must be a space-delimited string")}
    end
  end

  # No `scope` requested: assign the configured default (echoed back in the
  # §3.2.1 response), or none when unconfigured (fail-closed).
  defp default_scope(config) do
    case Config.registration_default_scope(config) do
      nil -> {:ok, nil}
      scopes -> {:ok, Enum.join(scopes, " ")}
    end
  end

  # Every requested scope must be in the catalog. MapSet membership is O(1) per
  # token; `&(&1 in catalog)` over a list was O(requested x catalog).
  defp check_requested_scope(scope, config) do
    catalog = MapSet.new(List.wrap(config.scopes_supported))

    scope
    |> String.split(" ", trim: true)
    |> Enum.reject(&MapSet.member?(catalog, &1))
    |> case do
      [] ->
        {:ok, scope}

      [unknown | _] ->
        {:error, error(@error_invalid_client_metadata, "scope #{inspect(unknown)} is unknown")}
    end
  end

  # ── Credential issuance ──────────────────────────────────────────────────

  # Mint the client identifier and (for a confidential client) the client
  # secret. The plaintext secret is held only long enough to put it in the
  # response and its hash in the persisted attributes; it is never logged or
  # evented. `client_id_issued_at` is the RFC 7591 §3.2.1 issuance time.
  defp issue_client(validated, config) do
    client_id = Secret.generate()
    client_secret = generate_secret(Map.fetch!(validated, "token_endpoint_auth_method"))
    registration_access_token = Secret.generate()

    issued =
      validated
      |> Map.put("client_id", client_id)
      |> Map.put("client_id_issued_at", System.system_time(:second))
      |> Map.put("registration_access_token", registration_access_token)
      |> Map.put("registration_client_uri", Config.registration_client_uri(config, client_id))
      |> put_client_secret(client_secret)

    {:ok, issued}
  end

  # RFC 6749 §2.1: a public client holds no secret.
  defp generate_secret(@auth_method_none), do: nil
  defp generate_secret(_confidential_method), do: Secret.generate()

  # RFC 7591 §3.2.1: `client_secret` and, when a secret is issued,
  # `client_secret_expires_at` are returned together. The latter is REQUIRED in
  # the response whenever a `client_secret` is present; `0` signals a secret that
  # does not expire. A public client (no secret) carries neither member.
  defp put_client_secret(issued, nil), do: issued

  defp put_client_secret(issued, secret) do
    issued
    |> Map.put("client_secret", secret)
    |> Map.put("client_secret_expires_at", @client_secret_non_expiring)
  end

  # ── Persistence (host-owned) ─────────────────────────────────────────────

  # Hand the validated, issuance-ready metadata to the host persistence
  # callback. The host owns the client registry; the library never touches it.
  # The plaintext client_secret is replaced with its one-way hash before
  # persistence so the store never holds the bearer value (RFC 6749 §2.3.1).
  defp persist(issued, config) do
    case Callback.invoke(Config.register_client_fun(config), [persistable_attrs(issued)]) do
      {:ok, stored} ->
        {:ok, stored}

      {:error, _reason} ->
        # A store-level rejection (constraint violation, unacceptable metadata)
        # is a client problem, not a server fault: render it as RFC 7591 §3.2.2
        # invalid_client_metadata rather than a 500.
        {:error, error(@error_invalid_client_metadata, "the requested client could not be registered")}
    end
  end

  defp persistable_attrs(issued) do
    issued
    |> put_client_secret_hash()
    |> put_registration_access_token_hash()
    # Response-only members (RFC 7591 §3.2.1 / RFC 7592 §2.1), not client
    # metadata, so they are not handed to the host persistence callback.
    |> Map.drop(["client_secret", "client_secret_expires_at", "registration_access_token", "registration_client_uri"])
  end

  defp put_client_secret_hash(issued) do
    case Map.get(issued, "client_secret") do
      nil -> issued
      plaintext -> Map.put(issued, "client_secret_hash", Secret.hash(plaintext))
    end
  end

  defp put_registration_access_token_hash(issued) do
    case Map.get(issued, "registration_access_token") do
      token when is_binary(token) ->
        Map.put(issued, "registration_access_token_hash", Secret.hash(token))

      _ ->
        issued
    end
  end

  # ── Response (RFC 7591 §3.2.1) ───────────────────────────────────────────

  # The client information response is the validated metadata as registered:
  # it carries the synthesised client_id, the plaintext client_secret (the one
  # and only time it is disclosed) with its RFC 7591 §3.2.1 REQUIRED
  # client_secret_expires_at, and client_id_issued_at. A `scope` of nil
  # (none requested) is omitted rather than serialised as JSON null.
  defp client_information_response(issued) do
    case Map.get(issued, "scope") do
      nil -> Map.delete(issued, "scope")
      _ -> issued
    end
  end

  # ── Event ────────────────────────────────────────────────────────────────

  # The event records WHICH client was registered, never the secret.
  defp emit_registered(_conn, config, issued) do
    Event.emit(config, :client_registered, %{client_id: Map.get(issued, "client_id")})
  end

  # ── Policy inputs ────────────────────────────────────────────────────────

  defp grant_types_supported(config) do
    case config_field(config, :grant_types_supported) do
      list when is_list(list) and list != [] -> list
      _ -> @default_grant_types_supported
    end
  end

  defp token_endpoint_auth_methods_supported(config) do
    case config_field(config, :token_endpoint_auth_methods_supported) do
      list when is_list(list) and list != [] -> list
      _ -> [@default_auth_method, @auth_method_none]
    end
  end

  # These two policy inputs are optional registration extensions to the core
  # config; read them defensively so a config struct without the field falls
  # back to the RFC defaults rather than crashing.
  defp config_field(config, key), do: Map.get(config, key)

  # ── Helpers ──────────────────────────────────────────────────────────────

  defp registration_bearer_token(conn) do
    with [header | _] <- get_req_header(conn, "authorization"),
         [scheme, token] when token != "" <- String.split(header, " ", parts: 2),
         true <- String.downcase(scheme) == "bearer" do
      {:ok, token}
    else
      _ ->
        {:error, invalid_registration_token_error()}
    end
  end

  defp verify_registration_access_token(config, client, token) do
    with callback when not is_nil(callback) <-
           Config.client_registration_access_token_hash_fun(config),
         hash when is_binary(hash) <- Callback.invoke(callback, [client]),
         true <- token |> Secret.hash() |> SecureCompare.equal?(hash) do
      :ok
    else
      _ -> {:error, invalid_registration_token_error()}
    end
  end

  defp unregister_client(config, client) do
    case Config.unregister_client_fun(config) do
      nil ->
        {:error,
         error(
           @error_invalid_client_metadata,
           "dynamic client registration management is not configured"
         )}

      callback ->
        case Callback.invoke(callback, [client]) do
          :ok -> :ok
          {:ok, _client} -> :ok
          {:error, _reason} -> {:error, invalid_registration_token_error()}
        end
    end
  end

  # ── Rendering (RFC 7591 §3.2.2) ──────────────────────────────────────────

  # RFC 6749 §3.1 / §10.1: registration mints and returns a plaintext
  # client_secret (create) and reads a registration-access-token bearer
  # credential (delete); neither may cross a plain-HTTP hop, so refuse cleartext
  # under `require_https`, exactly as the token/PAR/revocation endpoints do.
  defp check_https(conn, config) do
    case RequestContext.check_https(conn, config) do
      :ok -> :ok
      {:error, :insecure_transport} -> {:error, error(:invalid_request, "the request must be made over TLS")}
    end
  end

  defp render_error(conn, %OAuthError{} = err) do
    OAuthError.render(conn, err, auth_scheme: :none, config: config(conn))
  end

  defp error(code, description), do: OAuthError.new(code, description, status: 400)

  defp invalid_registration_token_error do
    OAuthError.new(@error_invalid_token, "registration access token is missing or invalid", status: 401)
  end
end
