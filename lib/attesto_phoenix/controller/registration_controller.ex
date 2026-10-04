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

  Human-readable client metadata remains untrusted after registration. It is
  stored verbatim after size, UTF-8, and control-character checks; a host
  consent or administration UI must HTML-escape it at the rendering sink.
  Logout callback URIs use an intentional HTTPS-only server profile even where
  an OpenID logout specification permits a confidential deployment to allow
  plain HTTP.

  ## Issued credentials

  This controller owns credential generation: it mints the `client_id` and (for
  `client_secret_basic` or `client_secret_post`) a
  high-entropy `client_secret` via `Attesto.Secret` (RFC 6749 §2.3.1
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

  use AttestoPhoenix.Controller, formats: [:json]

  import Plug.Conn

  alias Attesto.{Key, RedirectURI, Secret, SecureCompare, SigningAlg}
  alias AttestoPhoenix.{Callback, ClientIdMetadata, Config, Event, OAuthError, RequestContext}
  alias AttestoPhoenix.ClientIdMetadata.HostPolicy

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

  # Only shared-secret authentication requires a client_secret. Asymmetric,
  # certificate and attestation methods must not acquire a downgrade credential.
  # RFC 7591 §2 defaults an omitted method to client_secret_basic.
  @secret_auth_methods ~w(client_secret_basic client_secret_post)
  @default_auth_method "client_secret_basic"

  # `client_secret_jwt` is deliberately unavailable at registration. The
  # authentication layer implements Basic and form-post shared-secret
  # credentials, but it does not verify HMAC client assertions. Advertising or
  # registering the method would mint a credential that cannot authenticate.
  @unsupported_registration_auth_methods ~w(client_secret_jwt)

  # RFC 7591 §3.2.1: when a `client_secret` is issued, `client_secret_expires_at`
  # is REQUIRED in the client information response; `0` denotes a secret that
  # does not expire. This server issues non-expiring secrets.
  @client_secret_non_expiring 0

  # RFC 7591 §2: a grant type that issues an authorization code (and thus
  # redirects the resource owner back to the client) requires at least one
  # registered redirect URI (RFC 6749 §3.1.2). client_credentials does not.
  @redirect_requiring_grant_types ~w(authorization_code)

  # Human-facing values are untrusted text. They are stored verbatim so host UI
  # renderers must HTML-escape them, while this boundary rejects controls,
  # malformed UTF-8, and values large enough to become an unauthenticated DoS
  # input. A software statement is an opaque JWT and gets a separate, larger cap.
  @human_string_metadata ~w(client_name software_id software_version)
  @opaque_string_metadata ~w(software_statement)
  @web_uri_metadata ~w(client_uri logo_uri tos_uri policy_uri)
  @https_uri_metadata ~w(jwks_uri backchannel_logout_uri frontchannel_logout_uri)

  # RFC 8705 §2.1 client-certificate identity metadata. A tls_client_auth
  # registration must carry exactly one of these non-empty values.
  @tls_client_identity_metadata ~w(tls_client_auth_subject_dn tls_client_auth_san_dns
                                   tls_client_auth_san_uri tls_client_auth_san_ip
                                   tls_client_auth_san_email)

  # RFC 7591 §2 `contacts`: an array of strings (e.g. email addresses) carried
  # through to the host store. `post_logout_redirect_uris` (OpenID Connect
  # RP-Initiated Logout 1.0 §3) is the registered set the end-session endpoint
  # exact-matches the request `post_logout_redirect_uri` against.
  @string_array_metadata ~w(contacts)
  @attestation_alg_metadata ~w(client_attestation_signing_alg_values_supported)
  @attestation_pop_alg_metadata ~w(client_attestation_pop_signing_alg_values_supported)
  @attestation_method_metadata ~w(client_attestation_pop_methods_supported)

  # `post_logout_redirect_uris` is an array like `contacts`, but each entry is a
  # redirect target the end-session endpoint will later render into a link /
  # meta-refresh, so it gets URL+scheme validation - not merely is_binary - to
  # keep `javascript:`/`data:` out of that sink (the same class as
  # `redirect_uris`).
  @redirect_uri_array_metadata ~w(post_logout_redirect_uris)

  # Bounds for unauthenticated registration metadata. URL parsing and JOSE key
  # construction both run only after their input is capped.
  @max_human_metadata_bytes 4_096
  @max_opaque_metadata_bytes 65_536
  @max_uri_metadata_bytes 2_048
  @max_tls_identity_bytes 4_096
  @max_metadata_collection_entries 64
  @max_contact_bytes 1_024
  @max_capability_bytes 128
  @max_inline_jwks_bytes 65_536
  @max_inline_jwks_keys 16
  @max_jwk_public_member_bytes 2_048
  @max_x5c_chain_length 8
  @max_x5c_certificate_bytes 16_384
  @private_jwk_members ~w(d p q dp dq qi oth k)
  @asymmetric_jwk_types ~w(RSA EC OKP)

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
    config = Config.resolve!(conn)
    conn = OAuthError.no_store(conn, config)

    with :ok <- check_https(conn, config),
         :ok <- check_registration_enabled(config),
         :ok <- check_content_type(conn),
         {:ok, metadata} <- registration_metadata(conn),
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
    config = Config.resolve!(conn)
    conn = OAuthError.no_store(conn, config)

    with :ok <- check_https(conn, config),
         :ok <- check_registration_enabled(config),
         {:ok, token} <- registration_bearer_token(conn),
         {:ok, client} <- Config.client_store_load(config, client_id),
         :ok <- verify_registration_access_token(config, client, token),
         :ok <- unregister_client(config, client) do
      send_resp(conn, :no_content, "")
    else
      {:error, %{} = error} ->
        render_error(conn, error)

      {:error, reason} when reason in [:not_found, :revoked] ->
        render_error(conn, invalid_registration_token_error())
    end
  end

  # ── Request parsing ──────────────────────────────────────────────────────

  # RFC 7591 §3.1: the metadata document is the JSON request body. Read it from
  # the parsed body only; a query-string copy would leak into proxy logs and is
  # not part of the wire contract.
  defp registration_metadata(%Plug.Conn{} = conn) do
    case Map.get(conn, :body_params) do
      body when is_map(body) and not is_struct(body) -> {:ok, body}
      _other -> {:error, error(@error_invalid_client_metadata, "registration metadata must be a JSON object")}
    end
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
         {:ok, passthrough} <- validate_passthrough_metadata(metadata),
         :ok <- validate_key_source_metadata(passthrough),
         :ok <- validate_method_metadata(auth_method, passthrough, config),
         :ok <- validate_frontchannel_logout_origin(passthrough, redirect_uris) do
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
    Enum.map(@human_string_metadata, &{&1, :human_string}) ++
      Enum.map(@opaque_string_metadata, &{&1, :opaque_string}) ++
      Enum.map(@web_uri_metadata, &{&1, :web_uri}) ++
      Enum.map(@https_uri_metadata, &{&1, :https_uri}) ++
      Enum.map(@tls_client_identity_metadata, &{&1, :tls_client_identity}) ++
      Enum.map(@attestation_alg_metadata, &{&1, :attestation_algs}) ++
      Enum.map(@attestation_pop_alg_metadata, &{&1, :attestation_pop_algs}) ++
      Enum.map(@attestation_method_metadata, &{&1, :capability_strings}) ++
      Enum.map(@string_array_metadata, &{&1, :string_array}) ++
      Enum.map(@redirect_uri_array_metadata, &{&1, :redirect_uri_array}) ++
      [{"jwks", :jwks}] ++
      Enum.map(@boolean_metadata, &{&1, :boolean})
  end

  defp validate_passthrough_member(metadata, key, kind) do
    case Map.fetch(metadata, key) do
      :error -> :absent
      {:ok, value} -> validate_passthrough_value(key, kind, value)
    end
  end

  defp validate_passthrough_value(key, :human_string, value) do
    if bounded_text?(value, @max_human_metadata_bytes) do
      {:ok, value}
    else
      {:error,
       error(
         @error_invalid_client_metadata,
         "#{key} must be valid control-free UTF-8 no longer than #{@max_human_metadata_bytes} bytes"
       )}
    end
  end

  defp validate_passthrough_value(key, :opaque_string, value) do
    if bounded_text?(value, @max_opaque_metadata_bytes) do
      {:ok, value}
    else
      {:error,
       error(
         @error_invalid_client_metadata,
         "#{key} must be valid control-free UTF-8 no longer than #{@max_opaque_metadata_bytes} bytes"
       )}
    end
  end

  defp validate_passthrough_value(key, kind, value) when kind in [:web_uri, :https_uri] do
    schemes = if kind == :web_uri, do: ["https", "http"], else: ["https"]
    allow_fragment? = kind == :web_uri

    if valid_metadata_uri?(value, schemes, allow_fragment?) do
      {:ok, value}
    else
      scheme_description = if kind == :web_uri, do: "http(s)", else: "https"

      {:error,
       error(
         @error_invalid_client_metadata,
         "#{key} must be a bounded absolute #{scheme_description} URI without userinfo"
       )}
    end
  end

  defp validate_passthrough_value(key, :tls_client_identity, value) do
    if valid_tls_identity?(key, value) do
      {:ok, value}
    else
      {:error,
       error(
         @error_invalid_client_metadata,
         "#{key} must be non-empty control-free UTF-8 no longer than #{@max_tls_identity_bytes} bytes (RFC 8705 §2.1)"
       )}
    end
  end

  defp validate_passthrough_value(key, kind, value)
       when kind in [:attestation_algs, :attestation_pop_algs, :capability_strings] do
    prohibited =
      case kind do
        :attestation_algs -> ["none"]
        :attestation_pop_algs -> ["none", "HS256", "HS384", "HS512"]
        :capability_strings -> []
      end

    if bounded_string_list?(value, @max_metadata_collection_entries, @max_capability_bytes) and
         Enum.all?(value, &(&1 not in prohibited)) do
      {:ok, value}
    else
      {:error,
       error(@error_invalid_client_metadata, "#{key} must contain valid attestation capabilities (draft 11 §9)")}
    end
  end

  defp validate_passthrough_value(_key, :string_array, value) when is_list(value) do
    if bounded_string_list?(value, @max_metadata_collection_entries, @max_contact_bytes) do
      {:ok, value}
    else
      {:error, error(@error_invalid_client_metadata, "contacts must be an array of strings (RFC 7591 §2)")}
    end
  end

  defp validate_passthrough_value(key, :string_array, _value) do
    {:error, error(@error_invalid_client_metadata, "#{key} must be an array (RFC 7591 §2)")}
  end

  defp validate_passthrough_value(key, :redirect_uri_array, value) when is_list(value) do
    if list_within_limit?(value, @max_metadata_collection_entries) and
         Enum.uniq(value) == value and
         Enum.all?(value, &acceptable_logout_redirect_uri?/1) do
      {:ok, value}
    else
      {:error,
       error(
         @error_invalid_client_metadata,
         "#{key} entries must be HTTPS absolute URIs without a fragment"
       )}
    end
  end

  defp validate_passthrough_value(key, :redirect_uri_array, _value) do
    {:error, error(@error_invalid_client_metadata, "#{key} must be an array (RFC 7591 §2)")}
  end

  defp validate_passthrough_value("jwks", :jwks, value) do
    if valid_public_jwk_set?(value) do
      {:ok, value}
    else
      {:error,
       error(
         @error_invalid_client_metadata,
         "jwks must be a bounded public asymmetric JWK Set without private or symmetric key material"
       )}
    end
  end

  defp validate_passthrough_value(_key, :boolean, value) when is_boolean(value), do: {:ok, value}

  defp validate_passthrough_value(key, :boolean, _value) do
    {:error, error(@error_invalid_client_metadata, "#{key} must be a boolean")}
  end

  defp bounded_text?(value, max_bytes) when is_binary(value) and value != "" and byte_size(value) <= max_bytes do
    String.valid?(value) and not Regex.match?(~r/\p{Cc}/u, value)
  end

  defp bounded_text?(_value, _max_bytes), do: false

  defp bounded_string_list?(value, max_entries, max_bytes) when is_list(value) do
    list_within_limit?(value, max_entries) and
      Enum.uniq(value) == value and
      Enum.all?(value, &bounded_text?(&1, max_bytes))
  end

  defp bounded_string_list?(_value, _max_entries, _max_bytes), do: false

  defp list_within_limit?([], _remaining), do: true
  defp list_within_limit?([_value | rest], remaining) when remaining > 0, do: list_within_limit?(rest, remaining - 1)
  defp list_within_limit?(_values, 0), do: false

  # A post-logout redirect target is rendered into a link / meta-refresh by the
  # end-session endpoint, so this server profile requires an HTTPS absolute URI
  # with no
  # fragment - never a `javascript:`/`data:`/`vbscript:` payload (which
  # `is_binary/1` alone would wave through into that sink).
  defp acceptable_logout_redirect_uri?(value) when is_binary(value) and value != "" do
    with true <- bounded_text?(value, @max_uri_metadata_bytes),
         true <- RedirectURI.unambiguous?(value),
         false <- invalid_percent_encoding?(value),
         {:ok, %URI{scheme: scheme, host: host, fragment: nil} = uri} <- URI.new(value),
         true <- scheme == "https",
         true <- is_binary(host) and host != "",
         {:ok, _canonical_host} <- HostPolicy.canonicalize(host),
         true <- valid_uri_port?(uri.port) do
      true
    else
      _other -> false
    end
  end

  defp acceptable_logout_redirect_uri?(_value), do: false

  # URI metadata is untrusted even after JSON parsing. Bound it before parsing,
  # accept web schemes only, reject embedded credentials/parser ambiguity, and
  # canonicalize the host through the same IDNA gate as CIMD. Address policy is
  # enforced by the component that actually dereferences a URL: a registration-
  # time block cannot prevent DNS rebinding and would reject private deployments.
  defp valid_metadata_uri?(value, schemes, allow_fragment?)
       when is_binary(value) and value != "" and byte_size(value) <= @max_uri_metadata_bytes do
    with true <- bounded_text?(value, @max_uri_metadata_bytes),
         false <- String.contains?(value, "\\"),
         false <- invalid_percent_encoding?(value),
         {:ok, %URI{} = uri} <- URI.new(value),
         scheme when is_binary(scheme) <- uri.scheme,
         true <- String.downcase(scheme) in schemes,
         host when is_binary(host) and host != "" <- uri.host,
         {:ok, _canonical_host} <- HostPolicy.canonicalize(host),
         true <- is_nil(uri.userinfo),
         true <- allow_fragment? or is_nil(uri.fragment),
         true <- valid_uri_port?(uri.port) do
      true
    else
      _other -> false
    end
  end

  defp valid_metadata_uri?(_value, _schemes, _allow_fragment?), do: false

  defp invalid_percent_encoding?(value), do: Regex.match?(~r/%(?![0-9A-Fa-f]{2})/, value)

  defp valid_uri_port?(nil), do: true
  defp valid_uri_port?(port) when is_integer(port), do: port in 1..65_535
  defp valid_uri_port?(_port), do: false

  defp valid_tls_identity?(key, value) do
    bounded_text?(value, @max_tls_identity_bytes) and
      value == String.trim(value) and
      valid_tls_identity_value?(key, value)
  end

  defp valid_tls_identity_value?("tls_client_auth_san_dns", value),
    do: match?({:ok, _canonical_host}, HostPolicy.canonicalize(value))

  defp valid_tls_identity_value?("tls_client_auth_san_ip", value),
    do: match?({:ok, _address}, :inet.parse_address(String.to_charlist(value)))

  defp valid_tls_identity_value?("tls_client_auth_san_uri", value) do
    RedirectURI.unambiguous?(value) and not invalid_percent_encoding?(value) and
      match?({:ok, %URI{scheme: scheme}} when is_binary(scheme) and scheme != "", URI.new(value))
  end

  defp valid_tls_identity_value?("tls_client_auth_san_email", value) do
    case String.split(value, "@", parts: 3) do
      [local, domain] when local != "" and domain != "" ->
        not String.contains?(local, [" ", "\t", "\r", "\n"]) and
          match?({:ok, _canonical_host}, HostPolicy.canonicalize(domain))

      _other ->
        false
    end
  end

  # Full RFC 4514 normalization belongs to the certificate verifier. At the
  # unauthenticated registration boundary, reject empty/trimmed junk and the
  # most basic malformed form instead of silently persisting it.
  defp valid_tls_identity_value?("tls_client_auth_subject_dn", value), do: String.contains?(value, "=")
  defp valid_tls_identity_value?(_key, _value), do: false

  # RFC 7591 §2: an inline key set and jwks_uri are alternative key sources and
  # MUST NOT be supplied together.
  defp validate_key_source_metadata(metadata) do
    if Map.has_key?(metadata, "jwks") and Map.has_key?(metadata, "jwks_uri") do
      {:error, error(@error_invalid_client_metadata, "jwks and jwks_uri must not both be present (RFC 7591 §2)")}
    else
      :ok
    end
  end

  # RFC 8705 §2.1.2 requires exactly one certificate identity for PKI mTLS.
  # Self-signed mTLS instead binds the certificate through registered public
  # key material (RFC 8705 §2.2.2).
  defp validate_method_metadata("tls_client_auth", metadata, _config) do
    case Enum.count(@tls_client_identity_metadata, &Map.has_key?(metadata, &1)) do
      1 ->
        :ok

      _other ->
        {:error,
         error(
           @error_invalid_client_metadata,
           "tls_client_auth requires exactly one RFC 8705 certificate identity metadata field"
         )}
    end
  end

  defp validate_method_metadata("private_key_jwt", metadata, config) do
    cond do
      Map.has_key?(metadata, "jwks_uri") ->
        :ok

      inline_jwks_has_key?(metadata, &usable_signing_jwk?(&1, config)) ->
        :ok

      true ->
        {:error,
         error(
           @error_invalid_client_metadata,
           "private_key_jwt requires an https jwks_uri or an inline jwks containing a usable public signing key"
         )}
    end
  end

  defp validate_method_metadata("self_signed_tls_client_auth", metadata, _config) do
    cond do
      Map.has_key?(metadata, "jwks_uri") ->
        :ok

      inline_jwks_has_key?(metadata, &certificate_bound_jwk?/1) ->
        :ok

      true ->
        {:error,
         error(
           @error_invalid_client_metadata,
           "self_signed_tls_client_auth requires an https jwks_uri or an inline jwks containing an x5c certificate matched to its public JWK (RFC 8705 §2.2)"
         )}
    end
  end

  defp validate_method_metadata(_method, _metadata, _config), do: :ok

  # OpenID Connect Front-Channel Logout §2: the logout URI must share scheme,
  # host, and effective port with one of the client's registered redirect URIs.
  # The OP later renders this URI into a browser iframe, so accepting an
  # unrelated origin would let an untrusted registration trigger arbitrary
  # browser requests at logout time.
  defp validate_frontchannel_logout_origin(metadata, redirect_uris) do
    case Map.fetch(metadata, "frontchannel_logout_uri") do
      :error ->
        :ok

      {:ok, frontchannel_uri} ->
        if Enum.any?(redirect_uris, &same_web_origin?(&1, frontchannel_uri)) do
          :ok
        else
          {:error,
           error(
             @error_invalid_client_metadata,
             "frontchannel_logout_uri must share an origin with a registered redirect_uri"
           )}
        end
    end
  end

  defp same_web_origin?(left, right) do
    with {:ok, left_origin} <- web_origin(left),
         {:ok, right_origin} <- web_origin(right) do
      left_origin == right_origin
    else
      _other -> false
    end
  end

  defp web_origin(value) do
    with true <- RedirectURI.unambiguous?(value),
         {:ok, %URI{scheme: scheme, host: host} = uri} <- URI.new(value),
         true <- scheme in ["https", "http"],
         true <- is_binary(host) and host != "",
         {:ok, canonical_host} <- HostPolicy.canonicalize(host),
         true <- valid_uri_port?(uri.port) do
      {:ok, {scheme, canonical_host, effective_uri_port(uri)}}
    else
      _other -> {:error, :invalid_origin}
    end
  end

  defp effective_uri_port(%URI{port: port}) when is_integer(port), do: port
  defp effective_uri_port(%URI{scheme: scheme}), do: URI.default_port(scheme)

  defp inline_jwks_has_key?(%{"jwks" => %{"keys" => keys}}, predicate) when is_list(keys),
    do: Enum.any?(keys, predicate)

  defp inline_jwks_has_key?(_metadata, _predicate), do: false

  defp valid_public_jwk_set?(%{"keys" => keys} = jwks) when is_list(keys) do
    jwk_key_count_within_limit?(keys, @max_inline_jwks_keys) and
      jwks_serialized_size(jwks) <= @max_inline_jwks_bytes and
      Enum.all?(keys, &valid_public_jwk_entry?/1)
  end

  defp valid_public_jwk_set?(_jwks), do: false

  defp jwk_key_count_within_limit?([], _remaining), do: true

  defp jwk_key_count_within_limit?([_key | rest], remaining) when remaining > 0,
    do: jwk_key_count_within_limit?(rest, remaining - 1)

  defp jwk_key_count_within_limit?(_keys, 0), do: false

  defp jwks_serialized_size(jwks) do
    jwks
    |> JSON.encode!()
    |> IO.iodata_length()
  rescue
    _ -> @max_inline_jwks_bytes + 1
  catch
    _, _ -> @max_inline_jwks_bytes + 1
  end

  defp valid_public_jwk_entry?(%{"kty" => kty} = jwk) when is_binary(kty) and kty != "" and byte_size(kty) <= 64 do
    valid_public_jwk_common?(jwk, kty) and valid_public_jwk_for_type?(jwk, kty)
  end

  defp valid_public_jwk_entry?(_jwk), do: false

  defp valid_public_jwk_common?(jwk, kty) do
    Enum.all?(Map.keys(jwk), &is_binary/1) and
      kty != "oct" and
      not Enum.any?(@private_jwk_members, &Map.has_key?(jwk, &1)) and
      valid_public_jwk_metadata?(jwk)
  end

  defp valid_public_jwk_for_type?(jwk, kty) when kty in @asymmetric_jwk_types, do: valid_public_asymmetric_jwk?(jwk)

  defp valid_public_jwk_for_type?(jwk, _kty), do: not Map.has_key?(jwk, "x5c")

  defp valid_public_asymmetric_jwk?(%{"kty" => kty} = jwk) when kty in @asymmetric_jwk_types do
    with true <- Enum.all?(Map.keys(jwk), &is_binary/1),
         false <- Enum.any?(@private_jwk_members, &Map.has_key?(jwk, &1)),
         true <- valid_public_jwk_metadata?(jwk),
         true <- valid_public_key_members?(jwk),
         {:ok, parsed} <- parse_public_jwk(jwk),
         true <- valid_known_alg_compatibility?(jwk, parsed),
         true <- valid_x5c_member?(jwk, parsed) do
      true
    else
      _other -> false
    end
  end

  defp valid_public_asymmetric_jwk?(_jwk), do: false

  defp valid_public_jwk_metadata?(jwk) do
    valid_optional_jwk_string?(jwk, "use", 64) and
      valid_optional_jwk_string?(jwk, "alg", 128) and
      valid_optional_jwk_string?(jwk, "kid", 256) and
      valid_optional_jwk_thumbprint?(jwk, "x5t", 20) and
      valid_optional_jwk_thumbprint?(jwk, "x5t#S256", 32) and
      valid_jwk_key_ops?(jwk) and
      consistent_jwk_usage?(jwk)
  end

  defp valid_optional_jwk_string?(jwk, member, max_bytes) do
    case Map.fetch(jwk, member) do
      :error -> true
      {:ok, value} -> bounded_text?(value, max_bytes)
    end
  end

  defp valid_optional_jwk_thumbprint?(jwk, member, expected_bytes) do
    case Map.fetch(jwk, member) do
      :error ->
        true

      {:ok, value} ->
        case canonical_base64url(value) do
          {:ok, decoded} -> byte_size(decoded) == expected_bytes
          :error -> false
        end
    end
  end

  defp valid_jwk_key_ops?(jwk) do
    case Map.fetch(jwk, "key_ops") do
      :error ->
        true

      {:ok, ops} when is_list(ops) ->
        length(ops) <= 16 and Enum.uniq(ops) == ops and Enum.all?(ops, &bounded_text?(&1, 64))

      {:ok, _other} ->
        false
    end
  end

  @signature_key_ops ~w(sign verify)
  @encryption_key_ops ~w(encrypt decrypt wrapKey unwrapKey deriveKey deriveBits)

  defp consistent_jwk_usage?(%{"use" => "sig", "key_ops" => ops}) when is_list(ops),
    do: Enum.all?(ops, &(&1 in @signature_key_ops))

  defp consistent_jwk_usage?(%{"use" => "enc", "key_ops" => ops}) when is_list(ops),
    do: Enum.all?(ops, &(&1 in @encryption_key_ops))

  defp consistent_jwk_usage?(%{"use" => use, "key_ops" => _ops}) when use not in ["sig", "enc"], do: false
  defp consistent_jwk_usage?(_jwk), do: true

  defp valid_public_key_members?(%{"kty" => "RSA"} = jwk) do
    SigningAlg.rsa_params_ok?(jwk) and
      valid_base64url_member?(Map.get(jwk, "n")) and
      valid_base64url_member?(Map.get(jwk, "e"))
  end

  defp valid_public_key_members?(%{"kty" => "EC"} = jwk) do
    bounded_text?(Map.get(jwk, "crv"), 64) and
      valid_base64url_member?(Map.get(jwk, "x")) and
      valid_base64url_member?(Map.get(jwk, "y"))
  end

  defp valid_public_key_members?(%{"kty" => "OKP"} = jwk) do
    bounded_text?(Map.get(jwk, "crv"), 64) and valid_base64url_member?(Map.get(jwk, "x"))
  end

  defp valid_base64url_member?(value)
       when is_binary(value) and value != "" and byte_size(value) <= @max_jwk_public_member_bytes do
    match?({:ok, decoded} when byte_size(decoded) > 0, canonical_base64url(value))
  end

  defp valid_base64url_member?(_value), do: false

  defp canonical_base64url(value) when is_binary(value) and value != "" do
    case Base.url_decode64(value, padding: false) do
      {:ok, decoded} ->
        if Base.url_encode64(decoded, padding: false) == value, do: {:ok, decoded}, else: :error

      :error ->
        :error
    end
  end

  defp canonical_base64url(_value), do: :error

  defp parse_public_jwk(jwk) do
    case JOSE.JWK.from_map(jwk) do
      %JOSE.JWK{} = parsed -> {:ok, parsed}
      _other -> {:error, :malformed_jwk}
    end
  rescue
    _ -> {:error, :malformed_jwk}
  catch
    _, _ -> {:error, :malformed_jwk}
  end

  defp valid_known_alg_compatibility?(jwk, parsed) do
    case Map.get(jwk, "alg") do
      alg when is_binary(alg) ->
        if alg in SigningAlg.allowed() do
          SigningAlg.validate_for_key!(alg, parsed) == alg and
            match?({:ok, %JOSE.JWK{}}, Key.verification_jwk(jwk, alg: alg))
        else
          true
        end

      _absent_encryption_or_future_alg ->
        true
    end
  rescue
    _error -> false
  end

  defp usable_signing_jwk?(jwk, config) do
    with true <- valid_public_asymmetric_jwk?(jwk),
         {:ok, parsed} <- parse_public_jwk(jwk),
         {:ok, alg} <- signing_alg_for_jwk(jwk, parsed),
         true <- alg in configured_client_auth_algs(config),
         ^alg <- SigningAlg.validate_for_key!(alg, parsed),
         {:ok, %JOSE.JWK{}} <- Key.verification_jwk(jwk, alg: alg),
         true <- not enforce_client_auth_fapi?(config) or SigningAlg.fapi_compatible?(alg, parsed) do
      true
    else
      _other -> false
    end
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  defp configured_client_auth_algs(%Config{client_auth_signing_algs: [_ | _] = algs}), do: algs
  defp configured_client_auth_algs(%Config{}), do: SigningAlg.fapi_algs()

  defp enforce_client_auth_fapi?(%Config{client_auth_enforce_fapi_alg_policy: value}) when is_boolean(value), do: value

  defp enforce_client_auth_fapi?(%Config{client_auth_signing_algs: algs}), do: is_nil(algs)

  defp signing_alg_for_jwk(jwk, parsed) do
    alg = Map.get(jwk, "alg") || SigningAlg.infer(parsed)
    if alg in SigningAlg.allowed(), do: {:ok, alg}, else: {:error, :unsupported_alg}
  rescue
    _ -> {:error, :unsupported_alg}
  catch
    _, _ -> {:error, :unsupported_alg}
  end

  defp certificate_bound_jwk?(jwk) do
    Map.has_key?(jwk, "x5c") and valid_public_asymmetric_jwk?(jwk)
  end

  defp valid_x5c_member?(jwk, parsed) do
    case Map.fetch(jwk, "x5c") do
      :error ->
        true

      {:ok, chain} ->
        valid_x5c_chain?(chain) and
          x5c_leaf_matches_jwk?(chain, parsed) and
          x5c_thumbprints_match?(jwk, chain)
    end
  end

  defp x5c_thumbprints_match?(jwk, [leaf | _rest]) do
    with {:ok, der} <- Base.decode64(leaf),
         true <- optional_thumbprint_matches?(jwk, "x5t", :sha, der),
         true <- optional_thumbprint_matches?(jwk, "x5t#S256", :sha256, der) do
      true
    else
      _other -> false
    end
  end

  defp optional_thumbprint_matches?(jwk, member, digest, der) do
    case Map.fetch(jwk, member) do
      :error -> true
      {:ok, encoded} -> encoded == Base.url_encode64(:crypto.hash(digest, der), padding: false)
    end
  end

  defp x5c_leaf_matches_jwk?([leaf | _rest], parsed) do
    with {:ok, der} <- Base.decode64(leaf),
         {:ok, certificate_key} <- certificate_public_jwk(der) do
      JOSE.JWK.thumbprint(certificate_key) == JOSE.JWK.thumbprint(parsed)
    else
      _other -> false
    end
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  defp certificate_public_jwk(der) do
    pem = :public_key.pem_encode([{:Certificate, der, :not_encrypted}])

    case JOSE.JWK.from_pem(pem) do
      %JOSE.JWK{} = jwk -> {:ok, jwk}
      _other -> {:error, :invalid_certificate_key}
    end
  rescue
    _ -> {:error, :invalid_certificate_key}
  catch
    _, _ -> {:error, :invalid_certificate_key}
  end

  defp valid_x5c_chain?(chain) when is_list(chain) and chain != [] do
    length(chain) <= @max_x5c_chain_length and Enum.all?(chain, &valid_x5c_certificate?/1)
  end

  defp valid_x5c_chain?(_chain), do: false

  defp valid_x5c_certificate?(encoded) when is_binary(encoded) and encoded != "" do
    with {:ok, der} <- Base.decode64(encoded),
         true <- byte_size(der) <= @max_x5c_certificate_bytes,
         decoded = :public_key.pkix_decode_cert(der, :plain),
         true <- is_tuple(decoded) and elem(decoded, 0) == :Certificate do
      true
    else
      _other -> false
    end
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  defp valid_x5c_certificate?(_encoded), do: false

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

      {:ok, _other} ->
        {:error,
         error(
           @error_invalid_client_metadata,
           "application_type is invalid; expected web or native"
         )}
    end
  end

  defp validate_auth_method(metadata, config) do
    supported =
      config
      |> Config.token_endpoint_auth_methods_supported()
      |> Enum.reject(&(&1 in @unsupported_registration_auth_methods))

    case Map.fetch(metadata, "token_endpoint_auth_method") do
      :error ->
        if @default_auth_method in supported do
          {:ok, @default_auth_method}
        else
          {:error,
           error(
             @error_invalid_client_metadata,
             "the default token_endpoint_auth_method client_secret_basic is not supported"
           )}
        end

      {:ok, method} when is_binary(method) and byte_size(method) <= 128 ->
        if method in supported do
          {:ok, method}
        else
          {:error,
           error(
             @error_invalid_client_metadata,
             "token_endpoint_auth_method is not supported"
           )}
        end

      {:ok, _other} ->
        {:error, error(@error_invalid_client_metadata, "token_endpoint_auth_method must be a string")}
    end
  end

  # RFC 7591 §2: every requested grant type must be one the server supports
  # (RFC 6749 §1.3). Absent, the default is authorization_code.
  defp validate_grant_types(metadata, config) do
    supported = Config.grant_types_supported(config)

    case Map.fetch(metadata, "grant_types") do
      :error ->
        validate_requested_grant_types(["authorization_code"], supported)

      {:ok, grant_types} when is_list(grant_types) ->
        validate_requested_grant_types(grant_types, supported)

      {:ok, _other} ->
        {:error, error(@error_invalid_client_metadata, "grant_types must be an array")}
    end
  end

  defp validate_requested_grant_types(grant_types, supported) do
    invalid =
      not list_within_limit?(grant_types, @max_metadata_collection_entries) or
        Enum.uniq(grant_types) != grant_types or
        not Enum.all?(grant_types, &(is_binary(&1) and &1 != "" and byte_size(&1) <= 128))

    case if(invalid, do: [:invalid], else: Enum.reject(grant_types, &(&1 in supported))) do
      [] ->
        {:ok, grant_types}

      [_unsupported | _] ->
        {:error,
         error(
           @error_invalid_client_metadata,
           "grant_types contains an invalid or unsupported value"
         )}
    end
  end

  # RFC 7591 §2 / RFC 6749 §3.1.2: a grant type that redirects the resource
  # owner back to the client requires at least one absolute redirect URI; a
  # malformed or relative URI is rejected as invalid_redirect_uri.
  defp validate_redirect_uris(metadata, grant_types, application_type) do
    needs_redirect? = Enum.any?(grant_types, &(&1 in @redirect_requiring_grant_types))

    case Map.fetch(metadata, "redirect_uris") do
      :error when needs_redirect? ->
        {:error,
         error(
           @error_invalid_redirect_uri,
           "redirect_uris is required for the requested grant_types (RFC 6749 §3.1.2)"
         )}

      :error ->
        {:ok, []}

      {:ok, redirect_uris} when is_list(redirect_uris) ->
        validate_redirect_uri_list(redirect_uris, needs_redirect?, application_type)

      {:ok, _other} ->
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
    valid_collection? =
      list_within_limit?(redirect_uris, @max_metadata_collection_entries) and
        Enum.uniq(redirect_uris) == redirect_uris

    case valid_collection? and Enum.all?(redirect_uris, &valid_redirect_uri?(&1, application_type)) do
      true ->
        {:ok, redirect_uris}

      false ->
        {:error, error(@error_invalid_redirect_uri, "redirect_uris contains an invalid value")}
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
  defp valid_redirect_uri?(value, application_type)
       when is_binary(value) and value != "" and byte_size(value) <= @max_uri_metadata_bytes do
    with true <- bounded_text?(value, @max_uri_metadata_bytes),
         true <- RedirectURI.unambiguous?(value),
         false <- invalid_percent_encoding?(value),
         {:ok, uri} <- URI.new(value) do
      acceptable_redirect_uri?(uri, application_type, value)
    else
      _other -> false
    end
  end

  defp valid_redirect_uri?(_value, _application_type), do: false

  # RFC 6749 §3.1.2: "The redirection endpoint URI MUST NOT include a fragment
  # component." True of every client type, checked before anything else.
  defp acceptable_redirect_uri?(%URI{fragment: fragment}, _application_type, _original) when not is_nil(fragment),
    do: false

  # The ordinary form: scheme + authority. The scheme MUST be http/https. A
  # non-http(s) scheme WITH an authority - `javascript://x/%0aalert(document.domain)//`
  # parses to scheme "javascript", host "x", no fragment - would otherwise
  # register as a "trusted" redirect target and later be rendered into an
  # auto-executing sink (the `form_post`/`form_post.jwt` self-submitting form,
  # the logout continue-link / meta-refresh) as stored XSS in the AS origin.
  # Restricting the authority form to http/https closes that; native private-use
  # and loopback forms are handled by the clauses below.
  defp acceptable_redirect_uri?(%URI{scheme: "https", host: host} = uri, _application_type, _original)
       when is_binary(host) and host != "" do
    valid_uri_port?(uri.port) and match?({:ok, _canonical_host}, HostPolicy.canonicalize(host))
  end

  # RFC 9700 §2.1 permits plain HTTP only for native loopback redirects as
  # defined by RFC 8252 §7.3. External HTTP redirects are rejected for both web
  # and native registrations.
  defp acceptable_redirect_uri?(%URI{scheme: "http"}, "native", original),
    do: ClientIdMetadata.loopback_redirect_uri?(original)

  # RFC 8252 §7.1 private-use scheme: no authority, reverse-DNS scheme, and a
  # real path to call back to.
  defp acceptable_redirect_uri?(%URI{scheme: scheme, host: nil, path: path}, "native", _original)
       when is_binary(scheme) and scheme != "" and is_binary(path) and path != "", do: String.contains?(scheme, ".")

  defp acceptable_redirect_uri?(%URI{}, _application_type, _original), do: false

  # RFC 7591 §2 / RFC 6749 §3.3: the requested scope is a space-delimited
  # string; every requested scope must be in the server's effective
  # authorization-server catalog. Absent, the server MAY assign a default scope
  # (RFC 7591 §2) — `:registration_default_scope`, echoed back in the §3.2.1
  # response so the client learns what it got; with no default configured the
  # client registers with no scope (fail-closed).
  defp validate_scope(metadata, config) do
    case Map.fetch(metadata, "scope") do
      :error ->
        default_scope(config)

      {:ok, scope} when is_binary(scope) and byte_size(scope) > @max_scope_metadata_bytes ->
        # Registration is unauthenticated when enabled, so an uncapped `scope`
        # is a cheap lever: it was split into a list and every token checked for
        # catalog membership. Reject an absurd value in O(1), before the split.
        {:error, error(@error_invalid_client_metadata, "scope metadata is too large")}

      {:ok, scope} when is_binary(scope) ->
        check_requested_scope(scope, config)

      {:ok, _other} ->
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
    catalog = MapSet.new(Config.effective_scopes_supported(config))

    scope
    |> String.split(" ", trim: true)
    |> Enum.reject(&MapSet.member?(catalog, &1))
    |> case do
      [] ->
        {:ok, scope}

      [_unknown | _] ->
        {:error, error(@error_invalid_client_metadata, "scope contains an unknown value")}
    end
  end

  # ── Credential issuance ──────────────────────────────────────────────────

  # Mint the client identifier and, for a secret-based method, the client
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

  defp generate_secret(method) when method in @secret_auth_methods, do: Secret.generate()
  defp generate_secret(_method), do: nil

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

  # ── Helpers ──────────────────────────────────────────────────────────────

  defp registration_bearer_token(conn) do
    with [header] <- get_req_header(conn, "authorization"),
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

  # The router option controls whether these routes exist, while the runtime
  # config controls whether this deployment actually offers registration. A
  # route left mounted during a rollout or configuration mistake must return a
  # controlled failure instead of invoking a missing callback.
  defp check_registration_enabled(%Config{registration_enabled: true} = config) do
    if is_nil(Config.register_client_fun(config)) do
      {:error, error(@error_invalid_client_metadata, "dynamic client registration is unavailable")}
    else
      :ok
    end
  end

  defp check_registration_enabled(%Config{}) do
    {:error, error(@error_invalid_client_metadata, "dynamic client registration is disabled")}
  end

  defp render_error(conn, %OAuthError{} = err) do
    OAuthError.render(conn, err, auth_scheme: :none, config: Config.resolve!(conn))
  end

  defp error(code, description), do: OAuthError.new(code, description, status: 400)

  defp invalid_registration_token_error do
    OAuthError.new(@error_invalid_token, "registration access token is missing or invalid", status: 401)
  end
end
