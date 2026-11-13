defmodule AttestoPhoenix.ConsentGrant do
  @moduledoc """
  The request binding a single-use consent grant is tied to, and the canonical
  hash over it (RFC 6749 §4.1.1).

  A consent grant must approve *exactly* the authorization request the resource
  owner saw — the same client, redirect URI, scope and resource sets, requested
  claims, authorization details, DPoP key, PKCE challenge, and PKCE method — and
  nothing else. This
  module builds that binding from either
  raw authorization params (`binding_from_params/2`, used by the consent-screen
  mint action) or from a validated `%Attesto.AuthorizationRequest{}` (`binding/2`,
  used by the live `/authorize` consume side). Both builders feed the same
  canonical field list and therefore yield the same `binding_hash/1` for the
  equivalent request.

  ## Consent with park/resume

  A resume URL accepts only `resume`; carry the consent grant in the browser's
  session. Before parking in `:consent`, save
  `params = AttestoPhoenix.Interaction.request_params(conn)`, the validated
  `request`, and the authenticated subject in a host-owned consent context.
  Tie that context to this browser and `resume_id`. On the consent page,
  after checking the current subject, CSRF protection, and approval, mint:

      def approve_consent(conn, resume_id) do
        %{params: params, request: request, subject: subject} =
          load_consent_context!(conn, resume_id)

        binding = AttestoPhoenix.ConsentGrant.binding_from_params(
          params, subject, scope: request.scope
        )
        {:ok, token} = AttestoPhoenix.Store.EctoConsentGrantStore.mint(binding, 300)

        conn
        |> put_session(:consent_grant, %{"resume" => resume_id, "token" => token})
        |> redirect(to: "/oauth/authorize?resume=" <> resume_id)
      end

  The context helpers below are host code. Save trusted values on the server;
  do not accept replacement authorization parameters from the approval form.
  Consume the grant in `:consent` against the request validated on resume:

      def consent(conn, request, subject) do
        resume_id = conn.params["resume"]

        case get_session(conn, :consent_grant) do
          %{"resume" => ^resume_id, "token" => token} when is_binary(resume_id) ->
            binding = AttestoPhoenix.ConsentGrant.binding(request, subject.subject)

            case AttestoPhoenix.Store.EctoConsentGrantStore.consume(token, binding) do
              :ok -> {:consented, subject}
              {:error, reason} -> {:denied, reason}
            end

          _ ->
            params = AttestoPhoenix.Interaction.request_params(conn)
            {:ok, resume_id} = AttestoPhoenix.Interaction.park(conn, request)
            save_consent_context!(conn, resume_id, %{
              params: params, request: request, subject: subject.subject
            })
            {:halt, redirect(conn, to: "/consent?resume=" <> resume_id)}
        end
      end

  The session pairs the token with its resume id so a leftover token is not
  applied to a later authorization request. Session changes inside a
  `{:consented, subject}` callback are not persisted; `consume/2` enforces
  single use even if the token remains in the session. A token is not consent
  until its binding has been checked and it has been consumed.

  `request_params/1` returns front-channel parameters. For PAR or a signed
  Request Object, those do not contain all validated fields: save the binding
  built with `binding(request, subject)` in the trusted consent context and
  mint from it after approval instead of rebuilding from the raw parameters.

  ## Consent without resume

  The existing flow can still carry the token back as a `consent_grant`
  parameter alongside the original authorization parameters. Mint with
  `binding_from_params(params, subject, scope: request.scope)`, then have
  `:consent` read `conn.params["consent_grant"]` and consume it against
  `binding(request, subject.subject)`. This starts a fresh authorization
  request, including a fresh `prompt=login` check (OIDC Core §3.1.2.1,
  §3.1.2.3). Do not combine that parameter with `resume`.

  ## Canonical binding

  The binding contains `(subject, client_id, redirect_uri, scope, resource,
  claims, dpop_jkt, code_challenge, code_challenge_method)`, followed by
  `authorization_details` when the request carries any.

    * `subject` - the OIDC `sub` of the resource owner who consented. Binding to
      the subject stops one user's consent token from approving another's request.
    * `client_id` / `redirect_uri` - the requesting client and the exact
      redirect URI the code will be returned to (RFC 6749 §3.1.2). Binding both
      stops a consent shown for one client/redirect from authorizing a different
      one.
    * `scope` - the requested scope set. Order is **not** significant (RFC 6749
      §3.3), so the set is sorted before hashing: a request with
      `scope=openid profile` and one with `scope=profile openid` hash
      identically, while adding or dropping a scope changes the hash.
    * `resource` - the RFC 8707 resource set. Order and duplicates are
      insignificant, while changing the authorized resource changes the hash.
    * `claims` - the validated OIDC claims request. JSON objects are encoded
      recursively with sorted keys and explicit type/length framing.
    * `dpop_jkt` - the RFC 9449 authorization-code key binding, or `nil`.
    * `code_challenge` - the PKCE challenge (RFC 7636 §4.3), or the empty string
      when the request carries none. Binding it stops a consent from being
      replayed against a request that swapped in a different PKCE challenge.
    * `code_challenge_method` - the PKCE method (`S256`, RFC 7636 §4.3), or the
      empty string when the request carries no PKCE challenge. Binding it stops
      a consent granted for an `S256` request from being reused for a `plain`
      request with the same challenge value.
    * `authorization_details` - the RFC 9396 authorization details array, in
      request order. Each object is encoded like `claims`. Binding it stops a
      consent shown for a request without, or with different, authorization
      details from approving one that carries an entitlement such as an
      OID4VCI `openid_credential` configuration. An absent or empty array adds
      nothing to the encoding, so the hash of a request without authorization
      details does not depend on this field.

  `binding_hash/1` is SHA-256 over a type-tagged, length-framed canonical
  encoding, URL-base64 encoded without padding. It is stable across the mint
  and consume sides because both derive it from this one function.
  """

  @typedoc """
  The fields a consent grant is bound to. `subject`, `client_id`, and
  `redirect_uri` are required; `scope` is a (possibly empty) list whose order is
  normalized away; `code_challenge` and `code_challenge_method` are `nil` when
  the request carries no PKCE challenge.
  """
  @type binding :: %{
          optional(:authorization_details) => [map()],
          subject: String.t(),
          client_id: String.t(),
          redirect_uri: String.t(),
          scope: [String.t()],
          resource: [String.t()],
          claims: map(),
          dpop_jkt: String.t() | nil,
          code_challenge: String.t() | nil,
          code_challenge_method: String.t() | nil
        }

  # Always encoded, in this order. `authorization_details` follows only when it
  # is non-empty (see `encode_authorization_details/1`).
  @fixed_fields ~w(client_id redirect_uri scope resource claims dpop_jkt code_challenge code_challenge_method)a
  @binding_fields @fixed_fields ++ [:authorization_details]
  @canonical_fields [:subject] ++ @fixed_fields

  @doc """
  Builds the consent binding for `request` consented to by `subject`.

  `request` is the validated `%Attesto.AuthorizationRequest{}` (the front-channel
  request whose `client_id`, `redirect_uri`, `scope`, `code_challenge`, and
  `code_challenge_method` the user saw); `subject` is the authenticated resource
  owner's OIDC `sub`. The returned map feeds `binding_hash/1` and the store's
  `mint/2` / `consume/2`.
  """
  @spec binding(Attesto.AuthorizationRequest.t(), String.t()) :: binding()
  def binding(%Attesto.AuthorizationRequest{} = request, subject) when is_binary(subject) do
    request
    |> Map.from_struct()
    |> canonical_binding(subject)
  end

  @doc """
  Builds the consent binding from raw OAuth authorization params and `subject`.

  Use this on the consent-screen mint side, where the host has the raw
  string-keyed params that reached `/authorize` / the consent action rather than
  the validated `%Attesto.AuthorizationRequest{}`. The consume side should keep
  using `binding/2`.

  `params` is read by string keys. Scope and resource sets are normalized;
  `claims` may be the original JSON object string or an already-decoded map,
  and `authorization_details` the original JSON array string or an
  already-decoded list. Unknown params are ignored. Malformed values raise `ArgumentError`; callers
  handling untrusted data without an existing validation boundary should use
  `safe_binding_from_params/3`. For the equivalent validated request,
  `binding_hash(binding_from_params(params, subject, scope: request.scope)) ==
  binding_hash(binding(request, subject))`.

  ## The effective scope

  `binding/2` hashes the validated request's `scope`, which is the scope the
  scope policy decided: the client's request narrowed by the policy, or the
  policy's default when the request omitted `scope` (RFC 6749 §3.3), including
  a pushed request without one. The raw `scope` parameter can differ from it in
  both cases, so pass the scope the consent screen showed, which is
  `request.scope` in the `:consent` callback, as the `:scope` option. When
  `:scope` is given it replaces the `scope` parameter; it is a list of scope
  strings or a space-delimited string.
  """
  @spec binding_from_params(map(), String.t(), keyword()) :: binding()
  def binding_from_params(params, subject, opts \\ []) when is_map(params) and is_binary(subject) do
    case safe_binding_from_params(params, subject, opts) do
      {:ok, binding} -> binding
      {:error, :invalid_binding} -> raise ArgumentError, "invalid consent binding parameters"
    end
  end

  @doc """
  Safely builds a consent binding from untrusted raw parameters.

  Returns `{:error, :invalid_binding}` for an invalid required scalar, set,
  claims object, authorization details array, DPoP thumbprint value, or nested
  JSON value. Takes the same `:scope` option as `binding_from_params/3`.
  """
  @spec safe_binding_from_params(map(), String.t(), keyword()) ::
          {:ok, binding()} | {:error, :invalid_binding}
  def safe_binding_from_params(params, subject, opts \\ [])

  def safe_binding_from_params(params, subject, opts) when is_map(params) and is_binary(subject) and is_list(opts) do
    with :ok <- validate_required_string(subject),
         {:ok, params} <- put_effective_scope(params, opts),
         {:ok, source} <- safe_params_binding_source(params),
         {:ok, binding} <- validate_binding(canonical_binding(source, subject)) do
      {:ok, binding}
    else
      _ -> {:error, :invalid_binding}
    end
  end

  def safe_binding_from_params(_params, _subject, _opts), do: {:error, :invalid_binding}

  # The `:scope` option replaces the raw parameter with the scope the policy
  # decided; a list is joined so it goes through the same set normalization.
  defp put_effective_scope(params, opts) do
    case Keyword.fetch(opts, :scope) do
      :error ->
        {:ok, params}

      {:ok, scope} when is_binary(scope) ->
        {:ok, Map.put(params, "scope", scope)}

      {:ok, scope} when is_list(scope) ->
        if Enum.all?(scope, &(is_binary(&1) and &1 != "" and not String.contains?(&1, " "))),
          do: {:ok, Map.put(params, "scope", Enum.join(scope, " "))},
          else: {:error, :invalid_binding}

      {:ok, _other} ->
        {:error, :invalid_binding}
    end
  end

  @doc """
  The canonical binding hash for `binding`.

  SHA-256 over a type-tagged, length-framed encoding, URL-base64 encoded
  without padding. Scope and resource are sorted unique sets; nested claims
  maps are ordered by key. Identical on the mint and consume sides for the same
  request.
  """
  @spec binding_hash(binding()) :: String.t()
  def binding_hash(%{} = binding) do
    case validate_binding(binding) do
      {:ok, normalized} ->
        canonical =
          Enum.map(@canonical_fields, &encode_value(Map.fetch!(normalized, &1))) ++
            encode_authorization_details(normalized.authorization_details)

        :sha256 |> :crypto.hash(canonical) |> Base.url_encode64(padding: false)

      {:error, :invalid_binding} ->
        raise ArgumentError, "invalid consent binding"
    end
  end

  defp safe_params_binding_source(params) do
    with {:ok, client_id} <- required_param(params, "client_id"),
         {:ok, redirect_uri} <- required_param(params, "redirect_uri"),
         {:ok, scope} <- string_set(Map.get(params, "scope"), :space_delimited),
         {:ok, resource} <- string_set(Map.get(params, "resource"), :scalar_or_list),
         {:ok, claims} <- claims_param(Map.get(params, "claims")),
         {:ok, authorization_details} <-
           authorization_details_param(Map.get(params, "authorization_details")),
         {:ok, dpop_jkt} <- optional_string(Map.get(params, "dpop_jkt")),
         {:ok, code_challenge} <- optional_string(Map.get(params, "code_challenge")),
         {:ok, code_challenge_method} <- optional_string(Map.get(params, "code_challenge_method")) do
      {:ok,
       %{
         client_id: client_id,
         redirect_uri: redirect_uri,
         scope: scope,
         resource: resource,
         claims: claims,
         authorization_details: authorization_details,
         dpop_jkt: dpop_jkt,
         code_challenge: code_challenge,
         code_challenge_method: code_challenge_method
       }}
    else
      _ -> {:error, :invalid_binding}
    end
  end

  defp canonical_binding(%{} = source, subject) do
    @binding_fields
    |> Map.new(fn field -> {field, normalize_binding_value(field, Map.get(source, field))} end)
    |> Map.put(:subject, subject)
  end

  defp normalize_binding_value(field, nil) when field in [:scope, :resource, :authorization_details], do: []

  defp normalize_binding_value(:scope, scope) when is_binary(scope),
    do: scope |> String.split(" ", trim: true) |> Enum.uniq() |> Enum.sort()

  defp normalize_binding_value(field, values) when field in [:scope, :resource] and is_list(values),
    do: values |> Enum.uniq() |> Enum.sort()

  defp normalize_binding_value(:claims, nil), do: %{}

  defp normalize_binding_value(_field, value), do: value

  defp validate_binding(binding) do
    normalized = canonical_binding(binding, Map.get(binding, :subject))

    with :ok <- validate_required_string(normalized.subject),
         :ok <- validate_required_string(normalized.client_id),
         :ok <- validate_required_string(normalized.redirect_uri),
         :ok <- validate_string_list(normalized.scope),
         :ok <- validate_string_list(normalized.resource),
         :ok <- validate_json_value(normalized.claims),
         true <- is_map(normalized.claims),
         :ok <- validate_authorization_details(normalized.authorization_details),
         :ok <- validate_optional_string(normalized.dpop_jkt),
         :ok <- validate_optional_string(normalized.code_challenge),
         :ok <- validate_optional_string(normalized.code_challenge_method) do
      {:ok, normalized}
    else
      _ -> {:error, :invalid_binding}
    end
  end

  defp required_param(params, key) do
    case Map.get(params, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, :invalid_binding}
    end
  end

  defp string_set(nil, _mode), do: {:ok, []}

  defp string_set(value, :space_delimited) when is_binary(value) do
    value |> String.split(" ", trim: true) |> normalize_string_set()
  end

  defp string_set(value, _mode) when is_binary(value), do: normalize_string_set([value])
  defp string_set(values, _mode) when is_list(values), do: normalize_string_set(values)
  defp string_set(_value, _mode), do: {:error, :invalid_binding}

  defp normalize_string_set(values) do
    if Enum.all?(values, &(is_binary(&1) and &1 != "")) do
      {:ok, values |> Enum.uniq() |> Enum.sort()}
    else
      {:error, :invalid_binding}
    end
  end

  defp claims_param(nil), do: {:ok, %{}}

  defp claims_param(value) when is_binary(value) do
    case JSON.decode(value) do
      {:ok, claims} when is_map(claims) -> claims_param(claims)
      _ -> {:error, :invalid_binding}
    end
  end

  defp claims_param(value) when is_map(value) do
    case validate_json_value(value) do
      :ok -> {:ok, value}
      _ -> {:error, :invalid_binding}
    end
  end

  defp claims_param(_value), do: {:error, :invalid_binding}

  defp authorization_details_param(nil), do: {:ok, []}

  defp authorization_details_param(value) when is_binary(value) do
    case JSON.decode(value) do
      {:ok, details} when is_list(details) -> authorization_details_param(details)
      _ -> {:error, :invalid_binding}
    end
  end

  defp authorization_details_param(value) when is_list(value) do
    case validate_authorization_details(value) do
      :ok -> {:ok, value}
      _ -> {:error, :invalid_binding}
    end
  end

  defp authorization_details_param(_value), do: {:error, :invalid_binding}

  # RFC 9396 §2: a JSON array of JSON objects.
  defp validate_authorization_details(details) when is_list(details) do
    if Enum.all?(details, &(is_map(&1) and validate_json_value(&1) == :ok)),
      do: :ok,
      else: {:error, :invalid_binding}
  end

  defp validate_authorization_details(_details), do: {:error, :invalid_binding}

  defp encode_authorization_details([]), do: []
  defp encode_authorization_details(details), do: [encode_value(details)]

  defp optional_string(nil), do: {:ok, nil}
  defp optional_string(value) when is_binary(value), do: {:ok, value}
  defp optional_string(_value), do: {:error, :invalid_binding}

  defp validate_required_string(value) when is_binary(value) and value != "", do: :ok
  defp validate_required_string(_value), do: {:error, :invalid_binding}

  defp validate_optional_string(nil), do: :ok
  defp validate_optional_string(value) when is_binary(value), do: :ok
  defp validate_optional_string(_value), do: {:error, :invalid_binding}

  defp validate_string_list(values) when is_list(values) do
    if Enum.all?(values, &(is_binary(&1) and &1 != "")), do: :ok, else: {:error, :invalid_binding}
  end

  defp validate_string_list(_values), do: {:error, :invalid_binding}

  defp validate_json_value(nil), do: :ok
  defp validate_json_value(value) when is_boolean(value) or is_binary(value) or is_number(value), do: :ok

  defp validate_json_value(values) when is_list(values) do
    if Enum.all?(values, &(validate_json_value(&1) == :ok)), do: :ok, else: {:error, :invalid_binding}
  end

  defp validate_json_value(value) when is_map(value) and not is_struct(value) do
    if Enum.all?(value, fn {key, nested} -> is_binary(key) and validate_json_value(nested) == :ok end),
      do: :ok,
      else: {:error, :invalid_binding}
  end

  defp validate_json_value(_value), do: {:error, :invalid_binding}

  defp encode_value(nil), do: frame(0, <<>>)
  defp encode_value(false), do: frame(1, <<>>)
  defp encode_value(true), do: frame(2, <<>>)
  defp encode_value(value) when is_integer(value), do: frame(3, Integer.to_string(value))
  defp encode_value(value) when is_float(value), do: frame(4, :erlang.float_to_binary(value, [:compact]))
  defp encode_value(value) when is_binary(value), do: frame(5, value)
  defp encode_value(values) when is_list(values), do: frame(6, Enum.map(values, &encode_value/1))

  defp encode_value(value) when is_map(value) do
    entries =
      value
      |> Enum.sort_by(fn {key, _nested} -> key end)
      |> Enum.map(fn {key, nested} -> [encode_value(key), encode_value(nested)] end)

    frame(7, entries)
  end

  defp frame(tag, payload) do
    size = IO.iodata_length(payload)
    [<<tag, size::unsigned-big-64>>, payload]
  end
end
