defmodule AttestoPhoenix.ConsentGrant do
  @moduledoc """
  The request binding a single-use consent grant is tied to, and the canonical
  hash over it (RFC 6749 §4.1.1).

  A consent grant must approve *exactly* the authorization request the resource
  owner saw — the same client, redirect URI, scope and resource sets, requested
  claims, DPoP key, PKCE challenge, and PKCE method — and nothing else. This
  module builds that binding from either
  raw authorization params (`binding_from_params/2`, used by the consent-screen
  mint action) or from a validated `%Attesto.AuthorizationRequest{}` (`binding/2`,
  used by the live `/authorize` consume side). Both builders feed the same
  canonical field list and therefore yield the same `binding_hash/1` for the
  equivalent request.

  ## Canonical binding

  The binding contains `(subject, client_id, redirect_uri, scope, resource,
  claims, dpop_jkt, code_challenge, code_challenge_method)`.

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

  @binding_fields ~w(client_id redirect_uri scope resource claims dpop_jkt code_challenge code_challenge_method)a
  @canonical_fields [:subject] ++ @binding_fields

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
  `claims` may be the original JSON object string or an already-decoded map.
  Unknown params are ignored. Malformed values raise `ArgumentError`; callers
  handling untrusted data without an existing validation boundary should use
  `safe_binding_from_params/2`. For the equivalent validated request,
  `binding_hash(binding_from_params(params, subject)) ==
  binding_hash(binding(request, subject))`.
  """
  @spec binding_from_params(map(), String.t()) :: binding()
  def binding_from_params(params, subject) when is_map(params) and is_binary(subject) do
    case safe_binding_from_params(params, subject) do
      {:ok, binding} -> binding
      {:error, :invalid_binding} -> raise ArgumentError, "invalid consent binding parameters"
    end
  end

  @doc """
  Safely builds a consent binding from untrusted raw parameters.

  Returns `{:error, :invalid_binding}` for an invalid required scalar, set,
  claims object, DPoP thumbprint value, or nested JSON value.
  """
  @spec safe_binding_from_params(map(), String.t()) ::
          {:ok, binding()} | {:error, :invalid_binding}
  def safe_binding_from_params(params, subject) when is_map(params) and is_binary(subject) do
    with :ok <- validate_required_string(subject),
         {:ok, source} <- safe_params_binding_source(params),
         {:ok, binding} <- validate_binding(canonical_binding(source, subject)) do
      {:ok, binding}
    else
      _ -> {:error, :invalid_binding}
    end
  end

  def safe_binding_from_params(_params, _subject), do: {:error, :invalid_binding}

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
        canonical = Enum.map(@canonical_fields, &encode_value(Map.fetch!(normalized, &1)))
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

  defp normalize_binding_value(field, nil) when field in [:scope, :resource], do: []

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
