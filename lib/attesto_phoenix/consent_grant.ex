defmodule AttestoPhoenix.ConsentGrant do
  @moduledoc """
  The request binding a single-use consent grant is tied to, and the canonical
  hash over it (RFC 6749 §4.1.1).

  A consent grant must approve *exactly* the authorization request the resource
  owner saw — the same client, redirect URI, scope set, PKCE challenge, and
  PKCE method — and nothing else. This module builds that binding from either
  raw authorization params (`binding_from_params/2`, used by the consent-screen
  mint action) or from a validated `%Attesto.AuthorizationRequest{}` (`binding/2`,
  used by the live `/authorize` consume side). Both builders feed the same
  canonical field list and therefore yield the same `binding_hash/1` for the
  equivalent request.

  ## Canonical binding

  The binding is the tuple
  `(subject, client_id, redirect_uri, scope, code_challenge, code_challenge_method)`:

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
    * `code_challenge` - the PKCE challenge (RFC 7636 §4.3), or the empty string
      when the request carries none. Binding it stops a consent from being
      replayed against a request that swapped in a different PKCE challenge.
    * `code_challenge_method` - the PKCE method (`S256`, RFC 7636 §4.3), or the
      empty string when the request carries no PKCE challenge. Binding it stops
      a consent granted for an `S256` request from being reused for a `plain`
      request with the same challenge value.

  `binding_hash/1` is SHA-256 over the newline-joined canonical fields,
  URL-base64 encoded (no padding). It is stable across the mint and consume
  sides because both derive it from this one function.
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
          code_challenge: String.t() | nil,
          code_challenge_method: String.t() | nil
        }

  @binding_fields ~w(client_id redirect_uri scope code_challenge code_challenge_method)a
  @canonical_fields [:subject] ++ @binding_fields
  @required_hash_fields ~w(subject client_id redirect_uri)a

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

  `params` is read by string keys (`"client_id"`, `"redirect_uri"`, `"scope"`,
  `"code_challenge"`, and `"code_challenge_method"`). Missing `"scope"` becomes
  `[]`; a present scope string is split on spaces; missing PKCE fields become
  `nil`. Unknown params are ignored. For the equivalent validated request,
  `binding_hash(binding_from_params(params, subject)) ==
  binding_hash(binding(request, subject))`.
  """
  @spec binding_from_params(map(), String.t()) :: binding()
  def binding_from_params(params, subject) when is_map(params) and is_binary(subject) do
    params
    |> params_binding_source()
    |> canonical_binding(subject)
  end

  @doc """
  The canonical binding hash for `binding`.

  SHA-256 over the newline-joined canonical fields, URL-base64 encoded without
  padding. The scope set is order-normalized (sorted then space-joined) so scope
  order is not significant (RFC 6749 §3.3); a missing `code_challenge` and
  `code_challenge_method` each hash as the empty string. Identical on the mint
  and consume sides for the same request.
  """
  @spec binding_hash(binding()) :: String.t()
  def binding_hash(%{} = binding) do
    canonical = Enum.map_join(@canonical_fields, "\n", &canonical_hash_value(binding, &1))

    :sha256 |> :crypto.hash(canonical) |> Base.url_encode64(padding: false)
  end

  defp params_binding_source(params) do
    Map.new(@binding_fields, fn field ->
      {field, Map.get(params, Atom.to_string(field))}
    end)
  end

  defp canonical_binding(%{} = source, subject) do
    source
    |> Map.take(@binding_fields)
    |> Map.new(fn {field, value} -> {field, normalize_binding_value(field, value)} end)
    |> Map.put(:subject, subject)
  end

  defp normalize_binding_value(:scope, nil), do: []
  defp normalize_binding_value(:scope, scope) when is_binary(scope), do: String.split(scope, " ", trim: true)
  defp normalize_binding_value(:scope, scope), do: List.wrap(scope)

  defp normalize_binding_value(_field, value), do: value

  defp canonical_hash_value(binding, :scope) do
    binding |> Map.get(:scope) |> List.wrap() |> Enum.sort() |> Enum.join(" ")
  end

  defp canonical_hash_value(binding, field) when field in @required_hash_fields do
    binding |> Map.fetch!(field) |> to_string()
  end

  defp canonical_hash_value(binding, field) do
    binding |> Map.get(field) || ""
  end
end
