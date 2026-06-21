defmodule AttestoPhoenix.ConsentGrant do
  @moduledoc """
  The request binding a single-use consent grant is tied to, and the canonical
  hash over it (RFC 6749 §4.1.1).

  A consent grant must approve *exactly* the authorization request the resource
  owner saw — the same client, redirect URI, scope set, PKCE challenge, and
  PKCE method — and nothing else. This module builds that binding from an
  `%Attesto.AuthorizationRequest{}` (the validated front-channel request) plus
  the authenticated subject, and hashes it canonically so the grant and consume
  sides agree on one digest.

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
    %{
      subject: subject,
      client_id: request.client_id,
      redirect_uri: request.redirect_uri,
      scope: List.wrap(request.scope),
      code_challenge: request.code_challenge,
      code_challenge_method: request.code_challenge_method
    }
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
    canonical =
      [
        Map.fetch!(binding, :subject),
        Map.fetch!(binding, :client_id),
        Map.fetch!(binding, :redirect_uri),
        binding |> Map.get(:scope) |> List.wrap() |> Enum.sort() |> Enum.join(" "),
        Map.get(binding, :code_challenge) || "",
        Map.get(binding, :code_challenge_method) || ""
      ]
      |> Enum.map_join("\n", &to_string/1)

    :sha256 |> :crypto.hash(canonical) |> Base.url_encode64(padding: false)
  end
end
