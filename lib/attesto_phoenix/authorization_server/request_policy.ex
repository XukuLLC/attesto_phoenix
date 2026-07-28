defmodule AttestoPhoenix.AuthorizationServer.RequestPolicy do
  @moduledoc """
  Conn-free resolution of the per-request authorization-request validation
  policy shared by the authorization endpoint and the PAR endpoint.

  Both endpoints validate the same authorization request the same way (RFC 9126
  §2.1: "validate the pushed request as it would an authorization request sent
  to the authorization endpoint"), so the policy inputs `Attesto.AuthorizationRequest.validate/2`
  needs - the client's registered redirect URIs (RFC 6749 §3.1.2.3), how they
  are matched (RFC 8252 §7.3), whether PKCE is required (RFC 9700 §2.1.1), and
  whether `nonce` is required (OIDC Core §3.1.2.1) - are resolved here once,
  from `%AttestoPhoenix.Config{}` and the opaque host client, rather than
  duplicated per endpoint. This module reads only data: it touches no `conn` and
  carries no policy of its own beyond the fail-closed defaults documented on
  each function.
  """

  alias Attesto.AuthorizationRequest
  alias Attesto.RedirectURI
  alias AttestoPhoenix.AuthorizationServer.SenderConstraint
  alias AttestoPhoenix.{Callback, ClientIdMetadata, Config}

  @doc """
  Validate `params` as an authorization request for `client`, resolving the
  redirect-URI/PKCE/nonce policy from `config` and delegating to
  `Attesto.AuthorizationRequest.validate/2`.

  This is the shared entry point both the authorization endpoint and the PAR
  endpoint use so a request is validated identically wherever it arrives
  (RFC 9126 §2.1). Pass `extra_opts` to thread request-object verification
  inputs (`:request_object_jwks`, `:request_object_audience`,
  `:request_object_policy`) when the `params` still carry an unverified signed
  `request` object; omit them when the object has already been verified and
  merged.
  """
  @spec validate(Config.t(), term(), map(), keyword()) ::
          {:ok, AuthorizationRequest.t()} | {:error, AuthorizationRequest.error()}
  def validate(config, client, params, extra_opts \\ []) do
    opts =
      [
        registered_redirect_uris: registered_redirect_uris(config, client),
        redirect_uri_matching: redirect_uri_matching(config, client),
        require_pkce: require_pkce?(config, client),
        require_nonce: require_nonce?(config)
      ] ++ extra_opts

    AuthorizationRequest.validate(params, opts)
  end

  @doc """
  The client's registered redirect URIs (RFC 6749 §3.1.2.3).

  For a CIMD client (`{:cimd, metadata}`,
  `draft-ietf-oauth-client-id-metadata-document-01`) the document *is* the
  registration, so the registered set is the document's own `redirect_uris`
  (RFC 9700) and the host's per-client callback is never consulted. For a
  registered client the set is resolved through the host's
  `:client_redirect_uris` callback; an absent callback or a non-list return
  resolves to `[]`, which rejects every request with an unregistered redirect
  URI (fail closed).
  """
  @spec registered_redirect_uris(Config.t(), term()) :: [String.t()]
  def registered_redirect_uris(_config, {:cimd, metadata}), do: ClientIdMetadata.redirect_uris(metadata)

  def registered_redirect_uris(config, client) do
    case Callback.invoke(Config.client_redirect_uris_fun(config), [client], []) do
      uris when is_list(uris) -> uris
      _ -> []
    end
  end

  @doc """
  How the request `redirect_uri` is matched against the registered set
  (RFC 6749 §3.1.2.3, RFC 8252 §7.3).

  `:exact` - the RFC 6749 §3.1.2.3 simple string comparison - unless the host
  marked this client native via `:client_native?`, in which case it gets
  `:exact_allow_loopback_port` and its `http://127.0.0.1/...` /
  `http://[::1]/...` redirect URI matches on any port (see `Attesto.RedirectURI`
  for exactly how narrow that exception is).

  Marking the client native is the whole decision. RFC 8252 §7.3 says the
  authorization server MUST allow any port for a loopback redirect URI, so
  requiring a second server-wide opt-in on top would mean violating that MUST
  for a client the host had already declared to be an installed app.

  That is the entire argument, deliberately. A tempting second one - that §8.1
  and §8.4 already key on the mark alone, so §7.3 may too - does not hold up:
  those are RESTRICTIONS and this is a RELAXATION, and the two have very
  different blast radii when the mark is wrong. A mistaken restriction denies a
  client service loudly; a mistaken relaxation widens a security check
  silently. Which is why `:client_native?` is documented as an opt-in that a
  host must not export by accident.

  The default-off guarantee comes from `:client_native?` itself defaulting to
  `false`, not from a separate flag: a deployment that classifies no clients has
  no native clients and so sees exact matching everywhere, unchanged.

  `native_apps: [loopback_redirect: false]` remains available as a server-wide
  opt-out for a deployment that must forbid the exception outright (an operator
  kill switch, or one certifying against a profile that mandates exact
  matching). It defaults to `true`; it is an escape hatch, not a gate.

  A CIMD client is never native - its `client_id` is an `https` URL and its
  `redirect_uris` come from the document, which the authorization endpoint
  additionally holds to the same origin.
  """
  @spec redirect_uri_matching(Config.t(), term()) :: RedirectURI.matching()
  def redirect_uri_matching(_config, {:cimd, _metadata}), do: :exact

  def redirect_uri_matching(config, client) do
    if client_native?(config, client) and Config.native_app_loopback_redirect?(config) do
      :exact_allow_loopback_port
    else
      :exact
    end
  end

  @doc """
  Whether PKCE is required for this client (RFC 7636 §4.3 / RFC 9700 §2.1.1,
  RFC 8252 §8.1).

  A public client MUST use PKCE, so `client_public?/2` forces it regardless of
  config. A sender-constrained client (DPoP or mTLS) is a FAPI 2.0 client, and
  FAPI 2.0 Security Profile §5.3.1.2 / RFC 9700 §2.1.1 require PKCE for it even
  though it authenticates confidentially - so `client_requires_dpop?/2` and
  `client_requires_mtls?/2` force it too. RFC 8252 §8.1 requires it for a native
  app, so `client_native?/2` forces it as well; the requirement is stated for
  public native clients, and applying it to any native client is strictly
  safer - a native app that claims to be confidential cannot actually hold a
  secret (§8.4). For any other confidential client the global `:require_pkce`
  flag applies (default `true`). Fail closed: absent the host's deliberate
  opt-out, PKCE is required.

  RFC 8252 §8.1 also requires `S256` rather than `plain`. That needs no policy
  here: `Attesto.AuthorizationRequest` rejects `code_challenge_method=plain`
  and any non-`S256` method unconditionally, for every client.
  """
  @spec require_pkce?(Config.t(), term()) :: boolean()
  # A CIMD client is public (`none` + PKCE) or `private_key_jwt`; PKCE is
  # mandatory for it regardless of the host's `:require_pkce` flag, and the host
  # sender-constraint callbacks do not apply to the document.
  def require_pkce?(_config, {:cimd, _metadata}), do: true

  def require_pkce?(config, client) do
    client_public?(config, client) or
      client_native?(config, client) or
      SenderConstraint.client_requires_dpop?(config, client) or
      SenderConstraint.client_requires_mtls?(config, client) or
      Callback.config_flag(config, :require_pkce)
  end

  @doc """
  Classify the client as an installed native application (RFC 8252 / BCP 212)
  via the host's `:client_native?` callback.

  Absent the callback, the client is NOT native. Unlike `client_public?/2` this
  cannot fail closed by defaulting to `true`: "native" gates one relaxation
  (§7.3 loopback ports) alongside its restrictions, and a host that has not
  classified its clients must get the unmodified RFC 6749 behavior.
  """
  @spec client_native?(Config.t(), term()) :: boolean()
  # A CIMD client is identified by an `https` URL that resolves to a document
  # served over the network; it is not an installed native app.
  def client_native?(_config, {:cimd, _metadata}), do: false

  def client_native?(config, client) do
    Callback.invoke(Config.client_native_fun(config), [client], false) == true
  end

  @doc """
  Classify the client as public via the host's `:client_public?` callback.

  Absent the callback, fail closed by treating the client as public, so PKCE
  stays required (a confidential exemption demands a deliberate host
  classification).
  """
  @spec client_public?(Config.t(), term()) :: boolean()
  # A CIMD client holds no symmetric secret (document validation strips it), so
  # it is public by construction.
  def client_public?(_config, {:cimd, _metadata}), do: true

  def client_public?(config, client) do
    case Config.client_public_fun(config) do
      nil -> true
      callback -> Callback.invoke(callback, [client]) == true
    end
  end

  @doc """
  The host's OP nonce policy flag (OIDC Core §3.1.2.1).

  Returns the raw `:require_nonce` configuration. The OIDC openid-scope gate is
  NOT applied here: it must run on the EFFECTIVE request (after any signed
  `request` object is merged), which only `Attesto.AuthorizationRequest.validate/2`
  sees. Applying the gate on the raw outer params here would let a direct JAR
  carrying `scope=openid` only inside the signed object bypass the requirement.
  """
  @spec require_nonce?(Config.t()) :: boolean()
  def require_nonce?(config) do
    Callback.config_flag(config, :require_nonce)
  end
end
