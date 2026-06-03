defmodule AttestoPhoenix.ClaimsProvider do
  @moduledoc """
  The host-owned identity-claims contract (OpenID Connect Core §5).

  The library knows no user store: the identity claims an ID Token (OpenID
  Connect Core §3.1.3.6) and the UserInfo endpoint (OpenID Connect Core §5.3)
  carry are the host's to source. This behaviour is the home for that claims
  concern: it pairs the UserInfo claim source with the principal builder that
  shapes the claims minted into an access token, so a host can install a single
  module that owns "what claims this subject has". The library owns only the
  scope-to-claim shaping (OpenID Connect Core §5.4) and the guarantee that `sub`
  is always the verified token subject (OpenID Connect Core §5.3.2).

  A host implements this behaviour and wires each callback into
  `AttestoPhoenix.Config`; this module is the contract those keys install and
  the recommended production shape. Wiring is unchanged from passing the
  callbacks individually (an anonymous function, a `{module, function}` pair, or
  a `{module, function, extra_args}` triple).

  Each `@callback` corresponds to the identically named `AttestoPhoenix.Config`
  key:

    * `build_userinfo_claims/3` (`:build_userinfo_claims`)
    * `build_principal/3` (`:build_principal`)

  The `build_principal/3` callback is shared with `AttestoPhoenix.PrincipalStore`
  (it builds the principal the authorization-code grant mints a token for); it
  is restated here so a host can install its claim source and its principal
  builder behind one module.
  """

  @typedoc "The host's opaque client representation (e.g. an Ecto struct)."
  @type client :: term()

  @doc """
  Produce the claim values the UserInfo endpoint (OpenID Connect Core §5.3)
  returns for the authenticated subject.

  Receives the subject identifier (`sub`), the list of scopes on the access
  token, and the per-claim request map from the OpenID Connect `claims`
  parameter (`%{}` when none). The host owns the claim source; the library owns
  the scope-to-claim shaping (OpenID Connect Core §5.4) and forces `sub` to the
  verified token subject (OpenID Connect Core §5.3.2). Returns a map of claim
  values.
  """
  @callback build_userinfo_claims(
              subject :: String.t(),
              granted_scopes :: [String.t()],
              requested_claims :: map()
            ) :: map()

  @doc """
  Build the principal map passed to `Attesto.Token.mint/3` for an
  authorization-code grant. Receives the resolved client, the subject
  identifier, and the granted scope. The returned map carries at least
  `:subject` and any host-owned claims.

  Shared with `AttestoPhoenix.PrincipalStore.build_principal/3`.
  """
  @callback build_principal(
              client(),
              subject :: String.t(),
              scope :: [String.t()]
            ) :: map()

  @optional_callbacks build_userinfo_claims: 3, build_principal: 3
end
