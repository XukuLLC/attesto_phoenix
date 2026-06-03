defmodule AttestoPhoenix.ClaimsProvider do
  @moduledoc """
  The host-owned UserInfo claim source (OpenID Connect Core §5).

  The library knows no user store: the identity claims the UserInfo endpoint
  (OpenID Connect Core §5.3) returns are the host's to source. This behaviour is
  the home for that single concern — sourcing claim *values* for a subject. It
  deliberately does NOT own principal loading: building the principal an
  authorization-code grant mints a token for is a separate responsibility that
  lives on `AttestoPhoenix.PrincipalStore` (`build_principal/3`). Keeping claim
  sourcing and principal loading in distinct behaviours means a host installs
  each capability where it belongs rather than behind one overloaded module.

  A host implements this behaviour and wires its callback into
  `AttestoPhoenix.Config` under `:claims_provider` (or passes the flat
  `:build_userinfo_claims` callback). Wiring is unchanged from passing the
  callback individually (an anonymous function, a `{module, function}` pair, or
  a `{module, function, extra_args}` triple).

  The `@callback` corresponds to the identically named `AttestoPhoenix.Config`
  key:

    * `build_userinfo_claims/3` (`:build_userinfo_claims`)
  """

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

  # Optional on the behaviour: a host that installs `:claims_provider` but omits
  # this callback resolves to nil and the UserInfo claim source fails closed at
  # use, matching the boot-validation policy (`claims_provider` has no required
  # callbacks). An installed module need not export it to compile cleanly.
  @optional_callbacks build_userinfo_claims: 3
end
