defmodule AttestoPhoenix.PrincipalStore do
  @moduledoc """
  The host-owned subject/principal contract.

  The library resolves the subject during protected-resource authentication
  and builds the principal map minted into issued tokens, but the subject
  source (the host's user store) and the claim shaping are host policy. A host
  implements this behaviour and wires each callback into
  `AttestoPhoenix.Config`; this module is the contract those keys install and
  the recommended production shape.

  Each `@callback` corresponds to the identically named `AttestoPhoenix.Config`
  key:

    * `load_principal/1` (`:load_principal`, required)
    * `build_principal/3` (`:build_principal`)
    * `resolve_jwt_bearer_subject/1` (`:resolve_jwt_bearer_subject`, required only
      when the ID-JAG `jwt-bearer` grant is enabled)
  """

  @typedoc "The host's opaque principal/subject representation."
  @type principal :: term()

  @doc """
  Resolve the subject/principal by its identifier during protected-resource
  authentication. Returns `{:ok, principal}` or `{:error, :not_found}`.
  """
  @callback load_principal(subject_id :: String.t()) ::
              {:ok, principal()} | {:error, :not_found}

  @doc """
  Build the principal map passed to `Attesto.Token.mint/3` for an
  authorization-code grant. Receives the resolved client, the subject
  identifier, and the granted scope. The returned map carries at least
  `:subject` and any host-owned claims.
  """
  @callback build_principal(
              client :: term(),
              subject :: String.t(),
              scope :: [String.t()]
            ) :: map()

  @doc """
  Map a validated Identity Assertion JWT Authorization Grant (ID-JAG) to a local
  subject for the `urn:ietf:params:oauth:grant-type:jwt-bearer` grant
  (`draft-ietf-oauth-identity-assertion-authz-grant-04`).

  Receives the string-keyed, already-verified assertion claims (the signature,
  trusted `iss`, `aud`, `client_id` binding, `exp`/`iat`, and `jti` replay have
  all been checked). The host maps the asserted external identity - typically
  `claims["sub"]` (unique when scoped with `claims["iss"]`) and/or
  `claims["email"]` - to the local subject the issued token is minted for, the
  same subject string `build_principal/3` then receives.

  Returns `{:ok, subject}` (or a bare `subject` string) to authorize, or
  `{:error, reason}` (or any non-subject value) to deny - a deny becomes
  RFC 6749 §5.2 `invalid_grant`. Required only when the `jwt-bearer` grant is
  enabled (`AttestoPhoenix.Config` enforces this at boot).
  """
  @callback resolve_jwt_bearer_subject(claims :: map()) ::
              {:ok, subject :: String.t()} | String.t() | {:error, term()}

  @optional_callbacks build_principal: 3, resolve_jwt_bearer_subject: 1
end
