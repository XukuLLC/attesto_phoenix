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
    * `principal_kinds/0` (`:principal_kinds`)
    * `build_principal/3` (`:build_principal`)
    * `build_refresh_principal/2` (`:build_refresh_principal`)
    * `resolve_jwt_bearer_subject/1` (`:resolve_jwt_bearer_subject`, required only
      when the ID-JAG `jwt-bearer` grant is enabled)
  """

  @typedoc "The host's opaque principal/subject representation."
  @type principal :: term()

  @typedoc """
  Security context for a validated and atomically rotated refresh grant.

  `:scope` is the effective scope after token-endpoint policy. `:resource`,
  `:subject`, `:issuer`, authentication context, family identity, and
  `:session_id` come from the persisted grant rather than request parameters.
  `:client_id` is the client identity authenticated for this token request.
  """
  @type refresh_context :: %{
          required(:subject) => String.t(),
          required(:client_id) => String.t(),
          required(:issuer) => String.t(),
          required(:scope) => [String.t()],
          required(:resource) => [String.t()],
          required(:family_id) => String.t(),
          required(:generation) => non_neg_integer(),
          required(:acr) => String.t() | nil,
          required(:auth_time) => non_neg_integer() | nil,
          required(:session_id) => String.t() | nil
        }

  @doc """
  Resolve the subject/principal by its identifier during protected-resource
  authentication. Returns `{:ok, principal}` or `{:error, :not_found}`.
  """
  @callback load_principal(subject_id :: String.t()) ::
              {:ok, principal()} | {:error, :not_found}

  @doc """
  Return the non-empty principal-kind catalog passed to `Attesto.Config`.

  Each kind gives a token subject class its claim value and unambiguous `sub`
  prefix. This is host identity policy; the library cannot infer it from an
  Ecto schema or client record.
  """
  @callback principal_kinds() :: [Attesto.PrincipalKind.t(), ...]

  @doc """
  Build the principal map passed to `Attesto.Token.mint/3` for an
  authorization-code or `client_credentials` grant. Receives the resolved
  client, the subject identifier, and the granted scope. The returned map
  carries at least `:sub` and any host-owned claims.

  The returned `:sub` MUST be namespaced with the matching
  `Attesto.PrincipalKind` `sub_prefix` - `Attesto.Token` rejects an unprefixed
  subject at mint time (`:invalid_sub`). For the `client_credentials` grant
  (RFC 6749 §4.4) the subject handed in is the OAuth `client_id`, and Dynamic
  Client Registration (RFC 7591 §3.2.1) issues that id *unprefixed*: this
  callback is the sole place the kind prefix is applied. The prefix is mint-time
  defense-in-depth (a token's `sub` stays unambiguous across principal kinds),
  so namespacing here is mandatory rather than cosmetic.
  """
  @callback build_principal(
              client :: term(),
              subject :: String.t(),
              scope :: [String.t()]
            ) :: map()

  @doc """
  Revalidate host-owned principal and session state for a refresh grant, and
  build the principal map used without a second `build_principal/3` lookup.
  Protocol-owned claims and the authenticated `client_id` are reconciled before
  the map is passed to `Attesto.Token.mint/3`.

  This callback runs after the refresh credential, authenticated client,
  sender constraint, scope, resource, and rotation state have been validated
  atomically, but before an access token is minted or the successor refresh
  token is returned. Return a principal map to allow issuance. Return
  `{:error, :invalid_grant}` when the subject is locked or deactivated, its
  session is terminated, or its persisted tenant context is no longer valid.
  A denial revokes the entire refresh family and produces a generic OAuth
  `invalid_grant` response.

  The callback receives only stable grant identifiers and authorization
  context; it never receives either plaintext refresh token. It is optional so
  existing installations retain their current `build_principal/3` behavior.
  Immediate lost-response retries can invoke it again for the same family and
  generation, so keep it side-effect-free or idempotent.
  """
  @callback build_refresh_principal(
              client :: term(),
              context :: refresh_context()
            ) :: map() | {:error, :invalid_grant}

  @doc """
  Map a validated Identity Assertion JWT Authorization Grant (ID-JAG) to a local
  subject for the `urn:ietf:params:oauth:grant-type:jwt-bearer` grant
  (`draft-ietf-oauth-identity-assertion-authz-grant-04`).

  Receives the string-keyed, already-verified assertion claims after sender
  binding, resource, scope, and host policy have passed. The signature, trusted
  `iss`, `aud`, `client_id` binding, and `exp`/`iat` have all been checked; the
  atomic `jti` replay claim follows this callback because the replay-store seam
  has no non-consuming reservation operation. A validly signed replay can
  therefore reach this callback before rejection, so callbacks with side
  effects must be idempotent. The host maps the asserted external identity - typically
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

  @optional_callbacks principal_kinds: 0,
                      build_principal: 3,
                      build_refresh_principal: 2,
                      resolve_jwt_bearer_subject: 1
end
