defmodule AttestoPhoenix.ClientStore do
  @moduledoc """
  The host-owned OAuth client registry contract (RFC 6749 §2 / §3.1.2).

  The library never owns the client registry: it resolves a client from its
  identifier, verifies its secret in constant time, and reads the per-client
  attributes the authorization, token, PAR, and revocation endpoints need. A
  host implements this behaviour and wires each callback into
  `AttestoPhoenix.Config` as an anonymous function, a `{module, function}`
  pair, or a `{module, function, extra_args}` triple. This module is the
  contract those Config keys install; it is the recommended production shape
  but the wiring is unchanged from passing the callbacks individually.

  Each `@callback` corresponds to the identically named `AttestoPhoenix.Config`
  key:

    * `load_client/1` (`:load_client`, required)
    * `verify_client_secret/2` (`:verify_client_secret`, required)
    * `client_id/1` (`:client_id`)
    * `client_jwks/1` (`:client_jwks`)
    * `client_mtls_metadata/1` (`:client_mtls_metadata`)
    * `client_redirect_uris/1` (`:client_redirect_uris`)
    * `client_public?/1` (`:client_public?`)
    * `client_native?/1` (`:client_native?`)
    * `client_requires_mtls?/1` (`:client_requires_mtls?`)
    * `client_requires_dpop?/1` (`:client_requires_dpop?`)
    * `client_grant_types/1` (`:client_grant_types`)

  The `client` term is opaque to the library: whatever
  `load_client/1` returns is threaded back into the other callbacks unchanged.
  """

  @typedoc "The host's opaque client representation (e.g. an Ecto struct)."
  @type client :: term()

  @doc """
  Resolve an OAuth client by its identifier (RFC 6749 §2.2).

  Returns `{:ok, client}` for a usable client, `{:error, :not_found}` when no
  such client exists, or `{:error, :revoked}` when the client is known but has
  been revoked. The host owns the registry and the revocation policy.
  """
  @callback load_client(client_id :: String.t()) ::
              {:ok, client()} | {:error, :not_found} | {:error, :revoked}

  @doc """
  Constant-time verification of a presented client secret (RFC 6749 §2.3.1).

  Returns `true` iff `presented_secret` matches the client's stored secret.
  The host owns secret hashing; use `Attesto.SecureCompare` to avoid timing
  leaks.
  """
  @callback verify_client_secret(client(), presented_secret :: String.t()) :: boolean()

  @doc """
  The client's OAuth identifier (RFC 6749 §2.2), extracted from the host's
  client representation.
  """
  @callback client_id(client()) :: String.t()

  @doc """
  The client's trusted public JWK Set for `private_key_jwt` client
  authentication (RFC 7523 / OpenID Connect Core §9). Returns `nil` for a
  client that does not authenticate with a signed assertion.
  """
  @callback client_jwks(client()) :: map() | nil

  @doc """
  The client's RFC 8705 mutual-TLS authentication registration metadata.

  The map carries `token_endpoint_auth_method` set to `tls_client_auth` or
  `self_signed_tls_client_auth`. PKI clients also carry exactly one of the five
  `tls_client_auth_*` identity fields from RFC 8705 §2.1.2. Self-signed clients
  resolve their registered certificates through `client_jwks/1`.

  Return `nil` only when the client has no mTLS authentication registration.
  Storage and lookup failures must return `{:error, reason}`; authentication
  fails closed for those results and for malformed callback output.
  """
  @callback client_mtls_metadata(client()) :: map() | {:ok, map()} | nil | {:error, term()}

  @doc """
  The client's registered redirect URIs (RFC 6749 §3.1.2.2). The authorization
  endpoint exact-matches the request `redirect_uri` against this set
  (RFC 6749 §3.1.2.3); a client exposing none rejects every authorization
  request (fail closed).
  """
  @callback client_redirect_uris(client()) :: [String.t()]

  @doc """
  Whether the client may authenticate without a secret and rely on PKCE
  (RFC 6749 §2.1 / RFC 7636).
  """
  @callback client_public?(client()) :: boolean()

  @doc """
  Whether the client is an installed native application (RFC 8252 / BCP 212).

  A native app runs on the end user's own device — an iOS/Android app or a
  desktop binary — rather than on a server the operator controls. That single
  fact drives the RFC 8252 authorization-server obligations: its loopback
  redirect URI may vary in port (§7.3), PKCE is required for it (§8.1), and it
  must authenticate at the token endpoint with `none` because it cannot hold a
  secret confidentially (§8.4).

  Returns `false` when the callback is not exposed, so a host that has not
  classified its clients gets no RFC 8252 behavior at all.

  A host that accepts dynamic registrations can answer this from the client's
  own declaration rather than classifying by hand: the registration endpoint
  validates the OpenID Connect Registration §2 `application_type` member
  (`"web"` | `"native"`, defaulting to `"web"`) and passes it to
  `:register_client` in the client metadata, so persisting it makes
  `client_native?/1` a lookup:

      def client_native?(client), do: client.application_type == "native"

  > #### Exporting this name means opting in {: .warning}
  >
  > This callback is resolved automatically from an installed `:client_store`
  > module. If yours already exports `client_native?/1` meaning something else —
  > "native to our platform", "first-party" — those clients get the RFC 8252
  > profile, **including the §7.3 redirect-URI relaxation**. Rename it, or set
  > the flat `:client_native?` config key to a function returning `false`.

  Marking a client native is the whole decision — the RFC 8252 profile then
  applies to that client — with two consequences worth stating outright:

    * It enables the §7.3 loopback redirect exception for that client, so its
      `http://127.0.0.1/...` / `http://[::1]/...` redirect URI matches on any
      port. §7.3 states that as a MUST, which is why it needs no further
      opt-in; `native_apps: [loopback_redirect: false]` can forbid it
      server-wide if a deployment must.
    * Where no `client_public?/1` callback is configured at all, a native client
      counts as public — which both refuses its secret (§8.4) and admits it on
      the secretless `none` path. That is the §8.1/§8.4 posture for a native
      app, but it does mean marking a client native can open `none` for it in a
      deployment that classifies nothing. A host that wants the per-instance
      credential carve-out must say so with an explicit `client_public?/1`
      returning `false`.

  Note that a native public client cannot use the Pushed Authorization Request
  endpoint: PAR refuses secretless clients, and §8.4 refuses this one a secret.
  A deployment that sets `require_pushed_authorization_requests: true` therefore
  cannot also serve native public clients.
  """
  @callback client_native?(client()) :: boolean()

  @doc """
  Whether the client requires mTLS-bound token issuance (RFC 8705).
  """
  @callback client_requires_mtls?(client()) :: boolean()

  @doc """
  Whether the client requires DPoP-bound token issuance (RFC 9449).
  """
  @callback client_requires_dpop?(client()) :: boolean()

  @doc """
  The grant types registered for this client (RFC 7591 §2).

  When the host exposes this callback, the token endpoint rejects a requested
  `grant_type` not in the returned list before dispatching to the grant
  implementation. Return `nil` only when the host has no per-client grant
  registry and wants the package's legacy configured-supported-grants behavior.
  """
  @callback client_grant_types(client()) :: [String.t()] | nil

  @doc """
  The client's registered `post_logout_redirect_uris` (OpenID Connect
  RP-Initiated Logout 1.0 §2). The end-session endpoint exact-matches the
  request `post_logout_redirect_uri` against this set; a client exposing none
  has no validated return URI (fail closed — the OP renders its own page).
  """
  @callback client_post_logout_redirect_uris(client()) :: [String.t()]

  @doc """
  The client's registered `backchannel_logout_uri` (OpenID Connect Back-Channel
  Logout 1.0 §2.2), or `nil` when the client is not back-channel-logout capable.
  When present, the OP records a logout session at ID-Token mint and POSTs a
  `logout_token` here when the session ends.
  """
  @callback client_backchannel_logout_uri(client()) :: String.t() | nil

  @doc """
  Whether this client's `logout_token` MUST carry a `sid` claim
  (`backchannel_logout_session_required`, Back-Channel Logout 1.0 §2.2).
  Defaults to `false` when the callback is not exposed.
  """
  @callback client_backchannel_logout_session_required(client()) :: boolean()

  @doc """
  The client's registered `frontchannel_logout_uri` (OpenID Connect
  Front-Channel Logout 1.0 §2), or `nil` when the client is not
  front-channel-logout capable. When present, the OP records a logout session
  at ID-Token mint and renders the URI in an iframe on the end-session logout
  page when the session ends.
  """
  @callback client_frontchannel_logout_uri(client()) :: String.t() | nil

  @doc """
  Whether this client's rendered `frontchannel_logout_uri` must carry `iss` and
  `sid` query parameters (`frontchannel_logout_session_required`, Front-Channel
  Logout 1.0 §2). Defaults to `false` when the callback is not exposed.
  """
  @callback client_frontchannel_logout_session_required(client()) :: boolean()

  @doc """
  The client's registered OpenID Connect CIBA metadata (CIBA Core §4), as a map
  with `:token_delivery_mode` (`:poll` | `:ping` | `:push`),
  `:client_notification_endpoint` (the ping-mode
  `backchannel_client_notification_endpoint`), `:request_signing_alg` (the
  registered `backchannel_authentication_request_signing_alg`), and
  `:user_code_parameter` (the `backchannel_user_code_parameter` boolean). A
  client not registered for CIBA returns `%{}` (or `nil`), which the backchannel
  authentication endpoint treats as `unauthorized_client`.
  """
  @callback client_ciba_registration(client()) :: map() | nil

  @optional_callbacks client_id: 1,
                      client_jwks: 1,
                      client_mtls_metadata: 1,
                      client_redirect_uris: 1,
                      client_public?: 1,
                      client_native?: 1,
                      client_requires_mtls?: 1,
                      client_requires_dpop?: 1,
                      client_grant_types: 1,
                      client_post_logout_redirect_uris: 1,
                      client_backchannel_logout_uri: 1,
                      client_backchannel_logout_session_required: 1,
                      client_frontchannel_logout_uri: 1,
                      client_frontchannel_logout_session_required: 1,
                      client_ciba_registration: 1
end
