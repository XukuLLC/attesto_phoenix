defmodule AttestoPhoenix.ConsentGrantStore do
  @moduledoc """
  Behaviour for single-use, request-bound consent grants (RFC 6749 §4.1.1).

  A consent grant is the authorization-server correctness primitive that ties a
  single consent decision to the *exact* authorization request the resource
  owner saw, so that one Authorize click cannot approve a different client,
  redirect URI, scope set, PKCE challenge, or PKCE method than the one
  displayed. It is
  deliberately the primitive only: this library renders no consent screen,
  decides no "when is consent required" policy, and chooses no client-display
  wording. Those are host concerns. The host's consent UI mints a grant when the
  user authorizes; the host's `:consent` callback (`AttestoPhoenix.ConsentPolicy`)
  consumes it before a code is issued.

  The grant is bound to a hash over the canonical request fields
  (`subject + client_id + redirect_uri + sorted scope set + code_challenge +
  code_challenge_method`, built by `AttestoPhoenix.ConsentGrant.binding/2`).
  `mint/2` records a fresh row keyed on an unguessable token; `consume/2`
  atomically claims it iff the recomputed binding matches and the grant is
  unexpired and unconsumed, so a token works exactly once for exactly the
  request it was granted for.

  ## Why server-side consumption is mandatory

  The attesto `:consent` callback runs on the original authorization-endpoint
  conn and its `{:consented, _}` return goes straight to code issuance, so any
  session mutation the host makes there is discarded. A sticky session flag
  could never be consumed; a grant row can. The single-use guarantee is enforced
  by the store (a single conditional `UPDATE`), not advisory, so two concurrent
  presentations of one token cannot both succeed.

  ## Callbacks

    * `mint/2` records a grant for a binding and returns its opaque token.
    * `consume/2` atomically consumes the grant for a token iff the live binding
      matches, returning `:ok` to the single winning caller and a precise
      `{:error, reason}` to every other (unknown token, binding mismatch,
      expired, already used).
  """

  alias AttestoPhoenix.ConsentGrant

  @typedoc """
  The opaque, unguessable token the consent screen carries forward to the
  authorization endpoint. Treated as a credential: never logged, never displayed.
  """
  @type token :: String.t()

  @typedoc """
  Why a `consume/2` lost. Every reason refuses consent (fail closed); the
  distinction is for the host's audit/telemetry, never for relaxing the refusal.

    * `:not_found` - no grant for the token (never minted, swept, or a typo).
    * `:binding_mismatch` - a grant exists but the live request differs from the
      one consented to (different client/redirect/scope/challenge/method): the
      precise attack this primitive defends against.
    * `:expired` - the grant existed but its TTL elapsed.
    * `:consumed` - the grant was already spent (single use; a replay).
  """
  @type consume_error :: :not_found | :binding_mismatch | :expired | :consumed

  @doc """
  Mint a single-use consent grant bound to `binding`, with a lifetime of
  `ttl_seconds`.

  Returns `{:ok, token}` with the opaque token the consent screen carries
  forward to the authorization endpoint, or `{:error, reason}` if the grant
  could not be persisted.
  """
  @callback mint(binding :: ConsentGrant.binding(), ttl_seconds :: pos_integer()) ::
              {:ok, token()} | {:error, term()}

  @doc """
  Atomically consume the grant for `token` iff it matches `binding`, is
  unconsumed, and is unexpired.

  Returns `:ok` to the single winning caller and `{:error, reason}` to every
  other. The consume is one conditional statement, so exactly one of any number
  of concurrent presentations of the same token succeeds.
  """
  @callback consume(token :: token() | nil, binding :: ConsentGrant.binding()) ::
              :ok | {:error, consume_error()}
end
