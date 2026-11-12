defmodule AttestoPhoenix.RegistrationStore do
  @moduledoc """
  The host-owned dynamic client registration persistence contract
  (RFC 7591 §3 / RFC 7592 §2).

  The registration controller owns credential generation and protocol framing,
  but the client registry is host-owned: it persists a newly registered
  client, deletes one during registration management cleanup, and exposes the
  stored registration access-token hash for management requests. A host
  implements this behaviour and wires each callback into
  `AttestoPhoenix.Config`; this module is the contract those keys install and
  the recommended production shape.

  Each `@callback` corresponds to the identically named `AttestoPhoenix.Config`
  key:

    * `register_client/1` (`:register_client`, required when
      `:registration_enabled`)
    * `unregister_client/1` (`:unregister_client`)
    * `client_registration_access_token_hash/1`
      (`:client_registration_access_token_hash`)
    * `client_registration_metadata/1` (`:client_registration_metadata`)
    * `update_client/2` (`:update_client`)
  """

  @typedoc "The host's opaque client representation."
  @type client :: term()

  @doc """
  Persist a dynamically registered client (RFC 7591 §3.2.1).

  Receives the validated, issuance-ready attributes (the at-rest secret hash,
  never the plaintext). Returns `{:ok, client}` or `{:error, reason}`; a store
  rejection surfaces to the caller as `invalid_client_metadata` rather than a
  server fault.
  """
  @callback register_client(attrs :: map()) :: {:ok, client()} | {:error, term()}

  @doc """
  Delete a dynamically registered client during registration management cleanup
  (RFC 7592 §2). Returns `:ok`, `{:ok, client}`, or `{:error, reason}`. When
  the Config key is unset, DELETE requests to the management endpoint fail
  closed.
  """
  @callback unregister_client(client()) :: :ok | {:ok, client()} | {:error, term()}

  @doc """
  Return the stored hash of the registration access token issued with a dynamic
  client (RFC 7592 §2), or `nil`. When the Config key is unset, DELETE requests
  fail closed.
  """
  @callback client_registration_access_token_hash(client()) :: String.t() | nil

  @doc """
  Return the client's registered metadata (RFC 7592 §2.1): the string-keyed
  map `register_client/1` received, as currently stored. When the Config key
  is unset, GET and PUT requests to the management endpoint fail closed.
  """
  @callback client_registration_metadata(client()) :: map()

  @doc """
  Replace the client's registered metadata after a validated update request
  (RFC 7592 §2.2). `metadata` is the complete new registration with
  `client_id` and `client_id_issued_at`; the stored credential hashes are
  kept. Returns `{:ok, client}` or `{:error, reason}`; a rejection surfaces as
  `invalid_client_metadata`. When the Config key is unset, PUT requests fail
  closed.
  """
  @callback update_client(client(), metadata :: map()) :: {:ok, client()} | {:error, term()}

  @optional_callbacks unregister_client: 1,
                      client_registration_access_token_hash: 1,
                      client_registration_metadata: 1,
                      update_client: 2
end
