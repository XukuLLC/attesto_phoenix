defmodule AttestoPhoenix.ClientIdMetadata.Client do
  @moduledoc """
  The wrapper that marks a client as having been resolved through CIMD.

  A resolved CIMD client is not the host's opaque client value: its redirect
  URIs, keys and scopes come from a document the server fetched and validated,
  not from the host's `:client_redirect_uris` / `:client_jwks` callbacks, and it
  authenticates only as a public client or with `private_key_jwt`. Every policy
  decision that differs for such a client keys on this struct.

  ## Why a struct and not a tagged tuple

  The host's client value is opaque by contract - the library never inspects it,
  and a host may represent a client however it likes, including as a tuple. A
  marker like `{:cimd, metadata}` is therefore a shape a host could return from
  `:load_client` by coincidence, and the library would read it as "this client
  was resolved from a validated document" on the strength of the shape alone.
  That is the wrong way round: every CIMD-specific relaxation would apply to a
  client that never went through CIMD, and `client_public?/2` answers `true` for
  a CIMD client, so such a client would authenticate with no secret at all.

  A struct cannot be produced by coincidence. A host that constructs
  `%#{inspect(__MODULE__)}{}` has named this module explicitly, which is a
  deliberate act rather than an accident of representation.
  """

  alias AttestoPhoenix.ClientIdMetadata

  @enforce_keys [:metadata]
  defstruct [:metadata]

  @typedoc """
  A CIMD client: the normalized, string-keyed metadata map
  `Attesto.ClientIdMetadata.validate_document/2` produced, wrapped so it cannot
  be confused with a host-supplied client value.
  """
  @type t :: %__MODULE__{metadata: ClientIdMetadata.client()}

  @doc "Wrap a validated CIMD metadata document as a resolved client."
  @spec new(ClientIdMetadata.client()) :: t()
  def new(metadata) when is_map(metadata), do: %__MODULE__{metadata: metadata}
end
