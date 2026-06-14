defmodule AttestoPhoenix.Schema.PushedAuthorizationRequest do
  @moduledoc """
  Ecto schema for a single Pushed Authorization Request (RFC 9126).

  A PAR endpoint stores the normalized, validated authorization request
  parameters behind a one-time `request_uri` reference
  (`urn:ietf:params:oauth:request_uri:…`) and hands that reference to the
  client; the client then presents only the `request_uri` at `/authorize`. An
  in-memory store cannot share that reference across nodes - a `request_uri`
  pushed to one node is unknown to another - so a clustered (or simply
  load-balanced) deployment needs the reference in shared storage. This schema
  backs `AttestoPhoenix.Store.EctoPARStore`, persisting one row per pushed
  request so any node resolves a `request_uri` issued by any other.

  ## Columns

    * `request_uri` - the opaque `urn:ietf:params:oauth:request_uri:` reference
      (RFC 9126 §2.2) returned to the client. It is the PRIMARY KEY, so a
      reference is stored at most once and the authorization endpoint's lookup
      (and the optional single-use `take/1`) hits the primary key directly.
    * `params` - the stored, already-validated authorization request parameters
      (a string-keyed map; client authentication secrets are dropped before
      storage). Persisted as `jsonb`; the authorization endpoint re-runs the
      normal `Attesto.AuthorizationRequest` validation after resolving it.
    * `expires_at` - the reference's expiry (RFC 9126 §2.2). The store rejects an
      expired row on read, so an unswept expired reference is never honored.
    * `inserted_at` - when the reference was pushed (diagnostic; never a lookup
      key).
  """

  use Ecto.Schema

  import Ecto.Changeset

  @typedoc "A persisted pushed authorization request row."
  @type t :: %__MODULE__{
          request_uri: String.t() | nil,
          params: map() | nil,
          expires_at: DateTime.t() | nil,
          inserted_at: DateTime.t() | nil
        }

  # A pushed request is fully described by its reference, the stored params, and
  # the two instants; there is no surrogate id and no mutable state, so every
  # field is set once at insert.
  @insert_fields [:request_uri, :params, :expires_at, :inserted_at]

  @primary_key {:request_uri, :string, autogenerate: false}
  schema "attesto_pushed_authorization_requests" do
    field :params, :map
    field :expires_at, :utc_datetime
    field :inserted_at, :utc_datetime
  end

  @doc """
  Changeset for storing a freshly pushed authorization request.

  Requires the `request_uri` reference, the stored `params`, and both instants.
  A reference with no expiry would never fail closed, so a missing `:expires_at`
  is a hard validation error rather than a silently unlimited reference. The
  `unique_constraint/3` on the primary key surfaces a duplicate `request_uri` as
  a changeset error (which `EctoPARStore.put/3` maps to `{:error, _}`) rather
  than a raised exception.
  """
  @spec put_changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def put_changeset(request \\ %__MODULE__{}, attrs) do
    request
    |> cast(attrs, @insert_fields)
    |> validate_required(@insert_fields)
    |> unique_constraint(:request_uri, name: :attesto_pushed_authorization_requests_pkey)
  end
end
