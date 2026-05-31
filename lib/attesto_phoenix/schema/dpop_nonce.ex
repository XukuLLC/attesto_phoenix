defmodule AttestoPhoenix.Schema.DPoPNonce do
  @moduledoc """
  Ecto schema for a single server-issued DPoP nonce (RFC 9449 §8).

  Each row records one nonce, the instant it was issued, and the instant it
  was consumed (`nil` while still unused). The single-use guarantee of
  `Attesto.DPoP.NonceStore` is implemented at the storage layer by a
  conditional update against `used_at`; this schema only describes the row
  shape and does not embed any consumption policy.

  ## Columns

    * `nonce` - the opaque, unpredictable value returned to the client in the
      `DPoP-Nonce` response header (RFC 9449 §8.1). A unique index on this
      column is required so a nonce can be issued at most once.
    * `issued_at` - issuance instant. Combined with a caller-supplied TTL at
      consume time it defines the freshness window (RFC 9449 §8).
    * `expires_at` - precomputed expiry (`issued_at + ttl` at issuance) so a
      stateless freshness check has no TTL argument to supply.
    * `used_at` - consumption instant, or `nil` while unused. The transition
      from `nil` to non-`nil` happens exactly once.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @typedoc "A persisted DPoP nonce row."
  @type t :: %__MODULE__{
          id: Ecto.UUID.t() | nil,
          nonce: String.t() | nil,
          issued_at: DateTime.t() | nil,
          expires_at: DateTime.t() | nil,
          used_at: DateTime.t() | nil
        }

  # A freshly issued row is fully described by the opaque value and the two
  # instants that bound its life; `used_at` defaults to NULL (unused) and is
  # stamped only on consumption.
  @insert_fields [:nonce, :issued_at, :expires_at]

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "dpop_nonces" do
    field :nonce, :string
    field :issued_at, :utc_datetime
    field :expires_at, :utc_datetime
    field :used_at, :utc_datetime
  end

  @doc """
  Changeset for inserting a freshly issued nonce.

  Requires the opaque `:nonce` value and both bounding instants. A nonce with no
  expiry would never fail closed, so a missing `:expires_at` (or `:issued_at`) is
  a hard validation error rather than a silently issued unlimited nonce. The
  `unique_constraint/3` on `:nonce` surfaces a duplicate issuance as a changeset
  error rather than a raised exception, so a caller can treat a collision as a
  generation retry.
  """
  @spec issue_changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def issue_changeset(nonce \\ %__MODULE__{}, attrs) do
    nonce
    |> cast(attrs, @insert_fields)
    |> validate_required(@insert_fields)
    |> unique_constraint(:nonce)
  end

  @doc """
  Changeset that marks an issued nonce as consumed at `used_at`.

  Single-use acceptance (RFC 9449 §8): a nonce may be spent exactly once. The
  caller performs the load-and-stamp atomically (a conditional `update_all`
  guarded on `used_at IS NULL`) so two concurrent nodes cannot both observe the
  same nonce as unused; this changeset only describes the field write.
  """
  @spec consume_changeset(t(), DateTime.t()) :: Ecto.Changeset.t()
  def consume_changeset(%__MODULE__{} = nonce, %DateTime{} = used_at) do
    change(nonce, used_at: used_at)
  end
end
