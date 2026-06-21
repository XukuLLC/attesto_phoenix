defmodule AttestoPhoenix.Schema.ConsentGrant do
  @moduledoc """
  Ecto schema for a single-use, request-bound consent grant (RFC 6749 §4.1.1).

  Backs `AttestoPhoenix.Store.EctoConsentGrantStore`. The host consent screen
  mints one row per Authorize click, keyed on an unguessable `token` and
  carrying a `binding_hash` over the exact request the user saw (subject +
  client_id + redirect_uri + the requested scope set + code_challenge +
  code_challenge_method, built by `AttestoPhoenix.ConsentGrant`). The
  authorization-server `:consent` callback recomputes the hash from the live
  request, looks the row up by token, verifies the hash matches, and consumes it
  (single use) before a code is issued.

  ## Columns

    * `token` - the opaque, unguessable grant token (the PRIMARY KEY), so the
      consume's conditional `UPDATE` and the disambiguation read both hit the
      primary key directly. Never the plaintext of any other credential; the
      token is the grant's only secret.
    * `binding_hash` - the canonical SHA-256 hash over the bound request fields
      (`AttestoPhoenix.ConsentGrant.binding_hash/1`). The consume matches on it,
      so a grant only ever approves the request it was minted for.
    * `subject` - the OIDC `sub` of the resource owner who consented
      (diagnostic; the subject is also folded into `binding_hash`).
    * `consumed_at` - NULL until the single-use claim stamps it; a non-NULL value
      means the grant was already spent.
    * `expires_at` - the grant's short TTL (RFC 6749 §4.1.2: codes — and the
      consent that precedes them — are short-lived). The consume rejects an
      expired row, so an unswept expired grant is never honored.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @typedoc "A persisted consent-grant row."
  @type t :: %__MODULE__{
          token: String.t() | nil,
          binding_hash: String.t() | nil,
          subject: String.t() | nil,
          consumed_at: DateTime.t() | nil,
          expires_at: DateTime.t() | nil,
          inserted_at: DateTime.t() | nil,
          updated_at: DateTime.t() | nil
        }

  @insert_fields [:token, :binding_hash, :subject, :consumed_at, :expires_at]
  @required_fields [:token, :binding_hash, :subject, :expires_at]

  @primary_key {:token, :string, autogenerate: false}
  schema "attesto_consent_grants" do
    field :binding_hash, :string
    field :subject, :string
    field :consumed_at, :utc_datetime_usec
    field :expires_at, :utc_datetime_usec

    timestamps(type: :utc_datetime_usec)
  end

  @doc """
  Changeset for storing a freshly minted consent grant.

  Requires the `token`, the `binding_hash`, the `subject`, and the `expires_at`.
  A grant with no expiry would never fail closed, so a missing `:expires_at` is a
  hard validation error rather than a silently unlimited grant. The
  `unique_constraint/3` on the primary key surfaces a duplicate `token` as a
  changeset error rather than a raised exception.
  """
  @spec changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(grant \\ %__MODULE__{}, attrs) do
    grant
    |> cast(attrs, @insert_fields)
    |> validate_required(@required_fields)
    |> unique_constraint(:token, name: :attesto_consent_grants_pkey)
  end
end
