defmodule AttestoPhoenix.TestRepo.Migrations.CreateConsentGrants do
  @moduledoc """
  Test-suite migration for the single-use, request-bound consent-grant table
  (RFC 6749 §4.1.1).

  Mirrors the table a host application would generate via the migration task.
  The unguessable `token` is the primary key, so the conditional consume
  `UPDATE` and the disambiguation read both hit the primary key; `binding_hash`
  ties the grant to the exact request the user saw; `expires_at` bounds the
  short consent window and is indexed for sweeps.
  """

  use Ecto.Migration

  def change do
    create table(:attesto_consent_grants, primary_key: false) do
      add(:token, :string, primary_key: true, null: false)
      add(:binding_hash, :string, null: false)
      add(:subject, :string, null: false)
      add(:consumed_at, :utc_datetime_usec)
      add(:expires_at, :utc_datetime_usec, null: false)

      timestamps(type: :utc_datetime_usec)
    end

    create(index(:attesto_consent_grants, [:expires_at]))
  end
end
