defmodule AttestoPhoenix.TestRepo.Migrations.CreateCibaRequests do
  @moduledoc """
  Test-suite migration for the OpenID Connect CIBA authentication-request table
  (CIBA Core 1.0).

  Mirrors the table a host application generates via the migration task. Only
  the `auth_req_id` hash is stored, never the plaintext; the unique index on
  `auth_req_id_hash` is the token-endpoint redemption lookup key. The §7.3 poll
  interval is frozen into the `interval` column at issue.
  """

  use Ecto.Migration

  def change do
    create table(:attesto_ciba_requests, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:auth_req_id_hash, :string, null: false)
      add(:client_id, :string, null: false)
      add(:delivery_mode, :string, size: 16, null: false)
      add(:scope, {:array, :string}, null: false, default: [])
      add(:acr_values, {:array, :string}, null: false, default: [])
      add(:binding_message, :string)
      add(:client_notification_token, :string)
      add(:hint_subject, :string, null: false)
      add(:resource, {:array, :string}, null: false, default: [])
      add(:dpop_jkt, :string)
      add(:status, :string, size: 16, null: false, default: "pending")
      add(:subject, :string)
      add(:acr, :string)
      add(:auth_time, :utc_datetime)
      add(:granted_scope, {:array, :string})
      add(:granted_claims, :map)
      add(:interval, :integer, null: false, default: 0)
      add(:last_polled_at, :utc_datetime)
      add(:expires_at, :utc_datetime, null: false)

      timestamps(updated_at: false, type: :utc_datetime)
    end

    create(unique_index(:attesto_ciba_requests, [:auth_req_id_hash]))
    create(index(:attesto_ciba_requests, [:expires_at]))
  end
end
