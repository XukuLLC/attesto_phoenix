defmodule AttestoPhoenix.TestRepo.Migrations.CreateDeviceCodes do
  @moduledoc """
  Test-suite migration for the device-authorization-grant table (RFC 8628).

  Mirrors the table a host application generates via the migration task. Only
  the device-code hash is stored, never the plaintext (RFC 6749 §10.3); the
  unique index on `device_code_hash` is the poll lookup key and the unique index
  on `user_code` is the verification lookup key.
  """

  use Ecto.Migration

  def change do
    create table(:attesto_device_codes, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:device_code_hash, :string, null: false)
      add(:user_code, :string, null: false)
      add(:client_id, :string, null: false)
      add(:scope, {:array, :string}, null: false, default: [])
      add(:resource, {:array, :string}, null: false, default: [])
      add(:dpop_jkt, :string)
      add(:status, :string, size: 16, null: false, default: "pending")
      add(:subject, :string)
      add(:granted_scope, {:array, :string})
      add(:granted_claims, :map)
      add(:last_polled_at, :utc_datetime)
      add(:expires_at, :utc_datetime, null: false)

      timestamps(updated_at: false, type: :utc_datetime)
    end

    create(unique_index(:attesto_device_codes, [:device_code_hash]))
    create(unique_index(:attesto_device_codes, [:user_code]))
    create(index(:attesto_device_codes, [:expires_at]))
  end
end
