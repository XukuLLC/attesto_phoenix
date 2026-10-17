defmodule AttestoPhoenix.TestRepo.Migrations.CreateRefreshFamilyRevocations do
  @moduledoc """
  Test-suite migration for durable refresh-family revocation tombstones.
  """

  use Ecto.Migration

  def change do
    create table(:attesto_refresh_family_revocations, primary_key: false) do
      add(:family_id, :string, size: 255, primary_key: true, null: false)
      add(:revoked_at, :utc_datetime, null: false)
    end
  end
end
