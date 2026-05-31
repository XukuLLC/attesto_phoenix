defmodule AttestoPhoenix.TestRepo.Migrations.CreateDPoPReplays do
  @moduledoc """
  Test-suite migration for the DPoP proof replay table backing
  `AttestoPhoenix.Schema.DPoPReplay` / `AttestoPhoenix.Store.EctoReplayCheck`.

  Mirrors the table a host application would generate via the migration task.
  The proof's `jti` (RFC 9449 §4.2, RFC 7519 §4.1.7) is the primary key, so the
  atomic record-and-check is a single `INSERT ... ON CONFLICT DO NOTHING`: a
  conflict means the proof was already seen and is a replay (RFC 9449 §11.1).
  """

  use Ecto.Migration

  def change do
    create table(:dpop_replays, primary_key: false) do
      add(:jti, :string, primary_key: true, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
      add(:inserted_at, :utc_datetime_usec, null: false)
    end

    # Expiry sweeps scan by `expires_at`; replay decisions hit the primary key.
    create(index(:dpop_replays, [:expires_at]))
  end
end
