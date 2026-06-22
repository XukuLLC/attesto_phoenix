defmodule AttestoPhoenix.TestRepo.Migrations.CreateRefreshTokens do
  @moduledoc """
  Test-suite migration for the refresh-token table backing
  `AttestoPhoenix.Schema.RefreshToken` / `AttestoPhoenix.Store.EctoRefreshStore`.

  Mirrors the table a host application would generate via the migration task.
  Only the token hash is stored, never the plaintext (RFC 6749 §10.4); the
  unique index on `token_hash` makes it the single-use lookup key on which the
  atomic rotation claim depends. `family_revoked` carries sticky family
  revocation so a replayed token's whole family stays refused.
  """

  use Ecto.Migration

  def change do
    create table(:attesto_refresh_tokens, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:token_hash, :string, null: false)
      add(:family_id, :string, null: false)
      add(:generation, :integer, null: false, default: 0)
      add(:client_id, :string)
      add(:subject, :string, null: false)
      add(:scope, {:array, :string}, null: false, default: [])
      add(:resource, {:array, :string}, null: false, default: [])
      add(:cnf, :map)
      add(:claims, :map, null: false, default: %{})
      add(:consumed, :boolean, null: false, default: false)
      add(:consumed_at, :utc_datetime)
      add(:successor, :map)
      add(:family_revoked, :boolean, null: false, default: false)
      add(:expires_at, :utc_datetime, null: false)
      add(:parent_hash, :string)

      timestamps(updated_at: false, type: :utc_datetime)
    end

    create(unique_index(:attesto_refresh_tokens, [:token_hash]))
    create(index(:attesto_refresh_tokens, [:family_id]))
  end
end
