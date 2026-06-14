defmodule AttestoPhoenix.TestRepo.Migrations.CreateClientIdMetadata do
  @moduledoc """
  Test-suite migration for the Client ID Metadata Document cache table
  (`draft-ietf-oauth-client-id-metadata-document-01`).

  Mirrors the table a host application would generate via the migration task.
  The CIMD `client_id` URL is the primary key, so the cache lookup (`get/1`)
  hits the primary key and a re-fetch upserts the single row; the validated
  document lives in a jsonb `metadata` column, and `expires_at` bounds the
  cached document's freshness (RFC 9111) and is indexed for sweeps.
  """

  use Ecto.Migration

  def change do
    create table(:attesto_client_id_metadata, primary_key: false) do
      add(:url, :string, primary_key: true, null: false)
      add(:metadata, :map, null: false)
      add(:expires_at, :utc_datetime, null: false)
      add(:inserted_at, :utc_datetime, null: false)
    end

    create(index(:attesto_client_id_metadata, [:expires_at]))
  end
end
