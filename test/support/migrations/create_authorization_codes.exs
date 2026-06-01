defmodule AttestoPhoenix.TestRepo.Migrations.CreateAuthorizationCodes do
  @moduledoc """
  Test-suite migration for the authorization-code table.

  Mirrors the table a host application would generate via the migration task.
  Only the code hash is stored, never the plaintext code (RFC 6749 §10.5); the
  unique index on `code_hash` makes it the single-use lookup key (RFC 6749
  §4.1.2).
  """

  use Ecto.Migration

  def change do
    create table(:attesto_authorization_codes, primary_key: false) do
      add(:code_hash, :string, null: false)
      add(:client_id, :string, null: false)
      add(:subject, :string, null: false)
      add(:scope, {:array, :string}, null: false, default: [])
      add(:redirect_uri, :string, null: false)
      # PKCE optional at persistence: a confidential client the host exempted
      # from PKCE (Attesto.AuthorizationRequest's :require_pkce) issues a code
      # with no challenge, so both columns are nullable (mirrors the gen task).
      add(:code_challenge, :string)
      add(:code_challenge_method, :string)
      add(:cnf, :map)
      add(:nonce, :string)
      add(:claims, :map, null: false, default: %{})
      add(:family_id, :string)
      add(:access_token_jti, :string)
      add(:access_token_expires_at, :utc_datetime)
      add(:access_token_revoked_at, :utc_datetime)
      add(:expires_at, :utc_datetime, null: false)
      add(:consumed_at, :utc_datetime)
      add(:consumed_success, :boolean, null: false, default: false)
      add(:inserted_at, :utc_datetime, null: false)
    end

    create(unique_index(:attesto_authorization_codes, [:code_hash]))
    create(index(:attesto_authorization_codes, [:family_id]))
    create(index(:attesto_authorization_codes, [:access_token_jti]))
  end
end
