defmodule AttestoPhoenix.TestRepo.Migrations.CreateAuthorizationCodes do
  @moduledoc """
  Test-suite migration for the authorization-code table.

  Mirrors the table a host application would generate via the migration task.
  Only the code hash is stored, never the plaintext code (RFC 6749 §10.5); it
  is the primary key and the single-use lookup key (RFC 6749 §4.1.2).
  """

  use Ecto.Migration

  def change do
    create table(:attesto_authorization_codes, primary_key: false) do
      add(:code_hash, :string, size: 88, primary_key: true, null: false)
      add(:client_id, :string, size: 255, null: false)
      add(:subject, :string, size: 255, null: false)
      add(:scope, {:array, :string}, null: false, default: [])
      add(:resource, {:array, :string}, null: false, default: [])
      add(:redirect_uri, :text, null: false)
      # PKCE optional at persistence: a confidential client the host exempted
      # from PKCE (Attesto.AuthorizationRequest's :require_pkce) issues a code
      # with no challenge, so both columns are nullable (mirrors the gen task).
      add(:code_challenge, :string, size: 255)
      add(:code_challenge_method, :string, size: 16)
      add(:cnf, :map)
      add(:nonce, :string, size: 255)
      add(:claims, :map, null: false, default: %{})
      add(:family_id, :string, size: 255)
      add(:access_token_jti, :string, size: 255)
      add(:access_token_expires_at, :utc_datetime)
      add(:access_token_revoked_at, :utc_datetime)
      add(:expires_at, :utc_datetime, null: false)
      add(:consumed_at, :utc_datetime)
      add(:consumed_success, :boolean, null: false, default: false)
      add(:replay_retain_until, :utc_datetime)
      add(:inserted_at, :utc_datetime, null: false)
    end

    create(index(:attesto_authorization_codes, [:expires_at]))
    create(index(:attesto_authorization_codes, [:family_id]))
    create(index(:attesto_authorization_codes, [:access_token_jti]))
  end
end
