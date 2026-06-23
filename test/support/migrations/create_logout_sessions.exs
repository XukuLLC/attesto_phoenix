defmodule AttestoPhoenix.TestRepo.Migrations.CreateLogoutSessions do
  @moduledoc """
  Test-suite migration for the Back-Channel Logout session table
  (OpenID Connect Back-Channel Logout 1.0).

  Mirrors the table a host application generates via the migration task. One row
  per `(session, Relying Party)` pair, upserted on `(sid, client_id)` and read by
  `sid` or `subject` at the end-session endpoint.
  """

  use Ecto.Migration

  def change do
    create table(:attesto_logout_sessions, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:sid, :string, null: false)
      add(:subject, :string, null: false)
      add(:client_id, :string, null: false)
      add(:backchannel_logout_uri, :text, null: false)
      add(:session_required, :boolean, null: false, default: false)
      add(:expires_at, :utc_datetime, null: false)

      timestamps(updated_at: false, type: :utc_datetime)
    end

    create(unique_index(:attesto_logout_sessions, [:sid, :client_id]))
    create(index(:attesto_logout_sessions, [:subject]))
    create(index(:attesto_logout_sessions, [:expires_at]))
  end
end
