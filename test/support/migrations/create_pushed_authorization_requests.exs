defmodule AttestoPhoenix.TestRepo.Migrations.CreatePushedAuthorizationRequests do
  @moduledoc """
  Test-suite migration for the Pushed Authorization Request table (RFC 9126).

  Mirrors the table a host application would generate via the migration task.
  The one-time `request_uri` reference is the primary key, so resolution at
  `/authorize` (and the optional single-use `take/1` = `DELETE … RETURNING`)
  hits the primary key; `expires_at` bounds the reference's life and is indexed
  for sweeps.
  """

  use Ecto.Migration

  def change do
    create table(:attesto_pushed_authorization_requests, primary_key: false) do
      add(:request_uri, :string, primary_key: true, null: false)
      add(:params, :map, null: false)
      add(:expires_at, :utc_datetime, null: false)
      add(:inserted_at, :utc_datetime, null: false)
    end

    create(index(:attesto_pushed_authorization_requests, [:expires_at]))
  end
end
