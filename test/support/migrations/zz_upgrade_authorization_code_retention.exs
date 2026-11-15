defmodule AttestoPhoenix.TestRepo.Migrations.UpgradeAuthorizationCodeRetention do
  use Ecto.Migration

  def change do
    alter table(:attesto_authorization_codes) do
      add :authorization_family_id, :string, size: 255
    end
  end
end
