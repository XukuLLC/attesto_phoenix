defmodule AttestoPhoenix.Schema.RefreshFamilyRevocation do
  @moduledoc """
  Durable tombstones for revoked refresh-token families.

  Refresh-token rows are intentionally reclaimable by the store sweeper. This
  table keeps the family-level revocation decision after those rows have been
  removed, so a later insert cannot resurrect a revoked family.
  """

  use Ecto.Schema

  @primary_key false
  schema "attesto_refresh_family_revocations" do
    field(:family_id, :string, primary_key: true)
    field(:revoked_at, :utc_datetime)
  end
end
