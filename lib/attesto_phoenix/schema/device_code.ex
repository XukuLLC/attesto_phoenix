defmodule AttestoPhoenix.Schema.DeviceCode do
  @moduledoc """
  Ecto schema + record bridge for the RFC 8628 device-code store
  (`AttestoPhoenix.Store.EctoDeviceCodeStore`).

  Backs `Attesto.DeviceCodeStore`: a device code is a mutable row that moves
  through `pending` → (`approved` | `denied`) → `consumed`. `from_record/1`
  spreads the core's `Attesto.DeviceCodeStore.entry()` map across the row's
  columns for the initial `pending` insert; `to_entry/1` folds a loaded row back
  into that contract shape. The mutating transitions are done as guarded atomic
  `UPDATE`s in the store, not through this changeset.

  Only the device code's `Attesto.Secret.hash/1` is stored, never the plaintext;
  `user_code` is stored normalized.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @type t :: %__MODULE__{}

  @statuses [:pending, :approved, :denied, :consumed]

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "attesto_device_codes" do
    field :device_code_hash, :string
    field :user_code, :string
    field :client_id, :string
    field :scope, {:array, :string}, default: []
    # RFC 8707 resource indicator(s) bound at the device-authorization endpoint;
    # the token endpoint mints the access-token `aud` from this set.
    field :resource, {:array, :string}, default: []
    # RFC 9449 §10 DPoP holder-of-key pre-binding (nil for an unbound code).
    field :dpop_jkt, :string
    field :status, Ecto.Enum, values: @statuses, default: :pending
    # Set on approval (NULL until the user authorizes).
    field :subject, :string
    field :granted_scope, {:array, :string}
    field :granted_claims, :map
    field :last_polled_at, :utc_datetime
    field :expires_at, :utc_datetime

    timestamps(updated_at: false, type: :utc_datetime)
  end

  @required [:device_code_hash, :user_code, :client_id, :status, :expires_at]
  @optional [:scope, :resource, :dpop_jkt, :subject, :granted_scope, :granted_claims, :last_polled_at]

  @doc """
  Build the insert changeset for a new `pending` device code from the core
  store record. Fail-closed: a missing required field is rejected, not defaulted.
  """
  @spec from_record(Attesto.DeviceCodeStore.entry(), keyword()) :: Ecto.Changeset.t()
  def from_record(record, opts \\ []) when is_map(record) and is_list(opts) do
    prefix = Keyword.get(opts, :prefix)
    data = Map.get(record, :data, %{})

    attrs = %{
      device_code_hash: Map.get(record, :device_code_hash),
      user_code: Map.get(record, :user_code),
      client_id: Map.get(data, :client_id),
      scope: Map.get(data, :scope, []),
      resource: Map.get(data, :resource, []),
      dpop_jkt: Map.get(data, :dpop_jkt),
      status: Map.get(record, :status, :pending),
      expires_at: unix_to_datetime(Map.get(record, :expires_at)),
      last_polled_at: unix_to_datetime(Map.get(record, :last_polled_at))
    }

    %__MODULE__{}
    |> Ecto.put_meta(prefix: prefix)
    |> cast(attrs, @required ++ @optional)
    |> validate_required(@required)
    |> unique_constraint(:device_code_hash, name: :attesto_device_codes_device_code_hash_index)
    |> unique_constraint(:user_code, name: :attesto_device_codes_user_code_index)
  end

  @doc """
  Fold a loaded row into the `Attesto.DeviceCodeStore.entry()` contract shape.
  """
  @spec to_entry(t()) :: Attesto.DeviceCodeStore.entry()
  def to_entry(%__MODULE__{} = row) do
    %{
      device_code_hash: row.device_code_hash,
      user_code: row.user_code,
      data: %{
        client_id: row.client_id,
        scope: row.scope || [],
        resource: row.resource || [],
        dpop_jkt: row.dpop_jkt
      },
      status: row.status,
      subject: row.subject,
      granted_scope: row.granted_scope,
      granted_claims: row.granted_claims,
      expires_at: datetime_to_unix(row.expires_at),
      last_polled_at: datetime_to_unix(row.last_polled_at)
    }
  end

  @doc """
  The non-consuming `Attesto.DeviceCodeStore.pending_view()` for the verification
  page.
  """
  @spec to_pending_view(t()) :: Attesto.DeviceCodeStore.pending_view()
  def to_pending_view(%__MODULE__{} = row) do
    %{
      user_code: row.user_code,
      client_id: row.client_id,
      scope: row.scope || [],
      resource: row.resource || [],
      status: row.status,
      expires_at: datetime_to_unix(row.expires_at)
    }
  end

  defp unix_to_datetime(nil), do: nil
  defp unix_to_datetime(unix) when is_integer(unix), do: DateTime.from_unix!(unix) |> DateTime.truncate(:second)

  defp datetime_to_unix(nil), do: nil
  defp datetime_to_unix(%DateTime{} = dt), do: DateTime.to_unix(dt)
end
