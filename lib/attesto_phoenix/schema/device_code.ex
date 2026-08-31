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

  alias Attesto.Scope
  alias Attesto.Thumbprint

  @type t :: %__MODULE__{}

  @statuses [:pending, :approved, :denied, :consumed]
  @user_code_alphabet ~c"BCDFGHJKLMNPQRSTVWXZ"
  @min_user_code_length 8
  @max_user_code_length 64
  @canonical_data_keys [:client_id, :dpop_jkt, :resource, :scope]
  @canonical_data_error "device code has invalid canonical data"

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
  store record. The issue-time `:data` map must contain exactly the four atom
  keys emitted by `Attesto.DeviceCode.issue/3`; missing or extra keys raise a
  fixed, value-free `ArgumentError` before any field is projected into the row.
  The write envelope must also be pending with a valid expiry, and undecided:
  status must be explicit, while decision fields and `last_polled_at` must be
  nil or absent. Other missing required record fields remain changeset
  validation errors.
  """
  @spec from_record(Attesto.DeviceCodeStore.entry(), keyword()) :: Ecto.Changeset.t()
  def from_record(record, opts \\ []) when is_map(record) and is_list(opts) do
    prefix = Keyword.get(opts, :prefix)
    data = canonical_data!(record)

    attrs = %{
      device_code_hash: Map.get(record, :device_code_hash),
      user_code: Map.get(record, :user_code),
      client_id: data.client_id,
      scope: data.scope,
      resource: data.resource,
      dpop_jkt: data.dpop_jkt,
      status: Map.get(record, :status),
      subject: Map.get(record, :subject),
      granted_scope: Map.get(record, :granted_scope),
      granted_claims: Map.get(record, :granted_claims),
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
        scope: row.scope,
        resource: row.resource,
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
      scope: row.scope,
      resource: row.resource,
      status: row.status,
      expires_at: datetime_to_unix(row.expires_at)
    }
  end

  defp canonical_data!(record) do
    data = Map.get(record, :data)

    if is_map(data) and
         map_size(data) == length(@canonical_data_keys) and
         Enum.all?(@canonical_data_keys, &Map.has_key?(data, &1)) and
         valid_canonical_data?(data) and valid_record_envelope?(record) do
      data
    else
      raise ArgumentError, @canonical_data_error
    end
  end

  defp valid_canonical_data?(data) do
    non_empty_binary?(Map.get(data, :client_id)) and
      Scope.valid_list?(Map.get(data, :scope)) and
      valid_string_list?(Map.get(data, :resource)) and
      valid_optional_jkt?(Map.get(data, :dpop_jkt))
  end

  defp valid_record_envelope?(record) do
    non_empty_binary?(Map.get(record, :device_code_hash)) and
      valid_user_code?(Map.get(record, :user_code)) and
      Map.get(record, :status) == :pending and
      is_integer(Map.get(record, :expires_at)) and Map.get(record, :expires_at) >= 0 and
      is_nil(Map.get(record, :subject)) and
      is_nil(Map.get(record, :granted_scope)) and
      is_nil(Map.get(record, :granted_claims)) and
      is_nil(Map.get(record, :last_polled_at))
  end

  defp valid_user_code?(user_code) when is_binary(user_code) do
    byte_size(user_code) in @min_user_code_length..@max_user_code_length and
      Enum.all?(:binary.bin_to_list(user_code), &(&1 in @user_code_alphabet))
  end

  defp valid_user_code?(_user_code), do: false

  defp valid_optional_jkt?(nil), do: true
  defp valid_optional_jkt?(value), do: Thumbprint.valid?(value)

  defp valid_string_list?(value), do: is_list(value) and Enum.all?(value, &non_empty_binary?/1)

  defp non_empty_binary?(value), do: is_binary(value) and value != ""

  defp unix_to_datetime(nil), do: nil
  defp unix_to_datetime(unix) when is_integer(unix), do: DateTime.from_unix!(unix) |> DateTime.truncate(:second)

  defp datetime_to_unix(nil), do: nil
  defp datetime_to_unix(%DateTime{} = dt), do: DateTime.to_unix(dt)
end
