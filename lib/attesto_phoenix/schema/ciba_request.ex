defmodule AttestoPhoenix.Schema.CIBARequest do
  @moduledoc """
  Ecto schema + record bridge for the CIBA authentication-request store
  (`AttestoPhoenix.Store.EctoCIBAStore`).

  Backs `Attesto.CIBAStore`: a CIBA authentication request is a mutable row
  that moves through `pending` → (`approved` | `denied`) → `consumed` while the
  client polls the token endpoint (poll mode) or awaits a notification (ping
  mode). `from_record/1` spreads the core's `Attesto.CIBAStore.entry()` map
  across the row's columns for the initial `pending` insert; `to_entry/1` folds
  a loaded row back into that contract shape (reconstructing the `:data` map).
  The mutating transitions are done as guarded atomic `UPDATE`s in the store,
  not through this changeset.

  Only the `auth_req_id`'s `Attesto.Secret.hash/1` is stored, never the
  plaintext. The §7.3 minimum token-request interval is frozen into the row's
  `interval` column at issue (it is the value the client was told), so the
  poll throttle reads it per-row.

  ## `client_notification_token` at rest

  For ping mode the row stores the client-generated bearer
  `client_notification_token` in plaintext (parity with how PAR request params
  are stored): it is single-flow-scoped and short-lived (≤ the request's
  lifetime), and the ping deliverer needs it back to authenticate the
  notification, so it cannot be one-way hashed. A deployment that wants it
  encrypted at rest supplies its own store.
  """

  use Ecto.Schema

  @type t :: %__MODULE__{}

  @statuses [:pending, :approved, :denied, :consumed]
  @delivery_modes [:poll, :ping, :push]

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "attesto_ciba_requests" do
    field :auth_req_id_hash, :string
    field :client_id, :string
    field :delivery_mode, Ecto.Enum, values: @delivery_modes
    field :scope, {:array, :string}, default: []
    field :acr_values, {:array, :string}, default: []
    field :binding_message, :string
    # Ping/push only: the client-generated bearer secret the notification POST
    # carries (nil for poll mode).
    field :client_notification_token, :string
    # The hint-resolved end-user the OP set out to authenticate (CIBA §7.1:
    # identified BEFORE the auth_req_id is issued). Bound at issue.
    field :hint_subject, :string
    # RFC 8707 resource indicator(s) bound at the backchannel endpoint.
    field :resource, {:array, :string}, default: []
    # RFC 9449 §10 DPoP holder-of-key pre-binding (nil for an unbound request).
    field :dpop_jkt, :string
    field :status, Ecto.Enum, values: @statuses, default: :pending
    # Bound at approval (NULL until the user authenticates).
    field :subject, :string
    field :acr, :string
    field :auth_time, :utc_datetime
    field :granted_scope, {:array, :string}
    field :granted_claims, :map
    # The §7.3 minimum seconds between accepted polls, frozen at issue. 0
    # disables enforcement.
    field :interval, :integer, default: 0
    field :last_polled_at, :utc_datetime
    field :expires_at, :utc_datetime

    timestamps(updated_at: false, type: :utc_datetime)
  end

  @doc """
  Build the insert map for a new `pending` authentication request from the core
  store record. Returns `{schema_struct, prefix}` ready for `Repo.insert/2`.
  """
  @spec from_record(Attesto.CIBAStore.entry(), keyword()) :: t()
  def from_record(record, opts \\ []) when is_map(record) and is_list(opts) do
    prefix = Keyword.get(opts, :prefix)
    data = Map.get(record, :data, %{})

    %__MODULE__{
      auth_req_id_hash: Map.get(record, :auth_req_id_hash),
      client_id: Map.get(data, :client_id),
      delivery_mode: Map.get(data, :delivery_mode),
      scope: Map.get(data, :scope, []),
      acr_values: Map.get(data, :acr_values, []),
      binding_message: Map.get(data, :binding_message),
      client_notification_token: Map.get(data, :client_notification_token),
      hint_subject: Map.get(data, :subject),
      resource: Map.get(data, :resource, []),
      dpop_jkt: Map.get(data, :dpop_jkt),
      status: Map.get(record, :status, :pending),
      interval: Map.get(record, :interval, 0),
      expires_at: unix_to_datetime(Map.get(record, :expires_at)),
      last_polled_at: unix_to_datetime(Map.get(record, :last_polled_at))
    }
    |> Ecto.put_meta(prefix: prefix)
  end

  @doc """
  Fold a loaded row into the `Attesto.CIBAStore.entry()` contract shape.
  """
  @spec to_entry(t()) :: Attesto.CIBAStore.entry()
  def to_entry(%__MODULE__{} = row) do
    %{
      auth_req_id_hash: row.auth_req_id_hash,
      data: %{
        acr_values: row.acr_values || [],
        binding_message: row.binding_message,
        client_id: row.client_id,
        client_notification_token: row.client_notification_token,
        delivery_mode: row.delivery_mode,
        dpop_jkt: row.dpop_jkt,
        resource: row.resource || [],
        scope: row.scope || [],
        subject: row.hint_subject
      },
      status: row.status,
      subject: row.subject,
      acr: row.acr,
      auth_time: datetime_to_unix(row.auth_time),
      granted_scope: row.granted_scope,
      granted_claims: row.granted_claims,
      interval: row.interval || 0,
      expires_at: datetime_to_unix(row.expires_at),
      last_polled_at: datetime_to_unix(row.last_polled_at)
    }
  end

  defp unix_to_datetime(nil), do: nil
  defp unix_to_datetime(unix) when is_integer(unix), do: unix |> DateTime.from_unix!() |> DateTime.truncate(:second)

  defp datetime_to_unix(nil), do: nil
  defp datetime_to_unix(%DateTime{} = dt), do: DateTime.to_unix(dt)
end
