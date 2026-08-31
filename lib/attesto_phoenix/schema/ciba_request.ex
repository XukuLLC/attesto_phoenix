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

  alias Attesto.Scope
  alias Attesto.Thumbprint

  @type t :: %__MODULE__{}

  @statuses [:pending, :approved, :denied, :consumed]
  @delivery_modes [:poll, :ping, :push]
  @canonical_data_keys [
    :acr_values,
    :binding_message,
    :client_id,
    :client_notification_token,
    :delivery_mode,
    :dpop_jkt,
    :resource,
    :scope,
    :subject
  ]
  @canonical_data_error "CIBA request has invalid canonical data"
  @notification_token_pattern ~r/\A[A-Za-z0-9\-._~+\/]+=*\z/
  @notification_token_max_length 1024

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
  store record. The issue-time `:data` map must contain exactly the nine atom
  keys emitted by `Attesto.CIBA.issue/4`; missing or extra keys raise a fixed,
  value-free `ArgumentError` before any field is projected into the row. The
  write envelope must also be pending with a valid expiry and interval, and
  undecided: status and interval are explicit, while decision fields and
  `last_polled_at` must be nil or absent.
  """
  @spec from_record(Attesto.CIBAStore.entry(), keyword()) :: t()
  def from_record(record, opts \\ []) when is_map(record) and is_list(opts) do
    prefix = Keyword.get(opts, :prefix)
    data = canonical_data!(record)

    %__MODULE__{
      auth_req_id_hash: Map.get(record, :auth_req_id_hash),
      client_id: data.client_id,
      delivery_mode: data.delivery_mode,
      scope: data.scope,
      acr_values: data.acr_values,
      binding_message: data.binding_message,
      client_notification_token: data.client_notification_token,
      hint_subject: data.subject,
      resource: data.resource,
      dpop_jkt: data.dpop_jkt,
      status: Map.get(record, :status),
      subject: Map.get(record, :subject),
      acr: Map.get(record, :acr),
      auth_time: unix_to_datetime(Map.get(record, :auth_time)),
      granted_scope: Map.get(record, :granted_scope),
      granted_claims: Map.get(record, :granted_claims),
      interval: Map.get(record, :interval),
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
        acr_values: row.acr_values,
        binding_message: row.binding_message,
        client_id: row.client_id,
        client_notification_token: row.client_notification_token,
        delivery_mode: row.delivery_mode,
        dpop_jkt: row.dpop_jkt,
        resource: row.resource,
        scope: row.scope,
        subject: row.hint_subject
      },
      status: row.status,
      subject: row.subject,
      acr: row.acr,
      auth_time: datetime_to_unix(row.auth_time),
      granted_scope: row.granted_scope,
      granted_claims: row.granted_claims,
      interval: row.interval,
      expires_at: datetime_to_unix(row.expires_at),
      last_polled_at: datetime_to_unix(row.last_polled_at)
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
    valid_string_list?(Map.get(data, :acr_values)) and
      valid_optional_display_text?(Map.get(data, :binding_message)) and
      non_empty_binary?(Map.get(data, :client_id)) and
      valid_notification_binding?(Map.get(data, :delivery_mode), Map.get(data, :client_notification_token)) and
      valid_delivery_mode?(Map.get(data, :delivery_mode)) and
      valid_optional_jkt?(Map.get(data, :dpop_jkt)) and
      valid_string_list?(Map.get(data, :resource)) and
      Scope.valid_list?(Map.get(data, :scope)) and
      non_empty_binary?(Map.get(data, :subject))
  end

  defp valid_record_envelope?(record) do
    valid_required_record_envelope?(record) and valid_optional_record_envelope?(record)
  end

  defp valid_required_record_envelope?(record) do
    non_empty_binary?(Map.get(record, :auth_req_id_hash)) and
      Map.get(record, :status) == :pending and
      is_integer(Map.get(record, :interval)) and Map.get(record, :interval) >= 0 and
      is_integer(Map.get(record, :expires_at)) and Map.get(record, :expires_at) >= 0
  end

  defp valid_optional_record_envelope?(record) do
    is_nil(Map.get(record, :subject)) and
      is_nil(Map.get(record, :acr)) and
      is_nil(Map.get(record, :auth_time)) and
      is_nil(Map.get(record, :granted_scope)) and
      is_nil(Map.get(record, :granted_claims)) and
      is_nil(Map.get(record, :last_polled_at))
  end

  defp valid_delivery_mode?(mode), do: mode in @delivery_modes

  defp valid_notification_binding?(:poll, nil), do: true

  defp valid_notification_binding?(mode, token) when mode in [:ping, :push],
    do:
      is_binary(token) and token != "" and byte_size(token) <= @notification_token_max_length and
        Regex.match?(@notification_token_pattern, token)

  defp valid_notification_binding?(_mode, _token), do: false

  defp valid_optional_display_text?(nil), do: true

  defp valid_optional_display_text?(value) when is_binary(value) and value != "",
    do: String.valid?(value) and not Regex.match?(~r/[\x00-\x1F\x7F]/u, value)

  defp valid_optional_display_text?(_value), do: false

  defp valid_optional_jkt?(nil), do: true
  defp valid_optional_jkt?(value), do: Thumbprint.valid?(value)

  defp valid_string_list?(value), do: is_list(value) and Enum.all?(value, &non_empty_binary?/1)

  defp non_empty_binary?(value), do: is_binary(value) and value != ""

  defp unix_to_datetime(nil), do: nil
  defp unix_to_datetime(unix) when is_integer(unix), do: unix |> DateTime.from_unix!() |> DateTime.truncate(:second)

  defp datetime_to_unix(nil), do: nil
  defp datetime_to_unix(%DateTime{} = dt), do: DateTime.to_unix(dt)
end
