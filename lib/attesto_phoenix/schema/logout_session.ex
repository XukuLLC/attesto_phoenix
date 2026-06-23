defmodule AttestoPhoenix.Schema.LogoutSession do
  @moduledoc """
  Ecto schema + record bridge for the Back-Channel Logout session store
  (`AttestoPhoenix.Store.EctoLogoutSessionStore`).

  Backs `Attesto.LogoutSessionStore`: one row per `(session, Relying Party)`
  pair, recording where to POST a `logout_token` when the session ends. A row
  is written at ID-Token mint and read/deleted by the end-session endpoint.

  This is the OP-side delivery map, not the browser login session — see
  `Attesto.LogoutSessionStore`.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @type t :: %__MODULE__{}

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "attesto_logout_sessions" do
    field :sid, :string
    field :subject, :string
    field :client_id, :string
    field :backchannel_logout_uri, :string
    # The client's `backchannel_logout_session_required`: whether its logout
    # token MUST carry `sid` (Back-Channel Logout 1.0 §2.2).
    field :session_required, :boolean, default: false
    field :expires_at, :utc_datetime

    timestamps(updated_at: false, type: :utc_datetime)
  end

  @required [:sid, :subject, :client_id, :backchannel_logout_uri, :expires_at]
  @optional [:session_required]

  @doc """
  Build the insert changeset for a back-channel-logout session from the core
  store record. Fail-closed: a missing required field is rejected, not defaulted.
  """
  @spec from_record(Attesto.LogoutSessionStore.entry(), keyword()) :: Ecto.Changeset.t()
  def from_record(record, opts \\ []) when is_map(record) and is_list(opts) do
    prefix = Keyword.get(opts, :prefix)

    attrs = %{
      sid: Map.get(record, :sid),
      subject: Map.get(record, :subject),
      client_id: Map.get(record, :client_id),
      backchannel_logout_uri: Map.get(record, :backchannel_logout_uri),
      session_required: Map.get(record, :session_required, false),
      expires_at: unix_to_datetime(Map.get(record, :expires_at))
    }

    %__MODULE__{}
    |> Ecto.put_meta(prefix: prefix)
    |> cast(attrs, @required ++ @optional)
    |> validate_required(@required)
    |> unique_constraint([:sid, :client_id], name: :attesto_logout_sessions_sid_client_id_index)
  end

  @doc "Fold a loaded row into the `Attesto.LogoutSessionStore.target()` shape."
  @spec to_target(t()) :: Attesto.LogoutSessionStore.target()
  def to_target(%__MODULE__{} = row) do
    %{
      client_id: row.client_id,
      backchannel_logout_uri: row.backchannel_logout_uri,
      sid: row.sid,
      session_required: row.session_required || false
    }
  end

  defp unix_to_datetime(nil), do: nil
  defp unix_to_datetime(unix) when is_integer(unix), do: DateTime.from_unix!(unix) |> DateTime.truncate(:second)
end
