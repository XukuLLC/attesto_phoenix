defmodule AttestoPhoenix.Schema.LogoutSession do
  @moduledoc """
  Ecto schema + record bridge for the logout session store
  (`AttestoPhoenix.Store.EctoLogoutSessionStore`).

  Backs `Attesto.LogoutSessionStore`: one row per `(session, Relying Party)`
  pair, recording where to notify the RP when the session ends — the
  `backchannel_logout_uri` a `logout_token` is POSTed to (Back-Channel Logout
  1.0) and/or the `frontchannel_logout_uri` the logout page renders in an
  iframe (Front-Channel Logout 1.0). A row is written at ID-Token mint and
  read/deleted by the end-session endpoint; it carries at least one of the two
  URIs.

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
    field :frontchannel_logout_uri, :string
    # The client's `frontchannel_logout_session_required`: whether the rendered
    # logout URI must carry `iss`/`sid` (Front-Channel Logout 1.0 §2).
    field :frontchannel_session_required, :boolean, default: false
    field :expires_at, :utc_datetime

    timestamps(updated_at: false, type: :utc_datetime)
  end

  @required [:sid, :subject, :client_id, :expires_at]
  @optional [
    :backchannel_logout_uri,
    :session_required,
    :frontchannel_logout_uri,
    :frontchannel_session_required
  ]

  @doc """
  Build the insert changeset for a logout session from the core store record.
  Fail-closed: a missing required field is rejected, not defaulted, and a
  record carrying neither logout URI is rejected (there would be no way to
  notify the RP).
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
      frontchannel_logout_uri: Map.get(record, :frontchannel_logout_uri),
      frontchannel_session_required: Map.get(record, :frontchannel_session_required, false),
      expires_at: unix_to_datetime(Map.get(record, :expires_at))
    }

    %__MODULE__{}
    |> Ecto.put_meta(prefix: prefix)
    |> cast(attrs, @required ++ @optional)
    |> validate_required(@required)
    |> validate_logout_uri_present()
    |> unique_constraint([:sid, :client_id], name: :attesto_logout_sessions_sid_client_id_index)
  end

  @doc "Fold a loaded row into the `Attesto.LogoutSessionStore.target()` shape."
  @spec to_target(t()) :: Attesto.LogoutSessionStore.target()
  def to_target(%__MODULE__{} = row) do
    %{
      client_id: row.client_id,
      backchannel_logout_uri: row.backchannel_logout_uri,
      sid: row.sid,
      session_required: row.session_required || false,
      frontchannel_logout_uri: row.frontchannel_logout_uri,
      frontchannel_session_required: row.frontchannel_session_required || false
    }
  end

  # A logout session exists to notify the RP; with neither URI there is nothing
  # to deliver, so refuse the row rather than store dead weight.
  defp validate_logout_uri_present(changeset) do
    backchannel = get_field(changeset, :backchannel_logout_uri)
    frontchannel = get_field(changeset, :frontchannel_logout_uri)

    if is_binary(backchannel) or is_binary(frontchannel) do
      changeset
    else
      add_error(changeset, :backchannel_logout_uri, "at least one logout URI is required")
    end
  end

  defp unix_to_datetime(nil), do: nil
  defp unix_to_datetime(unix) when is_integer(unix), do: DateTime.from_unix!(unix) |> DateTime.truncate(:second)
end
