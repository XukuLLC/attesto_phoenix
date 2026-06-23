defmodule AttestoPhoenix.Store.EctoLogoutSessionStore do
  @moduledoc """
  Ecto/Postgres implementation of `Attesto.LogoutSessionStore`.

  One row per `(session, Relying Party)` pair, backing the schema
  `AttestoPhoenix.Schema.LogoutSession`:

    * `record/1` upserts on `(sid, client_id)` — re-issuing an ID Token for a
      session the RP already holds refreshes the row (expiry, uri) rather than
      duplicating it.
    * `targets/1` selects the live rows to notify, scoping to one session when a
      `:sid` is given, else to every session for the `:subject`. Expired rows
      are filtered out.
    * `delete/1` removes the matched rows after the fan-out, so a session is
      enumerated for logout exactly once.

  This persists only the OP-side delivery map; the browser login session is the
  host's (see `Attesto.LogoutSessionStore`).
  """

  @behaviour Attesto.LogoutSessionStore

  import Ecto.Query, only: [from: 2]

  alias AttestoPhoenix.Schema.LogoutSession

  @app :attesto_phoenix

  @impl Attesto.LogoutSessionStore
  @spec record(Attesto.LogoutSessionStore.entry()) :: :ok
  def record(%{sid: sid, client_id: client_id} = entry) when is_binary(sid) and is_binary(client_id) do
    entry
    |> LogoutSession.from_record()
    |> repo().insert(
      on_conflict: {:replace, [:subject, :backchannel_logout_uri, :session_required, :expires_at]},
      conflict_target: [:sid, :client_id]
    )

    :ok
  end

  @impl Attesto.LogoutSessionStore
  @spec targets(Attesto.LogoutSessionStore.criteria()) :: [Attesto.LogoutSessionStore.target()]
  def targets(criteria) when is_map(criteria) do
    case scope(criteria) do
      nil ->
        []

      filter ->
        now = now_dt()

        from(l in LogoutSession, where: l.expires_at > ^now)
        |> filter.()
        |> repo().all()
        |> Enum.map(&LogoutSession.to_target/1)
    end
  end

  @impl Attesto.LogoutSessionStore
  @spec delete(Attesto.LogoutSessionStore.criteria()) :: :ok
  def delete(criteria) when is_map(criteria) do
    case scope(criteria) do
      nil ->
        :ok

      filter ->
        LogoutSession
        |> filter.()
        |> repo().delete_all()

        :ok
    end
  end

  @impl Attesto.LogoutSessionStore
  @spec take_targets(Attesto.LogoutSessionStore.criteria()) :: [Attesto.LogoutSessionStore.target()]
  def take_targets(criteria) when is_map(criteria) do
    case scope(criteria) do
      nil ->
        []

      filter ->
        now = now_dt()

        # `DELETE ... RETURNING`: enumerate and remove the live rows in one
        # statement, so concurrent logouts cannot both deliver the same session.
        query =
          from(l in LogoutSession, where: l.expires_at > ^now, select: l)
          |> filter.()

        {_count, rows} = repo().delete_all(query)
        Enum.map(rows || [], &LogoutSession.to_target/1)
    end
  end

  # ----- internal -----

  # `:sid` takes precedence (session-scoped logout); fall back to `:subject`
  # (all of the subject's sessions). With neither, there is nothing to match.
  defp scope(%{sid: sid}) when is_binary(sid) and sid != "", do: fn query -> from(l in query, where: l.sid == ^sid) end

  defp scope(%{subject: subject}) when is_binary(subject) and subject != "",
    do: fn query -> from(l in query, where: l.subject == ^subject) end

  defp scope(_criteria), do: nil

  defp now_dt, do: DateTime.utc_now() |> DateTime.truncate(:second)

  defp repo do
    case Application.get_env(@app, :repo) do
      nil ->
        raise ArgumentError,
              "AttestoPhoenix: no :repo configured. Set `config #{inspect(@app)}, repo: MyApp.Repo`"

      repo ->
        repo
    end
  end
end
