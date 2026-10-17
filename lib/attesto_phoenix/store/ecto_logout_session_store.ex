defmodule AttestoPhoenix.Store.EctoLogoutSessionStore do
  @moduledoc """
  Ecto/Postgres implementation of `Attesto.LogoutSessionStore`.

  One row per `(session, Relying Party)` pair — carrying the RP's back-channel
  and/or front-channel logout URI — backing the schema
  `AttestoPhoenix.Schema.LogoutSession`:

    * `record/1` upserts on `(sid, client_id)` — re-issuing an ID Token for a
      session the RP already holds refreshes the row (expiry, uri) rather than
      duplicating it.
    * `lease_targets/4` reserves live rows atomically. Successful deliveries
      are deleted with `acknowledge_targets/2`; failed work is deferred with
      `release_targets/2` using bounded exponential backoff, and crashed
      workers' leases expire for retry. The supervised
      `AttestoPhoenix.Store.Sweeper` reclaims due or expired leases every
      configured `:sweep_interval_ms`.
    * The legacy `targets/1`, `delete/1`, and `take_targets/1` callbacks remain
      for compatibility with Attesto 2.5 and earlier callers.

  This persists only the OP-side delivery map; the browser login session is the
  host's (see `Attesto.LogoutSessionStore`).
  """

  @behaviour Attesto.LogoutSessionStore

  import Ecto.Query, only: [from: 2]

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Schema.LogoutSession
  alias AttestoPhoenix.Store.Ecto, as: StoreEcto

  @impl Attesto.LogoutSessionStore
  @spec record(Attesto.LogoutSessionStore.entry()) :: :ok
  def record(%{sid: sid, client_id: client_id} = entry) when is_binary(sid) and is_binary(client_id) do
    {repo, prefix} = StoreEcto.mutation_context()

    entry
    |> LogoutSession.from_record(prefix: prefix)
    |> repo.insert!(
      on_conflict:
        {:replace,
         [
           :subject,
           :delivery_id,
           :backchannel_logout_uri,
           :session_required,
           :frontchannel_logout_uri,
           :frontchannel_session_required,
           :expires_at,
           :lease_id,
           :lease_expires_at,
           :delivery_attempts
         ]},
      conflict_target: [:sid, :client_id],
      prefix: prefix,
      log: false,
      telemetry_event: nil
    )

    :ok
  end

  @impl Attesto.LogoutSessionStore
  @spec lease_targets(
          Attesto.LogoutSessionStore.criteria(),
          Attesto.LogoutSessionStore.lease_id(),
          non_neg_integer(),
          non_neg_integer()
        ) :: [Attesto.LogoutSessionStore.target()]
  def lease_targets(criteria, lease_id, now, lease_expires_at)
      when is_map(criteria) and is_binary(lease_id) and lease_id != "" and is_integer(now) and now >= 0 and
             is_integer(lease_expires_at) and lease_expires_at > now do
    case scope(criteria) do
      nil -> []
      filter -> lease_scoped_targets(filter, lease_id, now, lease_expires_at)
    end
  end

  @doc false
  @spec lease_retry_targets(
          module(),
          String.t() | nil,
          Attesto.LogoutSessionStore.lease_id(),
          non_neg_integer(),
          non_neg_integer(),
          pos_integer()
        ) :: [map()]
  def lease_retry_targets(repo, prefix, lease_id, now, lease_expires_at, limit)
      when is_atom(repo) and is_binary(lease_id) and is_integer(now) and is_integer(lease_expires_at) and
             is_integer(limit) do
    validate_retry_arguments!(prefix, lease_id, now, lease_expires_at, limit)

    now_dt = unix_to_datetime(now)
    lease_expires_at_dt = unix_to_datetime(lease_expires_at)

    query =
      from(l in LogoutSession,
        where: l.expires_at > ^now_dt,
        where: not is_nil(l.backchannel_logout_uri),
        # A non-NULL lease marks work that a confirmed logout already claimed.
        # Untouched live sessions remain NULL/NULL and must never be retried.
        where:
          not is_nil(l.lease_id) and not is_nil(l.lease_expires_at) and
            l.lease_expires_at <= ^now_dt,
        order_by: [asc: l.lease_expires_at, asc: l.inserted_at, asc: l.delivery_id],
        limit: ^limit,
        lock: "FOR UPDATE SKIP LOCKED"
      )

    {:ok, targets} =
      repo.transaction(
        fn ->
          lease_query(repo, prefix, query, lease_id, lease_expires_at_dt, &retry_target/1)
        end,
        log: false,
        telemetry_event: nil
      )

    targets
  end

  @doc false
  @spec validate_retry_schema!(module(), String.t() | nil) :: :ok
  def validate_retry_schema!(repo, prefix) when is_atom(repo) and (is_binary(prefix) or is_nil(prefix)) do
    from(l in LogoutSession,
      select: {l.delivery_id, l.lease_id, l.lease_expires_at, l.delivery_attempts},
      limit: 0
    )
    |> repo.all(prefix: prefix, log: false, telemetry_event: nil)

    :ok
  end

  @impl Attesto.LogoutSessionStore
  @spec acknowledge_targets(
          Attesto.LogoutSessionStore.lease_id(),
          [Attesto.LogoutSessionStore.delivery_id()]
        ) :: :ok
  def acknowledge_targets(lease_id, delivery_ids)
      when is_binary(lease_id) and lease_id != "" and is_list(delivery_ids) do
    mutate_lease(lease_id, delivery_ids, :acknowledge)
  end

  @impl Attesto.LogoutSessionStore
  @spec release_targets(
          Attesto.LogoutSessionStore.lease_id(),
          [Attesto.LogoutSessionStore.delivery_id()]
        ) :: :ok
  def release_targets(lease_id, delivery_ids) when is_binary(lease_id) and lease_id != "" and is_list(delivery_ids) do
    mutate_lease(lease_id, delivery_ids, :release)
  end

  @impl Attesto.LogoutSessionStore
  @spec targets(Attesto.LogoutSessionStore.criteria()) :: [Attesto.LogoutSessionStore.target()]
  def targets(criteria) when is_map(criteria) do
    case scope(criteria) do
      nil ->
        []

      filter ->
        now = now_dt()
        prefix = Config.table_prefix()

        from(l in LogoutSession,
          where: l.expires_at > ^now,
          where:
            is_nil(l.lease_id) or is_nil(l.lease_expires_at) or
              l.lease_expires_at <= ^now
        )
        |> filter.()
        |> repo().all(prefix: prefix, log: false, telemetry_event: nil)
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
        {repo, prefix} = StoreEcto.mutation_context()
        now = now_dt()

        LogoutSession
        |> where_available(now)
        |> filter.()
        |> repo.delete_all(prefix: prefix, log: false, telemetry_event: nil)

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
        {repo, prefix} = StoreEcto.mutation_context()

        # `DELETE ... RETURNING`: enumerate and remove the live rows in one
        # statement, so concurrent logouts cannot both deliver the same session.
        query =
          from(l in LogoutSession,
            where: l.expires_at > ^now,
            where:
              is_nil(l.lease_id) or is_nil(l.lease_expires_at) or
                l.lease_expires_at <= ^now,
            select: l
          )
          |> filter.()

        {_count, rows} =
          repo.delete_all(query, prefix: prefix, log: false, telemetry_event: nil)

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

  defp where_available(query, now) do
    from(l in query,
      where:
        is_nil(l.lease_id) or is_nil(l.lease_expires_at) or
          l.lease_expires_at <= ^now
    )
  end

  defp lease_scoped_targets(filter, lease_id, now, lease_expires_at) do
    {repo, prefix} = StoreEcto.mutation_context()
    now_dt = unix_to_datetime(now)
    lease_expires_at_dt = unix_to_datetime(lease_expires_at)

    {:ok, targets} =
      repo.transaction(
        fn ->
          query = available_query(LogoutSession, now_dt) |> filter.()
          lease_query(repo, prefix, query, lease_id, lease_expires_at_dt, &LogoutSession.to_target/1)
        end,
        log: false,
        telemetry_event: nil
      )

    targets
  end

  defp available_query(query, now) do
    from(l in query,
      where: l.expires_at > ^now,
      where:
        is_nil(l.lease_id) or is_nil(l.lease_expires_at) or
          l.lease_expires_at <= ^now,
      lock: "FOR UPDATE SKIP LOCKED"
    )
  end

  defp lease_query(repo, prefix, query, lease_id, lease_expires_at, mapper) do
    rows =
      repo.all(query, prefix: prefix, log: false, telemetry_event: nil)

    lease_rows(repo, prefix, rows, lease_id, lease_expires_at)
    Enum.map(rows, mapper)
  end

  defp retry_target(row), do: row |> LogoutSession.to_target() |> Map.put(:subject, row.subject)

  defp validate_retry_arguments!(prefix, lease_id, now, lease_expires_at, limit) do
    validate_retry_prefix!(prefix)
    validate_nonempty_retry_lease_id!(lease_id)
    validate_nonnegative_retry_now!(now)
    validate_retry_deadline!(lease_expires_at, now)
    validate_positive_retry_limit!(limit)
  end

  defp validate_retry_prefix!(nil), do: :ok
  defp validate_retry_prefix!(prefix) when is_binary(prefix), do: :ok
  defp validate_retry_prefix!(_prefix), do: raise(ArgumentError, "logout retry prefix must be a string or nil")

  defp validate_nonempty_retry_lease_id!(lease_id) when byte_size(lease_id) > 0, do: :ok
  defp validate_nonempty_retry_lease_id!(_lease_id), do: raise(ArgumentError, "logout retry lease id must not be empty")

  defp validate_nonnegative_retry_now!(now) when now >= 0, do: :ok
  defp validate_nonnegative_retry_now!(_now), do: raise(ArgumentError, "logout retry time must not be negative")

  defp validate_retry_deadline!(lease_expires_at, now) when lease_expires_at > now, do: :ok

  defp validate_retry_deadline!(_lease_expires_at, _now),
    do: raise(ArgumentError, "logout retry lease deadline must be after the current time")

  defp validate_positive_retry_limit!(limit) when limit > 0, do: :ok
  defp validate_positive_retry_limit!(_limit), do: raise(ArgumentError, "logout retry limit must be positive")

  defp lease_rows(_repo, _prefix, [], _lease_id, _lease_expires_at), do: :ok

  defp lease_rows(repo, prefix, rows, lease_id, lease_expires_at) do
    delivery_ids = Enum.map(rows, & &1.delivery_id)

    from(l in LogoutSession, where: l.delivery_id in ^delivery_ids)
    |> repo.update_all(
      [set: [lease_id: lease_id, lease_expires_at: lease_expires_at], inc: [delivery_attempts: 1]],
      prefix: prefix,
      log: false,
      telemetry_event: nil
    )

    :ok
  end

  defp mutate_lease(_lease_id, [], _operation), do: :ok

  defp mutate_lease(lease_id, delivery_ids, operation) do
    {repo, prefix} = StoreEcto.mutation_context()

    query =
      from(l in LogoutSession,
        where: l.lease_id == ^lease_id and l.delivery_id in ^delivery_ids
      )

    case operation do
      :acknowledge ->
        repo.delete_all(query, prefix: prefix, log: false, telemetry_event: nil)

      :release ->
        release_with_backoff(repo, prefix, query, lease_id)
    end

    :ok
  end

  defp release_with_backoff(repo, prefix, query, lease_id) do
    config = Config.request_config()
    now = now_dt()

    repo.transaction(
      fn ->
        query
        |> select_delivery_attempts()
        |> repo.all(prefix: prefix, log: false, telemetry_event: nil)
        |> Enum.group_by(fn {_delivery_id, attempts} ->
          Config.logout_retry_delay_seconds(config, attempts)
        end)
        |> Enum.each(fn {delay_seconds, rows} ->
          delivery_ids = Enum.map(rows, &elem(&1, 0))
          retry_at = DateTime.add(now, delay_seconds, :second)
          pending_id = Attesto.Secret.generate(24)

          from(l in LogoutSession,
            where: l.lease_id == ^lease_id and l.delivery_id in ^delivery_ids
          )
          |> repo.update_all(
            [set: [lease_id: pending_id, lease_expires_at: retry_at]],
            prefix: prefix,
            log: false,
            telemetry_event: nil
          )
        end)
      end,
      log: false,
      telemetry_event: nil
    )

    :ok
  end

  defp select_delivery_attempts(query) do
    from(l in query,
      select: {l.delivery_id, l.delivery_attempts},
      lock: "FOR UPDATE"
    )
  end

  defp now_dt, do: DateTime.utc_now() |> DateTime.truncate(:second)
  defp unix_to_datetime(value), do: DateTime.from_unix!(value) |> DateTime.truncate(:second)

  defp repo, do: Config.ecto_repo!()
end
