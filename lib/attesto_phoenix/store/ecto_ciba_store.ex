defmodule AttestoPhoenix.Store.EctoCIBAStore do
  @moduledoc """
  Ecto/Postgres implementation of `Attesto.CIBAStore`.

  Every state transition is a single guarded atomic statement, so the CIBA
  authentication-request state machine is race-free across nodes:

    * `approve/3` / `deny/2` — `UPDATE ... WHERE status = 'pending' AND
      expires_at > $now RETURNING`, so the user's decision is taken exactly
      once and never lands on an expired request.
    * `poll/2` — one conditional `UPDATE ... SET last_polled_at = $now WHERE
      auth_req_id_hash = $1 AND (last_polled_at IS NULL OR last_polled_at <=
      $now - interval) RETURNING`, enforcing the CIBA Core §7.3 minimum
      token-request interval (the ROW's `interval` column - the value the
      client was told at issue) and reading the row's state in the same
      statement. A zero-row result is disambiguated as `slow_down` vs unknown
      by one follow-up existence check (both are non-mint outcomes, so it is
      not a security race).
    * `consume/2` — `UPDATE ... SET status = 'consumed' WHERE status =
      'approved' AND expires_at > $now RETURNING`, so an approved request mints
      exactly one token family.

  Backs the schema `AttestoPhoenix.Schema.CIBARequest`. Only the `auth_req_id`'s
  hash is stored.
  """

  @behaviour Attesto.CIBAStore

  import Ecto.Query, only: [from: 2]

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Schema.CIBARequest
  alias AttestoPhoenix.Store.Ecto, as: StoreEcto
  alias AttestoPhoenix.Store.PendingDecision

  @invalid_approval_claims "CIBA approval has invalid granted claims"

  @impl Attesto.CIBAStore
  @spec put(Attesto.CIBAStore.entry()) :: :ok
  def put(%{auth_req_id_hash: hash} = record) when is_binary(hash) do
    {repo, prefix} = StoreEcto.mutation_context()

    record
    |> CIBARequest.from_record(prefix: prefix)
    |> repo.insert!(prefix: prefix, log: false, telemetry_event: nil)

    :ok
  end

  @impl Attesto.CIBAStore
  @spec lookup(Attesto.CIBAStore.auth_req_id_hash()) :: {:ok, Attesto.CIBAStore.entry()} | :error
  def lookup(hash) when is_binary(hash) do
    prefix = Config.table_prefix()

    case repo().one(from(c in CIBARequest, where: c.auth_req_id_hash == ^hash),
           prefix: prefix,
           log: false,
           telemetry_event: nil
         ) do
      nil -> :error
      row -> {:ok, CIBARequest.to_entry(row)}
    end
  end

  @impl Attesto.CIBAStore
  @spec approve(Attesto.CIBAStore.auth_req_id_hash(), map(), map()) ::
          {:ok, Attesto.CIBAStore.entry()} | {:error, :not_found | :already_decided | :expired}
  def approve(hash, approval, opts) when is_binary(hash) and is_map(approval) and is_map(opts) do
    granted_claims = Map.get(approval, :granted_claims, %{})
    PendingDecision.validate_granted_claims!(granted_claims, @invalid_approval_claims)
    now = decision_now(opts)

    PendingDecision.decide(CIBARequest, :auth_req_id_hash, hash, now,
      status: :approved,
      subject: Map.get(approval, :subject),
      acr: Map.get(approval, :acr),
      auth_time: unix_to_datetime(Map.get(approval, :auth_time)),
      granted_scope: Map.get(approval, :granted_scope),
      granted_claims: granted_claims
    )
  end

  @impl Attesto.CIBAStore
  @spec deny(Attesto.CIBAStore.auth_req_id_hash(), map()) ::
          {:ok, Attesto.CIBAStore.entry()} | {:error, :not_found | :already_decided | :expired}
  def deny(hash, opts) when is_binary(hash) and is_map(opts) do
    PendingDecision.decide(CIBARequest, :auth_req_id_hash, hash, decision_now(opts), status: :denied)
  end

  @impl Attesto.CIBAStore
  @spec poll(Attesto.CIBAStore.auth_req_id_hash(), map()) ::
          {:ok, Attesto.CIBAStore.entry()} | {:error, :slow_down} | :error
  def poll(hash, %{now: now}) when is_binary(hash) do
    {repo, prefix} = StoreEcto.mutation_context()
    now_dt = now |> DateTime.from_unix!() |> DateTime.truncate(:second)

    # The §7.3 throttle: accept the first poll (last_polled_at NULL) or a poll
    # at least the row's `interval` seconds after the last accepted one. The
    # interval is the ROW's column (the value the client was told at issue), so
    # `$now - interval` is computed per-row in SQL. interval 0 makes the cutoff
    # `$now`, so any past `last_polled_at` passes (enforcement disabled).
    query =
      from c in CIBARequest,
        where:
          c.auth_req_id_hash == ^hash and
            (is_nil(c.last_polled_at) or
               fragment(
                 "? <= CAST(? AS timestamp) - (? * interval '1 second')",
                 c.last_polled_at,
                 ^now_dt,
                 c.interval
               )),
        select: c

    case repo.update_all(query, [set: [last_polled_at: now_dt]],
           prefix: prefix,
           log: false,
           telemetry_event: nil
         ) do
      {1, [row]} -> {:ok, CIBARequest.to_entry(%{row | last_polled_at: now_dt})}
      {0, _} -> PendingDecision.slow_down_or_missing(CIBARequest, :auth_req_id_hash, hash, repo, prefix)
    end
  end

  @impl Attesto.CIBAStore
  @spec consume(Attesto.CIBAStore.auth_req_id_hash(), map()) :: {:ok, Attesto.CIBAStore.entry()} | :error
  def consume(hash, opts) when is_binary(hash) do
    PendingDecision.consume(
      CIBARequest,
      :auth_req_id_hash,
      hash,
      Map.get(opts, :now, System.system_time(:second))
    )
  end

  # ----- internal -----

  defp decision_now(opts), do: Map.get(opts, :now, System.system_time(:second))

  defp unix_to_datetime(nil), do: nil
  defp unix_to_datetime(unix) when is_integer(unix), do: unix |> DateTime.from_unix!() |> DateTime.truncate(:second)
  defp unix_to_datetime(%DateTime{} = dt), do: DateTime.truncate(dt, :second)

  defp repo, do: Config.ecto_repo!()
end
