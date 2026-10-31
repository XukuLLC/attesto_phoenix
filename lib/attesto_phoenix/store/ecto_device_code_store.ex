defmodule AttestoPhoenix.Store.EctoDeviceCodeStore do
  @moduledoc """
  Ecto/Postgres implementation of `Attesto.DeviceCodeStore`.

  Every state transition is a single guarded atomic statement, so the RFC 8628
  device-code state machine is race-free across nodes:

    * `approve/3` / `deny/2` — `UPDATE ... WHERE status = 'pending' AND
      expires_at > $now RETURNING`, so
      the user's decision is taken exactly once even under concurrent posts.
    * `poll/2` — one conditional `UPDATE ... SET last_polled_at = now WHERE
      device_code_hash = $1 AND (last_polled_at IS NULL OR last_polled_at <=
      now - interval) RETURNING`, enforcing the §3.5 minimum poll interval and
      reading the row's state in the same statement (no read-then-write race
      against a concurrent approval). A zero-row result is disambiguated as
      `slow_down` vs unknown by one follow-up existence check (both are non-mint
      outcomes, so it is not a security race).
    * `consume/2` — `UPDATE ... SET status = 'consumed' WHERE status = 'approved'
      AND expires_at > $now RETURNING`, so only an approved, unexpired code
      mints one token family.

  Backs the schema `AttestoPhoenix.Schema.DeviceCode`. Only the device code's
  hash is stored; `user_code` is stored normalized.
  """

  @behaviour Attesto.DeviceCodeStore

  import Ecto.Query, only: [dynamic: 2]

  alias AttestoPhoenix.Schema.DeviceCode
  alias AttestoPhoenix.Store.Ecto, as: StoreEcto
  alias AttestoPhoenix.Store.PendingDecision

  @invalid_approval_claims "device-code approval has invalid granted claims"

  @impl Attesto.DeviceCodeStore
  @spec put(Attesto.DeviceCodeStore.entry()) :: :ok | {:error, :user_code_taken}
  def put(%{device_code_hash: hash, user_code: user_code} = record) when is_binary(hash) and is_binary(user_code) do
    {repo, prefix} = StoreEcto.mutation_context()

    record
    |> DeviceCode.from_record(prefix: prefix)
    |> repo.insert(prefix: prefix, log: false, telemetry_event: nil)
    |> case do
      {:ok, _row} ->
        :ok

      {:error, changeset} ->
        # A user_code collision is expected (≈34.6-bit code) — signal a retry. A
        # device_code_hash collision is CSPRNG-grade impossible, so re-raise it
        # as the caller bug it would be.
        if Keyword.has_key?(changeset.errors, :user_code),
          do: {:error, :user_code_taken},
          else: raise(Ecto.InvalidChangesetError, action: :insert, changeset: changeset)
    end
  end

  @impl Attesto.DeviceCodeStore
  @spec lookup_user_code(Attesto.DeviceCodeStore.user_code()) ::
          {:ok, Attesto.DeviceCodeStore.entry()} | :error
  def lookup_user_code(user_code) when is_binary(user_code),
    do: PendingDecision.fetch(DeviceCode, :user_code, user_code)

  @impl Attesto.DeviceCodeStore
  @spec get(Attesto.DeviceCodeStore.device_code_hash()) :: {:ok, Attesto.DeviceCodeStore.entry()} | :error
  def get(hash) when is_binary(hash), do: PendingDecision.fetch(DeviceCode, :device_code_hash, hash)

  @impl Attesto.DeviceCodeStore
  @spec approve(Attesto.DeviceCodeStore.user_code(), map(), map()) ::
          {:ok, Attesto.DeviceCodeStore.entry()} | {:error, :not_found | :already_decided | :expired}
  def approve(user_code, approval, opts) when is_binary(user_code) and is_map(approval) and is_map(opts) do
    granted_claims = Map.get(approval, :granted_claims, %{})
    PendingDecision.validate_granted_claims!(granted_claims, @invalid_approval_claims)

    PendingDecision.decide(DeviceCode, :user_code, user_code, PendingDecision.decision_now(opts),
      status: :approved,
      subject: Map.get(approval, :subject),
      granted_scope: Map.get(approval, :granted_scope, []),
      granted_claims: granted_claims
    )
  end

  @impl Attesto.DeviceCodeStore
  @spec deny(Attesto.DeviceCodeStore.user_code(), map()) ::
          {:ok, Attesto.DeviceCodeStore.entry()} | {:error, :not_found | :already_decided | :expired}
  def deny(user_code, opts) when is_binary(user_code) and is_map(opts) do
    PendingDecision.decide(DeviceCode, :user_code, user_code, PendingDecision.decision_now(opts), status: :denied)
  end

  @impl Attesto.DeviceCodeStore
  @spec poll(Attesto.DeviceCodeStore.device_code_hash(), map()) ::
          {:ok, Attesto.DeviceCodeStore.entry()} | {:error, :slow_down} | :error
  def poll(hash, %{now: now, interval: interval}) when is_binary(hash) do
    # RFC 8628 §3.5: the interval is the one the core passes in.
    cutoff = PendingDecision.to_datetime(now - interval)
    PendingDecision.poll(DeviceCode, :device_code_hash, hash, now, dynamic([d], d.last_polled_at <= ^cutoff))
  end

  @impl Attesto.DeviceCodeStore
  @spec consume(Attesto.DeviceCodeStore.device_code_hash(), map()) ::
          {:ok, Attesto.DeviceCodeStore.entry()} | :error
  def consume(hash, opts) when is_binary(hash) do
    PendingDecision.consume(
      DeviceCode,
      :device_code_hash,
      hash,
      Map.get(opts, :now, System.system_time(:second))
    )
  end

  # ----- internal -----
end
