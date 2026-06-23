defmodule AttestoPhoenix.Store.EctoDeviceCodeStore do
  @moduledoc """
  Ecto/Postgres implementation of `Attesto.DeviceCodeStore`.

  Every state transition is a single guarded atomic statement, so the RFC 8628
  device-code state machine is race-free across nodes:

    * `approve/2` / `deny/2` — `UPDATE ... WHERE status = 'pending' RETURNING`, so
      the user's decision is taken exactly once even under concurrent posts.
    * `poll/2` — one conditional `UPDATE ... SET last_polled_at = now WHERE
      device_code_hash = $1 AND (last_polled_at IS NULL OR last_polled_at <=
      now - interval) RETURNING`, enforcing the §3.5 minimum poll interval and
      reading the row's state in the same statement (no read-then-write race
      against a concurrent approval). A zero-row result is disambiguated as
      `slow_down` vs unknown by one follow-up existence check (both are non-mint
      outcomes, so it is not a security race).
    * `consume/2` — `UPDATE ... SET status = 'consumed' WHERE status = 'approved'
      RETURNING`, so an approved code mints exactly one token family.

  Backs the schema `AttestoPhoenix.Schema.DeviceCode`. Only the device code's
  hash is stored; `user_code` is stored normalized.
  """

  @behaviour Attesto.DeviceCodeStore

  import Ecto.Query, only: [from: 2]

  alias AttestoPhoenix.Schema.DeviceCode

  @app :attesto_phoenix

  @impl Attesto.DeviceCodeStore
  @spec put(Attesto.DeviceCodeStore.entry()) :: :ok | {:error, :user_code_taken}
  def put(%{device_code_hash: hash, user_code: user_code} = record) when is_binary(hash) and is_binary(user_code) do
    record
    |> DeviceCode.from_record()
    |> repo().insert()
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
          {:ok, Attesto.DeviceCodeStore.pending_view()} | :error
  def lookup_user_code(user_code) when is_binary(user_code) do
    case repo().one(from d in DeviceCode, where: d.user_code == ^user_code) do
      nil -> :error
      row -> {:ok, DeviceCode.to_pending_view(row)}
    end
  end

  @impl Attesto.DeviceCodeStore
  @spec approve(Attesto.DeviceCodeStore.user_code(), map()) ::
          :ok | {:error, :not_found | :already_decided | :expired}
  def approve(user_code, approval) when is_binary(user_code) and is_map(approval) do
    decide(user_code,
      status: :approved,
      subject: Map.get(approval, :subject),
      granted_scope: Map.get(approval, :granted_scope, []),
      granted_claims: Map.get(approval, :granted_claims, %{})
    )
  end

  @impl Attesto.DeviceCodeStore
  @spec deny(Attesto.DeviceCodeStore.user_code()) :: :ok | {:error, :not_found | :already_decided | :expired}
  def deny(user_code) when is_binary(user_code) do
    decide(user_code, status: :denied)
  end

  @impl Attesto.DeviceCodeStore
  @spec poll(Attesto.DeviceCodeStore.device_code_hash(), map()) ::
          {:ok, Attesto.DeviceCodeStore.entry()} | {:error, :slow_down} | :error
  def poll(hash, %{now: now, interval: interval}) when is_binary(hash) do
    now_dt = DateTime.from_unix!(now) |> DateTime.truncate(:second)
    cutoff = DateTime.from_unix!(now - interval) |> DateTime.truncate(:second)

    query =
      from d in DeviceCode,
        where: d.device_code_hash == ^hash and (is_nil(d.last_polled_at) or d.last_polled_at <= ^cutoff),
        select: d

    case repo().update_all(query, set: [last_polled_at: now_dt]) do
      {1, [row]} -> {:ok, DeviceCode.to_entry(row)}
      {0, _} -> slow_down_or_missing(hash)
    end
  end

  @impl Attesto.DeviceCodeStore
  @spec consume(Attesto.DeviceCodeStore.device_code_hash(), map()) ::
          {:ok, Attesto.DeviceCodeStore.entry()} | :error
  def consume(hash, opts) when is_binary(hash) do
    now = opts |> Map.get(:now, System.system_time(:second)) |> DateTime.from_unix!() |> DateTime.truncate(:second)

    # Guard on approval AND unexpiry, so a code that expires between the core's
    # poll-time check and this transition cannot mint.
    query =
      from d in DeviceCode,
        where: d.device_code_hash == ^hash and d.status == :approved and d.expires_at > ^now,
        select: d

    case repo().update_all(query, set: [status: :consumed]) do
      {1, [row]} -> {:ok, DeviceCode.to_entry(%{row | status: :consumed})}
      {0, _} -> :error
    end
  end

  # ----- internal -----

  # The shared guarded transition for approve/deny: flip a `pending` row to the
  # target status in one statement. Zero rows means the row is gone (not_found)
  # or already past pending (already_decided) — distinguished by a follow-up
  # read (neither outcome mints, so this is not a race).
  defp decide(user_code, set) do
    query =
      from d in DeviceCode,
        where: d.user_code == ^user_code and d.status == :pending,
        select: d

    case repo().update_all(query, set: set) do
      {1, [_row]} -> :ok
      {0, _} -> decide_miss(user_code)
    end
  end

  defp decide_miss(user_code) do
    case repo().one(from d in DeviceCode, where: d.user_code == ^user_code, select: d.status) do
      nil -> {:error, :not_found}
      _status -> {:error, :already_decided}
    end
  end

  defp slow_down_or_missing(hash) do
    if repo().exists?(from d in DeviceCode, where: d.device_code_hash == ^hash),
      do: {:error, :slow_down},
      else: :error
  end

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
