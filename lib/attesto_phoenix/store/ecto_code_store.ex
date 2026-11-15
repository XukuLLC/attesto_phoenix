defmodule AttestoPhoenix.Store.EctoCodeStore do
  @moduledoc """
  PostgreSQL implementation of the required `Attesto.CodeStore` contract.

  Immutable grant bindings survive the explicit live, claimed and redeemed
  states. Conditional updates implement claim, replay flagging and finish.
  Finish returns one concurrent revocation flag in its UPDATE RETURNING; protocol decisions
  and refresh-family revocation belong to `Attesto.AuthorizationCode`.

  Every query suppresses application SQL logging and repository telemetry,
  including binding reads, because rows contain code hashes and private claims.
  Database-server logging remains the host's responsibility. Repository and
  prefix resolution follow the request-local `AttestoPhoenix.Config`.

  Upgrade existing databases with the migration generator's
  `--upgrade 4.19` milestone before rolling nodes.
  The previous release continues to read and write the same lifecycle columns.
  """
  @behaviour Attesto.CodeStore

  import Ecto.Query, only: [from: 2]

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Schema.Authorization
  alias AttestoPhoenix.Store.Ecto, as: StoreEcto

  @claims_query_opts [log: false, telemetry_event: nil]

  @impl Attesto.CodeStore
  @spec put(Attesto.CodeStore.entry()) :: :ok
  def put(%{code_hash: code_hash, data: data, expires_at: expires_at} = record)
      when is_binary(code_hash) and is_map(data) and is_integer(expires_at) do
    {repo, prefix} = StoreEcto.mutation_context()

    record
    |> Authorization.from_record(prefix: prefix)
    |> repo.insert([prefix: prefix] ++ @claims_query_opts)
    |> case do
      {:ok, _row} -> :ok
      {:error, %Ecto.Changeset{} = changeset} -> raise_sanitized_insert_error(changeset)
    end
  end

  @impl Attesto.CodeStore
  def read(hash) do
    case repo().one(
           from(a in Authorization, where: a.code_hash == ^hash),
           [prefix: Config.table_prefix()] ++ @claims_query_opts
         ) do
      nil -> :error
      row -> {:ok, Authorization.to_state_record(row)}
    end
  end

  @impl Attesto.CodeStore
  def claim(hash) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    transition(hash, :live, consumed_at: now, replay_retain_until: DateTime.add(now, 300, :second))
  end

  @impl Attesto.CodeStore
  def flag_replay(hash) do
    transition(hash, :claimed, access_token_revoked_at: DateTime.utc_now() |> DateTime.truncate(:second))
  end

  defp transition(hash, state, updates) do
    {repo, prefix} = StoreEcto.mutation_context()
    query = from a in Authorization, where: a.code_hash == ^hash

    query =
      case state do
        :live -> from a in query, where: is_nil(a.consumed_at)
        :claimed -> from a in query, where: not is_nil(a.consumed_at) and a.consumed_success == false
      end

    case repo.update_all(preserve_legacy_values(query, updates), [], [prefix: prefix] ++ @claims_query_opts) do
      {1, _} -> :ok
      {0, _} -> :error
    end
  end

  @impl Attesto.CodeStore
  def finish(hash, redemption) do
    Attesto.CodeStore.validate_redemption!(redemption)
    %{family_id: family, replay_retain_until: deadline} = redemption
    {repo, prefix} = StoreEcto.mutation_context()

    query =
      from a in Authorization,
        where: a.code_hash == ^hash and not is_nil(a.consumed_at) and a.consumed_success == false,
        select: not is_nil(a.access_token_revoked_at)

    updates = [
      consumed_success: true,
      family_id: family,
      replay_retain_until: if(deadline, do: DateTime.from_unix!(deadline))
    ]

    case repo.update_all(preserve_legacy_values(query, updates), [], [prefix: prefix] ++ @claims_query_opts) do
      {1, [revoked]} -> {:ok, revoked}
      {0, _} -> :error
    end
  end

  @impl Attesto.CodeStore
  def delete_unclaimed(criteria) do
    criteria = Attesto.RevocationCriteria.new!(criteria)
    {repo, prefix} = StoreEcto.mutation_context()
    opts = [prefix: prefix] ++ @claims_query_opts

    {:ok, count} =
      repo.transaction(
        fn ->
          query =
            from a in Authorization,
              where: a.consumed_success == false,
              order_by: a.code_hash,
              lock: "FOR UPDATE",
              select: %{code_hash: a.code_hash, consumed_at: a.consumed_at}

          rows =
            case StoreEcto.where_criteria(query, criteria) do
              :none -> []
              query -> repo.all(query, opts)
            end

          live = for %{consumed_at: nil, code_hash: hash} <- rows, do: hash
          claimed = for %{consumed_at: at, code_hash: hash} <- rows, not is_nil(at), do: hash
          {count, _} = repo.delete_all(from(a in Authorization, where: a.code_hash in ^live), opts)

          repo.update_all(
            preserve_legacy_values(
              from(a in Authorization, where: a.code_hash in ^claimed),
              access_token_revoked_at: DateTime.utc_now() |> DateTime.truncate(:second)
            ),
            [],
            opts
          )

          count
        end,
        @claims_query_opts
      )

    {:ok, count}
  end

  @impl Attesto.CodeStore
  def record_access_token_for_code(hash, jti, expiry) do
    {repo, prefix} = StoreEcto.mutation_context()

    query =
      from a in Authorization,
        where: a.code_hash == ^hash and not is_nil(a.consumed_at) and is_nil(a.access_token_jti)

    case repo.update_all(
           preserve_legacy_values(query, access_token_jti: jti, access_token_expires_at: DateTime.from_unix!(expiry)),
           [],
           [prefix: prefix] ++ @claims_query_opts
         ) do
      {1, _} -> :ok
      {0, _} -> raise ArgumentError, "access-token linkage requires a claimed or redeemed code without a token"
    end
  end

  @impl Attesto.CodeStore
  def revoke_access_token_for_code(hash) do
    revoke_links(from a in Authorization, where: a.code_hash == ^hash)
  end

  @impl Attesto.CodeStore
  def revoke_family_access_tokens(family) do
    revoke_links(from a in Authorization, where: a.consumed_success == true and a.family_id == ^family)
  end

  defp revoke_links(query) do
    {repo, prefix} = StoreEcto.mutation_context()
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    repo.update_all(
      preserve_legacy_values(query, access_token_revoked_at: now),
      [],
      [prefix: prefix] ++ @claims_query_opts
    )

    :ok
  end

  @impl Attesto.CodeStore
  def access_token_revoked?(jti) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    query =
      from a in Authorization,
        where: a.access_token_jti == ^jti and not is_nil(a.access_token_revoked_at) and a.access_token_expires_at > ^now

    repo().exists?(query, [prefix: Config.table_prefix()] ++ @claims_query_opts)
  end

  # Capture provenance before any finalization overwrites family_id. Finished
  # legacy rows have already lost that information and must not infer it.
  defp preserve_legacy_values(query, updates) do
    from a in query,
      update: [
        set: [
          authorization_family_id:
            fragment(
              "CASE WHEN ? = false THEN COALESCE(?, ?) ELSE ? END",
              a.consumed_success,
              a.authorization_family_id,
              a.family_id,
              a.authorization_family_id
            )
        ]
      ],
      update: [set: ^updates]
  end

  defp raise_sanitized_insert_error(%Ecto.Changeset{} = original) do
    safe_changeset =
      original.errors
      |> Enum.map(&elem(&1, 0))
      |> Enum.uniq()
      |> Enum.reduce(Ecto.Changeset.change(%Authorization{}), fn field, changeset ->
        Ecto.Changeset.add_error(changeset, field, "authorization code could not be stored")
      end)
      |> ensure_sanitized_error()

    raise Ecto.InvalidChangesetError, action: :insert, changeset: safe_changeset
  end

  defp ensure_sanitized_error(%Ecto.Changeset{errors: []} = changeset) do
    Ecto.Changeset.add_error(changeset, :base, "authorization code could not be stored")
  end

  defp ensure_sanitized_error(%Ecto.Changeset{} = changeset), do: changeset

  defp repo, do: Config.ecto_repo!()
end
