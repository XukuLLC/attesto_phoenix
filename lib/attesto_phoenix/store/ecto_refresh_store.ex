defmodule AttestoPhoenix.Store.EctoRefreshStore do
  @moduledoc """
  PostgreSQL implementation of `Attesto.RefreshStore`.

  Rotation is one family-serialized transaction. The transaction locks the
  family with a transaction-scoped advisory lock, locks the parent row, marks
  the parent consumed with its authenticated retry state, and inserts the
  successor before it commits. A blocked caller therefore sees either the
  complete committed winner or a complete reuse record; it can never observe
  a consumed parent before its successor exists.

  Positive retry state is authenticated-encrypted before the transaction. The
  encryption key must be stable across every node that can serve the family.
  Strict rotation stores only `%{retry_until: now, recoverable: false}` and
  needs no encryption secret. Expired retry state is redacted by the sweeper,
  while a consumed parent is retained until that deadline or its own expiry,
  whichever comes first. Family revocation
  is also recorded in the separate `RefreshFamilyRevocation` table, whose
  tombstones are never swept.
  """

  @behaviour Attesto.RefreshStore

  import Ecto.Query

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.RefreshSuccessorCipher
  alias AttestoPhoenix.Schema.RefreshFamilyRevocation
  alias AttestoPhoenix.Schema.RefreshToken
  alias AttestoPhoenix.Store.Sweeper

  @app :attesto_phoenix
  @advisory_lock_namespace 0x4154_5246
  @valid_deadline_sql "jsonb_typeof(?->'retry_until') = 'number' AND " <>
                        "(?->>'retry_until') ~ '^-{0,1}(0|[1-9][0-9]*)$' AND " <>
                        "(?->'retry_until') >= to_jsonb(0::numeric) AND " <>
                        "(?->'retry_until') <= to_jsonb(9223372036854775807::numeric)"
  @fallback_deadline_sql "CASE WHEN ? IS NOT NULL AND ? IS NOT NULL THEN " <>
                           "LEAST(" <>
                           "GREATEST(LEAST(floor(extract(epoch from ?)) + ?, 9223372036854775807::numeric), 0::numeric), " <>
                           "GREATEST(LEAST(floor(extract(epoch from ?)) - 1, 9223372036854775807::numeric), 0::numeric)) " <>
                           "ELSE GREATEST(?::numeric, 0::numeric) END"
  @parent_deadline_sql "GREATEST(LEAST(floor(extract(epoch from ?)) - 1, 9223372036854775807::numeric), 0::numeric)"
  # JSONB maps are untrusted persisted state. A v1 wrapper is recognized only
  # when its version, ciphertext type, and exact two-key set all match. The
  # caller wraps this predicate in COALESCE because JSON operators return NULL
  # for missing/null members, and malformed state must never disappear from a
  # three-valued SQL predicate.
  @legacy_wrapper_sql "jsonb_typeof(?) = 'object' AND " <>
                        "(? - 'v' - 'ciphertext') = '{}'::jsonb AND " <>
                        "jsonb_typeof(?->'v') = 'number' AND " <>
                        "?->>'v' = '1' AND " <>
                        "jsonb_typeof(?->'ciphertext') = 'string'"
  # Current wrappers carry an authenticated deadline and child binding. Keep
  # retention logic limited to this exact v2 envelope and its expected JSON
  # types; unknown keys or versions use the conservative malformed path.
  @modern_wrapper_sql "jsonb_typeof(?) = 'object' AND " <>
                        "(? - 'v' - 'ciphertext' - 'retry_until' - 'child_hash') = '{}'::jsonb AND " <>
                        "jsonb_typeof(?->'v') = 'number' AND " <>
                        "?->>'v' = '2' AND " <>
                        "jsonb_typeof(?->'ciphertext') = 'string' AND " <>
                        "jsonb_typeof(?->'retry_until') = 'number' AND " <>
                        "jsonb_typeof(?->'child_hash') = 'string'"
  @modern_valid_wrapper_sql "COALESCE((" <>
                              @modern_wrapper_sql <>
                              " AND (" <> @valid_deadline_sql <> ")), false)"
  @malformed_wrapper_sql "NOT COALESCE((" <>
                           @modern_wrapper_sql <> " AND (" <> @valid_deadline_sql <> ")), false)"
  @legacy_retention_sql "NOT COALESCE((" <>
                          @legacy_wrapper_sql <>
                          "), false) OR " <>
                          "? IS NULL OR ? IS NULL OR (" <>
                          @fallback_deadline_sql <> ") < ?::numeric"
  @tombstone_wrapper_sql "jsonb_typeof(?) = 'object' AND " <>
                           "(? - 'v' - 'retry_until' - 'recoverable') = '{}'::jsonb AND " <>
                           "jsonb_typeof(?->'v') = 'number' AND " <>
                           "?->>'v' = '1' AND " <>
                           "jsonb_typeof(?->'retry_until') = 'number' AND " <>
                           "jsonb_typeof(?->'recoverable') = 'boolean' AND " <>
                           "?->>'recoverable' = 'false' AND (" <> @valid_deadline_sql <> ")"
  @valid_tombstone_sql "NOT COALESCE((" <> @tombstone_wrapper_sql <> "), false)"
  @modern_redaction_sql "jsonb_build_object('v', 1, 'retry_until', CASE WHEN ?->'retry_until' < to_jsonb(" <>
                          @parent_deadline_sql <>
                          ") THEN ?->'retry_until' ELSE to_jsonb(" <>
                          @parent_deadline_sql <>
                          ") END, 'recoverable', false)"
  @redaction_sql "jsonb_build_object('v', 1, 'retry_until', " <>
                   @fallback_deadline_sql <> ", 'recoverable', false)"

  @type rotation_error ::
          :family_revoked
          | :retry_state_unavailable
          | :token_conflict
          | :family_integrity_error
          | :invalid_rotation
          | :expired

  @doc """
  Persists a new unconsumed refresh token.

  Family revocation and `(family_id, generation)`/token uniqueness are checked
  while holding the same family lock used by rotation and revocation.
  """
  @impl Attesto.RefreshStore
  @spec insert(Attesto.RefreshStore.entry()) :: :ok | {:error, :family_revoked | :conflict}
  def insert(%{} = record) do
    validate_new_record!(record)
    prefix = table_prefix()
    repo = repo()
    Sweeper.check_running_for_store(repo, prefix)
    family_id = record.family_id

    result =
      repo.transaction(
        fn ->
          lock_family!(family_id)
          insert_locked(record, family_id, prefix)
        end,
        log: false,
        telemetry_event: nil
      )

    normalize_insert_result(result)
  end

  def insert(_record), do: invalid_record!()

  @doc """
  Strong primary read of a refresh record.

  Revoked families are intentionally hidden from the protocol layer. The
  query is always executed through the configured primary repo and carries the
  configured Ecto prefix explicitly.
  """
  @impl Attesto.RefreshStore
  @spec get(Attesto.RefreshStore.token_hash()) :: {:ok, Attesto.RefreshStore.entry()} | :error
  def get(token_hash) when is_binary(token_hash) do
    query =
      from(r in RefreshToken,
        left_join: revocation in RefreshFamilyRevocation,
        on: revocation.family_id == r.family_id,
        where: r.token_hash == ^token_hash and r.family_revoked == false,
        where: is_nil(revocation.family_id),
        select: r
      )

    case repo().one(query, prefix: table_prefix(), log: false, telemetry_event: nil) do
      %RefreshToken{} = row ->
        record = to_store_record(row)

        if valid_recovered_successor?(row, record.successor, table_prefix()) do
          {:ok, record}
        else
          {:ok, %{record | successor: nil}}
        end

      nil ->
        :error
    end
  end

  @doc """
  Atomically rotates `parent_hash` into `child`.

  The successor is protected before any database work. A positive successor
  requires the stable refresh-successor secret; failure to protect it returns
  `:retry_state_unavailable` without touching the database. Strict mode uses
  an exact non-secret tombstone and remains usable without that secret.
  """
  @impl Attesto.RefreshStore
  @spec rotate(
          Attesto.RefreshStore.token_hash(),
          Attesto.RefreshStore.entry(),
          map(),
          keyword()
        ) ::
          {:ok, Attesto.RefreshStore.entry(), Attesto.RefreshStore.entry()}
          | {:reuse, Attesto.RefreshStore.entry()}
          | {:error, rotation_error()}
          | :error
  def rotate(parent_hash, child, successor, opts \\ [])
      when is_binary(parent_hash) and is_map(child) and is_map(successor) and is_list(opts) do
    now = Keyword.get(opts, :now)

    with {:ok, now} <- valid_now(now),
         {:ok, protected} <- protect_successor(parent_hash, child, successor, now) do
      repo = repo()
      prefix = table_prefix()
      Sweeper.check_running_for_store(repo, prefix)
      result = rotate_transaction(parent_hash, child, successor, protected, now, repo, prefix)
      result
    else
      {:error, :retry_state_unavailable} -> {:error, :retry_state_unavailable}
      {:error, :invalid_rotation} -> {:error, :invalid_rotation}
    end
  end

  @doc """
  Serializes family revocation with inserts and rotations, durably records the
  tombstone, and removes every row in the family.
  """
  @impl Attesto.RefreshStore
  @spec revoke_family(Attesto.RefreshStore.family_id()) :: :ok
  def revoke_family(family_id) when is_binary(family_id) do
    prefix = table_prefix()
    repo = repo()
    Sweeper.check_running_for_store(repo, prefix)

    case repo.transaction(
           fn ->
             lock_family!(family_id)

             revoke_rows!(family_id, prefix)

             :ok
           end,
           log: false,
           telemetry_event: nil
         ) do
      {:ok, :ok} ->
        :ok

      {:error, _reason} ->
        raise RuntimeError, "#{inspect(__MODULE__)} revoke_family/1 transaction failed"

      _invalid_return ->
        raise RuntimeError,
              "#{inspect(__MODULE__)} revoke_family/1 violated the repo transaction contract"
    end
  end

  @doc false
  @spec redact_expired_successors(module(), DateTime.t(), keyword()) :: non_neg_integer()
  def redact_expired_successors(repo, %DateTime{} = now, opts \\ []) when is_atom(repo) and is_list(opts) do
    prefix = Keyword.get(opts, :prefix)
    grace = Keyword.get(opts, :legacy_grace_seconds, 0)

    if not (is_integer(grace) and grace >= 0) do
      raise ArgumentError, ":legacy_grace_seconds must be a non-negative integer"
    end

    now_unix = DateTime.to_unix(now, :second)

    # JSONB numbers are arbitrary precision and may be decimal or exponent
    # notation. Never cast a value read from JSONB to bigint: an adversarial
    # value can overflow before a predicate has a chance to reject it. The
    # text check admits only canonical integer syntax, while the JSONB numeric
    # comparisons enforce the range needed by the store contract.
    modern =
      from(r in RefreshToken,
        where: not is_nil(r.successor),
        where:
          fragment(
            @modern_valid_wrapper_sql,
            r.successor,
            r.successor,
            r.successor,
            r.successor,
            r.successor,
            r.successor,
            r.successor,
            r.successor,
            r.successor,
            r.successor,
            r.successor
          ),
        where:
          fragment("(?->'retry_until') < to_jsonb(?::numeric)", r.successor, ^now_unix) or
            r.expires_at <= ^now,
        update: [
          set: [
            successor:
              fragment(
                @modern_redaction_sql,
                r.successor,
                r.expires_at,
                r.successor,
                r.expires_at
              )
          ]
        ]
      )

    # Every other wrapper is malformed or legacy-undated. Redact it as well,
    # so bad state cannot retain credential-equivalent ciphertext forever.
    # Where timestamps are usable, preserve the v1 stopped-cutover deadline
    # calculation; otherwise use the already safe sweep instant.
    malformed =
      from(r in RefreshToken,
        where: not is_nil(r.successor),
        where:
          fragment(
            @malformed_wrapper_sql,
            r.successor,
            r.successor,
            r.successor,
            r.successor,
            r.successor,
            r.successor,
            r.successor,
            r.successor,
            r.successor,
            r.successor,
            r.successor
          ),
        where:
          fragment(
            @valid_tombstone_sql,
            r.successor,
            r.successor,
            r.successor,
            r.successor,
            r.successor,
            r.successor,
            r.successor,
            r.successor,
            r.successor,
            r.successor,
            r.successor
          ),
        where:
          fragment(
            @legacy_retention_sql,
            r.successor,
            r.successor,
            r.successor,
            r.successor,
            r.successor,
            r.consumed_at,
            r.expires_at,
            r.consumed_at,
            r.expires_at,
            r.consumed_at,
            ^grace,
            r.expires_at,
            ^now_unix,
            ^now_unix
          ),
        update: [
          set: [
            successor:
              fragment(
                @redaction_sql,
                r.consumed_at,
                r.expires_at,
                r.consumed_at,
                ^grace,
                r.expires_at,
                ^now_unix
              )
          ]
        ]
      )

    {modern_count, _} =
      repo.update_all(modern, [], prefix: prefix, log: false, telemetry_event: nil)

    {legacy_count, _} =
      repo.update_all(malformed, [], prefix: prefix, log: false, telemetry_event: nil)

    modern_count + legacy_count
  end

  defp rotate_transaction(parent_hash, child, successor, protected, now, repo, prefix) do
    repo.transaction(
      fn ->
        parent_query =
          from(r in RefreshToken,
            where: r.token_hash == ^parent_hash,
            select: r
          )

        case repo.one(parent_query, prefix: prefix, log: false, telemetry_event: nil) do
          nil ->
            repo.rollback(:not_found)

          %RefreshToken{family_id: family_id} ->
            # Discover the family from persisted state before taking the family
            # lock. Locking a caller-provided child family first lets malformed
            # input create lock-order inversions with a concurrent rotation or
            # revocation of the real parent family.
            lock_family!(family_id)

            locked_parent_query =
              from(r in RefreshToken,
                where: r.token_hash == ^parent_hash,
                lock: "FOR UPDATE",
                select: r
              )

            rotate_loaded_parent_or_revoke(
              repo.one(locked_parent_query, prefix: prefix, log: false, telemetry_event: nil),
              family_id,
              parent_hash,
              child,
              successor,
              protected,
              now,
              prefix
            )
        end
      end,
      log: false,
      telemetry_event: nil
    )
    |> unwrap_transaction()
  end

  defp rotate_loaded_parent_or_revoke(nil, family_id, parent_hash, child, successor, protected, now, prefix) do
    if family_revoked?(family_id, prefix) do
      repo().rollback(:family_revoked)
    else
      rotate_loaded_parent(nil, parent_hash, child, successor, protected, now, prefix)
    end
  end

  defp rotate_loaded_parent_or_revoke(
         %RefreshToken{} = row,
         _family_id,
         parent_hash,
         child,
         successor,
         protected,
         now,
         prefix
       ) do
    if family_revoked?(row.family_id, prefix) do
      repo().rollback(:family_revoked)
    else
      rotate_loaded_parent(row, parent_hash, child, successor, protected, now, prefix)
    end
  end

  defp rotate_loaded_parent(nil, _parent_hash, _child, _successor, _protected, _now, _prefix) do
    repo().rollback(:not_found)
  end

  defp rotate_loaded_parent(
         %RefreshToken{family_revoked: true},
         _parent_hash,
         _child,
         _successor,
         _protected,
         _now,
         _prefix
       ) do
    repo().rollback(:family_revoked)
  end

  defp rotate_loaded_parent(
         %RefreshToken{consumed: true} = row,
         _parent_hash,
         _child,
         _successor,
         _protected,
         _now,
         _prefix
       ) do
    {:reuse, to_store_record(row)}
  end

  defp rotate_loaded_parent(%RefreshToken{} = row, parent_hash, child, successor, protected, now, prefix) do
    case validate_rotation(row, parent_hash, child, successor, now, prefix) do
      :ok ->
        commit_rotation(row, child, protected, now, prefix)

      {:error, :family_integrity_error} ->
        revoke_rows!(row.family_id, prefix)
        {:error, :family_integrity_error}

      {:error, reason} ->
        repo().rollback(reason)
    end
  end

  defp insert_locked(record, family_id, prefix) do
    cond do
      family_revoked?(family_id, prefix) ->
        repo().rollback(:family_revoked)

      generation_taken?(family_id, Map.get(record, :generation, 0), prefix) ->
        repo().rollback(:conflict)

      true ->
        insert_record(record, prefix)
    end
  end

  defp validate_new_record!(record) do
    if RefreshToken.valid_store_record?(record) and
         Map.get(record, :consumed) == false and
         is_nil(Map.get(record, :consumed_at)) and
         is_nil(Map.get(record, :successor)) do
      :ok
    else
      invalid_record!()
    end
  end

  defp invalid_record!, do: raise(ArgumentError, "refresh token record violates the canonical store contract")

  defp insert_record(record, prefix) do
    changeset =
      %RefreshToken{}
      |> RefreshToken.insert_changeset(RefreshToken.from_store_record(record, prefix: prefix))

    case repo().insert(changeset, prefix: prefix, log: false, telemetry_event: nil) do
      {:ok, _row} -> :ok
      {:error, changeset} -> repo().rollback(insert_error(changeset))
    end
  end

  defp normalize_insert_result({:ok, :ok}), do: :ok
  defp normalize_insert_result({:error, :family_revoked}), do: {:error, :family_revoked}
  defp normalize_insert_result({:error, :conflict}), do: {:error, :conflict}
  defp normalize_insert_result({:error, _reason}), do: {:error, :conflict}

  defp commit_rotation(row, child, protected, now, prefix) do
    parent_changeset =
      row
      |> RefreshToken.claim_changeset(DateTime.from_unix!(now, :second))
      |> Ecto.Changeset.change(successor: protected)

    # The successor wrapper contains credential-equivalent encrypted state.
    # Ecto logs bound parameters at debug level unless told otherwise, so this
    # write must never enter the host's query log.
    with {:ok, committed_parent} <-
           repo().update(parent_changeset, prefix: prefix, log: false, telemetry_event: nil),
         {:ok, committed_child} <- insert_child(child, row.token_hash, prefix) do
      {:ok, to_store_record(committed_parent), to_store_record(committed_child)}
    else
      {:error, changeset} -> repo().rollback(insert_error(changeset))
    end
  end

  defp insert_child(child, parent_hash, prefix) do
    changeset =
      %RefreshToken{}
      |> RefreshToken.insert_changeset(RefreshToken.from_store_record(child, parent_hash: parent_hash))

    repo().insert(changeset, prefix: prefix, log: false, telemetry_event: nil)
  end

  defp validate_rotation(row, parent_hash, child, successor, now, prefix) do
    with :ok <- validate_parent(row, parent_hash),
         :ok <- validate_child_record(child),
         :ok <- validate_child(row, child, parent_hash),
         :ok <- validate_expiry(row, child, now),
         :ok <- validate_generation(row, child, prefix),
         :ok <- validate_token_hash(child, prefix) do
      validate_successor(successor, child, now)
    end
  end

  defp validate_child_record(child) do
    if RefreshToken.valid_store_record?(child) and
         Map.get(child, :consumed) == false and
         is_nil(Map.get(child, :consumed_at)) and
         is_nil(Map.get(child, :successor)) do
      :ok
    else
      {:error, :invalid_rotation}
    end
  end

  defp validate_parent(%RefreshToken{token_hash: token_hash}, token_hash), do: :ok
  defp validate_parent(_row, _parent_hash), do: {:error, :invalid_rotation}

  defp validate_child(row, child, parent_hash) do
    token_hash = Map.get(child, :token_hash)
    family_id = Map.get(child, :family_id)
    generation = Map.get(child, :generation)
    consumed = Map.get(child, :consumed)
    consumed_at = Map.get(child, :consumed_at)

    cond do
      not is_binary(token_hash) or token_hash == parent_hash -> {:error, :invalid_rotation}
      family_id != row.family_id -> {:error, :invalid_rotation}
      generation != row.generation + 1 -> {:error, :invalid_rotation}
      consumed != false or not is_nil(consumed_at) -> {:error, :invalid_rotation}
      true -> :ok
    end
  end

  defp validate_expiry(row, child, now) do
    child_expires_at = Map.get(child, :expires_at)

    cond do
      not is_integer(child_expires_at) or child_expires_at <= now -> {:error, :invalid_rotation}
      DateTime.to_unix(row.expires_at, :second) <= now -> {:error, :expired}
      true -> :ok
    end
  end

  defp validate_generation(row, child, prefix) do
    if generation_taken?(row.family_id, Map.get(child, :generation), prefix),
      do: {:error, :family_integrity_error},
      else: :ok
  end

  defp validate_token_hash(child, prefix) do
    if token_hash_taken?(Map.get(child, :token_hash), prefix),
      do: {:error, :token_conflict},
      else: :ok
  end

  defp validate_successor(successor, child, now) do
    if valid_positive_successor?(successor, child, now) or valid_strict_successor?(successor, now),
      do: :ok,
      else: {:error, :invalid_rotation}
  end

  defp valid_positive_successor?(
         %{token: token, generation: generation, context: context, retry_until: retry_until} = successor,
         child,
         now
       )
       when is_binary(token) and token != "" and is_integer(generation) and
              (is_map(context) and is_integer(retry_until)) do
    child_family_id = Map.get(child, :family_id)
    child_generation = Map.get(child, :generation)
    child_expires_at = Map.get(child, :expires_at)

    valid_successor_contexts?(child, context) and
      valid_child_identity?(child, token, child_family_id, child_generation, child_expires_at) and
      valid_successor_payload?(child, token, generation, context) and
      valid_successor_deadline?(retry_until, child_expires_at, now) and
      exact_positive_successor_keys?(successor)
  end

  defp valid_positive_successor?(_successor, _child, _now), do: false

  defp valid_child_identity?(child, token, family_id, generation, expires_at) do
    is_binary(family_id) and is_integer(generation) and is_integer(expires_at) and
      token_hash(token) == Map.get(child, :token_hash)
  end

  defp valid_successor_contexts?(child, context) do
    RefreshToken.valid_context?(Map.get(child, :data)) and RefreshToken.valid_context?(context)
  end

  defp valid_successor_payload?(child, token, generation, context) do
    generation == Map.get(child, :generation) and context == Map.get(child, :data) and token != ""
  end

  defp valid_successor_deadline?(retry_until, expires_at, now) do
    retry_until >= now and retry_until < expires_at
  end

  defp exact_positive_successor_keys?(successor) do
    Map.keys(successor) |> Enum.sort() == [:context, :generation, :retry_until, :token]
  end

  defp valid_strict_successor?(%{retry_until: retry_until, recoverable: false} = successor, now)
       when is_integer(retry_until), do: retry_until == now and map_size(successor) == 2

  defp valid_strict_successor?(_successor, _now), do: false

  defp protect_successor(parent_hash, child, successor, now) do
    cond do
      valid_strict_successor?(successor, now) ->
        {:ok, %{"v" => 1, "retry_until" => now, "recoverable" => false}}

      valid_positive_successor?(successor, child, now) ->
        aad =
          RefreshSuccessorCipher.binding_aad(
            parent_hash,
            child.family_id,
            child.generation - 1,
            child.token_hash,
            successor.retry_until
          )

        case RefreshSuccessorCipher.encrypt(successor, aad) do
          {:ok, ciphertext} ->
            {:ok,
             %{
               "v" => 2,
               "ciphertext" => ciphertext,
               "retry_until" => successor.retry_until,
               "child_hash" => child.token_hash
             }}

          :error ->
            {:error, :retry_state_unavailable}
        end

      true ->
        {:error, :invalid_rotation}
    end
  end

  defp unwrap_transaction({:ok, result}), do: result
  defp unwrap_transaction({:error, :not_found}), do: :error

  defp unwrap_transaction({:error, reason})
       when reason in [
              :family_revoked,
              :retry_state_unavailable,
              :token_conflict,
              :family_integrity_error,
              :invalid_rotation,
              :expired
            ], do: {:error, reason}

  defp valid_now(now) when is_integer(now) and now >= 0, do: {:ok, now}
  defp valid_now(_), do: {:error, :invalid_rotation}

  defp family_revoked?(family_id, prefix) do
    repo().exists?(
      from(r in RefreshFamilyRevocation, where: r.family_id == ^family_id),
      prefix: prefix,
      log: false,
      telemetry_event: nil
    ) or
      repo().exists?(
        from(r in RefreshToken, where: r.family_id == ^family_id and r.family_revoked == true),
        prefix: prefix,
        log: false,
        telemetry_event: nil
      )
  end

  defp generation_taken?(family_id, generation, prefix) when is_binary(family_id) and is_integer(generation) do
    repo().exists?(
      from(r in RefreshToken, where: r.family_id == ^family_id and r.generation == ^generation),
      prefix: prefix,
      log: false,
      telemetry_event: nil
    )
  end

  defp generation_taken?(_family_id, _generation, _prefix), do: true

  defp token_hash_taken?(hash, prefix) do
    repo().exists?(
      from(r in RefreshToken, where: r.token_hash == ^hash),
      prefix: prefix,
      log: false,
      telemetry_event: nil
    )
  end

  defp revoke_rows!(family_id, prefix) do
    mark_family_revoked!(family_id, prefix)

    repo().delete_all(
      from(r in RefreshToken, where: r.family_id == ^family_id),
      prefix: prefix,
      log: false,
      telemetry_event: nil
    )

    :ok
  end

  defp mark_family_revoked!(family_id, prefix) do
    revoked_at = DateTime.utc_now() |> DateTime.truncate(:second)

    case repo().insert(
           %RefreshFamilyRevocation{family_id: family_id, revoked_at: revoked_at},
           on_conflict: :nothing,
           conflict_target: [:family_id],
           prefix: prefix,
           log: false,
           telemetry_event: nil
         ) do
      {:ok, _row} ->
        :ok

      {:error, _changeset} ->
        raise RuntimeError, "#{inspect(__MODULE__)} could not persist refresh-family revocation"
    end
  end

  defp insert_error(%Ecto.Changeset{} = changeset) do
    if Enum.any?(changeset.errors, fn {field, {_message, opts}} ->
         field in [:token_hash, :family_id, :generation] and opts[:constraint] == :unique
       end) do
      :token_conflict
    else
      :invalid_rotation
    end
  end

  defp insert_error(_), do: :invalid_rotation

  defp lock_family!(family_id) do
    repo().query!(
      "SELECT pg_advisory_xact_lock($1::int4, hashtext($2))",
      [@advisory_lock_namespace, family_id],
      log: false,
      telemetry_event: nil
    )
  end

  defp token_hash(token), do: Attesto.Secret.hash(token)

  # A v1 successor wrapper did not persist its retry deadline. Resolve the
  # configured grace once per read and let the schema derive a deadline from
  # the row's consumed_at/expiry timestamps. Request-local config wins so
  # tenant-specific settings cannot bleed into another request.
  defp to_store_record(%RefreshToken{} = row) do
    RefreshToken.to_store_record(row, legacy_grace_seconds: refresh_rotation_grace_seconds())
  end

  # v2 carries the child hash in its authenticated wrapper. Legacy v1
  # ciphertext predates that binding, so establish the missing family,
  # generation, token-hash, and context relation from durable lineage before
  # exposing its decrypted token. A 2.x child has no parent_hash, so the
  # legacy path accepts that exact child while still rejecting copied state
  # from another family or a current child with a different lineage marker.
  defp valid_recovered_successor?(_row, nil, _prefix), do: true

  defp valid_recovered_successor?(_row, %{recoverable: false}, _prefix), do: true

  defp valid_recovered_successor?(
         %RefreshToken{token_hash: parent_hash, family_id: family_id, generation: parent_generation} = row,
         %{token: token, generation: generation, context: context},
         prefix
       )
       when is_binary(token) and is_integer(parent_generation) and is_integer(generation) and
              generation == parent_generation + 1 and is_map(context) do
    child_hash = token_hash(token)

    child_query =
      from(child in RefreshToken,
        where:
          child.token_hash == ^child_hash and child.family_id == ^family_id and
            child.generation == ^generation,
        select: child
      )

    child = repo().one(child_query, prefix: prefix, log: false, telemetry_event: nil)
    valid_recovered_child?(row, child, parent_hash, generation, context)
  end

  defp valid_recovered_successor?(_row, _successor, _prefix), do: false

  defp valid_recovered_child?(_row, nil, _parent_hash, _generation, _context), do: false

  defp valid_recovered_child?(row, %RefreshToken{} = child, parent_hash, generation, context) do
    recovered_child_lineage_matches?(row, child, parent_hash) and
      recovered_child_matches?(child, generation, context)
  end

  defp recovered_child_lineage_matches?(row, child, parent_hash) do
    child.parent_hash == parent_hash or
      (legacy_v1_wrapper?(row.successor) and is_nil(child.parent_hash))
  end

  defp legacy_v1_wrapper?(%{"v" => 1, "ciphertext" => ciphertext} = wrapper) when is_binary(ciphertext),
    do: Map.keys(wrapper) |> Enum.sort() == ["ciphertext", "v"]

  defp legacy_v1_wrapper?(%{v: 1, ciphertext: ciphertext} = wrapper) when is_binary(ciphertext),
    do: Map.keys(wrapper) |> Enum.sort() == [:ciphertext, :v]

  defp legacy_v1_wrapper?(_wrapper), do: false

  defp recovered_child_matches?(%RefreshToken{} = child, generation, context) do
    child_record = to_store_record(child)
    child_record.generation == generation and child_record.data == context
  rescue
    ArgumentError -> false
  end

  defp refresh_rotation_grace_seconds do
    case Config.request_config() do
      %Config{refresh_token_rotation_grace_seconds: grace} ->
        grace

      nil ->
        case Application.get_env(@app, :otp_app) do
          otp_app when is_atom(otp_app) and not is_nil(otp_app) ->
            Config.from_otp_app(otp_app).refresh_token_rotation_grace_seconds

          _other ->
            0
        end
    end
  end

  defp table_prefix, do: Config.table_prefix()

  defp repo do
    Config.ecto_repo!(
      "#{inspect(__MODULE__)} requires an Ecto.Repo configured as " <>
        "config #{inspect(@app)}, repo: MyApp.Repo"
    )
  end
end
