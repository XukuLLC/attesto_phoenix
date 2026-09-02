defmodule AttestoPhoenix.Store.EctoCodeStore do
  @moduledoc """
  Ecto implementation of the `Attesto.CodeStore` behaviour.

  Authorization codes are single-use (RFC 6749 §4.1.2) and, with PKCE
  mandatory (RFC 7636), the code is the only browser-deliverable secret in
  the authorization-code flow. The single-use guarantee therefore cannot be
  advisory: it must be enforced by the store so that two concurrent
  redemptions of one code cannot both succeed.

  `take/1` issues an `UPDATE ... WHERE consumed_at IS NULL RETURNING ...`, so
  the fetch and the consumption mark are one statement. Exactly one of any
  number of racing redemptions sees the row as fresh; later callers either get
  `:error` for an unsuccessful first presentation or `{:error, :consumed, meta}`
  for a code that was already successfully redeemed. This holds across all
  nodes sharing the database. The code is consumed even when the caller later
  rejects the redemption (mismatched redirect URI, failed PKCE verifier): a code
  presented once is spent, which denies an attacker repeated validation
  attempts against a captured code.

  The plaintext code is never persisted; the unique database key is the
  `Attesto.Secret.hash/1` digest of the code. The column layout and the
  record bridge live in `AttestoPhoenix.Schema.Authorization`; the bridge
  emits core's canonical authorization-code data map, with `S256` implicit and
  the OIDC `nonce` inside `claims`. This module owns the atomic code operations
  and the optional access-token linkage used
  by replay containment. Refresh-flow linkage is selected by code hash before
  the core binds the row to its newly issued refresh family.

  The repository module is resolved at call time from the validated
  request-local configuration, then the host configuration selected by
  `:otp_app`; the package-level `:attesto_phoenix` setting is only the legacy
  fallback when no `:otp_app` pointer exists. A store with no backing
  repository can make no guarantees, so a missing `:repo` fails closed rather
  than silently no-opping.

  ## Query observability

  The `claims` column carries the authentication context and, for a host that
  configures `:authorization_code_private_context`, that host's private
  authorization state. Ecto SQL query telemetry reports params, cast params,
  and decoded results, and every authorization-row query carries at least one
  security-sensitive value - a code hash, subject, family ID, or access-token
  JTI - even when it does not touch the `claims` column. So every operation in
  this store suppresses both application SQL logging and the
  `[:my_app, :repo, :query]` telemetry event. The reuse-detection reads
  additionally select only the columns they report, keeping the `claims` JSONB
  out of the decoded row as defence in depth.

  > #### Suppression is unconditional {: .warning}
  >
  > It applies to every deployment, including one that never enables
  > `:authorization_code_private_context`. Repository resolution can use the
  > request-local `AttestoPhoenix.Config`, but observability does not vary with
  > that option; standalone store calls may have no request-local config at all.
  > Custom stores and database-server logging remain the host's responsibility.
  """

  @behaviour Attesto.CodeStore

  import Ecto.Query, only: [from: 2]

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Schema.Authorization

  # Ecto SQL query telemetry includes params/cast_params and decoded results.
  # Every authorization-row query carries at least one security-sensitive value
  # - a code hash, subject, family ID, or access-token JTI - even when it does
  # not select the private-context column, so all of them suppress application
  # logging and telemetry.
  @claims_query_opts [log: false, telemetry_event: nil]

  @doc """
  Persists an authorization-code record keyed by its `:code_hash`.

  The record is the plain map the protocol layer hands over: a `:code_hash`,
  the opaque grant `:data`, and an integer `:expires_at` in unix seconds.
  `AttestoPhoenix.Schema.Authorization.from_record/1` spreads it across the
  row's columns and validates it fail-closed (missing required field or a
  non-`S256` PKCE method is rejected, not defaulted). The record returned by
  `take/1` contains core's canonical data keys only; database compatibility
  columns for the PKCE method and legacy top-level nonce are not emitted.

  The hash is the unique database key, so a duplicate insert is a caller bug:
  `Attesto.AuthorizationCode` derives the hash from freshly generated random
  bytes, so a collision means the random source repeated or the same entry
  was put twice. A unique-constraint violation raises a sanitized
  `Ecto.InvalidChangesetError` rather than exposing the failed changeset, which
  can contain authorization claims and host-private context. Fail closed; no
  upsert.
  """
  @impl Attesto.CodeStore
  @spec put(Attesto.CodeStore.entry()) :: :ok
  def put(%{code_hash: code_hash, data: data, expires_at: expires_at} = record)
      when is_binary(code_hash) and is_map(data) and is_integer(expires_at) do
    prefix = Config.table_prefix()

    record
    |> Authorization.from_record(prefix: prefix)
    |> repo().insert([prefix: prefix] ++ @claims_query_opts)
    |> case do
      {:ok, _row} -> :ok
      {:error, %Ecto.Changeset{}} -> raise_sanitized_insert_error()
    end
  end

  @doc """
  Atomically fetches and consumes the record for `code_hash`.

  Returns `{:ok, entry}` when the row existed and was still live,
  `{:error, :consumed, meta}` when it was already successfully redeemed, or
  `:error` when it was absent. The fetch and the consume mark are one
  indivisible statement (`UPDATE ... WHERE consumed_at IS NULL RETURNING ...`),
  so the single-use contract of `Attesto.CodeStore` holds against concurrent
  redemptions.

  The loaded row is folded back into the `:code_hash` / canonical `:data` /
  `:expires_at` (unix seconds) map via
  `AttestoPhoenix.Schema.Authorization.to_record/1`. Expiry is not checked
  here: `Attesto.AuthorizationCode` re-checks `:expires_at` after `take/1`,
  and consuming the row regardless of freshness preserves single use, since
  an expired-but-present code is still spent on first presentation.
  """
  @impl Attesto.CodeStore
  @spec take(Attesto.CodeStore.code_hash()) ::
          {:ok, Attesto.CodeStore.entry()} | :error | {:error, :consumed, Attesto.CodeStore.consumed_meta()}
  def take(code_hash) when is_binary(code_hash) do
    prefix = Config.table_prefix()
    consumed_at = DateTime.utc_now() |> DateTime.truncate(:second)

    query =
      from a in Authorization,
        where: a.code_hash == ^code_hash and is_nil(a.consumed_at),
        select: a

    case repo().update_all(query, [set: [consumed_at: consumed_at]], [prefix: prefix] ++ @claims_query_opts) do
      {1, [row]} -> {:ok, Authorization.to_record(row)}
      {0, _} -> consumed_or_missing(code_hash, prefix)
    end
  end

  @doc """
  Reads the live (unconsumed) record for `code_hash` WITHOUT consuming it.

  Returns `{:ok, entry}` for a present, not-yet-consumed code, or `:error`
  otherwise. Unlike `take/1` this is a plain SELECT - it does NOT mark the code
  consumed - so it is safe for read-only pre-checks at the token endpoint (e.g.
  a holder-of-key / DPoP requirement, RFC 9449 §10) without burning single use.
  """
  @impl Attesto.CodeStore
  @spec get(Attesto.CodeStore.code_hash()) :: {:ok, Attesto.CodeStore.entry()} | :error
  def get(code_hash) when is_binary(code_hash) do
    prefix = Config.table_prefix()

    query =
      from a in Authorization,
        where: a.code_hash == ^code_hash and is_nil(a.consumed_at),
        select: a

    case repo().one(query, [prefix: prefix] ++ @claims_query_opts) do
      nil -> :error
      row -> {:ok, Authorization.to_record(row)}
    end
  end

  @doc """
  Marks a successfully redeemed code as reuse-trackable.

  `Attesto.AuthorizationCode.redeem/4` calls this after every validation step
  has passed. A later `take/1` for the same hash can then surface
  `{:error, :consumed, meta}` instead of treating the replay as an unknown code.
  When the core's `issue_refresh_and_finalize/6` composition supplies the
  family actually issued, this update binds that family to the consumed
  authorization row atomically with the success marker. That lets access-token
  revocation index the minted token under the same family used by replay
  containment without accepting a caller-supplied family identifier.
  """
  @impl Attesto.CodeStore
  @spec mark_consumed(Attesto.CodeStore.code_hash(), Attesto.CodeStore.consumed_meta()) :: :ok
  def mark_consumed(code_hash, %{family_id: family_id})
      when is_binary(code_hash) and is_binary(family_id) and family_id != "" do
    mark_consumed_row(code_hash, family_id: family_id)
  end

  def mark_consumed(code_hash, %{family_id: nil}) when is_binary(code_hash) do
    # `nil` is an explicit no-refresh marker. Clear any authorization-code
    # provenance family so replay containment cannot mistake it for a refresh
    # family during a later redemption.
    mark_consumed_row(code_hash, family_id: nil)
  end

  def mark_consumed(code_hash, %{}) when is_binary(code_hash) do
    mark_consumed_row(code_hash, family_id: nil)
  end

  def mark_consumed(_code_hash, _invalid_meta) do
    raise ArgumentError, "#{inspect(__MODULE__)}.mark_consumed/2 received invalid consumed metadata"
  end

  defp mark_consumed_row(code_hash, family_updates) when is_binary(code_hash) and is_list(family_updates) do
    prefix = Config.table_prefix()
    query = from a in Authorization, where: a.code_hash == ^code_hash
    updates = [consumed_success: true] ++ family_updates

    query
    |> repo().update_all([set: updates], prefix: prefix, log: false, telemetry_event: nil)
    |> expect_one_updated!(:mark_consumed)
  end

  @doc false
  @spec record_access_token(String.t(), String.t(), integer()) :: :ok
  def record_access_token(family_id, jti, expires_at)
      when is_binary(family_id) and is_binary(jti) and is_integer(expires_at) do
    prefix = Config.table_prefix()
    query = from a in Authorization, where: a.family_id == ^family_id

    record_access_token_row(query, jti, expires_at, prefix)
  end

  # Records a minted access token against the authorization row for `code_hash`.
  # This form is used before initial refresh issuance finalizes the code, when
  # the family returned by RefreshToken.issue/3 is not known yet. The code hash
  # selects the exact consumed row; finalization then binds its family ID.
  @doc false
  @spec record_access_token_for_code(String.t(), String.t(), integer()) :: :ok
  def record_access_token_for_code(code_hash, jti, expires_at)
      when is_binary(code_hash) and code_hash != "" and is_binary(jti) and is_integer(expires_at) do
    prefix = Config.table_prefix()
    query = from a in Authorization, where: a.code_hash == ^code_hash

    record_access_token_row(query, jti, expires_at, prefix)
  end

  defp record_access_token_row(query, jti, expires_at, prefix) do
    expect_one_updated!(
      repo().update_all(
        query,
        [
          set: [
            access_token_jti: jti,
            access_token_expires_at: DateTime.from_unix!(expires_at)
          ]
        ],
        prefix: prefix,
        log: false,
        telemetry_event: nil
      ),
      :record_access_token
    )
  end

  @doc false
  @spec revoke_family_access_tokens(String.t()) :: :ok
  def revoke_family_access_tokens(family_id) when is_binary(family_id) do
    prefix = Config.table_prefix()
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    query =
      from a in Authorization,
        where: a.family_id == ^family_id and not is_nil(a.access_token_jti)

    repo().update_all(query, [set: [access_token_revoked_at: now]],
      prefix: prefix,
      log: false,
      telemetry_event: nil
    )

    :ok
  end

  @doc false
  @spec revoke_access_token_for_code(String.t()) :: :ok
  def revoke_access_token_for_code(code_hash) when is_binary(code_hash) and code_hash != "" do
    prefix = Config.table_prefix()
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    # 2.14.x consumed-code rows can predate access-token linkage. Replay
    # containment is deliberately idempotent for those rows: there is no token
    # to revoke, and requiring an UPDATE count of one would turn an ordinary
    # invalid_grant into a 500. Update first so a concurrent sweeper cannot
    # delete a row between a read and the security-critical revocation.
    query =
      from a in Authorization,
        where:
          a.code_hash == ^code_hash and not is_nil(a.access_token_jti) and
            a.access_token_jti != ^""

    case repo().update_all(query, [set: [access_token_revoked_at: now]],
           prefix: prefix,
           log: false,
           telemetry_event: nil
         ) do
      {1, _rows} ->
        :ok

      {0, _rows} ->
        # A zero count is safe only for an absent row or the legacy nil-JTI
        # record. If a linked row remains, fail closed instead of claiming that
        # its access token was revoked.
        legacy_or_missing_revoke(code_hash, prefix)

      _unexpected_count ->
        raise RuntimeError,
              "#{inspect(__MODULE__)}.revoke_access_token_for_code failed to update exactly one authorization record"
    end
  end

  # Selects only the linkage column it inspects, for the same reason as
  # `consumed_or_missing/2`: a whole-row read would publish `claims` through
  # query telemetry.
  defp legacy_or_missing_revoke(code_hash, prefix) do
    query =
      from a in Authorization,
        where: a.code_hash == ^code_hash,
        select: [:access_token_jti]

    case repo().one(query, [prefix: prefix] ++ @claims_query_opts) do
      nil ->
        :ok

      %Authorization{access_token_jti: nil} ->
        :ok

      %Authorization{access_token_jti: jti} when is_binary(jti) and jti != "" ->
        raise RuntimeError,
              "#{inspect(__MODULE__)}.revoke_access_token_for_code failed to update exactly one authorization record"

      _malformed_row ->
        raise RuntimeError,
              "#{inspect(__MODULE__)}.revoke_access_token_for_code found invalid access-token linkage"
    end
  end

  @doc false
  @spec access_token_revoked?(String.t()) :: boolean()
  def access_token_revoked?(jti) when is_binary(jti) do
    prefix = Config.table_prefix()
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    query =
      from a in Authorization,
        where:
          a.access_token_jti == ^jti and not is_nil(a.access_token_revoked_at) and
            a.access_token_expires_at > ^now

    repo().exists?(query, prefix: prefix, log: false, telemetry_event: nil)
  end

  # Selects only the three columns it reports, and suppresses logging and
  # telemetry like every other authorization-row query. The narrow select is
  # defence in depth: it keeps the `claims` JSONB - which carries host private
  # context - out of the decoded row entirely, so re-enabling observability here
  # could not leak it. `redact: true` would not help; telemetry carries the raw
  # row, not the struct.
  defp consumed_or_missing(code_hash, prefix) do
    query =
      from a in Authorization,
        where: a.code_hash == ^code_hash,
        select: [:family_id, :subject, :consumed_success]

    case repo().one(query, [prefix: prefix] ++ @claims_query_opts) do
      %Authorization{consumed_success: true} = row ->
        {:error, :consumed, Authorization.consumed_meta(row)}

      _ ->
        :error
    end
  end

  defp expect_one_updated!({1, _rows}, _operation), do: :ok

  defp expect_one_updated!({_unexpected_count, _rows}, operation) do
    raise RuntimeError,
          "#{inspect(__MODULE__)}.#{operation} failed to update exactly one authorization record"
  end

  # `Ecto.InvalidChangesetError.message/1` renders the original changes and
  # params without consulting schema redaction. Keep the established exception
  # class while replacing the failed insert changeset with a value-free one.
  defp raise_sanitized_insert_error do
    safe_changeset =
      %Authorization{}
      |> Ecto.Changeset.change()
      |> Ecto.Changeset.add_error(:code_hash, "authorization code could not be stored")

    raise Ecto.InvalidChangesetError, action: :insert, changeset: safe_changeset
  end

  defp repo, do: Config.ecto_repo!()
end
