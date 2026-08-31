defmodule AttestoPhoenix.Schema.RefreshToken do
  @moduledoc """
  Ecto schema for the refresh-token records that back an Ecto-backed
  `Attesto.RefreshStore`.

  Refresh tokens are rotated single-use credentials (RFC 6749 §6, §10.4;
  OAuth 2.0 Security BCP §4.14). Presenting a token consumes it and mints a
  successor in the same *family*. An immediate matching retry may recover the
  same still-unused successor inside its fixed grace window; an already-
  consumed token presented outside those conditions is the captured-token
  signal that revokes the whole family. Token hashes are persisted instead of
  the presented plaintext. When retry grace is enabled, the already-minted
  successor is retained as encrypted, credential-equivalent state only until
  its fixed retry deadline; the supervised store sweeper irreversibly removes
  the ciphertext on its next run.

  Successor recovery accepts the stopped-cutover legacy v1 envelope (`v` plus
  authenticated `ciphertext`) and the current v2 envelope (those fields plus
  the bound child hash and matching retry deadline). v1 uses the package-wide
  authenticated-data value, so its binding is deliberately reduced: it is not
  cryptographically tied to a parent or family. The Ecto store compensates by
  requiring a matching durable child lineage before exposing a v1 successor.
  It also accepts the exact strict v1 tombstone (`v`, `retry_until`,
  `recoverable: false`). Legacy v1 ciphertext payloads may omit the deadline
  and derive it from persisted consumption time and configured grace;
  unsupported or extra payload members are rejected.

  ## Columns

    * `:token_hash` - `Attesto.Secret.hash/1` of the token. The lookup key;
      a unique index enforces one row per token.
    * `:family_id` - groups every token descended from one authorization
      grant. Revoked together on reuse detection.
    * `:generation` - rotation generation within the family (`0` for the
      first token).
    * `:client_id` - the OAuth client the token was issued to (RFC 6749 §10.4
      requires rotation to be confined to the issuing client). `nil` for a
      token with no client binding.
    * `:subject` - the resource owner the token authorizes.
    * `:scope` - the granted scope as a list of strings (RFC 6749 §3.3); a
      successor's scope MUST be a subset of its predecessor's.
    * `:cnf` - the RFC 7800 confirmation claim binding the token to a proof of
      possession (e.g. `%{"jkt" => thumbprint}` for a DPoP key, RFC 9449;
      `%{"x5t#S256" => thumbprint}` for an mTLS certificate, RFC 8705). `nil`
      for a bearer token.
    * `:claims` - opaque issuer context round-tripped into the next access
      token. A recursively portable JSON object with string keys; never `nil`.
    * `:consumed` - whether the token has already been rotated. The atomic
      transition of this flag (see `claim_changeset/1`) is what makes reuse
      detection reliable.
    * `:consumed_at` - when the token was rotated, used for the short
      idempotency window on honest refresh retries.
    * `:successor` - encrypted already-minted successor returned during an
      idempotent retry. The plaintext successor token is never stored directly
      in the database.
    * `:family_revoked` - whether the token's family has been revoked. A
      revoked family fails closed: no row in it may be rotated, and no
      successor may be inserted into it (sticky revocation).
    * `:expires_at` - absolute expiry. A token at or past its expiry is
      refused without being consumed.
    * `:parent_hash` - the `:token_hash` of the predecessor that minted this
      token, or `nil` for the first token in a family. Diagnostic lineage; it
      is never used as a lookup key.
    * `:inserted_at` - issuance time, set on insert.

  ## Confirmation translation

  `Attesto.RefreshToken` carries the proof-of-possession binding as a
  `:dpop_jkt` thumbprint inside its opaque context map. This schema persists
  the binding as a structured `:cnf` confirmation so the same column can hold
  any RFC 7800 member. `from_store_record/2` folds a `:dpop_jkt` into a `cnf`,
  and `to_store_record/1` unfolds it back, so the protocol layer continues to
  speak `:dpop_jkt` while storage stays confirmation-shaped. The bridge accepts
  only `nil` or an exact one-member DPoP confirmation (`%{"jkt" => thumbprint}`
  from JSONB, or `%{jkt: thumbprint}` from an atom-keyed compatibility row),
  where the thumbprint is canonical. An unsupported RFC 7800 member, an extra
  confirmation member, or a malformed thumbprint remains invalid on recovery;
  it is never projected to an unbound (`nil`) token.
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Attesto.Claims
  alias Attesto.Scope
  alias Attesto.Thumbprint
  alias AttestoPhoenix.RefreshSuccessorCipher

  # RFC 9449 (DPoP): the confirmation member naming the JWK thumbprint of the
  # bound key.
  @cnf_jkt "jkt"
  @canonical_context_keys [:subject, :scope, :resource, :acr, :auth_time, :client_id, :dpop_jkt, :claims]
  @canonical_context_string_keys Enum.map(@canonical_context_keys, &Atom.to_string/1)
  @invalid_confirmation :invalid_refresh_confirmation
  @invalid_record_message "refresh token record violates the canonical store contract"
  @type t :: %__MODULE__{}

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "attesto_refresh_tokens" do
    field :token_hash, :string
    field :family_id, :string
    field :generation, :integer, default: 0
    field :client_id, :string
    field :subject, :string
    field :scope, {:array, :string}, default: []
    field :resource, {:array, :string}, default: []
    # RFC 9470 / OIDC Core §2: the ORIGINAL authentication context, carried
    # across rotation so a refresh-minted access token reports the real auth
    # event (auth_time is never re-stamped). `auth_time` is unix seconds.
    field :acr, :string
    field :auth_time, :integer
    field :cnf, :map
    field :claims, :map, default: %{}
    field :consumed, :boolean, default: false
    field :consumed_at, :utc_datetime
    field :successor, :map
    field :family_revoked, :boolean, default: false
    field :expires_at, :utc_datetime
    field :parent_hash, :string

    timestamps(updated_at: false, type: :utc_datetime)
  end

  @required [:token_hash, :family_id, :subject, :expires_at]
  @permitted [
    :token_hash,
    :family_id,
    :generation,
    :client_id,
    :subject,
    :scope,
    :resource,
    :acr,
    :auth_time,
    :cnf,
    :claims,
    :consumed,
    :consumed_at,
    :successor,
    :family_revoked,
    :expires_at,
    :parent_hash
  ]

  @doc """
  Changeset for inserting a new (unconsumed) refresh-token record.

  Validates the columns the store contract requires and enforces single-use
  storage via the unique constraint on `:token_hash`. A new record is always
  unconsumed and never starts revoked; passing either flag as true is refused
  so an insert cannot smuggle a token into a consumed or revoked state.
  """
  @spec insert_changeset(t(), map()) :: Ecto.Changeset.t()
  def insert_changeset(struct \\ %__MODULE__{}, attrs) when is_map(struct) and is_map(attrs) do
    struct
    |> cast(attrs, @permitted)
    |> validate_required(@required)
    |> normalize_claims()
    |> validate_json_claims()
    |> validate_empty_successor()
    |> validate_inclusion(:consumed, [false], message: "a new refresh token must be unconsumed (RFC 6749 §6)")
    |> validate_inclusion(:family_revoked, [false], message: "a new refresh token must not start revoked")
    |> unique_constraint(:token_hash, name: :attesto_refresh_tokens_token_hash_index)
    |> unique_constraint(:generation, name: :attesto_refresh_tokens_family_id_generation_index)
  end

  @doc """
  Changeset for the parent mutation inside an atomic rotation.

  `AttestoPhoenix.Store.EctoRefreshStore.rotate/4` applies this change inside
  the family-serialized transaction that also persists the successor row and
  its retry state. Keeping the mutation in a changeset makes the persisted
  `consumed`/`consumed_at` pair explicit while the store owns transaction and
  locking semantics.
  """
  @spec claim_changeset(t(), DateTime.t()) :: Ecto.Changeset.t()
  def claim_changeset(%__MODULE__{} = record, %DateTime{} = consumed_at) do
    change(record, consumed: true, consumed_at: consumed_at)
  end

  @doc """
  Build the insert attributes for a store record handed in by
  `Attesto.RefreshToken`.

  The protocol layer's record is `%{token_hash, family_id, generation, data,
  expires_at, consumed}` where `data` is the opaque context
  (`%{subject, scope, client_id, dpop_jkt, claims}`). This flattens `data`
  into the schema's columns, translating `:dpop_jkt` into an RFC 7800 `:cnf`
  confirmation, and renders `:expires_at` (unix seconds in the contract) as a
  `DateTime`. `:parent_hash` is taken from `opts[:parent_hash]` when the store
  threads predecessor lineage; the contract does not carry it.
  """
  @spec from_store_record(map(), keyword()) :: map()
  def from_store_record(record, opts \\ []) when is_map(record) and is_list(opts) do
    validate_record_for_projection!(record)
    data = Map.get(record, :data, %{})

    %{
      token_hash: Map.fetch!(record, :token_hash),
      family_id: Map.fetch!(record, :family_id),
      generation: Map.fetch!(record, :generation),
      subject: Map.get(data, :subject),
      scope: Map.get(data, :scope, []),
      resource: Map.get(data, :resource, []),
      acr: Map.get(data, :acr),
      auth_time: Map.get(data, :auth_time),
      client_id: Map.get(data, :client_id),
      cnf: cnf_from_context(data),
      claims: Map.get(data, :claims, %{}),
      consumed: Map.get(record, :consumed, false),
      consumed_at: nullable_datetime(Map.get(record, :consumed_at)),
      successor: Map.get(record, :successor),
      expires_at: to_datetime(Map.fetch!(record, :expires_at)),
      parent_hash: Keyword.get(opts, :parent_hash)
    }
  end

  @doc """
  Render a persisted row back into the `Attesto.RefreshStore` record shape the
  protocol layer expects.

  Inverse of `from_store_record/2`: it rebuilds the opaque `:data` context
  (unfolding the `:cnf` confirmation back into `:dpop_jkt`) and renders
  `:expires_at` back to unix seconds. `:generation` is read from its persisted
  column without a fallback, so a malformed persisted value cannot be widened
  into a valid generation.
  """
  @spec to_store_record(t()) :: map()
  def to_store_record(%__MODULE__{} = row), do: to_store_record(row, [])

  @doc """
  Render a row with optional stopped-cutover compatibility settings.

  `:legacy_grace_seconds` supplies the currently configured retry grace for a
  v1 encrypted successor that predates persisted retry deadlines. The derived
  deadline is bounded by both `consumed_at + grace` and the parent expiry, so
  reading an old row never extends its authority.
  """
  @spec to_store_record(t(), keyword()) :: map()
  def to_store_record(%__MODULE__{} = row, opts) when is_list(opts) do
    %{
      token_hash: row.token_hash,
      family_id: row.family_id,
      generation: row.generation,
      data: %{
        subject: row.subject,
        scope: row.scope,
        resource: row.resource,
        acr: row.acr,
        auth_time: row.auth_time,
        client_id: row.client_id,
        dpop_jkt: jkt_from_cnf(row.cnf),
        claims: row.claims
      },
      expires_at: to_unix(row.expires_at),
      consumed: row.consumed,
      consumed_at: nullable_unix(row.consumed_at),
      successor: successor_from_row(row.successor, row, opts)
    }
  end

  @doc false
  @spec valid_store_record?(map()) :: boolean()
  def valid_store_record?(record), do: valid_record_for_projection?(record)

  @doc false
  @spec valid_context?(map()) :: boolean()
  def valid_context?(context), do: valid_context?(context, :atoms)

  # ----- confirmation translation (RFC 7800) -----

  # The DPoP binding (RFC 9449) is carried in the protocol context as a bare
  # thumbprint; persist it as the `jkt` member of an RFC 7800 confirmation so
  # the column generalizes to other confirmation methods. No binding stores no
  # confirmation rather than an empty map, keeping bearer tokens unconstrained.
  defp cnf_from_context(%{dpop_jkt: jkt}) when is_binary(jkt), do: %{@cnf_jkt => jkt}
  defp cnf_from_context(_data), do: nil

  # PostgreSQL's JSONB decoder returns string keys. Atom-keyed maps are also
  # accepted for rows assembled by tests or a stopped-cutover adapter. Any
  # other confirmation, including an unsupported RFC 7800 member, is kept as
  # an invalid non-nil marker so the core rejects the record instead of
  # silently turning a constrained token into a bearer token.
  defp jkt_from_cnf(%{@cnf_jkt => jkt} = cnf) when is_binary(jkt) do
    if map_size(cnf) == 1 and Thumbprint.valid?(jkt), do: jkt, else: @invalid_confirmation
  end

  defp jkt_from_cnf(%{jkt: jkt} = cnf) when is_binary(jkt) do
    if map_size(cnf) == 1 and Thumbprint.valid?(jkt), do: jkt, else: @invalid_confirmation
  end

  defp jkt_from_cnf(nil), do: nil
  defp jkt_from_cnf(_cnf), do: @invalid_confirmation

  # ----- normalization -----

  defp normalize_claims(changeset) do
    case get_field(changeset, :claims) do
      nil -> put_change(changeset, :claims, %{})
      _claims -> changeset
    end
  end

  defp validate_json_claims(changeset) do
    validate_change(changeset, :claims, fn :claims, claims ->
      if portable_json_object?(claims),
        do: [],
        else: [claims: "must contain only portable JSON values with string keys"]
    end)
  end

  defp validate_empty_successor(changeset) do
    validate_change(changeset, :successor, fn :successor, _successor ->
      [successor: "must be empty when inserting an unconsumed refresh token"]
    end)
  end

  # ----- time rendering -----

  # The store contract represents expiry as absolute unix seconds; the column
  # is a timestamp. Translate at the boundary so neither side leaks the other's
  # representation.
  defp to_datetime(%DateTime{} = dt), do: dt
  defp to_datetime(seconds) when is_integer(seconds), do: DateTime.from_unix!(seconds, :second)
  defp nullable_datetime(nil), do: nil
  defp nullable_datetime(%DateTime{} = dt), do: dt

  defp nullable_datetime(seconds) when is_integer(seconds), do: DateTime.from_unix!(seconds, :second)

  defp to_unix(%DateTime{} = dt), do: DateTime.to_unix(dt, :second)
  defp nullable_unix(nil), do: nil
  defp nullable_unix(%DateTime{} = dt), do: DateTime.to_unix(dt, :second)

  # Ecto map columns round-trip through JSON on Postgres, so atom keys come
  # back as strings. Rebuild only the successor forms the core understands;
  # extra or missing members are rejected rather than projected away.
  defp successor_from_row(nil, _row, _opts), do: nil

  defp successor_from_row(
         %{"v" => 2, "ciphertext" => ciphertext, "retry_until" => retry_until, "child_hash" => child_hash} = wrapper,
         row,
         opts
       )
       when is_binary(ciphertext) and is_integer(retry_until) and is_binary(child_hash) do
    if exact_keys?(wrapper, ["v", "ciphertext", "retry_until", "child_hash"]) do
      decrypt_successor(ciphertext, retry_until, row, child_hash, opts)
    end
  end

  defp successor_from_row(
         %{v: 2, ciphertext: ciphertext, retry_until: retry_until, child_hash: child_hash} = wrapper,
         row,
         opts
       )
       when is_binary(ciphertext) and is_integer(retry_until) and is_binary(child_hash) do
    if exact_keys?(wrapper, [:v, :ciphertext, :retry_until, :child_hash]) do
      decrypt_successor(ciphertext, retry_until, row, child_hash, opts)
    end
  end

  # Version-one ciphertext wrappers are retained for a stopped cutover. They
  # used the package-wide AAD and therefore cannot be bound to a particular
  # parent, but they remain authenticated and are still subject to the core's
  # live-child checks. The legacy payload itself must be exactly a complete
  # successor without a deadline; unsupported payload members are not dropped.
  defp successor_from_row(%{"v" => 1, "ciphertext" => ciphertext} = wrapper, row, opts) when is_binary(ciphertext) do
    if exact_keys?(wrapper, ["v", "ciphertext"]), do: decrypt_successor_v1(ciphertext, row, opts)
  end

  defp successor_from_row(%{v: 1, ciphertext: ciphertext} = wrapper, row, opts) when is_binary(ciphertext) do
    if exact_keys?(wrapper, [:v, :ciphertext]), do: decrypt_successor_v1(ciphertext, row, opts)
  end

  # The only non-secret persisted form is the exact strict tombstone. It is
  # deliberately not inferred from a missing `recoverable` member.
  defp successor_from_row(%{"v" => 1, "retry_until" => retry_until, "recoverable" => false} = tombstone, _row, _opts)
       when is_integer(retry_until) do
    if exact_keys?(tombstone, ["v", "retry_until", "recoverable"]),
      do: %{retry_until: retry_until, recoverable: false}
  end

  defp successor_from_row(%{v: 1, retry_until: retry_until, recoverable: false} = tombstone, _row, _opts)
       when is_integer(retry_until) do
    if exact_keys?(tombstone, [:v, :retry_until, :recoverable]),
      do: %{retry_until: retry_until, recoverable: false}
  end

  defp successor_from_row(_malformed, _row, _opts), do: nil

  # This decoder is intentionally private to authenticated ciphertext paths.
  # A JSONB map with a plaintext `token` key is never accepted as a successor
  # just because it happens to resemble the decrypted payload.
  defp decode_inner_successor(%{} = successor) do
    retry_until = value(successor, :retry_until)

    if exact_successor_keys?(successor, retry_until) and valid_successor_context?(value(successor, :context)) do
      %{
        token: value(successor, :token),
        generation: value(successor, :generation),
        context: context_from_row(value(successor, :context))
      }
      |> maybe_put_retry_until(retry_until)
    end
  end

  defp decrypt_successor(ciphertext, outer_retry_until, row, child_hash, _opts) do
    aad =
      RefreshSuccessorCipher.binding_aad(
        row.token_hash,
        row.family_id,
        row.generation || 0,
        child_hash,
        outer_retry_until
      )

    case RefreshSuccessorCipher.decrypt(ciphertext, aad) do
      {:ok, %{} = successor} ->
        inner_retry_until = value(successor, :retry_until)

        if exact_successor_keys?(successor, inner_retry_until) and
             matching_retry_deadlines?(outer_retry_until, inner_retry_until) and
             child_token_matches?(successor, child_hash) and
             valid_successor_context?(value(successor, :context)) do
          decode_inner_successor(successor)
        end

      _unreadable_or_invalid ->
        nil
    end
  end

  defp child_token_matches?(successor, child_hash) do
    case value(successor, :token) do
      token when is_binary(token) and token != "" -> Attesto.Secret.hash(token) == child_hash
      _ -> false
    end
  end

  defp decrypt_successor_v1(ciphertext, row, opts) do
    case RefreshSuccessorCipher.decrypt(ciphertext) do
      {:ok, %{} = successor} ->
        if exact_successor_keys?(successor, nil) and valid_successor_context?(value(successor, :context)) do
          successor
          |> decode_inner_successor()
          |> derive_legacy_retry_deadline(row, opts)
        end

      _unreadable_or_invalid ->
        nil
    end
  end

  # Wrappers written before the cleartext housekeeping deadline was introduced
  # remain readable. New v2 wrappers carry the deadline both outside and inside
  # the authenticated ciphertext; disagreement means corrupted state and is
  # rejected rather than permitting deadline extension.
  defp matching_retry_deadlines?(outer, inner) when is_integer(outer) and is_integer(inner), do: outer == inner

  defp matching_retry_deadlines?(_outer, _inner), do: false

  # v1 ciphertexts did not carry a retry deadline. After a stopped cutover,
  # reconstruct one only from persisted consumption time and the current
  # configured grace. Clamp it before token expiry and refuse malformed or
  # empty windows; no request-scoped value can enlarge the historical window.
  defp derive_legacy_retry_deadline(nil, _row, _opts), do: nil

  defp derive_legacy_retry_deadline(successor, %__MODULE__{} = row, opts) do
    grace = Keyword.get(opts, :legacy_grace_seconds, 0)

    with true <- is_integer(grace) and grace > 0,
         %DateTime{} = consumed_at <- row.consumed_at,
         %DateTime{} = expires_at <- row.expires_at do
      consumed_unix = DateTime.to_unix(consumed_at, :second)
      expiry_unix = DateTime.to_unix(expires_at, :second)
      deadline = min(consumed_unix + grace, expiry_unix - 1)

      if deadline > consumed_unix do
        Map.put(successor, :retry_until, deadline)
      else
        successor
      end
    else
      _ -> successor
    end
  end

  # Successors written before fixed retry deadlines were introduced remain
  # readable without one; new records preserve the authenticated deadline so a
  # later request cannot enlarge the original retry window.
  defp maybe_put_retry_until(successor, nil), do: successor
  defp maybe_put_retry_until(successor, retry_until), do: Map.put(successor, :retry_until, retry_until)

  defp context_from_row(%{} = context) do
    %{
      subject: value(context, :subject),
      scope: value(context, :scope),
      resource: value(context, :resource),
      acr: value(context, :acr),
      auth_time: value(context, :auth_time),
      client_id: value(context, :client_id),
      dpop_jkt: value(context, :dpop_jkt),
      claims: value(context, :claims)
    }
  end

  defp exact_successor_keys?(successor, retry_until) do
    case retry_until do
      nil ->
        exact_keys?(successor, [:token, :generation, :context]) or
          exact_keys?(successor, ["token", "generation", "context"])

      retry when is_integer(retry) ->
        exact_keys?(successor, [:token, :generation, :context, :retry_until]) or
          exact_keys?(successor, ["token", "generation", "context", "retry_until"])

      _invalid ->
        false
    end
  end

  defp valid_successor_context?(context), do: valid_context?(context, :either)

  defp validate_record_for_projection!(record) do
    if valid_record_for_projection?(record), do: :ok, else: invalid_record!()
  end

  defp invalid_record!, do: raise(ArgumentError, @invalid_record_message)

  defp valid_record_for_projection?(record) when is_map(record) do
    non_empty_binary?(Map.get(record, :token_hash)) and
      non_empty_binary?(Map.get(record, :family_id)) and
      is_integer(Map.get(record, :generation)) and Map.get(record, :generation) >= 0 and
      valid_context?(Map.get(record, :data), :atoms) and
      valid_unix_seconds?(Map.get(record, :expires_at)) and
      is_boolean(Map.get(record, :consumed)) and
      valid_nullable_unix_seconds?(Map.get(record, :consumed_at))
  end

  defp valid_record_for_projection?(_record), do: false

  defp valid_context?(context, key_style) when is_map(context) do
    exact_context_keys?(context, key_style) and valid_context_values?(context)
  end

  defp valid_context?(_context, _key_style), do: false

  defp valid_context_values?(context) do
    non_empty_binary?(value(context, :subject)) and
      Scope.valid_list?(value(context, :scope)) and
      is_list(value(context, :resource)) and Enum.all?(value(context, :resource), &non_empty_binary?/1) and
      valid_optional_binary?(value(context, :client_id)) and
      valid_optional_jkt?(value(context, :dpop_jkt)) and
      valid_optional_binary?(value(context, :acr)) and
      valid_optional_integer?(value(context, :auth_time)) and
      valid_claims?(value(context, :claims))
  end

  defp exact_context_keys?(context, :atoms), do: exact_keys?(context, @canonical_context_keys)
  defp exact_context_keys?(context, :strings), do: exact_keys?(context, @canonical_context_string_keys)

  defp exact_context_keys?(context, :either) do
    exact_context_keys?(context, :atoms) or exact_context_keys?(context, :strings)
  end

  defp exact_keys?(map, expected) when is_map(map), do: Map.keys(map) |> Enum.sort() == Enum.sort(expected)

  defp valid_optional_binary?(nil), do: true
  defp valid_optional_binary?(value), do: non_empty_binary?(value)

  defp valid_optional_jkt?(nil), do: true
  defp valid_optional_jkt?(value), do: Thumbprint.valid?(value)

  defp valid_optional_integer?(nil), do: true
  defp valid_optional_integer?(value), do: is_integer(value) and value >= 0

  defp valid_unix_seconds?(value) when is_integer(value) and value >= 0 do
    match?({:ok, %DateTime{}}, DateTime.from_unix(value, :second))
  end

  defp valid_unix_seconds?(_value), do: false

  defp valid_nullable_unix_seconds?(nil), do: true
  defp valid_nullable_unix_seconds?(value), do: valid_unix_seconds?(value)

  defp non_empty_binary?(value), do: is_binary(value) and value != ""

  # During a stopped cutover the core predicate may come from an older
  # dependency that does not guard every VM term (for example a Decimal
  # struct) before traversing it. Treat any such failure as malformed claims;
  # persisted refresh context must fail closed rather than leak an encoder
  # exception through the store boundary.
  defp portable_json_object?(claims) do
    Claims.portable_json_object?(claims)
  rescue
    _exception -> false
  end

  defp valid_claims?(claims), do: is_map(claims) and portable_json_object?(claims)

  defp value(map, key) when is_map(map) do
    cond do
      Map.has_key?(map, key) -> Map.get(map, key)
      Map.has_key?(map, Atom.to_string(key)) -> Map.get(map, Atom.to_string(key))
      true -> nil
    end
  end
end
