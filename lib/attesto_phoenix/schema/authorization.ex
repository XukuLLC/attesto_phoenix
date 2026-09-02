defmodule AttestoPhoenix.Schema.Authorization do
  @moduledoc """
  Ecto schema for the single-use authorization codes backing an
  `Attesto.CodeStore`.

  This is the persistent record shape behind the authorization-code grant
  (RFC 6749 §4.1). The store layer mints one row per code at the
  authorization endpoint and consumes it at the token endpoint; this module
  only describes the row and translates it to and from the protocol struct
  `Attesto.AuthorizationCode.Grant`. All protocol decisions (code
  generation and hashing, PKCE verification, DPoP/mTLS binding checks,
  expiry, single-use semantics) live in `attesto`; nothing here re-derives
  them.

  ## What is stored, and what is not

  Only the *hash* of the code is persisted (`:code_hash`), never the
  plaintext code handed to the client. The plaintext is a bearer secret
  (RFC 6749 §10.5): a database disclosure must not yield a usable code, so
  the column is the output of `Attesto.Secret.hash/1` and is the unique
  lookup key.

  The remaining columns are the authorization-request context that must be
  reproduced at redemption time:

    * `:client_id` - the client the code was issued to (RFC 6749 §4.1.3:
      the code MUST be redeemed by that same client).
    * `:subject` - the resource owner the code authenticates.
    * `:scope` - the granted scope, a list of scope tokens.
    * `:redirect_uri` - the registered redirect URI, compared by exact
      string match at redemption (RFC 6749 §3.1.2 / §4.1.3).
    * `:code_challenge` / `:code_challenge_method` - the PKCE challenge and
      its transform (RFC 7636). Only `S256` is a valid method. The method
      column remains for database compatibility and auditability; the core
      grant data treats `S256` as implicit and does not include this key.
    * `:cnf` - the optional confirmation/key-binding map (RFC 7800). When
      present for an authorization-code row it is exactly `%{"jkt" => jkt}`
      (or the legacy atom-key form `%{jkt: jkt}`), where `jkt` is a canonical
      RFC 7638 SHA-256 thumbprint. `nil` means no binding. Other keys, mixed
      key styles, malformed thumbprints, and an `x5t#S256`-only binding are
      rejected; a bound code MUST be redeemed presenting the same DPoP key.
    * `:nonce` - a legacy compatibility column for the OIDC request `nonce`
      (OpenID Connect Core §3.1.2.1). Canonical grant data carries this value
      under `:claims`.
    * `:claims` - a portable, lossless JSON object of additional request
      context carried from the authorization request to redemption. Keys are
      strings at every level; values are JSON `null`, booleans, strings,
      exact-range integers, arrays, or nested objects. Floats and other VM
      terms are not persisted because the Ecto JSONB boundary must round-trip
      the grant context unchanged. The column uses Ecto redaction so ordinary
      struct and changeset inspection hides it. It carries the authentication
      context and, for a host that configures
      `:authorization_code_private_context`, that host's private state under the
      reserved key owned by `AttestoPhoenix.AuthorizationCodePrivateContext`.

  ## Lifecycle columns

    * `:family_id` - the grant family this code will mint into, used to revoke
      descendants when a redeemed code is replayed.
    * `:access_token_jti` / `:access_token_expires_at` - the access token
      produced by the successful code redemption. Stored only after issuance,
      and used to deny the token if the code is later replayed.
    * `:access_token_revoked_at` - set when code reuse revokes that token.
    * `:expires_at` - absolute expiry as a `utc_datetime`. Authorization
      codes are short-lived (RFC 6749 §4.1.2 recommends a maximum of ten
      minutes).
    * `:consumed_at` - set when the code is spent. The single-use contract
      (RFC 6749 §4.1.2) is enforced by an atomic claim in the store; this
      column also lets a later presentation be recognized as reuse instead of
      an unknown code.
    * `:consumed_success` - whether the first presentation completed all
      redemption checks. Only successful redemption is replayed as reuse.
    * `:inserted_at` - insertion timestamp.

  ## Record bridge

  `Attesto.CodeStore` exchanges plain maps with a `:code_hash`, a
  `:data` map, and an integer `:expires_at` (unix seconds). `from_record/2`
  builds an Ecto changeset from such a map for insertion, and `to_record/1`
  rebuilds the exact nine-key canonical data map that the protocol layer uses
  to hydrate the authorization-code grant. The database-only PKCE-method and
  legacy nonce columns are not returned as sibling data keys.

  ## Table name and prefix

  The table is `attesto_authorization_codes` by default and is namespaced
  by the optional schema prefix passed via `from_record/2`'s `:prefix`
  option (or the schema-wide prefix configured through
  `AttestoPhoenix.Config`), letting a host isolate the
  authorization-server tables in their own schema.
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Attesto.Claims
  alias Attesto.PKCE
  alias Attesto.Scope
  alias Attesto.Thumbprint

  @default_table "attesto_authorization_codes"

  # RFC 7636 §4.3: the only code-challenge transform a compliant server
  # accepts. `plain` is forbidden so an intercepted authorization request
  # cannot downgrade PKCE.
  @code_challenge_method_s256 "S256"
  @canonical_data_keys [
    :client_id,
    :code_challenge,
    :claims,
    :dpop_jkt,
    :family_id,
    :redirect_uri,
    :resource,
    :scope,
    :subject
  ]
  @canonical_data_error "authorization code record has invalid canonical data"
  @cnf_error "authorization code record has invalid confirmation binding"

  @typedoc "A persisted authorization-code row."
  @type t :: %__MODULE__{
          code_hash: String.t() | nil,
          client_id: String.t() | nil,
          subject: String.t() | nil,
          scope: [String.t()] | nil,
          resource: [String.t()] | nil,
          redirect_uri: String.t() | nil,
          code_challenge: String.t() | nil,
          code_challenge_method: String.t() | nil,
          cnf: map() | nil,
          nonce: String.t() | nil,
          claims: map() | nil,
          family_id: String.t() | nil,
          access_token_jti: String.t() | nil,
          access_token_expires_at: DateTime.t() | nil,
          access_token_revoked_at: DateTime.t() | nil,
          expires_at: DateTime.t() | nil,
          consumed_at: DateTime.t() | nil,
          consumed_success: boolean(),
          inserted_at: DateTime.t() | nil
        }

  @typedoc """
  The plain map exchanged with `Attesto.CodeStore`: the code hash, the
  grant `:data`, and the absolute expiry in unix seconds.
  """
  @type store_record :: %{
          required(:code_hash) => String.t(),
          required(:data) => map(),
          required(:expires_at) => integer()
        }

  @primary_key false
  schema @default_table do
    field :code_hash, :string
    field :client_id, :string
    field :subject, :string
    field :scope, {:array, :string}, default: []
    field :resource, {:array, :string}, default: []
    field :redirect_uri, :string
    field :code_challenge, :string
    # No default: a code issued without a PKCE challenge (the host relaxed PKCE
    # for a confidential client; see Attesto.AuthorizationRequest's :require_pkce)
    # must persist with a NULL method, not a spurious "S256" for a challenge that
    # is not there. When a challenge IS present, from_record/2 sets the method.
    field :code_challenge_method, :string
    field :cnf, :map
    field :nonce, :string
    # `redact: true`: the claims map carries the authentication context (nonce,
    # acr, amr, sid) and, when the host configures
    # `:authorization_code_private_context`, host-private authorization state
    # under a reserved key. This hides the field from ordinary struct and
    # changeset inspection. Ecto exception messages can render raw changes and
    # params, so the bundled store sanitizes failed-insert exceptions; direct
    # callers and custom stores must provide equivalent handling.
    field :claims, :map, default: %{}, redact: true
    field :family_id, :string
    field :access_token_jti, :string
    field :access_token_expires_at, :utc_datetime
    field :access_token_revoked_at, :utc_datetime
    field :expires_at, :utc_datetime
    field :consumed_at, :utc_datetime
    field :consumed_success, :boolean, default: false
    field :inserted_at, :utc_datetime
  end

  @required [
    :code_hash,
    :client_id,
    :subject,
    :redirect_uri,
    :expires_at
  ]

  # PKCE is optional at persistence: a confidential client the host exempted
  # from PKCE (Attesto.AuthorizationRequest's :require_pkce) issues a code with
  # no challenge/method. When present they are still constrained (the method to
  # S256, see validate_inclusion below); when absent the columns are NULL.
  @optional [
    :scope,
    :resource,
    :cnf,
    :nonce,
    :claims,
    :family_id,
    :access_token_jti,
    :access_token_expires_at,
    :access_token_revoked_at,
    :consumed_at,
    :consumed_success,
    :code_challenge,
    :code_challenge_method
  ]

  @doc """
  The default table name for this schema.
  """
  @spec table() :: String.t()
  def table, do: @default_table

  @doc """
  The only accepted PKCE code-challenge method (RFC 7636 §4.3, `S256`).
  """
  @spec code_challenge_method() :: String.t()
  def code_challenge_method, do: @code_challenge_method_s256

  @doc """
  Builds an insertable changeset from a `Attesto.CodeStore` record map.

  `record` is the map the protocol layer persists: a `:code_hash`, the grant
  `:data`, and an integer `:expires_at` in unix seconds. The
  fields inside `:data` (client, subject, scope, redirect URI, PKCE
  challenge, optional DPoP thumbprint, claims, and family) are spread across
  the row's columns so they can be queried and audited individually. The
  canonical core data map keeps the OIDC nonce inside `:claims`; the
  database-only `:nonce` column remains readable for legacy rows. When
  populated, it is promoted into a valid claims map as the authoritative
  string-key nonce after removing any legacy atom- or string-key nonce entries.
  When the column is NULL, a canonical string-key nonce already in `claims` is
  preserved, while atom-key or mixed maps remain malformed for core validation.
  A malformed NULL claims value is preserved, even when the legacy nonce is
  populated; it is not repaired. A top-level `:nonce` in the core data map is
  not canonical and is rejected.

  Options:

    * `:prefix` - the Ecto schema prefix (database schema) to write the row
      into. Defaults to no prefix.
    * `:now` - the insertion clock as a `DateTime`. Defaults to
      `DateTime.utc_now/0`. Provided for deterministic tests.

  Validation is fail-closed: a missing required field (hash, client,
  subject, redirect URI, or expiry) is rejected rather than defaulted. PKCE
  is optional at persistence (a confidential client the host exempted from
  PKCE via `Attesto.AuthorizationRequest`'s `:require_pkce` issues a code with
  no challenge). A challenge implies `S256` (RFC 7636 §4.3), and a
  challenge-less code stores a NULL database method; the database-only method
  column is not accepted as a sibling in canonical core data.
  """
  @spec from_record(store_record(), keyword()) :: Ecto.Changeset.t()
  def from_record(record, opts \\ []) when is_map(record) and is_list(opts) do
    now = Keyword.get(opts, :now, DateTime.utc_now()) |> DateTime.truncate(:second)
    prefix = Keyword.get(opts, :prefix)
    data = canonical_data!(record)

    attrs = %{
      code_hash: Map.get(record, :code_hash),
      client_id: data.client_id,
      subject: data.subject,
      scope: data.scope,
      resource: data.resource,
      redirect_uri: data.redirect_uri,
      code_challenge: data.code_challenge,
      code_challenge_method: code_challenge_method_for(data),
      cnf: cnf_from_data(data),
      nonce: nil,
      claims: data.claims,
      family_id: data.family_id,
      expires_at: unix_to_datetime(Map.get(record, :expires_at)),
      inserted_at: now
    }

    %__MODULE__{}
    |> Ecto.put_meta(prefix: prefix)
    |> cast(attrs, @required ++ @optional ++ [:inserted_at])
    |> validate_required(@required ++ [:inserted_at])
    |> validate_inclusion(:code_challenge_method, [@code_challenge_method_s256])
    |> unique_constraint(:code_hash, name: :attesto_authorization_codes_code_hash_index)
  end

  @doc """
  Rebuilds the `Attesto.CodeStore` record map from a loaded row.

  The columns are folded back into the exact nine-key canonical grant `:data`
  map the protocol layer expects. `code_challenge_method` is implicit as
  `S256` in that contract, and a non-NULL legacy `nonce` column is promoted
  into `claims` as the authoritative string-key nonce, removing any atom-key
  or conflicting string-key nonce. If the legacy column is NULL, a canonical
  string-key nonce already present in `claims` is preserved; atom-key or mixed
  nonce maps remain malformed so the core JSON-object validation rejects them.
  A NULL `claims` value remains malformed even when the legacy nonce column is
  populated; it is not repaired into a new map. The row's confirmation binding is accepted only when
  it is `nil`, an exact string-key `jkt` map, or an exact legacy atom-key `jkt`
  map containing a canonical thumbprint; malformed or unsupported bindings
  raise a fixed, value-free `ArgumentError` rather than becoming `nil`. The
  `:expires_at` `utc_datetime` is converted back to unix seconds. Database
  non-NULL constraints keep scope, resource, and claims populated for normal
  rows; malformed NULL values are preserved for the protocol layer to reject,
  rather than defaulted into a valid-looking grant. The protocol layer
  re-checks expiry after taking the record, so a row that is past `:expires_at`
  is still returned here and rejected downstream.
  """
  @spec to_record(t()) :: store_record()
  def to_record(%__MODULE__{} = row) do
    %{
      code_hash: row.code_hash,
      data: %{
        client_id: row.client_id,
        subject: row.subject,
        scope: row.scope,
        resource: row.resource,
        redirect_uri: row.redirect_uri,
        code_challenge: row.code_challenge,
        dpop_jkt: dpop_jkt_from_cnf!(row.cnf),
        claims: claims_from_row(row),
        family_id: row.family_id
      },
      expires_at: datetime_to_unix(row.expires_at)
    }
  end

  defp claims_from_row(%__MODULE__{claims: claims, nonce: nonce}) do
    case claims do
      claims when is_map(claims) ->
        if is_nil(nonce) do
          claims
        else
          claims
          |> Map.drop(["nonce", :nonce])
          |> Map.put("nonce", nonce)
        end

      nil ->
        nil

      invalid_claims ->
        invalid_claims
    end
  end

  @doc false
  @spec consumed_meta(t()) :: map()
  def consumed_meta(%__MODULE__{} = row) do
    %{
      family_id: row.family_id,
      subject: row.subject
    }
  end

  # RFC 7800: the `cnf` member carries the key the token (and here, the
  # code) is bound to. RFC 9449 §6 names the DPoP thumbprint `jkt`; the
  # store's grant `:data` carries it flat as `:dpop_jkt`, so promote it
  # into a `cnf` map for column storage. A code with no binding stores no
  # `cnf` (NULL), never an empty map, so "unbound" and "bound to nothing"
  # cannot be confused.
  defp canonical_data!(record) do
    data = Map.get(record, :data)

    if is_map(data) and
         map_size(data) == length(@canonical_data_keys) and
         Enum.all?(@canonical_data_keys, &Map.has_key?(data, &1)) and
         valid_canonical_data?(data) do
      data
    else
      raise ArgumentError, @canonical_data_error
    end
  end

  defp valid_canonical_data?(data) do
    non_empty_binary?(Map.get(data, :client_id)) and
      non_empty_binary?(Map.get(data, :subject)) and
      non_empty_binary?(Map.get(data, :redirect_uri)) and
      valid_optional_challenge?(Map.get(data, :code_challenge)) and
      Scope.valid_list?(Map.get(data, :scope)) and
      valid_string_list?(Map.get(data, :resource)) and
      valid_optional_jkt?(Map.get(data, :dpop_jkt)) and
      valid_optional_non_empty_binary?(Map.get(data, :family_id)) and
      Claims.portable_json_object?(Map.get(data, :claims))
  end

  defp cnf_from_data(data) do
    case Map.get(data, :dpop_jkt) do
      nil ->
        nil

      jkt when is_binary(jkt) ->
        if Thumbprint.valid?(jkt), do: %{"jkt" => jkt}, else: raise(ArgumentError, @cnf_error)

      _invalid ->
        raise ArgumentError, @cnf_error
    end
  end

  # RFC 7636 §4.3: the challenge method is meaningful only when a challenge is
  # present. A code issued without a challenge (PKCE relaxed for a confidential
  # client; see Attesto.AuthorizationRequest's :require_pkce) persists with a
  # NULL method, not a spurious "S256". The canonical core map has no method
  # sibling: a present challenge always means S256.
  defp code_challenge_method_for(%{code_challenge: nil}), do: nil
  defp code_challenge_method_for(%{code_challenge: _challenge}), do: @code_challenge_method_s256

  # Ecto/Postgres decodes JSON object keys as strings. The atom-key clause is a
  # deliberately narrow compatibility path for rows built by older adapters;
  # both forms must be an exact one-key map containing a canonical thumbprint.
  # Every other form is rejected instead of being treated as an unbound code.
  defp dpop_jkt_from_cnf!(nil), do: nil

  defp dpop_jkt_from_cnf!(%{"jkt" => jkt} = cnf) when map_size(cnf) == 1 do
    valid_cnf_jkt!(jkt)
  end

  defp dpop_jkt_from_cnf!(%{jkt: jkt} = cnf) when map_size(cnf) == 1 do
    valid_cnf_jkt!(jkt)
  end

  defp dpop_jkt_from_cnf!(_cnf), do: raise(ArgumentError, @cnf_error)

  defp valid_cnf_jkt!(jkt) do
    if Thumbprint.valid?(jkt), do: jkt, else: raise(ArgumentError, @cnf_error)
  end

  defp valid_optional_challenge?(nil), do: true
  defp valid_optional_challenge?(value), do: PKCE.valid_challenge?(value)

  defp valid_optional_jkt?(nil), do: true
  defp valid_optional_jkt?(value), do: Thumbprint.valid?(value)

  defp valid_optional_non_empty_binary?(nil), do: true
  defp valid_optional_non_empty_binary?(value), do: non_empty_binary?(value)

  defp valid_string_list?(value), do: is_list(value) and Enum.all?(value, &non_empty_binary?/1)

  defp non_empty_binary?(value), do: is_binary(value) and value != ""

  defp unix_to_datetime(nil), do: nil

  defp unix_to_datetime(seconds) when is_integer(seconds) do
    DateTime.from_unix!(seconds, :second)
  end

  defp datetime_to_unix(nil), do: nil
  defp datetime_to_unix(%DateTime{} = dt), do: DateTime.to_unix(dt, :second)
end
