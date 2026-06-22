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
      its transform (RFC 7636). Only `S256` is a valid method.
    * `:cnf` - the optional confirmation/key-binding map (RFC 7800). When
      present it holds a `jkt` (DPoP key thumbprint, RFC 9449 §6) and/or an
      `x5t#S256` (mTLS certificate thumbprint, RFC 8705 §3.1); a bound code
      MUST be redeemed presenting the same binding.
    * `:nonce` - the OIDC request `nonce` (OpenID Connect Core §3.1.2.1),
      round-tripped into the eventual ID Token.
    * `:claims` - an opaque map of additional request context carried from
      the authorization request to redemption.

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
  rebuilds the map from a loaded row so the protocol layer can hydrate the
  authorization-code grant from `record.data`.

  ## Table name and prefix

  The table is `attesto_authorization_codes` by default and is namespaced
  by the optional schema prefix passed via `from_record/2`'s `:prefix`
  option (or the schema-wide prefix configured through
  `AttestoPhoenix.Config`), letting a host isolate the
  authorization-server tables in their own schema.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @default_table "attesto_authorization_codes"

  # RFC 7636 §4.3: the only code-challenge transform a compliant server
  # accepts. `plain` is forbidden so an intercepted authorization request
  # cannot downgrade PKCE.
  @code_challenge_method_s256 "S256"

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
  opaque grant `:data`, and the absolute expiry in unix seconds.
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
    field :claims, :map, default: %{}
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

  `record` is the map the protocol layer persists: a `:code_hash`, the
  opaque grant `:data`, and an integer `:expires_at` in unix seconds. The
  fields inside `:data` (client, subject, scope, redirect URI, PKCE
  challenge, optional DPoP thumbprint, OIDC nonce, and request claims) are
  spread across the row's columns so they can be queried and audited
  individually while still round-tripping losslessly via `to_record/1`.

  Options:

    * `:prefix` - the Ecto schema prefix (database schema) to write the row
      into. Defaults to no prefix.
    * `:now` - the insertion clock as a `DateTime`. Defaults to
      `DateTime.utc_now/0`. Provided for deterministic tests.

  Validation is fail-closed: a missing required field (hash, client,
  subject, redirect URI, or expiry) is rejected rather than defaulted. PKCE
  is optional at persistence (a confidential client the host exempted from
  PKCE via `Attesto.AuthorizationRequest`'s `:require_pkce` issues a code with
  no challenge); when a `code_challenge_method` is present it is constrained to
  `S256` (RFC 7636 §4.3), and a challenge-less code stores a NULL method.
  """
  @spec from_record(store_record(), keyword()) :: Ecto.Changeset.t()
  def from_record(record, opts \\ []) when is_map(record) and is_list(opts) do
    now = Keyword.get(opts, :now, DateTime.utc_now()) |> DateTime.truncate(:second)
    prefix = Keyword.get(opts, :prefix)
    data = Map.get(record, :data, %{})

    attrs = %{
      code_hash: Map.get(record, :code_hash),
      client_id: Map.get(data, :client_id),
      subject: Map.get(data, :subject),
      scope: Map.get(data, :scope, []),
      resource: Map.get(data, :resource, []),
      redirect_uri: Map.get(data, :redirect_uri),
      code_challenge: Map.get(data, :code_challenge),
      code_challenge_method: code_challenge_method_for(data),
      cnf: cnf_from_data(data),
      nonce: Map.get(data, :nonce),
      claims: Map.get(data, :claims, %{}),
      family_id: Map.get(data, :family_id),
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

  The columns are folded back into the opaque grant `:data` map in exactly
  the shape the protocol layer expects, and the
  `:expires_at` `utc_datetime` is converted back to unix seconds. The
  protocol layer re-checks expiry after taking the record, so a row that is
  past `:expires_at` is still returned here and rejected downstream.
  """
  @spec to_record(t()) :: store_record()
  def to_record(%__MODULE__{} = row) do
    %{
      code_hash: row.code_hash,
      data: %{
        client_id: row.client_id,
        subject: row.subject,
        scope: row.scope || [],
        resource: row.resource || [],
        redirect_uri: row.redirect_uri,
        code_challenge: row.code_challenge,
        code_challenge_method: row.code_challenge_method,
        dpop_jkt: dpop_jkt_from_cnf(row.cnf),
        nonce: row.nonce,
        claims: row.claims || %{},
        family_id: row.family_id
      },
      expires_at: datetime_to_unix(row.expires_at)
    }
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
  defp cnf_from_data(data) do
    case Map.get(data, :dpop_jkt) do
      nil -> nil
      jkt when is_binary(jkt) -> %{"jkt" => jkt}
    end
  end

  # RFC 7636 §4.3: the challenge method is meaningful only when a challenge is
  # present. A code issued without a challenge (PKCE relaxed for a confidential
  # client; see Attesto.AuthorizationRequest's :require_pkce) persists with a
  # NULL method, not a spurious "S256"; a code with a challenge defaults the
  # method to S256 when the grant did not carry one (S256 is the only method
  # accepted at issuance).
  defp code_challenge_method_for(data) do
    case Map.get(data, :code_challenge) do
      nil -> nil
      _challenge -> Map.get(data, :code_challenge_method, @code_challenge_method_s256)
    end
  end

  defp dpop_jkt_from_cnf(nil), do: nil
  defp dpop_jkt_from_cnf(%{"jkt" => jkt}) when is_binary(jkt), do: jkt
  defp dpop_jkt_from_cnf(%{jkt: jkt}) when is_binary(jkt), do: jkt
  defp dpop_jkt_from_cnf(_cnf), do: nil

  defp unix_to_datetime(nil), do: nil

  defp unix_to_datetime(seconds) when is_integer(seconds) do
    DateTime.from_unix!(seconds, :second)
  end

  defp datetime_to_unix(nil), do: nil
  defp datetime_to_unix(%DateTime{} = dt), do: DateTime.to_unix(dt, :second)
end
