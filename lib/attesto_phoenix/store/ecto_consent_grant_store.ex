defmodule AttestoPhoenix.Store.EctoConsentGrantStore do
  @moduledoc """
  Postgres-backed `AttestoPhoenix.ConsentGrantStore` (RFC 6749 §4.1.1).

  A consent grant ties one consent decision to the exact authorization request
  the resource owner saw, so a single Authorize click cannot approve a different
  client, redirect URI, scope set, or PKCE challenge. The host consent screen
  `mint/2`s a grant when the user authorizes; the host `:consent` callback
  `consume/2`s it before a code is issued. The single-use guarantee is enforced
  here, at the database, not advisory: it must hold against two concurrent
  presentations of one token, on any node sharing the database.

  ## Behaviour callbacks

    * `mint/2` inserts a grant keyed on an unguessable token, with the canonical
      `binding_hash` and a TTL-derived `expires_at`, and returns the token.
    * `consume/2` issues one conditional `UPDATE ... WHERE token AND binding_hash
      AND consumed_at IS NULL AND expires_at > now` that stamps `consumed_at`.
      Postgres serialises the update on the row, so exactly one of any number of
      concurrent callers observes an affected-row count of 1 and gets `:ok`. A
      count of 0 is disambiguated into a precise `{:error, reason}` by reading
      the row back — fail closed: every reason still refuses consent.

  The repository module is supplied by the host application (`:repo` under the
  `:attesto_phoenix` app) and read at call time; a store with no backing
  repository cannot enforce single use, so it fails closed rather than silently
  no-opping.
  """

  @behaviour AttestoPhoenix.ConsentGrantStore

  import Ecto.Query, only: [from: 2]

  alias AttestoPhoenix.ConsentGrant
  alias AttestoPhoenix.Schema.ConsentGrant, as: Grant

  @app :attesto_phoenix

  # The grant token is the only secret in the consent hop and is short-lived, so
  # 32 bytes of CSPRNG output (256 bits) url-base64 encoded is an unguessable,
  # URL-safe token the consent screen can carry forward.
  @token_bytes 32

  @doc """
  Mints a single-use consent grant bound to `binding`, valid for `ttl_seconds`.

  Returns `{:ok, token}` with the opaque token the consent screen carries
  forward to the authorization endpoint, or `{:error, changeset}` if the row
  could not be persisted (e.g. an astronomically unlikely token collision).
  """
  @impl AttestoPhoenix.ConsentGrantStore
  @spec mint(ConsentGrant.binding(), pos_integer()) :: {:ok, String.t()} | {:error, Ecto.Changeset.t()}
  def mint(%{} = binding, ttl_seconds) when is_integer(ttl_seconds) and ttl_seconds > 0 do
    token = :crypto.strong_rand_bytes(@token_bytes) |> Base.url_encode64(padding: false)
    now = DateTime.utc_now()

    attrs = %{
      token: token,
      binding_hash: ConsentGrant.binding_hash(binding),
      subject: Map.fetch!(binding, :subject),
      expires_at: DateTime.add(now, ttl_seconds, :second)
    }

    attrs
    |> Grant.changeset()
    |> repo().insert()
    |> case do
      {:ok, _grant} -> {:ok, token}
      {:error, changeset} -> {:error, changeset}
    end
  end

  @doc """
  Atomically consumes the grant for `token` iff it matches `binding`, is
  unconsumed, and is unexpired.

  Returns `:ok` to the single winning caller and `{:error, reason}` to every
  other (`:not_found`, `:binding_mismatch`, `:expired`, `:consumed`). A `nil` or
  blank token short-circuits to `{:error, :not_found}` without touching the
  database.
  """
  @impl AttestoPhoenix.ConsentGrantStore
  @spec consume(String.t() | nil, ConsentGrant.binding()) ::
          :ok | {:error, AttestoPhoenix.ConsentGrantStore.consume_error()}
  def consume(token, %{} = binding) when is_binary(token) and token != "" do
    now = DateTime.utc_now()
    hash = ConsentGrant.binding_hash(binding)

    query =
      from g in Grant,
        where:
          g.token == ^token and g.binding_hash == ^hash and is_nil(g.consumed_at) and
            g.expires_at > ^now

    case repo().update_all(query, set: [consumed_at: now]) do
      {1, _} -> :ok
      {0, _} -> disambiguate(token, hash, now)
    end
  end

  def consume(_token, %{}), do: {:error, :not_found}

  # The conditional update matched nothing. Read the row back so the caller gets
  # a precise reason (fail closed: any reason still refuses consent). The order
  # of clauses matters: an already-consumed grant is reported `:consumed` even
  # when it is also expired, so a replay is never miscategorised as a stale TTL.
  defp disambiguate(token, hash, now) do
    case repo().get(Grant, token) do
      nil ->
        {:error, :not_found}

      %Grant{binding_hash: stored} when stored != hash ->
        {:error, :binding_mismatch}

      %Grant{consumed_at: consumed} when not is_nil(consumed) ->
        {:error, :consumed}

      %Grant{expires_at: expires_at} ->
        if DateTime.after?(expires_at, now) do
          # The row is present, unconsumed, unexpired, and the hash matches, yet
          # the conditional update affected nothing — only a concurrent consume
          # that already won the row can produce this. Refuse: a single use was
          # already spent.
          {:error, :consumed}
        else
          {:error, :expired}
        end
    end
  end

  defp repo do
    case Application.get_env(@app, :repo) do
      nil ->
        # Fail closed: a consent-grant store with no backing repository cannot
        # enforce single use, so refuse rather than silently no-op.
        raise ArgumentError,
              "AttestoPhoenix: no :repo configured. Set `config #{inspect(@app)}, repo: MyApp.Repo`"

      repo ->
        repo
    end
  end
end
