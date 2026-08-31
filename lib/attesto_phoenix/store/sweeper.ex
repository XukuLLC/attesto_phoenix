defmodule AttestoPhoenix.Store.Sweeper do
  @moduledoc """
  Periodic housekeeping `GenServer` that deletes expired rows from the
  Ecto-backed authorization-code, refresh-token, device-code, CIBA-request,
  logout-session, DPoP-nonce, DPoP-replay, pushed-authorization-request,
  client-id-metadata-cache, and consent-grant tables.

  Each of these tables carries an `expires_at` column whose semantics are fixed
  by the relevant RFC:

    * authorization codes - RFC 6749 §4.1.2 ("The authorization code MUST expire
      shortly after it is issued") and §10.5 (codes are short-lived,
      single-use).
    * refresh tokens - RFC 6749 §1.5 / §6 (refresh tokens MAY expire); the
      stored expiry bounds the credential's lifetime.
    * server-issued DPoP nonces - RFC 9449 §8 / §9 (the `nonce` the resource or
      authorization server requires the client to echo is time-bounded).
    * DPoP proof `jti` replay records - RFC 9449 §11.1 (a `jti` need only be
      remembered for the proof `iat` acceptance window; past that window the
      record is dead weight).
    * pushed authorization requests - RFC 9126 §2.2 (a `request_uri` reference is
      short-lived; past its expiry it can resolve nothing).
    * cached Client ID Metadata Documents -
      `draft-ietf-oauth-client-id-metadata-document-01` §6 / RFC 9111 (a cached
      document is fresh only until its `expires_at`; past that it is re-fetched).
    * consent grants - RFC 6749 §4.1.1 / §4.1.2 (consent precedes a short-lived
      authorization code; a grant past its `expires_at` can authorize nothing,
      and `consume/2` already rejects it on read).
    * back-channel-logout sessions - OpenID Connect Back-Channel Logout 1.0 (a
      recorded `(session, RP)` delivery row past its `expires_at` belongs to an
      abandoned session and is no longer a logout target).
    * CIBA authentication requests - OpenID Connect CIBA Core 1.0 §7.3 (an
      `auth_req_id` past its `expires_at` yields `expired_token` and can mint
      nothing; `redeem/4` already re-checks expiry on read).

  ## Correctness vs. housekeeping

  Expiry-row deletion is not required for authorization correctness. Every store re-validates
  `expires_at` against the current time on read, so an expired row that has not
  yet been swept is never honored: an expired authorization code is rejected, an
  expired nonce is rejected, and an expired replay record no longer blocks a
  fresh `jti`. Those deletes only bound table growth by reclaiming rows that can
  no longer affect any decision.

  The process also irreversibly redacts refresh-successor ciphertext whose
  short retry deadline has passed, on the next scheduled sweep. When the Ecto
  refresh store uses a positive retry grace, this bounded credential cleanup
  requires the sweeper. The
  installer adds it to the host supervision tree automatically; manually wired
  applications MUST supervise it with a positive `:sweep_interval_ms`.

  The remaining work is generic TTL housekeeping: it issues a single `DELETE
  ... WHERE expires_at < $now` per swept table.

  ## Comparison boundary (fail-closed)

  Deletion uses a strict `<` comparison against a single `DateTime` captured
  once per sweep (`DateTime.utc_now/0`) and reused across every table, so a
  sweep applies one consistent boundary. A row whose `expires_at` equals "now"
  is retained, never deleted, so the sweeper can only ever remove rows that the
  stores themselves already treat as expired. The sweeper widens no acceptance
  window.

  ## Configuration

  All policy is read from `AttestoPhoenix.Config`; nothing is hardcoded here.

    * `:repo` - the `Ecto.Repo` the deletes run against (required by
      `AttestoPhoenix.Config`).
    * `:sweep_interval_ms` - how often a sweep runs, in milliseconds. Manual
      supervision fails fast when this key is unset. The installer uses the
      explicit `:if_configured` mode so a rerun against an older or custom-store
      host leaves the child ignored when no interval was configured.
    * `:schema_prefix` - optional PostgreSQL schema applied to every delete so
      a host that installed the generated tables under a non-default schema
      sweeps the same tables it created.

  The set of swept tables is fixed by the generated schema and is not
  host-configurable: every Ecto-backed store the library generates carries an
  `expires_at` column and is swept.
  """

  use GenServer

  import Ecto.Query, only: [from: 2]

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Store.EctoRefreshStore

  # The Ecto-backed stores the migration generator installs. Each table has an
  # `expires_at` column; the set is exhaustive over the generated stores and is
  # intentionally not host-overridable (sweeping a partial set would let one
  # table grow unbounded). The names are module attributes (compile-time
  # literals) because Ecto's `from/2` requires a literal string source: a
  # runtime-interpolated source is rejected, which keeps the swept set static by
  # construction.
  @authorization_codes "attesto_authorization_codes"
  @refresh_tokens "attesto_refresh_tokens"
  @device_codes "attesto_device_codes"
  @ciba_requests "attesto_ciba_requests"
  @logout_sessions "attesto_logout_sessions"
  @dpop_nonces "dpop_nonces"
  @dpop_replays "dpop_replays"
  @pushed_authorization_requests "attesto_pushed_authorization_requests"
  @client_id_metadata "attesto_client_id_metadata"
  @consent_grants "attesto_consent_grants"

  @doc """
  Starts the sweeper.

  Requires a `%AttestoPhoenix.Config{}` under the `:config` key. The config's
  `:sweep_interval_ms` MUST be a positive integer; a missing or non-positive
  interval raises `ArgumentError` so a misconfigured host fails at boot instead
  of starting a process that never sweeps.

  The installer passes `:if_configured` as `true` for upgrade compatibility.
  In that mode an absent interval returns `:ignore`, allowing an existing host
  that does not use the bundled Ecto stores to keep the sweeper disabled. An
  invalid non-nil interval still raises, and direct/manual supervision retains
  the fail-fast default.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) when is_list(opts) do
    config = fetch_config!(opts)

    case configured_interval(config, opts) do
      :ignore ->
        :ignore

      {:ok, _interval} ->
        name = if Keyword.has_key?(opts, :name), do: opts[:name], else: default_name(config)
        GenServer.start_link(__MODULE__, config, name: name)
    end
  end

  @doc false
  def child_spec(opts) do
    %{
      id: Keyword.get(opts, :id, child_id(opts)),
      restart: :permanent,
      shutdown: 5_000,
      start: {__MODULE__, :start_link, [opts]},
      type: :worker
    }
  end

  @impl true
  @spec init(Config.t()) :: {:ok, map()}
  def init(%Config{} = config) do
    interval_ms = sweep_interval_ms!(config)
    schedule_sweep(interval_ms)

    {:ok,
     %{
       repo: config.repo,
       # Keep this state key private to avoid a broad internal rename; the
       # public configuration field is `:schema_prefix`.
       table_prefix: Config.table_prefix(config),
       refresh_rotation_grace_seconds: config.refresh_token_rotation_grace_seconds,
       interval_ms: interval_ms
     }}
  end

  @impl true
  def handle_info(:sweep, state) do
    sweep(state)
    schedule_sweep(state.interval_ms)
    {:noreply, state}
  end

  @doc """
  Runs a single sweep synchronously and returns the number of rows deleted per
  table. Test- and diagnostic-facing; the supervised process drives sweeps via
  the configured interval, not this call.
  """
  @spec sweep_now(GenServer.server()) :: %{optional(String.t()) => non_neg_integer()}
  def sweep_now(server \\ __MODULE__) do
    GenServer.call(server, :sweep_now)
  end

  @impl true
  def handle_call(:sweep_now, _from, state) do
    {:reply, sweep(state), state}
  end

  # Deletes, per table, every row whose `expires_at` is strictly before the
  # single "now" captured for this sweep. Returns a map of table => deleted
  # count. A `DELETE` that raises (e.g. a missing table) propagates: silently
  # swallowing a failed sweep would let a table grow unbounded with no signal,
  # so this fails loud rather than fails quiet.
  defp sweep(%{repo: repo, table_prefix: prefix, refresh_rotation_grace_seconds: grace}) do
    now = DateTime.utc_now()

    _redacted =
      EctoRefreshStore.redact_expired_successors(repo, now,
        prefix: prefix,
        legacy_grace_seconds: grace
      )

    %{
      @authorization_codes => delete_expired(repo, expired_query(@authorization_codes, now), prefix),
      @refresh_tokens => delete_expired(repo, refresh_expired_query(now), prefix),
      @device_codes => delete_expired(repo, expired_query(@device_codes, now), prefix),
      @ciba_requests => delete_expired(repo, expired_query(@ciba_requests, now), prefix),
      @logout_sessions => delete_expired(repo, expired_query(@logout_sessions, now), prefix),
      @dpop_nonces => delete_expired(repo, expired_query(@dpop_nonces, now), prefix),
      @dpop_replays => delete_expired(repo, expired_query(@dpop_replays, now), prefix),
      @pushed_authorization_requests =>
        delete_expired(repo, expired_query(@pushed_authorization_requests, now), prefix),
      @client_id_metadata => delete_expired(repo, expired_query(@client_id_metadata, now), prefix),
      @consent_grants => delete_expired(repo, expired_query(@consent_grants, now), prefix)
    }
  end

  # `from/2` requires a literal string source, so each generated table gets its
  # own clause keyed off the compile-time module attribute. All five clauses are
  # the identical strict `WHERE expires_at < $now` predicate.
  defp expired_query(@authorization_codes, now), do: from(r in @authorization_codes, where: r.expires_at < ^now)

  defp expired_query(@refresh_tokens, now), do: from(r in @refresh_tokens, where: r.expires_at < ^now)

  defp expired_query(@device_codes, now), do: from(r in @device_codes, where: r.expires_at < ^now)

  defp expired_query(@ciba_requests, now), do: from(r in @ciba_requests, where: r.expires_at < ^now)

  defp expired_query(@logout_sessions, now), do: from(r in @logout_sessions, where: r.expires_at < ^now)

  defp expired_query(@dpop_nonces, now), do: from(r in @dpop_nonces, where: r.expires_at < ^now)

  defp expired_query(@dpop_replays, now), do: from(r in @dpop_replays, where: r.expires_at < ^now)

  defp expired_query(@pushed_authorization_requests, now),
    do: from(r in @pushed_authorization_requests, where: r.expires_at < ^now)

  defp expired_query(@client_id_metadata, now), do: from(r in @client_id_metadata, where: r.expires_at < ^now)

  defp expired_query(@consent_grants, now), do: from(r in @consent_grants, where: r.expires_at < ^now)

  # Parent expiry is authoritative. A consumed parent cannot recover after its
  # own expiry, even when a successor retry deadline is later.
  defp refresh_expired_query(now), do: from(r in @refresh_tokens, where: r.expires_at < ^now)

  defp delete_expired(repo, query, prefix) do
    {deleted, _} = repo.delete_all(query, prefix: prefix)
    deleted
  end

  defp schedule_sweep(interval_ms) do
    Process.send_after(self(), :sweep, interval_ms)
  end

  defp fetch_config!(opts) do
    case Keyword.fetch(opts, :config) do
      {:ok, %Config{} = config} ->
        config

      {:ok, other} ->
        raise ArgumentError,
              "AttestoPhoenix.Store.Sweeper: :config must be a %AttestoPhoenix.Config{}, " <>
                "got: #{inspect(other)}"

      :error ->
        raise ArgumentError,
              "AttestoPhoenix.Store.Sweeper: :config (a %AttestoPhoenix.Config{}) is required"
    end
  end

  # A host may mount more than one validated profile. Child identity must be
  # tied to the actual Ecto target, otherwise one profile can accidentally
  # install a second sweeper over the same tables or prevent a distinct schema
  # from receiving housekeeping. The tuple is also safe for arbitrary module
  # names and validated schema-prefix values.
  defp child_id(opts) do
    case Keyword.get(opts, :config) do
      %Config{repo: repo} = config -> {__MODULE__, repo, Config.table_prefix(config)}
      _ -> __MODULE__
    end
  end

  defp default_name(%Config{repo: repo} = config) do
    digest = :crypto.hash(:sha256, :erlang.term_to_binary({repo, Config.table_prefix(config)}))
    String.to_atom("attesto_phoenix_sweeper_" <> Base.encode16(digest, case: :lower))
  end

  defp configured_interval(%Config{sweep_interval_ms: nil} = config, opts) do
    if if_configured?(opts), do: :ignore, else: raise_invalid_interval(config.sweep_interval_ms)
  end

  defp configured_interval(%Config{} = config, opts) do
    _if_configured = if_configured?(opts)
    {:ok, sweep_interval_ms!(config)}
  end

  defp if_configured?(opts) do
    case Keyword.get(opts, :if_configured, false) do
      value when is_boolean(value) -> value
      invalid -> raise ArgumentError, ":if_configured must be true or false; got #{inspect(invalid)}"
    end
  end

  defp sweep_interval_ms!(%Config{sweep_interval_ms: interval}) when is_integer(interval) and interval > 0 do
    interval
  end

  defp sweep_interval_ms!(%Config{sweep_interval_ms: interval}) do
    raise_invalid_interval(interval)
  end

  defp raise_invalid_interval(interval) do
    raise ArgumentError,
          "AttestoPhoenix.Store.Sweeper: :sweep_interval_ms must be a positive integer to run " <>
            "the sweeper; got #{inspect(interval)}. Leave the sweeper out of the supervision " <>
            "tree instead of configuring a non-positive interval."
  end
end
