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
  no longer affect any decision. A consumed code's expired row can still carry
  the replay-revocation link for a live access token, so that row is retained
  until the linked token expires.

  The process also irreversibly redacts refresh-successor ciphertext whose
  short retry deadline has passed, on the next scheduled sweep. When the Ecto
  refresh store uses a positive retry grace, this bounded credential cleanup
  requires the packaged sweeper or an acknowledged equivalent cleanup worker.
  The installer adds the packaged worker to the host supervision tree
  automatically; manually wired applications MUST either supervise it with a
  positive `:sweep_interval_ms` or register an equivalent worker.

  The remaining work is TTL housekeeping: it issues one delete per swept table
  using `expires_at < $now`. Authorization-code cleanup additionally keeps a
  row while its non-empty access-token link has a future
  `access_token_expires_at`, preserving replay revocation until that token dies.

  ## Comparison boundary (fail-closed)

  Row expiry uses a strict `<` comparison against a single `DateTime` captured
  once per sweep (`DateTime.utc_now/0`) and reused across every table, so a
  sweep applies one consistent boundary. A row whose `expires_at` equals "now"
  is retained. For an already-expired authorization-code row, however, a
  linked access token whose own expiry equals "now" is no longer live and does
  not delay cleanup. The sweeper widens no acceptance window.

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

  ## Runtime signal

  Application-facing mutations through the bundled Ecto stores whose tables
  the sweeper maintains check cleanup-worker liveness without waiting for
  telemetry handlers or Logger. The sweeper's own maintenance queries do not
  recursively signal. Diagnostic failures never change store results; signal
  delivery is asynchronous and best effort.

  With no registered worker, the first mutation schedules a warning and this
  telemetry event:

    * `[:attesto_phoenix, :store, :sweeper_unsupervised]` — measurements
      `%{count: 1}`; metadata `%{repo: repo, schema_prefix: prefix}`.

  Repeated mutations for the same repository/schema pair are suppressed for
  one hour, then a later mutation may schedule a reminder. Registering a
  cleanup worker cancels a queued warning when recovery is observed before
  delivery. At most 1,024 repository/schema pairs are retained for diagnostics.
  Suppression state is in memory, so a monitoring-process restart may begin a
  new episode. The two exceptional signals are:

    * `[:attesto_phoenix, :store, :sweeper_signal_capacity]` — measurements
      `%{count: 1}`; metadata `%{}`. It is scheduled once while the cap remains
      exhausted and rearms after capacity becomes available.
    * `[:attesto_phoenix, :store, :sweeper_monitor_unavailable]` — measurements
      `%{count: 1}`; metadata `%{repo: repo, schema_prefix: prefix}`. It is
      scheduled at most once per lifecycle-monitor outage and rearms only after
      recovery.

  Telemetry metadata contains identifiers only, never configuration structs,
  tokens, refresh-successor secrets, or client credentials.

  The package isolates this best-effort machinery from the host supervision
  tree. If its diagnostic supervisor exhausts its restart budget, OTP reports
  that failure and leaves diagnostics stopped until the `:attesto_phoenix`
  application restarts; store operations continue with their original results.

  The `running?/0,1`, `verify_running!/0,1`, and `sweep_now/0` functions read
  process liveness from a registry owned by the package root supervisor, so
  their answers stay correct while the diagnostics supervisor restarts or
  remains stopped.
  """

  use GenServer

  import Ecto.Query, only: [from: 2]

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Store.EctoRefreshStore
  alias AttestoPhoenix.Store.Sweeper.Lifecycle
  alias AttestoPhoenix.Store.Sweeper.Liveness
  alias AttestoPhoenix.Store.Sweeper.Registration
  alias AttestoPhoenix.Store.Sweeper.Signal

  @lifecycle_retry_ms 50
  @lifecycle_retry_max_ms 5_000

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
      :ignore -> :ignore
      {:ok, _interval} -> start_sweeper_process(config, opts)
    end
  end

  defp start_sweeper_process(config, opts) do
    if Keyword.has_key?(opts, :name) do
      start_named_process(config, opts[:name])
    else
      GenServer.start_link(__MODULE__, config, name: default_name(config))
    end
  end

  defp start_named_process(config, nil), do: GenServer.start_link(__MODULE__, config)
  defp start_named_process(config, name), do: GenServer.start_link(__MODULE__, config, name: name)

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
    target = {config.repo, Config.table_prefix(config)}
    schedule_sweep(interval_ms)

    state = %{
      repo: config.repo,
      # Keep this state key private to avoid a broad internal rename; the
      # public configuration field is `:schema_prefix`.
      table_prefix: Config.table_prefix(config),
      refresh_rotation_grace_seconds: config.refresh_token_rotation_grace_seconds,
      interval_ms: interval_ms,
      lifecycle_target: target,
      lifecycle_pid: nil,
      lifecycle_ref: nil,
      lifecycle_retry_ms: @lifecycle_retry_ms
    }

    _ = Liveness.register_sweeper(target)

    {:ok, register_with_lifecycle_or_retry(state)}
  end

  @impl true
  def handle_info(:sweep, state) do
    sweep(state)
    schedule_sweep(state.interval_ms)
    {:noreply, state}
  end

  def handle_info({:DOWN, ref, :process, pid, _reason}, %{lifecycle_ref: ref, lifecycle_pid: pid} = state) do
    send(self(), :register_sweeper_lifecycle)
    {:noreply, %{state | lifecycle_pid: nil, lifecycle_ref: nil}}
  end

  def handle_info(:register_sweeper_lifecycle, %{lifecycle_pid: lifecycle_pid} = state) when is_pid(lifecycle_pid) do
    {:noreply, state}
  end

  def handle_info(:register_sweeper_lifecycle, state) do
    {:noreply, register_with_lifecycle_or_retry(state)}
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp register_with_lifecycle_or_retry(state) do
    case Lifecycle.register_sweeper(state.lifecycle_target, self()) do
      {:ok, lifecycle_pid} ->
        %{
          state
          | lifecycle_pid: lifecycle_pid,
            lifecycle_ref: Process.monitor(lifecycle_pid),
            lifecycle_retry_ms: @lifecycle_retry_ms
        }

      {:error, _reason} ->
        delay = Map.get(state, :lifecycle_retry_ms, @lifecycle_retry_ms)
        Process.send_after(self(), :register_sweeper_lifecycle, delay)
        next_delay = min(delay * 2, @lifecycle_retry_max_ms)
        %{state | lifecycle_retry_ms: next_delay}
    end
  end

  @doc """
  Runs a single sweep synchronously and returns the number of rows deleted per
  table. Test- and diagnostic-facing; the supervised process drives sweeps via
  the configured interval, not this call.

  The zero-arity form resolves the packaged sweeper registered for the current
  request or application configuration. It raises `RuntimeError` when that
  sweeper is not registered; an acknowledged equivalent cleanup worker is not
  invoked as though it were this GenServer.
  """
  @spec sweep_now() :: %{optional(String.t()) => non_neg_integer()}
  def sweep_now, do: sweep_now(default_server())

  @spec sweep_now(GenServer.server()) :: %{optional(String.t()) => non_neg_integer()}
  def sweep_now(server) do
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
  # own clause keyed off the compile-time module attribute. Authorization-code
  # rows carry replay-revocation provenance after successful redemption. Keep a
  # code row until its linked access token is no longer live; otherwise a replay
  # can no longer find the row and revoke the issued token.
  defp expired_query(@authorization_codes, now) do
    from(r in @authorization_codes,
      where:
        r.expires_at < ^now and
          (is_nil(r.access_token_jti) or r.access_token_jti == "" or
             is_nil(r.access_token_expires_at) or r.access_token_expires_at <= ^now)
    )
  end

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
    {deleted, _} =
      repo.delete_all(query,
        prefix: prefix,
        log: false,
        telemetry_event: nil
      )

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

  @doc """
  Determines whether an `AttestoPhoenix.Store.Sweeper` (or an acknowledged equivalent
  cleanup worker) is running for the current request configuration (or application default).

  Note: Observable process liveness is confirmed; supervision tree ancestry is not claimed.
  """
  @spec running?() :: boolean()
  def running? do
    target = resolve_default_target()
    running?(target)
  end

  @doc """
  Determines whether an `AttestoPhoenix.Store.Sweeper` (or an acknowledged equivalent
  cleanup worker) is running for `target`.

  `target` may be a `%Config{}`, `{repo, schema_prefix}`, local `pid`, locally
  registered name, or one of these keyword forms: `[config: config]`,
  `[repo: repo]`, `[repo: repo, schema_prefix: prefix]`, `[pid: pid]`, `[name: name]`,
  `[config: config, pid: pid]`, or `[config: config, name: name]`.
  Unknown, duplicate, and ambiguous options return `false`.

  Note: Observable process liveness is confirmed; supervision tree ancestry is not claimed.
  """
  @spec running?(Config.t() | {module(), String.t() | nil} | GenServer.server() | keyword() | nil) ::
          boolean()
  def running?(nil), do: false

  def running?(%Config{} = config) do
    case config_target(config) do
      {:ok, target} -> Lifecycle.running_target?(target)
      {:error, _reason} -> false
    end
  end

  def running?(pid) when is_pid(pid) do
    if node(pid) == node(), do: Lifecycle.registered_worker?(pid), else: false
  end

  def running?(name) when is_atom(name) do
    running_registered_name?(name)
  end

  def running?({:global, _term} = name), do: running_registered_name?(name)
  def running?({:via, _module, _term} = name), do: running_registered_name?(name)

  def running?({repo, prefix} = target)
      when is_atom(repo) and not is_nil(repo) and (is_binary(prefix) or is_nil(prefix)) do
    if valid_target?(target), do: Lifecycle.running_target?(target), else: false
  end

  def running?({name, node_name} = server) when is_atom(name) and is_atom(node_name) do
    if node_name == node(), do: running_registered_name?(server), else: false
  end

  def running?(opts) when is_list(opts), do: running_opts?(opts)
  def running?(_other), do: false

  defp running_opts?(opts) do
    case parse_running_options(opts) do
      {:config, config} -> running?(config)
      {:configured_worker, config, worker} -> running_configured_worker?(config, worker)
      {:target, target} -> running?(target)
      {:worker, worker} -> running?(worker)
      {:error, _reason} -> false
    end
  end

  defp running_configured_worker?(config, worker) do
    with {:ok, target} <- config_target(config),
         pid when is_pid(pid) <- resolve_registered_name(worker) do
      Lifecycle.registered_worker_for_target?(pid, target)
    else
      _ ->
        false
    end
  end

  defp running_registered_name?(name) do
    case resolve_registered_name(name) do
      pid when is_pid(pid) -> Lifecycle.registered_worker?(pid)
      _other -> false
    end
  end

  defp resolve_registered_name(nil), do: nil

  defp resolve_registered_name({:global, _term} = name), do: safe_whereis(name)
  defp resolve_registered_name({:via, _module, _term} = name), do: safe_whereis(name)

  defp resolve_registered_name({_name, node_name}) when is_atom(node_name) and node_name != node(), do: nil

  defp resolve_registered_name(name), do: safe_whereis(name)

  defp safe_whereis(name) do
    GenServer.whereis(name)
  rescue
    _error -> nil
  catch
    _kind, _reason -> nil
  end

  @doc """
  Verifies that an `AttestoPhoenix.Store.Sweeper` (or an acknowledged equivalent cleanup worker)
  is running for `target` (or the current request/application configuration).

  Returns `:ok` when verified. Raises `RuntimeError` with an actionable diagnostic
  when no registered worker is running.
  """
  @spec verify_running!() :: :ok
  def verify_running! do
    case resolve_default_config_or_target() do
      {:config, config} ->
        verify_running!(config)

      {:target, target} ->
        verify_running!(target)

      :none ->
        raise RuntimeError,
              "AttestoPhoenix.Store.Sweeper is not running: no repository or configuration was provided or resolvable."
    end
  end

  @doc """
  Verifies that a sweeper or acknowledged equivalent cleanup worker is running
  for `target`.

  Accepts the same target forms as `running?/1`. Returns `:ok` when verified;
  otherwise raises `RuntimeError` with an actionable diagnostic.
  """
  @spec verify_running!(Config.t() | {module(), String.t() | nil} | GenServer.server() | keyword() | nil) ::
          :ok
  def verify_running!(target) do
    if running?(target) do
      :ok
    else
      raise RuntimeError, verification_error(target)
    end
  end

  @doc """
  Registers an acknowledged host-supplied equivalent cleanup worker process for the given target.

  The target must be a `%Config{}`, `{repo, schema_prefix}`, `[config: config]`,
  `[repo: repo]`, or `[repo: repo, schema_prefix: prefix]`. Unknown, duplicate,
  and ambiguous options raise `ArgumentError`.

  While the worker process remains alive, `running?/1` returns `true` for the
  target and missing-sweeper warnings are suppressed. When the worker process
  terminates, missing-sweeper episode detection is rearmed. This API is intended
  for a finite set of trusted, application-owned cleanup workers registered at
  startup. A registration for a still-live PID is restored when the
  `:attesto_phoenix` application restarts in the same VM. Register again when
  the cleanup worker itself restarts or on a new node boot.

  The worker PID must belong to the local node. Each node registers and
  monitors its own cleanup worker.

  The call returns `:ok` only after the lifecycle monitor has acknowledged the
  registration. If that monitor is restarting, the call raises and the host
  must retry after the application recovers.
  """
  @spec register_cleanup_worker(Config.t() | {module(), String.t() | nil} | keyword()) :: :ok
  @spec register_cleanup_worker(
          Config.t() | {module(), String.t() | nil} | keyword(),
          pid()
        ) :: :ok
  def register_cleanup_worker(target, pid \\ self())

  def register_cleanup_worker(target, pid) when is_pid(pid) do
    if node(pid) != node() do
      raise ArgumentError, "cleanup worker must be a local pid"
    end

    {repo, prefix} = parse_cleanup_target!(target)

    case Registration.register({repo, prefix}, pid) do
      :ok ->
        :ok

      {:error, :worker_not_alive} ->
        raise ArgumentError, "cleanup worker is not alive"

      {:error, :not_started} ->
        raise "#{inspect(Registration)} is not running; start the :attesto_phoenix application"

      {:error, :timeout} ->
        raise "#{inspect(Registration)} did not respond while registering the cleanup worker; retry registration"

      {:error, :lifecycle_not_started} ->
        raise "#{inspect(Lifecycle)} is not running; wait for the :attesto_phoenix application " <>
                "to recover, then register the cleanup worker again"

      {:error, reason} ->
        raise "could not monitor cleanup worker: #{inspect(reason)}"
    end
  end

  def register_cleanup_worker(_target, _pid) do
    raise ArgumentError, "cleanup worker must be a pid"
  end

  @doc false
  def check_running_for_store(repo, prefix) do
    with true <- is_atom(repo) and not is_nil(repo),
         true <- is_binary(prefix) or is_nil(prefix),
         {:ok, target} <- safe_normalize_target({repo, prefix}) do
      signal_if_missing(target)
      :ok
    else
      _ -> :ok
    end
  rescue
    _ -> :ok
  catch
    :exit, _ -> :ok
    _, _ -> :ok
  end

  defp signal_if_missing(target) do
    if not Lifecycle.running_target?(target) do
      signal_target(target)
    end
  end

  defp signal_target(target) do
    case Lifecycle.check_target(target) do
      :ok -> :ok
      :unavailable -> Signal.monitor_unavailable(target)
    end
  end

  defp verification_error(target) do
    case verification_subject(target) do
      {:target, {repo, prefix}} ->
        "AttestoPhoenix.Store.Sweeper is not running for #{inspect(repo)} " <>
          "(schema_prefix: #{inspect(prefix)}). " <>
          "Start AttestoPhoenix.Store.Sweeper with a positive :sweep_interval_ms in your " <>
          "application supervision tree (or register an equivalent cleanup worker) " <>
          "to redact expired refresh-successor ciphertext and prune expired TTL rows."

      {:worker, worker} ->
        "The supplied sweeper or cleanup worker #{inspect(worker)} is not registered and " <>
          "running on this node."

      {:configured_worker, worker, {repo, prefix}} ->
        "The supplied sweeper or cleanup worker #{inspect(worker)} is not registered and " <>
          "running for #{inspect(repo)} (schema_prefix: #{inspect(prefix)}) on this node."

      :invalid ->
        "AttestoPhoenix.Store.Sweeper is not running: the target is invalid or no " <>
          "repository/configuration could be resolved."
    end
  end

  defp verification_subject(%Config{} = config) do
    case config_target(config) do
      {:ok, target} -> {:target, target}
      {:error, _reason} -> :invalid
    end
  end

  defp verification_subject({repo, prefix} = target)
       when is_atom(repo) and not is_nil(repo) and (is_binary(prefix) or is_nil(prefix)) do
    case safe_normalize_target(target) do
      {:ok, target} -> {:target, target}
      {:error, _reason} -> :invalid
    end
  end

  defp verification_subject(opts) when is_list(opts) do
    case parse_running_options(opts) do
      {:config, config} ->
        verification_subject(config)

      {:target, target} ->
        verification_subject(target)

      {:worker, worker} ->
        {:worker, worker}

      {:configured_worker, config, worker} ->
        case config_target(config) do
          {:ok, target} -> {:configured_worker, worker, target}
          {:error, _reason} -> :invalid
        end

      {:error, _reason} ->
        :invalid
    end
  end

  defp verification_subject(pid) when is_pid(pid), do: {:worker, pid}
  defp verification_subject(name) when is_atom(name) and not is_nil(name), do: {:worker, name}
  defp verification_subject({:global, _term} = name), do: {:worker, name}
  defp verification_subject({:via, _module, _term} = name), do: {:worker, name}

  defp verification_subject({name, node_name} = server) when is_atom(name) and is_atom(node_name) do
    if String.contains?(Atom.to_string(node_name), "@"), do: {:worker, server}, else: :invalid
  end

  defp verification_subject(_other), do: :invalid

  defp valid_target?(target) do
    case safe_normalize_target(target) do
      {:ok, _} -> true
      {:error, _} -> false
    end
  end

  defp safe_normalize_target({repo, prefix} = target) when is_atom(repo) and not is_nil(repo) do
    case prefix do
      nil ->
        {:ok, target}

      prefix when is_binary(prefix) ->
        try do
          Config.validate_schema_prefix!(prefix)
          {:ok, target}
        rescue
          ArgumentError -> {:error, :invalid_prefix}
        end

      _other ->
        {:error, :invalid_prefix}
    end
  end

  defp safe_normalize_target(_), do: {:error, :invalid_target}

  defp parse_cleanup_target!(%Config{} = config) do
    config
    |> config_target()
    |> normalize_parsed_target!()
  end

  defp parse_cleanup_target!({repo, prefix}) do
    {repo, prefix}
    |> safe_normalize_target()
    |> normalize_parsed_target!()
  end

  defp parse_cleanup_target!(opts) when is_list(opts) do
    result =
      case validate_option_keys(opts, [:config, :repo, :schema_prefix]) do
        :ok ->
          keys = MapSet.new(Keyword.keys(opts))

          cond do
            keys == MapSet.new([:config]) ->
              config_target(opts[:config])

            keys == MapSet.new([:repo]) ->
              safe_normalize_target({opts[:repo], nil})

            keys == MapSet.new([:repo, :schema_prefix]) ->
              safe_normalize_target({opts[:repo], opts[:schema_prefix]})

            true ->
              {:error, :invalid_options}
          end

        {:error, reason} ->
          {:error, reason}
      end

    normalize_parsed_target!(result)
  end

  defp parse_cleanup_target!(_other), do: invalid_cleanup_target!()

  defp normalize_parsed_target!({:ok, target}), do: target

  defp normalize_parsed_target!({:error, _reason}), do: invalid_cleanup_target!()

  defp invalid_cleanup_target! do
    raise ArgumentError,
          "sweeper target must be {repo_module, schema_prefix}, " <>
            "a %AttestoPhoenix.Config{}, [config: config], or " <>
            "[repo: repo_module] / [repo: repo_module, schema_prefix: prefix]"
  end

  defp parse_running_options(opts) do
    with :ok <- validate_option_keys(opts, [:config, :repo, :schema_prefix, :name, :pid]) do
      keys = MapSet.new(Keyword.keys(opts))

      cond do
        keys == MapSet.new([:config]) ->
          {:config, opts[:config]}

        keys == MapSet.new([:config, :name]) ->
          {:configured_worker, opts[:config], opts[:name]}

        keys == MapSet.new([:config, :pid]) ->
          {:configured_worker, opts[:config], opts[:pid]}

        keys == MapSet.new([:repo]) ->
          {:target, {opts[:repo], nil}}

        keys == MapSet.new([:repo, :schema_prefix]) ->
          {:target, {opts[:repo], opts[:schema_prefix]}}

        keys == MapSet.new([:name]) ->
          {:worker, opts[:name]}

        keys == MapSet.new([:pid]) ->
          {:worker, opts[:pid]}

        true ->
          {:error, :invalid_options}
      end
    end
  end

  defp validate_option_keys(opts, allowed_keys) do
    cond do
      not Keyword.keyword?(opts) ->
        {:error, :not_keyword}

      length(Keyword.keys(opts)) != length(Enum.uniq(Keyword.keys(opts))) ->
        {:error, :duplicate_keys}

      Enum.any?(Keyword.keys(opts), &(&1 not in allowed_keys)) ->
        {:error, :unknown_key}

      true ->
        :ok
    end
  end

  defp config_target(%Config{} = config) do
    safe_normalize_target({config.repo, Config.table_prefix(config)})
  rescue
    _error -> {:error, :invalid_config}
  catch
    :exit, _reason -> {:error, :invalid_config}
    _kind, _reason -> {:error, :invalid_config}
  end

  defp config_target(_other), do: {:error, :invalid_config}

  defp resolve_default_config_or_target do
    case Config.request_config() do
      %Config{} = config -> {:config, config}
      nil -> resolve_fallback_config_or_target()
    end
  end

  defp resolve_fallback_config_or_target do
    case safe_resolve_config() do
      %Config{} = config -> {:config, config}
      nil -> resolve_repo_env_target()
    end
  end

  defp safe_resolve_config do
    Config.resolve!()
  rescue
    _ -> nil
  catch
    :exit, _reason -> nil
    _kind, _reason -> nil
  end

  defp resolve_repo_env_target do
    case Application.get_env(:attesto_phoenix, :repo) do
      repo when is_atom(repo) and not is_nil(repo) ->
        try do
          {:target, {repo, Config.table_prefix()}}
        rescue
          _error -> :none
        catch
          :exit, _reason -> :none
          _kind, _reason -> :none
        end

      _ ->
        :none
    end
  end

  defp resolve_default_target do
    case resolve_default_config_or_target() do
      {:config, config} ->
        case config_target(config) do
          {:ok, target} -> target
          {:error, _reason} -> {nil, nil}
        end

      {:target, target} ->
        target

      :none ->
        {nil, nil}
    end
  end

  defp default_server do
    config = Config.request_config() || Config.resolve!()
    target = {config.repo, Config.table_prefix(config)}

    case Lifecycle.get_sweeper(target) do
      {:ok, pid} ->
        pid

      :error ->
        raise RuntimeError,
              "AttestoPhoenix.Store.Sweeper is not running for #{inspect(config.repo)} " <>
                "(schema_prefix: #{inspect(Config.table_prefix(config))})"
    end
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
