defmodule AttestoPhoenix.Store.EctoPARStore do
  @moduledoc """
  Postgres-backed `AttestoPhoenix.PARStore` for clustered deployments
  (RFC 9126).

  A Pushed Authorization Request endpoint stores the validated authorization
  request parameters behind a one-time `request_uri` reference and returns that
  reference to the client; the client then presents only the `request_uri` at
  `/authorize`. The default `AttestoPhoenix.Store.PAR.ETS` keeps that mapping in
  per-node memory, so a `request_uri` pushed to one node is unknown to another -
  fatal behind a load balancer, and FAPI 2.0 *requires* PAR. This store persists
  each pushed request so any node resolves a `request_uri` issued by any other,
  matching the Ecto-backed code/refresh/nonce/replay stores.

  ## Behaviour callbacks

    * `put/3` inserts the reference, the stored params, and the derived expiry.
    * `fetch/1` resolves a live (unexpired) reference WITHOUT consuming it - the
      authorization endpoint may re-enter with the same `request_uri` after a
      login/consent detour (RFC 9126), so resolution must not spend it. Expiry
      is enforced on read, so an unswept expired reference is never honored.
    * `take/1` resolves and atomically deletes a live reference in one
      `DELETE … RETURNING` statement, for hosts that want single-use semantics.
      Exactly one of any number of racing callers gets the row.

  The repository module is supplied by the host application (`:repo` under the
  `:attesto_phoenix` app) and read at call time; a store with no backing
  repository fails closed rather than silently no-opping.
  """

  @behaviour AttestoPhoenix.PARStore

  import Ecto.Query, only: [from: 2]

  alias AttestoPhoenix.Schema.PushedAuthorizationRequest, as: PushedRequest

  @app :attesto_phoenix

  @doc """
  Persists a pushed authorization request under `request_uri` for
  `ttl_seconds`.

  `params` is the stored, string-keyed parameter map; it is round-tripped
  through `jsonb`, so the authorization endpoint reads back the same string-keyed
  map it stored. A duplicate `request_uri` (an astronomically unlikely random
  collision) surfaces as `{:error, changeset}` rather than overwriting an
  existing reference.
  """
  @impl AttestoPhoenix.PARStore
  @spec put(String.t(), map(), pos_integer()) :: :ok | {:error, term()}
  def put(request_uri, params, ttl_seconds)
      when is_binary(request_uri) and is_map(params) and is_integer(ttl_seconds) and ttl_seconds > 0 do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    expires_at = DateTime.add(now, ttl_seconds, :second)

    %{request_uri: request_uri, params: params, expires_at: expires_at, inserted_at: now}
    |> PushedRequest.put_changeset()
    |> repo().insert()
    |> case do
      {:ok, _row} -> :ok
      {:error, changeset} -> {:error, changeset}
    end
  end

  @doc """
  Resolves a live `request_uri` without consuming it.

  Returns `{:ok, params}` when a row exists and has not expired, or `:error`
  when it is absent or expired. Non-consuming by contract: the authorization
  endpoint may resolve the same `request_uri` more than once across a
  login/consent detour (RFC 9126); TTL, not resolution, ends its life.
  """
  @impl AttestoPhoenix.PARStore
  @spec fetch(String.t()) :: {:ok, map()} | :error
  def fetch(request_uri) when is_binary(request_uri) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    query =
      from p in PushedRequest,
        where: p.request_uri == ^request_uri and p.expires_at > ^now,
        select: p.params

    case repo().one(query) do
      nil -> :error
      params -> {:ok, params}
    end
  end

  @doc """
  Atomically resolves and deletes a live `request_uri`.

  The resolve and the delete are one indivisible `DELETE … WHERE … RETURNING`
  statement, so for hosts that opt into single-use PAR references exactly one of
  any number of concurrent callers (on any node) gets `{:ok, params}`; the rest
  get `:error`. An expired row is treated as absent.
  """
  @impl AttestoPhoenix.PARStore
  @spec take(String.t()) :: {:ok, map()} | :error
  def take(request_uri) when is_binary(request_uri) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    query =
      from p in PushedRequest,
        where: p.request_uri == ^request_uri and p.expires_at > ^now,
        select: p.params

    case repo().delete_all(query) do
      {1, [params]} -> {:ok, params}
      {0, _} -> :error
    end
  end

  defp repo do
    case Application.get_env(@app, :repo) do
      nil ->
        # Fail closed: a PAR store with no backing repository cannot share a
        # reference across nodes, so refuse rather than silently no-op.
        raise ArgumentError,
              "AttestoPhoenix: no :repo configured. Set `config #{inspect(@app)}, repo: MyApp.Repo`"

      repo ->
        repo
    end
  end
end
