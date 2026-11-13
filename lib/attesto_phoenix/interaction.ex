defmodule AttestoPhoenix.Interaction do
  @moduledoc """
  Park an authorization request while the End-User authenticates, and resume
  it afterwards.

  When `:authenticate_resource_owner` has to send the End-User to a login page
  (no session, `prompt=login`, or an authentication older than `max_age`), the
  host needs a way back to the same authorization request. `park/2` stores the
  request and returns a `resume_id`; the host redirects to its login page with
  that id and, once the End-User has authenticated, sends the browser to the
  authorization endpoint with `?resume=<resume_id>` and nothing else.

      def authenticate_resource_owner(conn, request, auth_opts) do
        case current_session(conn, auth_opts) do
          {:ok, subject} ->
            {:authenticated, subject}

          :login_needed ->
            {:ok, resume_id} = AttestoPhoenix.Interaction.park(conn, request)
            {:halt, redirect(conn, to: "/login?resume=" <> resume_id)}
        end
      end

  ## What a resume does

  The authorization endpoint takes the parked request out of the store and
  runs it as it would a fresh request with the same parameters: the client is
  loaded again, the request is validated again, the scope policy runs again.
  Nothing the first pass decided is trusted. The host's
  `:authenticate_resource_owner` then receives `auth_opts.resumed: true` and `auth_opts.parked_at` (Unix seconds).
  When the original request included `prompt=login`, the returned `auth_time`
  must be at or after `parked_at`. A stale session, missing time, or invalid
  time is a host contract violation: it is logged and returned as
  `server_error`. The host must perform reauthentication before resuming.

  A parked request can be resumed once. It is bound to the browser that parked
  it through the host's `:interaction_browser_binding` callback
  (`(conn -> binary)`): a value that is stable for one browser and that
  another browser cannot present, typically a pre-login session identifier
  kept in a cookie. Only a hash of it is stored. A resume from a browser whose
  value differs is refused, and that attempt spends the parked request.

  `resume` cannot be combined with any other parameter. An unknown, expired,
  already used or wrong-browser `resume` is answered with a direct error page,
  never a redirect, since nothing about the request can be trusted.

  ## `max_age`

  A request with `max_age` normally allows a short interval beyond `max_age`
  for the trip back from the login page. On a resumed request that interval is
  replaced by an exact rule: an authentication performed after the request was
  parked satisfies `max_age` (the End-User re-authenticated for this request);
  one performed before it must still be within `max_age` now. `max_age=0` on a
  resumed request therefore requires an authentication newer than the park.

  ## Storage

  Parked requests live in the configured `:par_store`, under a key no pushed
  authorization request can have, for `:interaction_ttl` seconds (default 600,
  at most 3600). The store must implement atomic `take/1`. The bundled stores
  expire the rows as they do pushed requests (the Ecto store through the
  sweeper), and parked requests count toward the ETS store's
  `:par_max_entries`.
  """

  alias Attesto.AuthorizationRequest
  alias Attesto.Secret
  alias AttestoPhoenix.Callback
  alias AttestoPhoenix.Config
  # Not a `urn:ietf:params:oauth:request_uri:` reference, so the key space is
  # disjoint from pushed authorization requests held in the same store.
  alias AttestoPhoenix.Store.PAR.ETS
  alias Plug.Conn.Unfetched

  @key_prefix "urn:attesto:interaction:"
  @resume_id_bytes 32

  @type parked :: %{params: map(), client_id: String.t(), parked_at: integer()}

  @doc """
  Store the authorization request being processed on `conn` and return the
  identifier that resumes it.

  `request` is the validated request the host callback received. Call this
  from `:authenticate_resource_owner` (or `:consent`), where `conn` still
  carries the authorization request's parameters.

  Raises `ArgumentError` when the configuration cannot park a request: no
  `:interaction_browser_binding`, a `:par_store` without `take/1`, or a
  callback that returns no usable browser value.
  """
  @spec park(Plug.Conn.t(), AuthorizationRequest.t()) :: {:ok, String.t()} | {:error, term()}
  def park(%Plug.Conn{} = conn, %AuthorizationRequest{} = request) do
    config = Config.resolve!(conn)
    store = store!(config)
    binding = browser_binding!(config, conn)
    resume_id = Secret.generate(@resume_id_bytes)

    entry = %{
      "params" => parked_params(conn),
      "client_id" => request.client_id,
      "binding" => binding_hash(binding),
      "parked_at" => System.system_time(:second)
    }

    case store.put(@key_prefix <> resume_id, entry, config.interaction_ttl) do
      :ok -> {:ok, resume_id}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Take the request parked under `resume_id` for the browser on `conn`.

  Returns `{:ok, %{params: ..., client_id: ..., parked_at: ...}}`, or
  `{:error, :invalid_resume}` when the id is unknown, expired or already used,
  the browser value does not match, or the configuration cannot resume. The
  entry is consumed by the lookup in every case in which it was found.
  """
  @spec take(Config.t(), Plug.Conn.t(), term()) :: {:ok, parked()} | {:error, :invalid_resume}
  def take(%Config{} = config, %Plug.Conn{} = conn, resume_id) when is_binary(resume_id) and resume_id != "" do
    with {:ok, store} <- store(config),
         {:ok, binding} <- browser_binding(config, conn),
         {:ok, entry} <- store.take(@key_prefix <> resume_id),
         %{"params" => params, "client_id" => client_id, "binding" => stored, "parked_at" => parked_at}
         when is_map(params) and is_binary(client_id) and is_binary(stored) and is_integer(parked_at) <- entry,
         true <- Plug.Crypto.secure_compare(stored, binding_hash(binding)) do
      {:ok, %{params: params, client_id: client_id, parked_at: parked_at}}
    else
      _ -> {:error, :invalid_resume}
    end
  end

  def take(%Config{}, %Plug.Conn{}, _resume_id), do: {:error, :invalid_resume}

  @doc """
  Whether `key` is in the key space parked requests use. The authorization
  endpoint refuses such a value as a `request_uri`.
  """
  @spec reserved_key?(term()) :: boolean()
  def reserved_key?(key) when is_binary(key), do: String.starts_with?(key, @key_prefix)
  def reserved_key?(_key), do: false

  @doc """
  The interval beyond `max_age` a resumed request is allowed, given the
  authentication time the host returned (see "`max_age`" above).

  An authentication at or after `parked_at` gets the time since the park, which
  always satisfies `max_age`; anything else gets zero.
  """
  @spec max_age_allowance(integer(), term(), integer()) :: non_neg_integer()
  def max_age_allowance(parked_at, auth_time, now)
      when is_integer(parked_at) and is_integer(auth_time) and is_integer(now) and auth_time >= parked_at,
      do: max(now - parked_at, 0)

  def max_age_allowance(_parked_at, _auth_time, _now), do: 0

  # The authorization parameters as they arrived: query and body, without
  # router path parameters. A `request_uri` among them is kept as the
  # reference; the pushed request is resolved again on resume.
  defp parked_params(%Plug.Conn{} = conn) do
    conn = Plug.Conn.fetch_query_params(conn)

    body =
      case conn.body_params do
        %Unfetched{} -> %{}
        %{} = params -> params
      end

    conn.query_params |> Map.merge(body) |> Map.delete("resume")
  end

  defp store!(config) do
    case store(config) do
      {:ok, store} ->
        store

      :error ->
        raise ArgumentError,
              "AttestoPhoenix.Interaction: :par_store must implement put/3 and atomic take/1 to park a request"
    end
  end

  defp store(config) do
    store = config.par_store || ETS

    if Code.ensure_loaded?(store) and function_exported?(store, :put, 3) and function_exported?(store, :take, 1),
      do: {:ok, store},
      else: :error
  end

  defp browser_binding!(config, conn) do
    case browser_binding(config, conn) do
      {:ok, binding} ->
        binding

      :error ->
        raise ArgumentError,
              "AttestoPhoenix.Interaction: :interaction_browser_binding must be configured and return a " <>
                "non-empty binary for the current browser"
    end
  end

  defp browser_binding(%Config{interaction_browser_binding: nil}, _conn), do: :error

  defp browser_binding(%Config{interaction_browser_binding: callback}, conn) do
    case Callback.invoke(callback, [conn]) do
      binding when is_binary(binding) and binding != "" -> {:ok, binding}
      _ -> :error
    end
  end

  defp binding_hash(binding), do: Secret.hash(binding)
end
