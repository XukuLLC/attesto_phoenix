defmodule AttestoPhoenix.Plug.CORS do
  @moduledoc """
  Cross-Origin Resource Sharing (CORS) support for authorization-server and
  protected-resource endpoints (RFC 10017 §6.3.3.4).

  Browser-based OAuth clients make cross-origin `fetch()` calls to metadata,
  JWKS, token, revocation, introspection, dynamic registration, UserInfo, and
  protected-resource endpoints, including `OPTIONS` preflight requests when
  sending `Authorization`, `DPoP`, or `Content-Type: application/json` headers.

  Policy resolution order:

    1. The `:origins` option passed to the plug or helper.
    2. `:cors_origins` on `conn.private[:attesto_phoenix_config]`.
    3. Default `:*` (wildcard `Access-Control-Allow-Origin: *`, never paired
       with `Access-Control-Allow-Credentials`).

  Set `cors_origins: false` to disable CORS headers and refuse preflights
  through the router's normal missing-route handling, or configure an
  explicit list of allowed origins (`["https://app.example"]`) or a 1-arity
  predicate callback (`(origin -> boolean())`). When an allowlist or callback
  is used, responses vary by `Origin` (`Vary: origin`) and only echo a
  matching origin.
  """

  @behaviour Plug

  import Plug.Conn

  alias AttestoPhoenix.{Callback, Config}
  alias Phoenix.Router.NoRouteError

  @default_methods "GET, POST, PUT, DELETE, OPTIONS"
  @default_allow_headers "authorization, content-type, dpop, oauth-client-attestation, oauth-client-attestation-pop"
  @default_expose_headers "www-authenticate, dpop-nonce, oauth-client-attestation-challenge"
  @default_max_age "600"

  @impl Plug
  @spec init(keyword()) :: keyword()
  def init(opts) when is_list(opts), do: opts

  @impl Plug
  @spec call(Plug.Conn.t(), keyword()) :: Plug.Conn.t()
  def call(%Plug.Conn{method: "OPTIONS"} = conn, opts) do
    preflight(conn, opts)
  end

  def call(%Plug.Conn{} = conn, opts) do
    apply_headers(conn, opts)
  end

  @doc """
  Applies CORS response headers to `conn` according to the active policy.

  Existing `access-control-allow-origin` headers set earlier in the pipeline
  are preserved.
  """
  @spec apply_headers(Plug.Conn.t(), keyword()) :: Plug.Conn.t()
  def apply_headers(%Plug.Conn{} = conn, opts \\ []) when is_list(opts) do
    if get_resp_header(conn, "access-control-allow-origin") == [] do
      put_cors_headers(conn, resolve_policy(conn, opts), false, opts)
    else
      conn
    end
  end

  @doc """
  Answers an HTTP `OPTIONS` CORS preflight request with `204 No Content` and
  halted connection state. When the effective policy is `false`, raises
  `Phoenix.Router.NoRouteError` with the connection and router. Outside a
  Phoenix router, sends an empty `404` response instead.
  """
  @spec preflight(Plug.Conn.t(), keyword()) :: Plug.Conn.t()
  def preflight(%Plug.Conn{} = conn, opts \\ []) when is_list(opts) do
    case resolve_policy(conn, opts) do
      false ->
        no_route(conn)

      policy ->
        conn
        |> put_cors_headers(policy, true, opts)
        |> send_resp(204, "")
        |> halt()
    end
  end

  @doc false
  def reject_disabled_preflight(conn, opts \\ []) do
    if resolve_policy(conn, opts) == false, do: no_route(conn), else: conn
  end

  defp no_route(conn) do
    case conn.private[:phoenix_router] do
      nil -> conn |> send_resp(404, "") |> halt()
      router -> raise NoRouteError, conn: conn, router: router
    end
  end

  defp resolve_policy(conn, opts) do
    case Keyword.fetch(opts, :origins) do
      {:ok, policy} when not is_nil(policy) ->
        policy

      _ ->
        case conn.private[:attesto_phoenix_config] do
          %Config{cors_origins: policy} -> policy
          _ -> :*
        end
    end
  end

  defp put_cors_headers(conn, false, _preflight?, _opts), do: conn

  defp put_cors_headers(conn, policy, preflight?, opts) when policy in [:*, :all, "*"] do
    conn
    |> put_resp_header("access-control-allow-origin", "*")
    |> put_expose_and_preflight_headers(preflight?, opts)
  end

  defp put_cors_headers(conn, origins, preflight?, opts) when is_list(origins) do
    with [origin] <- get_req_header(conn, "origin"),
         true <- origin in origins do
      conn
      |> put_vary_origin()
      |> put_resp_header("access-control-allow-origin", origin)
      |> put_expose_and_preflight_headers(preflight?, opts)
    else
      _ -> put_vary_origin(conn)
    end
  end

  defp put_cors_headers(conn, callback, preflight?, opts) do
    with [origin] <- get_req_header(conn, "origin"),
         true <- Callback.invoke(callback, [origin]) == true do
      conn
      |> put_vary_origin()
      |> put_resp_header("access-control-allow-origin", origin)
      |> put_expose_and_preflight_headers(preflight?, opts)
    else
      _ -> put_vary_origin(conn)
    end
  end

  defp put_expose_and_preflight_headers(conn, false, _opts) do
    put_resp_header(conn, "access-control-expose-headers", @default_expose_headers)
  end

  defp put_expose_and_preflight_headers(conn, true, opts) do
    methods = Keyword.get(opts, :methods, @default_methods) |> normalize_header_list()
    allow_headers = Keyword.get(opts, :allow_headers, @default_allow_headers) |> normalize_header_list()
    max_age = opts |> Keyword.get(:max_age, @default_max_age) |> to_string()

    conn
    |> put_resp_header("access-control-allow-methods", methods)
    |> put_resp_header("access-control-allow-headers", allow_headers)
    |> put_resp_header("access-control-expose-headers", @default_expose_headers)
    |> put_resp_header("access-control-max-age", max_age)
  end

  defp normalize_header_list(value) when is_list(value), do: Enum.join(value, ", ")
  defp normalize_header_list(value) when is_binary(value), do: value

  defp put_vary_origin(conn) do
    existing =
      conn
      |> get_resp_header("vary")
      |> Enum.flat_map(&String.split(&1, ","))
      |> Enum.map(&String.trim/1)
      |> Enum.reject(&(&1 == ""))

    if Enum.any?(existing, &(String.downcase(&1) == "origin")) do
      conn
    else
      merged = Enum.join(existing ++ ["origin"], ", ")
      put_resp_header(conn, "vary", merged)
    end
  end
end
