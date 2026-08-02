if Code.ensure_loaded?(Plug.Conn) do
  defmodule AttestoPhoenix.OAuthError do
    @moduledoc """
    The error value type and the wire-rendering helpers for the
    authorization-server controllers and the protected-resource plugs.

    This module is both:

      * **a struct** - the controllers build `%AttestoPhoenix.OAuthError{}`
        with `new/2` / `new/3` and thread it through their `with` chains as
        the `{:error, error}` term, then render it once at the boundary with
        `render/3`; and

      * **a set of header helpers** - `unauthorized/4`, `use_dpop_nonce/3`,
        `insufficient_scope/3`, `no_store/2`, and `www_authenticate/3` -
        used by the protected-resource plugs to emit `WWW-Authenticate`
        challenges and cache-suppression headers directly.

    It is the single place the library turns an internal error into the bytes
    a client receives. It covers four surfaces, each governed by a different
    RFC:

      * **Token / endpoint errors** (RFC 6749 §5.2) - the JSON body
        `{"error": <code>, "error_description": <text>}` returned by the
        token, revocation, and registration endpoints. The caller explicitly
        selects whether rendering adds a Basic, Bearer, or DPoP challenge, or
        preserves a challenge already attached by an authentication context.
        Rendering never infers an auth scheme from request headers.

      * **Protected-resource challenges** (RFC 6750 §3 / RFC 9449 §7.1) - a
        `WWW-Authenticate` response header naming the `Bearer` or `DPoP`
        scheme and carrying the `error`, `error_description`, `scope`, and
        (for DPoP) `algs` auth-params.

      * **DPoP nonce challenges** (RFC 9449 §8 / §9) - the `use_dpop_nonce`
        error returned with a fresh `DPoP-Nonce` response header, telling
        the client to retry the request carrying that nonce.

      * **Cache suppression** (RFC 6749 §5.1) - `no_store/2` marks a
        response uncacheable with `Cache-Control: no-store` and
        `Pragma: no-cache`, mandatory on every response that carries a
        token, and applied to every error response here for defense in depth.

    Every quoted auth-param value is escaped per the `WWW-Authenticate`
    quoted-string grammar (RFC 9110 §11.2 / RFC 7235): a bare `"` or `\\`
    inside a value would otherwise let an attacker break out of the quotes
    and inject additional challenge parameters.

    ## Configuration callbacks

    The transport details are policy a host may override. Each is read from
    `AttestoPhoenix.Config` and falls back to the RFC-correct default
    implemented here when the host does not set it:

      * `:send_error` - `(conn, status, body_map -> conn)`. Serializes the
        RFC 6749 §5.2 envelope and sends the response. Default encodes JSON
        with `application/json` and halts.
      * `:no_store` - `(conn -> conn)`. Sets the RFC 6749 §5.1 cache
        headers. Default sets `Cache-Control: no-store` and
        `Pragma: no-cache`.
      * `:www_authenticate` - `(conn, challenge_string -> conn)`. Writes the
        challenge header. Default sets the `www-authenticate` response
        header.

    The RFC envelope, cache headers, challenge formatting, and escaping are
    owned by this module. The caller still owns the endpoint's status, error
    values, and explicit authentication context; only serialization/transport
    is overridable.

    This module compiles only when `Plug` is available.
    """

    import Plug.Conn

    alias AttestoPhoenix.Callback
    alias AttestoPhoenix.Config

    @typedoc "The protected-resource authentication scheme a challenge names."
    @type scheme :: :bearer | :dpop

    @typedoc "The explicit challenge selection for endpoint-error rendering."
    @type auth_scheme :: :none | :basic | :bearer | :dpop | :from_error_context

    @type challenge_scheme :: :basic | :bearer | :dpop | String.t()

    @typedoc "An OAuth 2.0 error value rendered to the RFC 6749 §5.2 envelope."
    @type t :: %__MODULE__{
            error: atom(),
            error_description: String.t() | nil,
            status: pos_integer(),
            headers: [{String.t(), String.t()}]
          }

    @enforce_keys [:error, :status]
    defstruct [:error, :error_description, :status, headers: []]

    # RFC 6749 §5.1: token responses MUST NOT be cached by any intermediary.
    @cache_control_no_store "no-store"
    @pragma_no_cache "no-cache"

    # RFC 9449 §8 / §9: the error code that asks a client to retry carrying a
    # server-issued nonce, paired with the `DPoP-Nonce` response header.
    @use_dpop_nonce "use_dpop_nonce"

    # RFC 6750 §3.1: the error code returned when a valid token lacks the
    # scope the request requires, paired with the `scope` auth-param.
    @insufficient_scope "insufficient_scope"

    # RFC 6749 §2.3.1 names HTTP Basic as the mandatory-to-support scheme for
    # confidential-client authentication at the token endpoint; a 401 from an
    # `Authorization`-authenticated request advertises it (RFC 6749 §5.2).
    @basic_scheme "Basic"
    @default_realm "OAuth"

    # RFC 6749 §5.2 default status mapping. `invalid_client` defaults to 400;
    # callers that know an Authorization-header attempt requires 401 set that
    # status explicitly before rendering. RFC 6750 §3.1
    # / RFC 9449 §7.1 protected-resource codes (`invalid_token`,
    # `invalid_dpop_proof`, `use_dpop_nonce`) are 401 and `insufficient_scope`
    # is 403; those are emitted through the dedicated challenge helpers below.
    @default_status %{
      invalid_request: 400,
      invalid_client: 400,
      invalid_grant: 400,
      unauthorized_client: 400,
      unsupported_grant_type: 400,
      invalid_scope: 400,
      invalid_dpop_proof: 400,
      invalid_token: 401,
      use_dpop_nonce: 401,
      insufficient_scope: 403,
      # RFC 7591 §3.2.2 dynamic-registration error codes.
      invalid_client_metadata: 400,
      invalid_redirect_uri: 400,
      # A library-internal code for "this endpoint is not enabled"; rendered
      # like any other so the host never sees a route it did not opt into.
      not_found: 404
    }

    @doc """
    Build an OAuth 2.0 error value (RFC 6749 §5.2).

    `code` is the error code atom (e.g. `:invalid_request`, `:invalid_client`).
    `description` is the human-readable `error_description` (or `nil`). The
    HTTP status defaults from the RFC 6749 §5.2 mapping for `code` and can be
    overridden with the `:status` option. The `:headers` option carries extra
    response headers a caller must emit alongside the error (e.g. the
    RFC 9449 §8 `DPoP-Nonce` header on a `use_dpop_nonce` error); it defaults
    to `[]`.
    """
    @spec new(atom(), String.t() | nil, keyword()) :: t()
    def new(code, description \\ nil, opts \\ []) when is_atom(code) do
      %__MODULE__{
        error: code,
        error_description: description,
        status: Keyword.get(opts, :status, default_status(code)),
        headers: Keyword.get(opts, :headers, [])
      }
    end

    @doc """
    Render an `%AttestoPhoenix.OAuthError{}` to the RFC 6749 §5.2 wire format.

    Writes the JSON envelope `{"error": code, "error_description": desc}` with
    the error's status, applies the RFC 6749 §5.1 no-store headers, and applies
    the caller-selected auth challenge. `:none` adds no challenge,
    `:from_error_context` preserves a challenge already carried in
    `error.headers`, and the concrete schemes use `format_challenge/2`.

    Options:

      * `:auth_scheme` - `:none`, `:basic`, `:bearer`, `:dpop`, or
        `:from_error_context`. The `/2` form uses `:none` for compatibility;
        rendering never guesses from the request's `Authorization` header.
      * `:challenge_params` - explicit auth-params for a generated challenge.
        When omitted, Basic uses the configured realm and Bearer/DPoP use the
        error code and optional description.
      * `:config` - an explicit `%AttestoPhoenix.Config{}` when the controller
        resolved configuration outside `conn.private`.
    """
    @spec render(Plug.Conn.t(), t()) :: Plug.Conn.t()
    def render(conn, %__MODULE__{} = error) do
      render(conn, error, auth_scheme: :none)
    end

    @spec render(Plug.Conn.t(), t(), keyword()) :: Plug.Conn.t()
    def render(conn, %__MODULE__{} = error, opts) when is_list(opts) do
      config = Keyword.get(opts, :config) || fetch_config(conn)
      auth_scheme = Keyword.get(opts, :auth_scheme, :none)
      params = challenge_params(error, config, opts, auth_scheme)

      body =
        %{"error" => Atom.to_string(error.error)}
        |> maybe_put("error_description", error.error_description)

      conn
      |> no_store(config)
      |> merge_resp_headers(error.headers)
      |> maybe_challenge(config, auth_scheme, params)
      |> do_send_error(config, error.status, body)
    end

    @doc """
    Format an escaping-safe `WWW-Authenticate` challenge.

    `params` may be a keyword list or a list of `{name, value}` pairs. The
    three protocol schemes are named explicitly; a validated binary scheme is
    also accepted so an authentication context can preserve its scheme token
    without lowercasing or rewriting it.
    """
    @spec format_challenge(challenge_scheme(), keyword() | [{String.t(), String.t()}]) :: String.t()
    def format_challenge(scheme, params \\ []) when is_list(params) do
      label = challenge_scheme_label(scheme)

      params =
        if Keyword.keyword?(params) do
          Enum.map(params, fn {key, value} -> {to_string(key), value} end)
        else
          params
        end

      case params do
        [] ->
          label

        params ->
          label <> " " <> Enum.map_join(params, ", ", fn {key, value} -> ~s(#{key}="#{escape(value)}") end)
      end
    end

    @doc """
    Respond 401 with a protected-resource `WWW-Authenticate` challenge for
    `scheme` (RFC 6750 §3 / RFC 9449 §7.1).

    The challenge carries `error` (an OAuth error code string) and, when
    supplied, the optional auth-params. Options:

      * `:description` - the `error_description` auth-param.
      * `:scope` - a space-delimited scope string for the `scope` auth-param.
      * `:algs` - a space-delimited list of acceptable DPoP signing
        algorithms for the RFC 9449 §5.1 `algs` auth-param (`:dpop` scheme).
      * `:dpop_nonce` - sets the RFC 9449 §8 `DPoP-Nonce` response header.

    Sets the status, the challenge header, any DPoP nonce header, the
    RFC 6749 §5.1 no-store headers, and writes the RFC 6749 §5.2 body.
    """
    @spec unauthorized(Plug.Conn.t(), scheme(), String.t(), keyword()) :: Plug.Conn.t()
    def unauthorized(conn, scheme, error, opts \\ []) when scheme in [:bearer, :dpop] and is_binary(error) do
      config = fetch_config(conn)

      params =
        [{"error", error}]
        |> append_param("error_description", Keyword.get(opts, :description))
        |> append_param("scope", Keyword.get(opts, :scope))
        |> append_param("algs", Keyword.get(opts, :algs))

      conn
      |> no_store(config)
      |> maybe_put_dpop_nonce(Keyword.get(opts, :dpop_nonce))
      |> www_authenticate(config, format_challenge(scheme, params))
      |> do_send_error(config, 401, error_body(error, Keyword.get(opts, :description)))
    end

    @doc """
    Respond 401 `#{@use_dpop_nonce}` carrying a fresh `DPoP-Nonce` header
    (RFC 9449 §8 / §9).

    The protected resource (or token endpoint) uses this to demand the client
    retry the request including the server-issued `nonce`. Emits a `DPoP`
    challenge whose `error` is `use_dpop_nonce`, sets the `DPoP-Nonce`
    response header, and applies the RFC 6749 §5.1 no-store headers.
    """
    @spec use_dpop_nonce(Plug.Conn.t(), String.t(), keyword()) :: Plug.Conn.t()
    def use_dpop_nonce(conn, nonce, opts \\ []) when is_binary(nonce) do
      unauthorized(
        conn,
        :dpop,
        @use_dpop_nonce,
        opts
        |> Keyword.put(:dpop_nonce, nonce)
        |> Keyword.put_new(
          :description,
          "Authorization server requires a nonce in the DPoP proof."
        )
      )
    end

    @doc """
    Respond 403 `#{@insufficient_scope}` naming the `required` scopes
    (RFC 6750 §3.1).

    The `WWW-Authenticate` challenge for `scheme` carries the `error`,
    `error_description`, and the RFC 6750 §3.1 `scope` auth-param listing the
    scopes the request would need. Applies the RFC 6749 §5.1 no-store headers.
    """
    @spec insufficient_scope(Plug.Conn.t(), [String.t()], scheme()) :: Plug.Conn.t()
    def insufficient_scope(conn, required, scheme \\ :bearer) when is_list(required) and scheme in [:bearer, :dpop] do
      config = fetch_config(conn)
      scope = Enum.join(required, " ")
      description = "The request requires higher privileges: #{scope}"

      params = [
        {"error", @insufficient_scope},
        {"error_description", description},
        {"scope", scope}
      ]

      conn
      |> no_store(config)
      |> www_authenticate(config, format_challenge(scheme, params))
      |> do_send_error(config, 403, error_body(@insufficient_scope, description))
    end

    @doc """
    Apply the RFC 6749 §5.1 cache-suppression headers to `conn`.

    Sets `Cache-Control: no-store` and `Pragma: no-cache`. Mandatory on every
    response that carries an access or refresh token. Delegates to the host's
    `:no_store` callback when configured.
    """
    @spec no_store(Plug.Conn.t(), Config.t() | nil) :: Plug.Conn.t()
    def no_store(conn, config \\ nil) do
      case config_callback(config, :no_store) do
        nil -> default_no_store(conn)
        callback -> Callback.invoke(callback, [conn])
      end
    end

    @doc """
    Set the `WWW-Authenticate` response header to `challenge`.

    Delegates to the host's `:www_authenticate` callback when configured;
    otherwise sets the `www-authenticate` header directly.
    """
    @spec www_authenticate(Plug.Conn.t(), Config.t() | nil, String.t()) :: Plug.Conn.t()
    def www_authenticate(conn, config \\ nil, challenge) when is_binary(challenge) do
      case config_callback(config, :www_authenticate) do
        nil -> put_resp_header(conn, "www-authenticate", challenge)
        callback -> Callback.invoke(callback, [conn, challenge])
      end
    end

    # ----- internal -----

    defp default_status(code), do: Map.get(@default_status, code, 400)

    defp basic_realm(config) when is_map(config), do: Map.get(config, :basic_realm) || @default_realm

    defp basic_realm(_config), do: @default_realm

    # The config is threaded onto the conn by the router/pipeline; when it is
    # absent (e.g. a plug emitting a challenge before the config is assigned)
    # the RFC-correct default transport is used.
    defp fetch_config(conn) do
      case conn.private do
        %{attesto_phoenix_config: %Config{} = config} -> config
        _ -> nil
      end
    end

    defp do_send_error(conn, config, status, body) do
      case config_callback(config, :send_error) do
        nil -> default_send_error(conn, status, body)
        callback -> Callback.invoke(callback, [conn, status, body])
      end
    end

    # The transport callbacks (`:send_error`, `:no_store`, `:www_authenticate`)
    # are read defensively: a host that supplies them overrides the default
    # transport, while a config (or a `nil` config, before the pipeline has
    # assigned one) that omits them falls through to the RFC-correct default.
    defp config_callback(%Config{} = config, key), do: Callback.config_callback(config, key)
    defp config_callback(_config, _key), do: nil

    defp default_send_error(conn, status, body) do
      conn
      |> put_resp_content_type("application/json")
      |> send_resp(status, JSON.encode!(body))
      |> halt()
    end

    defp default_no_store(conn) do
      conn
      |> put_resp_header("cache-control", @cache_control_no_store)
      |> put_resp_header("pragma", @pragma_no_cache)
    end

    defp challenge_params(_error, _config, opts, auth_scheme) when auth_scheme in [:none, :from_error_context],
      do: Keyword.get(opts, :challenge_params, [])

    defp challenge_params(_error, config, opts, :basic) do
      case Keyword.fetch(opts, :challenge_params) do
        {:ok, params} -> params
        :error -> [realm: basic_realm(config)]
      end
    end

    defp challenge_params(error, _config, opts, auth_scheme) when auth_scheme in [:bearer, :dpop] do
      case Keyword.fetch(opts, :challenge_params) do
        {:ok, params} ->
          params

        :error ->
          [{"error", Atom.to_string(error.error)}]
          |> append_param("error_description", error.error_description)
      end
    end

    defp challenge_params(_error, _config, opts, _auth_scheme), do: Keyword.get(opts, :challenge_params, [])

    defp maybe_challenge(conn, _config, auth_scheme, _params) when auth_scheme in [:none, :from_error_context], do: conn

    defp maybe_challenge(conn, config, auth_scheme, params) do
      www_authenticate(conn, config, format_challenge(auth_scheme, params))
    end

    defp challenge_scheme_label(:basic), do: @basic_scheme
    defp challenge_scheme_label(:bearer), do: "Bearer"
    defp challenge_scheme_label(:dpop), do: "DPoP"

    defp challenge_scheme_label(scheme) when is_binary(scheme) do
      if Regex.match?(~r/\A[!#$%&'*+\-.^_`|~0-9A-Za-z]+\z/, scheme) do
        if String.downcase(scheme) == "basic", do: @basic_scheme, else: scheme
      else
        raise ArgumentError, "invalid WWW-Authenticate scheme"
      end
    end

    defp challenge_scheme_label(_scheme), do: raise(ArgumentError, "invalid WWW-Authenticate scheme")

    defp error_body(error, nil), do: %{"error" => error}

    defp error_body(error, description), do: %{"error" => error, "error_description" => description}

    defp append_param(params, _key, nil), do: params
    defp append_param(params, key, value), do: params ++ [{key, value}]

    defp maybe_put_dpop_nonce(conn, nil), do: conn
    defp maybe_put_dpop_nonce(conn, nonce), do: put_resp_header(conn, "dpop-nonce", nonce)

    defp maybe_put(map, _key, nil), do: map
    defp maybe_put(map, key, value), do: Map.put(map, key, value)

    # `WWW-Authenticate` auth-param values are quoted-strings (RFC 9110
    # §11.2 / RFC 7235); escape the two characters that would otherwise let a
    # value break out of the surrounding quotes and inject new auth-params.
    defp escape(value) do
      value
      |> to_string()
      |> String.replace("\\", "\\\\")
      |> String.replace("\"", "\\\"")
    end
  end
end
