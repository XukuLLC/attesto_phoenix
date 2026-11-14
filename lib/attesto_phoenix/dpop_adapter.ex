defmodule AttestoPhoenix.DPoP.Adapter do
  @moduledoc """
  Resolve the callback and option boundary between `AttestoPhoenix.Config` and
  `Attesto.DPoP`.

  The adapter deliberately stops at option construction. It never verifies a
  proof and never records a replay identity. Callers choose whether
  `:replay_check` is included because token-endpoint sender constraints must
  defer that check until the grant has validated, while PAR and device
  authorization verify their proof inline.
  """

  alias Attesto.DPoP.ReplayCache
  alias AttestoPhoenix.{Callback, Config, RequestContext}
  alias AttestoPhoenix.Store.NonceStore

  @type verification_mode :: :inline | :deferred

  @doc """
  Build the conn-free options for `Attesto.DPoP.verify_proof/2`.

  `:replay_check` defaults to `:inline`, which preserves the behavior of proof
  binding at PAR and device authorization. Pass `replay_check: :deferred` for
  the token endpoint; that mode omits the callback and leaves the returned
  replay identity for the caller to commit after grant validation.

  `nonce_check: true` adds the configured nonce callback. It is opt-in because
  not every DPoP proof path currently requires server-issued nonces.
  `http_method_default` preserves the device-authorization default for direct
  callers that do not populate the request method.
  """
  @spec verification_opts(Config.t(), map(), keyword()) :: keyword()
  def verification_opts(%Config{} = config, input, options \\ []) when is_map(input) do
    opts = [
      http_method: Map.get(input, :http_method, Keyword.get(options, :http_method_default)),
      http_uri: Map.get(input, :http_uri)
    ]

    opts
    |> maybe_put(
      :replay_check,
      replay_check(config),
      Keyword.get(options, :replay_check, :inline) == :inline
    )
    |> maybe_put(:nonce_check, nonce_check(config), Keyword.get(options, :nonce_check, false))
  end

  @doc """
  Verify a DPoP `proof` with options built from `config` and `input`.

  When `Canonical` / `:htu` resolves to `nil` (or any non-string), returns
  `{:error, :invalid_http_uri}` instead of calling `Attesto.DPoP.verify_proof/2`
  and raising `ArgumentError`.
  """
  @spec verify_proof(Config.t(), binary(), map(), keyword()) :: {:ok, map()} | {:error, term()}
  def verify_proof(%Config{} = config, proof, input, options \\ []) when is_binary(proof) and is_map(input) do
    opts = verification_opts(config, input, options)

    case Keyword.get(opts, :http_uri) do
      uri when is_binary(uri) and uri != "" -> Attesto.DPoP.verify_proof(proof, opts)
      _other -> {:error, :invalid_http_uri}
    end
  end

  @doc """
  Build the DPoP/mTLS options consumed by `Attesto.Plug.Authenticate`.

  This is the protected-resource path: replay checking is disabled when DPoP
  is disabled, while `htu`, nonce, nonce issuance, and certificate extraction
  are resolved from the same Phoenix config used by the endpoint. When neither
  `:htu` nor `:resource_origin` is set on `config`, `:htu` is omitted so
  `Attesto.Plug.Authenticate.init/1` requires an explicit per-route `:origin`
  or `:htu` whenever DPoP is accepted.
  """
  @spec protected_resource_opts(Config.t()) :: keyword()
  def protected_resource_opts(%Config{} = config) do
    [
      replay_check: protected_resource_replay_check(config),
      nonce_check: nonce_check(config),
      nonce_issue: nonce_issue(config),
      cert_der: cert_der(config),
      htu: htu(config)
    ]
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
  end

  @doc "Adapt the configured replay callback to the verifier's 2-arity form."
  @spec replay_check(Config.t()) :: (String.t(), pos_integer() -> any())
  def replay_check(%Config{replay_check: nil}), do: &ReplayCache.check_and_record/2
  def replay_check(%Config{replay_check: callback}), do: Callback.to_fun2(callback)

  @doc "Resolve the server-issued nonce validator, or `nil` when unused."
  @spec nonce_check(Config.t()) :: (String.t() | nil -> :ok | {:error, :use_dpop_nonce}) | nil
  def nonce_check(%Config{dpop_nonce_required: true, nonce_store: store} = config)
      when is_atom(store) and not is_nil(store) do
    fn nonce ->
      if NonceStore.valid?(config, store, nonce), do: :ok, else: {:error, :use_dpop_nonce}
    end
  end

  def nonce_check(%Config{}), do: nil

  @doc "Resolve the fresh-nonce issuer, or `nil` when nonce checks are unused."
  @spec nonce_issue(Config.t()) :: (-> String.t()) | nil
  def nonce_issue(%Config{dpop_nonce_required: true, nonce_store: store} = config)
      when is_atom(store) and not is_nil(store) do
    fn -> NonceStore.issue(config, store) end
  end

  def nonce_issue(%Config{}), do: nil

  @doc """
  Adapt the configured mTLS certificate extractor to the verifier's 1-arity
  callback form.
  """
  @spec cert_der(Config.t()) :: (Plug.Conn.t() -> binary() | nil) | nil
  def cert_der(%Config{mtls_enabled: true} = config), do: fn conn -> RequestContext.cert_der(conn, config) end

  def cert_der(%Config{}), do: nil

  @doc """
  Resolve the protected-resource DPoP `htu` callback, or `nil` when no target
  origin or callback is configured.

  See `AttestoPhoenix.RequestContext.protected_resource_url/2`: a configured
  `:htu` callback or `:resource_origin` decides. Without either, `nil` is
  returned so protected resources that accept DPoP must pin `:origin` or
  `:htu` explicitly instead of trusting the request `Host` header.
  """
  @spec htu(Config.t()) :: (Plug.Conn.t() -> String.t() | nil) | nil
  def htu(%Config{htu: htu} = config) when not is_nil(htu) do
    fn conn -> RequestContext.protected_resource_url(conn, config) end
  end

  def htu(%Config{resource_origin: origin} = config) when is_binary(origin) do
    fn conn -> RequestContext.protected_resource_url(conn, config) end
  end

  def htu(%Config{}), do: nil

  defp protected_resource_replay_check(%Config{dpop_enabled: false}), do: nil
  defp protected_resource_replay_check(%Config{} = config), do: replay_check(config)

  defp maybe_put(opts, _key, _value, false), do: opts
  defp maybe_put(opts, _key, nil, true), do: opts
  defp maybe_put(opts, key, value, true), do: Keyword.put(opts, key, value)
end
