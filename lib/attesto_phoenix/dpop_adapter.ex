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
  Build the DPoP/mTLS options consumed by `Attesto.Plug.Authenticate`.

  This is the protected-resource path: replay checking is disabled when DPoP
  is disabled, while `htu`, nonce, nonce issuance, and certificate extraction
  are resolved from the same Phoenix config used by the endpoint.
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
  def cert_der(%Config{mtls_enabled: true, cert_der: callback}) when not is_nil(callback),
    do: Callback.to_fun1(callback)

  def cert_der(%Config{}), do: nil

  @doc "Resolve the canonical request URL callback used for DPoP `htu`."
  @spec htu(Config.t()) :: (Plug.Conn.t() -> String.t())
  def htu(%Config{} = config), do: fn conn -> RequestContext.canonical_url(conn, config) end

  defp protected_resource_replay_check(%Config{dpop_enabled: false}), do: nil
  defp protected_resource_replay_check(%Config{} = config), do: replay_check(config)

  defp maybe_put(opts, _key, _value, false), do: opts
  defp maybe_put(opts, _key, nil, true), do: opts
  defp maybe_put(opts, key, value, true), do: Keyword.put(opts, key, value)
end
