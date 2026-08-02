defmodule AttestoPhoenix.DPoP.AdapterTest do
  @moduledoc false
  use ExUnit.Case, async: true

  import Plug.Test

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.DPoP.Adapter

  defmodule ReplayCallbacks do
    @moduledoc false

    def check(key, ttl), do: {key, ttl}
  end

  defmodule NonceCallbacks do
    @moduledoc false

    @behaviour Attesto.DPoP.NonceStore

    @impl true
    def issue(_ttl), do: raise("config-free issue/1 must not be called")

    @impl true
    def valid?(_nonce), do: raise("config-free valid?/1 must not be called")

    def issue(%Config{issuer: issuer}, ttl), do: "issued:#{issuer}:#{ttl}"
    def valid?(%Config{issuer: issuer}, nonce), do: nonce == "live:#{issuer}"
  end

  defmodule CertificateCallbacks do
    @moduledoc false

    def cert_der(conn, marker), do: {conn.request_path, marker}
  end

  defmodule HtuCallbacks do
    @moduledoc false

    def htu(conn), do: "https://configured.example" <> conn.request_path
  end

  defp config(overrides) do
    struct!(
      Config,
      Keyword.merge(
        [
          issuer: "https://issuer.example",
          audience: "https://api.example.com",
          keystore: __MODULE__,
          repo: __MODULE__,
          load_client: fn _ -> {:error, :not_found} end,
          verify_client_secret: fn _, _ -> false end,
          load_principal: fn _ -> {:error, :not_found} end
        ],
        overrides
      )
    )
  end

  test "adapts replay and nonce callbacks while keeping deferred replay explicit" do
    config =
      config(
        replay_check: {ReplayCallbacks, :check},
        dpop_nonce_required: true,
        nonce_store: NonceCallbacks
      )

    input = %{http_method: "POST", http_uri: "https://issuer.example/oauth/token"}

    inline = Adapter.verification_opts(config, input, nonce_check: true)
    assert inline[:replay_check].("replay-key", 30) == {"replay-key", 30}
    assert inline[:nonce_check].("live:https://issuer.example") == :ok
    assert inline[:nonce_check].("stale") == {:error, :use_dpop_nonce}

    deferred = Adapter.verification_opts(config, input, replay_check: :deferred, nonce_check: true)
    refute Keyword.has_key?(deferred, :replay_check)
    assert deferred[:nonce_check].("live:https://issuer.example") == :ok
    assert deferred[:http_method] == "POST"
    assert deferred[:http_uri] == "https://issuer.example/oauth/token"
  end

  test "preserves the device proof method default and omits nonce unless requested" do
    opts = Adapter.verification_opts(config(replay_check: {ReplayCallbacks, :check}), %{}, http_method_default: "POST")

    assert opts[:http_method] == "POST"
    assert opts[:http_uri] == nil
    assert is_function(opts[:replay_check], 2)
    refute Keyword.has_key?(opts, :nonce_check)
  end

  test "resolves protected-resource htu, replay, nonce, issuance, and certificate options" do
    config =
      config(
        replay_check: {ReplayCallbacks, :check},
        dpop_nonce_required: true,
        nonce_store: NonceCallbacks,
        mtls_enabled: true,
        cert_der: {CertificateCallbacks, :cert_der, ["from-mfa"]},
        htu: {HtuCallbacks, :htu}
      )

    opts = Adapter.protected_resource_opts(config)
    conn = conn(:get, "/reports")

    assert opts[:replay_check].("key", 5) == {"key", 5}
    assert opts[:nonce_check].("live:https://issuer.example") == :ok
    assert opts[:nonce_issue].() == "issued:https://issuer.example:300"
    assert opts[:cert_der].(conn) == {"/reports", "from-mfa"}
    assert opts[:htu].(conn) == "https://configured.example/reports"
  end

  test "protected-resource replay is disabled with DPoP disabled" do
    opts = Adapter.protected_resource_opts(config(dpop_enabled: false))

    refute Keyword.has_key?(opts, :replay_check)
    assert is_function(opts[:htu], 1)
  end
end
