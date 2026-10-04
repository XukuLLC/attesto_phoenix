defmodule AttestoPhoenix.ConfigSecurityTest do
  use ExUnit.Case, async: true

  alias AttestoPhoenix.Config

  defmodule ClientStore do
    @behaviour AttestoPhoenix.ClientStore

    @impl true
    def load_client(_id), do: {:ok, :trusted_client}

    @impl true
    def verify_client_secret(_client, _secret), do: false

    @impl true
    def client_auth_method(:trusted_client), do: "private_key_jwt"
  end

  defp config(opts) do
    Config.new(
      Keyword.merge(
        [
          issuer: "https://issuer.example",
          audience: "https://resource.example",
          keystore: __MODULE__,
          repo: __MODULE__,
          client_store: ClientStore,
          load_principal: fn _ -> {:error, :not_found} end
        ],
        opts
      )
    )
  end

  test "registered method resolves from the client store, with explicit override precedence" do
    assert Config.client_auth_method_fun(config([])) == {ClientStore, :client_auth_method}

    override = fn :trusted_client -> "client_secret_basic" end
    assert Config.client_auth_method_fun(config(client_auth_method: override)) == override
  end

  test "invalid method callback arity is rejected at configuration time" do
    assert_raise ArgumentError, ~r/client_auth_method.*one-argument/, fn ->
      config(client_auth_method: fn _, _ -> "private_key_jwt" end)
    end
  end

  test "resource controls cannot be disabled by zero, negative, or noninteger values" do
    limits = [
      :max_document_bytes,
      :request_timeout_ms,
      :max_concurrent_fetches,
      :max_concurrent_fetches_per_host,
      :max_fetches_per_window,
      :max_fetches_per_host_per_window,
      :fetch_rate_window_ms,
      :failure_backoff_ms,
      :max_flow_entries,
      :max_singleflight_waiters,
      :cache_max_entries,
      :cache_max_record_bytes
    ]

    for limit <- limits, invalid <- [0, -1, nil, "16", :infinity] do
      assert_raise ArgumentError, ~r/client_id_metadata.*positive integer/, fn ->
        config(client_id_metadata: [{limit, invalid}])
      end
    end
  end
end
