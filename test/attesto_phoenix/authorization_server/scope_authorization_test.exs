defmodule AttestoPhoenix.AuthorizationServer.ScopeAuthorizationTest do
  use ExUnit.Case, async: true

  alias AttestoPhoenix.AuthorizationServer.ScopeAuthorization
  alias AttestoPhoenix.Config

  defmodule Keystore do
    @moduledoc false
    def signing_pem, do: "unused"
    def verification_pems, do: ["unused"]
  end

  defmodule TwoArgumentPolicy do
    @moduledoc false
    @behaviour AttestoPhoenix.ScopePolicy

    @impl true
    def authorize_scope(_client, requested), do: {:ok, requested -- ["admin"]}
  end

  defmodule ThreeArgumentPolicy do
    @moduledoc false
    @behaviour AttestoPhoenix.ScopePolicy

    @impl true
    def authorize_scope(_client, _requested, ["https://forbidden.example" | _]), do: {:error, :invalid_target}
    def authorize_scope(_client, requested, resources), do: {:ok, requested ++ Enum.map(resources, &("for:" <> &1))}
  end

  defmodule BothFormsPolicy do
    @moduledoc false
    @behaviour AttestoPhoenix.ScopePolicy

    @impl true
    def authorize_scope(_client, _requested), do: {:ok, ["two"]}

    @impl true
    def authorize_scope(_client, _requested, _resources), do: {:ok, ["three"]}
  end

  defmodule NoFormPolicy do
    @moduledoc false
  end

  defp config(overrides) do
    Config.new(
      Keyword.merge(
        [
          issuer: "https://issuer.example",
          keystore: Keystore,
          repo: __MODULE__.Repo,
          audience: "https://api.example.com",
          load_client: fn _ -> {:error, :not_found} end,
          verify_client_secret: fn _, _ -> false end,
          load_principal: fn _ -> {:error, :not_found} end
        ],
        overrides
      )
    )
  end

  @client %{id: "client-1"}

  describe "authorize/4" do
    test "the built-in policy accepts catalog scopes and refuses the rest" do
      config = config(scopes_supported: ["read", "write"])

      assert {:ok, ["read"]} = ScopeAuthorization.authorize(config, @client, ["read"], [])
      assert {:error, :invalid_scope} = ScopeAuthorization.authorize(config, @client, ["read", "admin"], [])
    end

    test "a two-argument callback never sees the resources" do
      config = config(authorize_scope: fn client, requested -> {:ok, [inspect(client.id) | requested]} end)

      assert {:ok, [~s("client-1"), "read"]} =
               ScopeAuthorization.authorize(config, @client, ["read"], ["https://api.example.com"])
    end

    test "a three-argument callback receives the resolved resources" do
      test_pid = self()

      config =
        config(
          authorize_scope: fn _client, requested, resources ->
            send(test_pid, {:resources, resources})
            {:ok, requested}
          end
        )

      assert {:ok, ["read"]} = ScopeAuthorization.authorize(config, @client, ["read"], ["https://api.example.com"])
      assert_received {:resources, ["https://api.example.com"]}
    end

    test "only the three-argument form may answer invalid_target" do
      three = config(authorize_scope: fn _client, _requested, _resources -> {:error, :invalid_target} end)
      assert {:error, :invalid_target} = ScopeAuthorization.authorize(three, @client, ["read"], [])

      two = config(authorize_scope: fn _client, _requested -> {:error, :invalid_target} end)

      assert_raise RuntimeError, ~r/:authorize_scope callback violated its return contract/, fn ->
        ScopeAuthorization.authorize(two, @client, ["read"], [])
      end
    end

    test "any other return value violates the contract" do
      for bad <- [:ok, {:ok, "read"}, {:error, :access_denied}, nil] do
        config = config(authorize_scope: fn _client, _requested -> bad end)

        assert_raise RuntimeError, ~r/violated its return contract/, fn ->
          ScopeAuthorization.authorize(config, @client, ["read"], [])
        end
      end
    end
  end

  describe ":scope_policy modules" do
    test "a module with only authorize_scope/2 is called with two arguments" do
      config = config(scope_policy: TwoArgumentPolicy)
      assert {{TwoArgumentPolicy, :authorize_scope}, 2} = Config.authorize_scope_callback(config)
      assert {:ok, ["read"]} = ScopeAuthorization.authorize(config, @client, ["read", "admin"], [])
    end

    test "a module with only authorize_scope/3 boots and is called with the resources" do
      config = config(scope_policy: ThreeArgumentPolicy)
      assert {{ThreeArgumentPolicy, :authorize_scope}, 3} = Config.authorize_scope_callback(config)

      assert {:ok, ["read", "for:https://api.example.com"]} =
               ScopeAuthorization.authorize(config, @client, ["read"], ["https://api.example.com"])

      assert {:error, :invalid_target} =
               ScopeAuthorization.authorize(config, @client, ["read"], ["https://forbidden.example"])
    end

    test "the three-argument form is preferred when a module exports both" do
      config = config(scope_policy: BothFormsPolicy)
      assert {:ok, ["three"]} = ScopeAuthorization.authorize(config, @client, ["read"], [])
    end

    test "an explicit :authorize_scope wins over the module" do
      config = config(scope_policy: BothFormsPolicy, authorize_scope: fn _client, _requested -> {:ok, ["flat"]} end)
      assert {:ok, ["flat"]} = ScopeAuthorization.authorize(config, @client, ["read"], [])
    end

    test "a module exporting neither form is refused at boot" do
      assert_raise ArgumentError, ~r/does not export authorize_scope\/2 or authorize_scope\/3/, fn ->
        config(scope_policy: NoFormPolicy)
      end
    end
  end
end
