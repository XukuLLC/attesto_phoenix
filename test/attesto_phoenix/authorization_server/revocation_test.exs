defmodule AttestoPhoenix.AuthorizationServer.RevocationTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.Secret
  alias AttestoPhoenix.AuthorizationServer.Revocation
  alias AttestoPhoenix.{Config, Event}

  @refresh_issuer_claim "urn:attesto:refresh-token:issuer"

  defmodule StubKeystore do
    @moduledoc false
  end

  defmodule StubRepo do
    @moduledoc false
  end

  defmodule StubRefreshStore do
    @moduledoc false
    @behaviour Attesto.RefreshStore

    @impl true
    def insert(_entry), do: :ok

    @impl true
    def get(token_hash), do: Process.get({:refresh_record, token_hash}, :error)

    @impl true
    def rotate(_parent_hash, _child, _successor, _opts), do: :error

    @impl true
    def revoke_family(family_id) do
      send(self(), {:revoked_family, family_id})
      :ok
    end
  end

  defp build_config(overrides \\ []) do
    base = [
      issuer: "https://issuer.example",
      audience: "https://api.example.com",
      keystore: StubKeystore,
      repo: StubRepo,
      refresh_store: StubRefreshStore,
      load_client: fn _id -> {:error, :not_found} end,
      verify_client_secret: fn _client, _secret -> false end,
      load_principal: fn _sub -> {:error, :not_found} end
    ]

    Config.new(Keyword.merge(base, overrides))
  end

  defp put_refresh_record(raw_token, family_id, client_id) do
    token_hash = Secret.hash(raw_token)

    record = %{
      token_hash: token_hash,
      family_id: family_id,
      generation: 0,
      expires_at: System.system_time(:second) + 600,
      consumed: false,
      consumed_at: nil,
      successor: nil,
      data: %{
        subject: "usr_1",
        client_id: client_id,
        scope: ["openid"],
        resource: [],
        claims: %{@refresh_issuer_claim => "https://issuer.example"}
      }
    }

    Process.put({:refresh_record, token_hash}, {:ok, record})
  end

  describe "fetch_token/1" do
    test "extracts a non-empty binary token and returns :invalid_request otherwise" do
      assert {:ok, "rt-123"} = Revocation.fetch_token(%{"token" => "rt-123"})
      assert {:error, :invalid_request} = Revocation.fetch_token(%{})
      assert {:error, :invalid_request} = Revocation.fetch_token(%{"token" => ""})
      assert {:error, :invalid_request} = Revocation.fetch_token(%{"token" => 123})
    end
  end

  describe "revoke/5" do
    test "revokes the token family for the owning client and returns the :token_revoked event with typed token_type_hint" do
      config = build_config()
      raw_token = "live-refresh-token"
      put_refresh_record(raw_token, "family-1", "client-1")

      assert {:ok, [%Event{name: :token_revoked} = event]} =
               Revocation.revoke(config, "client-1", raw_token, "refresh_token")

      assert_received {:revoked_family, "family-1"}
      assert event.client_id == "client-1"
      assert event.metadata == %{token_type_hint: "refresh_token"}
    end

    test "does not revoke another client's token family (including when client_id is nil)" do
      config = build_config()
      raw_token = "owned-refresh-token"
      put_refresh_record(raw_token, "family-owned", "owner-client")

      assert {:ok, [%Event{name: :token_revoked, client_id: "other-client"}]} =
               Revocation.revoke(config, "other-client", raw_token)

      refute_received {:revoked_family, _}

      assert {:ok, [%Event{name: :token_revoked, client_id: nil}]} =
               Revocation.revoke(config, nil, raw_token)

      refute_received {:revoked_family, _}
    end
  end
end
