defmodule AttestoPhoenix.RevocationTest do
  @moduledoc """
  Criteria-based revocation against PostgreSQL: the Ecto code store's
  `delete_unconsumed/1`, the Ecto refresh store's `revoke_families/1`, and the
  `AttestoPhoenix.Revocation` facade over both.
  """

  use AttestoPhoenix.DataCase, async: false

  alias AttestoPhoenix.AuthorizationServer.Token
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Revocation
  alias AttestoPhoenix.Schema.RefreshFamilyRevocation
  alias AttestoPhoenix.Store.EctoCodeStore
  alias AttestoPhoenix.Store.EctoRefreshStore
  alias AttestoPhoenix.Store.Sweeper

  @moduletag :ecto

  defmodule Keystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem, do: "revocation-test"

    @impl true
    def verification_pems, do: [signing_pem()]
  end

  defmodule CodeStoreWithoutCriteria do
    @moduledoc false
    def put(_entry), do: :ok
    def take(_hash), do: :error
  end

  setup do
    previous_otp_app = Application.get_env(:attesto_phoenix, :otp_app, :missing)
    previous_config = Application.get_env(__MODULE__, Config, :missing)

    Application.put_env(:attesto_phoenix, :otp_app, __MODULE__)
    Application.put_env(__MODULE__, Config, config())
    :ok = Sweeper.register_cleanup_worker({TestRepo, nil}, self())

    on_exit(fn ->
      case previous_otp_app do
        :missing -> Application.delete_env(:attesto_phoenix, :otp_app)
        value -> Application.put_env(:attesto_phoenix, :otp_app, value)
      end

      case previous_config do
        :missing -> Application.delete_env(__MODULE__, Config)
        value -> Application.put_env(__MODULE__, Config, value)
      end
    end)

    # Two subjects, two clients, three sessions; one code and one refresh
    # family per grant.
    for {name, subject, client_id, sid} <- [
          {"u1-a", "usr_1", "client_a", "s1"},
          {"u1-b", "usr_1", "client_b", "s2"},
          {"u2-a", "usr_2", "client_a", "s3"}
        ] do
      :ok = EctoCodeStore.put(code(name, subject, client_id, sid))
      :ok = EctoRefreshStore.insert(refresh(name, subject, client_id, sid))
    end

    :ok
  end

  defp config(overrides \\ []) do
    Config.new(
      Keyword.merge(
        [
          issuer: "https://issuer.example",
          audience: "https://resource.example",
          keystore: Keystore,
          repo: TestRepo,
          code_store: EctoCodeStore,
          refresh_store: EctoRefreshStore,
          sweep_interval_ms: 60_000,
          load_client: fn _ -> {:error, :not_found} end,
          verify_client_secret: fn _, _ -> false end,
          load_principal: fn _ -> {:error, :not_found} end
        ],
        overrides
      )
    )
  end

  defp code(name, subject, client_id, sid) do
    %{
      code_hash: "code-" <> name,
      data: %{
        client_id: client_id,
        subject: subject,
        scope: ["openid"],
        resource: [],
        redirect_uri: "https://rp.example/cb",
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        dpop_jkt: nil,
        family_id: "code-fam-" <> name,
        claims: %{"sid" => sid}
      },
      expires_at: System.system_time(:second) + 600
    }
  end

  defp refresh(name, subject, client_id, sid, generation \\ 0) do
    %{
      token_hash: "refresh-#{name}-#{generation}",
      family_id: "fam-" <> name,
      generation: generation,
      data: %{
        subject: subject,
        scope: ["openid"],
        resource: [],
        acr: nil,
        auth_time: nil,
        client_id: client_id,
        dpop_jkt: nil,
        claims: %{Token.refresh_session_id_claim() => sid}
      },
      expires_at: 1_900_000_100,
      consumed: false
    }
  end

  # The shared test database can hold tombstones other suites committed, so
  # only this file's families are compared.
  defp revoked_test_families do
    RefreshFamilyRevocation
    |> TestRepo.all()
    |> Enum.map(& &1.family_id)
    |> Enum.filter(&String.starts_with?(&1, "fam-u"))
    |> Enum.sort()
  end

  defp code_present?(name), do: match?({:ok, _}, EctoCodeStore.get("code-" <> name))
  defp refresh_present?(name), do: match?({:ok, _}, EctoRefreshStore.get("refresh-#{name}-0"))

  describe "EctoCodeStore.delete_unconsumed/1" do
    test "deletes the matching unredeemed codes" do
      assert {:ok, 2} = EctoCodeStore.delete_unconsumed(subject: "usr_1")

      refute code_present?("u1-a")
      refute code_present?("u1-b")
      assert code_present?("u2-a")
      assert :error = EctoCodeStore.take("code-u1-a")
    end

    test "criteria are ANDed and sid is matched inside the claims column" do
      assert {:ok, 1} = EctoCodeStore.delete_unconsumed(subject: "usr_1", client_id: "client_a")
      assert {:ok, 1} = EctoCodeStore.delete_unconsumed(sid: "s3")
      assert {:ok, 0} = EctoCodeStore.delete_unconsumed(sid: "s1")
      assert {:ok, 0} = EctoCodeStore.delete_unconsumed(sid: "s2", sid_claim: "other")
      assert code_present?("u1-b")
    end

    test "a redeemed code is kept, with its reuse marker" do
      assert {:ok, _} = EctoCodeStore.take("code-u1-a")
      assert :ok = EctoCodeStore.mark_consumed("code-u1-a", %{family_id: nil})

      assert {:ok, 1} = EctoCodeStore.delete_unconsumed(subject: "usr_1")
      assert {:error, :consumed, _meta} = EctoCodeStore.take("code-u1-a")
    end

    test "a value PostgreSQL cannot bind as text matches nothing" do
      assert {:ok, 0} = EctoCodeStore.delete_unconsumed(subject: "usr_1" <> <<0>>)
      assert code_present?("u1-a")
    end

    test "empty criteria are refused" do
      assert_raise ArgumentError, fn -> EctoCodeStore.delete_unconsumed([]) end
      assert code_present?("u1-a")
    end
  end

  describe "EctoRefreshStore.revoke_families/1" do
    test "revokes every matching family and records the sticky marker" do
      :ok = EctoRefreshStore.insert(refresh("u1-a", "usr_1", "client_a", "s1", 1))

      assert {:ok, 2} = EctoRefreshStore.revoke_families(subject: "usr_1")

      refute refresh_present?("u1-a")
      refute refresh_present?("u1-b")
      assert refresh_present?("u2-a")

      assert revoked_test_families() == ["fam-u1-a", "fam-u1-b"]

      assert {:error, :family_revoked} = EctoRefreshStore.insert(refresh("u1-a", "usr_1", "client_a", "s1", 2))
    end

    test "criteria are ANDed and sid_claim names where the session is recorded" do
      assert {:ok, 0} = EctoRefreshStore.revoke_families(sid: "s3")
      assert {:ok, 1} = EctoRefreshStore.revoke_families(sid: "s3", sid_claim: Token.refresh_session_id_claim())
      assert {:ok, 1} = EctoRefreshStore.revoke_families(subject: "usr_1", client_id: "client_b")
      assert refresh_present?("u1-a")
    end

    test "empty criteria are refused" do
      assert_raise ArgumentError, fn -> EctoRefreshStore.revoke_families([]) end
      assert refresh_present?("u1-a")
    end
  end

  describe "AttestoPhoenix.Revocation" do
    test "revoke_subject/2 removes the subject's codes and families across clients" do
      assert {:ok, %{codes: 2, refresh_families: 2}} = Revocation.revoke_subject(config(), "usr_1")

      refute code_present?("u1-a")
      refute refresh_present?("u1-b")
      assert code_present?("u2-a")
      assert refresh_present?("u2-a")
    end

    test "revoke_client/2 removes the client's codes and families across subjects" do
      assert {:ok, %{codes: 2, refresh_families: 2}} = Revocation.revoke_client(config(), "client_a")

      assert code_present?("u1-b")
      assert refresh_present?("u1-b")
    end

    test "revoke_session/2 finds the session in both stores, which record it under different keys" do
      assert {:ok, %{codes: 1, refresh_families: 1}} = Revocation.revoke_session(config(), "s2")

      refute code_present?("u1-b")
      refute refresh_present?("u1-b")
      assert code_present?("u1-a")
      assert refresh_present?("u1-a")
    end

    test "inside the host's transaction, a rollback restores everything" do
      assert {:error, :host_failure} =
               TestRepo.transaction(fn ->
                 assert {:ok, %{codes: 2, refresh_families: 2}} = Revocation.revoke_subject(config(), "usr_1")
                 TestRepo.rollback(:host_failure)
               end)

      assert code_present?("u1-a")
      assert refresh_present?("u1-a")
      assert revoked_test_families() == []
      assert :ok = EctoRefreshStore.insert(refresh("u1-a", "usr_1", "client_a", "s1", 1))
    end

    test "an unconfigured store contributes zero" do
      assert {:ok, %{codes: 2, refresh_families: 0}} =
               Revocation.revoke_subject(config(refresh_store: nil), "usr_1")
    end

    test "a store without the callback raises before anything is reported revoked" do
      assert_raise ArgumentError, ~r/:code_store .* does not implement delete_unconsumed\/1/, fn ->
        Revocation.revoke_subject(config(code_store: CodeStoreWithoutCriteria), "usr_1")
      end

      assert refresh_present?("u1-a")
    end

    test "invalid criteria raise before either store is touched" do
      assert_raise ArgumentError, fn -> Revocation.revoke_subject(config(), "") end
      assert_raise ArgumentError, fn -> Revocation.revoke(config(), []) end
      assert code_present?("u1-a")
    end
  end
end
