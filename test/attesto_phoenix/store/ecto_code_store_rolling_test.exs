defmodule AttestoPhoenix.Store.EctoCodeStoreRollingTest do
  use ExUnit.Case, async: false

  import Ecto.Query

  alias Attesto.AuthorizationCode
  alias Attesto.Secret
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Legacy418.EctoCodeStore, as: Old
  alias AttestoPhoenix.Legacy418.Sweeper, as: OldSweeper
  alias AttestoPhoenix.Schema.Authorization
  alias AttestoPhoenix.Schema.RefreshToken
  alias AttestoPhoenix.Store.EctoCodeStore, as: New
  alias AttestoPhoenix.Store.EctoRefreshStore
  alias AttestoPhoenix.Store.Sweeper
  alias AttestoPhoenix.TestRepo
  alias Ecto.Adapters.SQL.Sandbox

  @moduletag :ecto
  @params %{client_id: "rolling-client", redirect_uri: "https://client.example/cb"}

  setup do
    :ok = Sandbox.checkout(TestRepo, sandbox: false)

    on_exit(fn ->
      Sandbox.checkout(TestRepo, sandbox: false)
      TestRepo.delete_all(from a in Authorization, where: a.client_id == "rolling-client")
      TestRepo.delete_all(from r in RefreshToken, where: r.client_id == "rolling-client")
      Sandbox.checkin(TestRepo)
    end)

    :ok
  end

  defp issue(store, family \\ nil) do
    code = Secret.generate()

    :ok =
      store.put(%{
        code_hash: Secret.hash(code),
        expires_at: System.system_time(:second) + 600,
        data: %{
          client_id: "rolling-client",
          redirect_uri: @params.redirect_uri,
          subject: "rolling-subject",
          scope: [],
          resource: [],
          code_challenge: nil,
          dpop_jkt: nil,
          family_id: family,
          claims: %{}
        }
      })

    code
  end

  defp config do
    struct!(Config,
      issuer: "https://issuer.example",
      keystore: __MODULE__,
      repo: TestRepo,
      code_store: New,
      refresh_store: EctoRefreshStore
    )
  end

  defp backend, do: TestRepo.query!("SELECT pg_backend_pid()", [], log: false).rows

  defp another_connection(fun) do
    original = backend()

    Task.async(fn ->
      :ok = Sandbox.checkout(TestRepo, sandbox: false)

      try do
        refute backend() == original
        Config.with_request_config(config(), fun)
      after
        Sandbox.checkin(TestRepo)
      end
    end)
    |> Task.await(10_000)
  end

  defp redemption(family \\ nil), do: %{family_id: family, subject: "rolling-subject", replay_retain_until: nil}

  test "old take and new claim race on separate connections and only one wins" do
    for _ <- 1..20 do
      code = issue(Old)
      hash = Secret.hash(code)
      parent = self()

      tasks =
        for callback <- [&Old.take/1, &New.claim/1] do
          Task.async(fn ->
            :ok = Sandbox.checkout(TestRepo, sandbox: false)

            try do
              send(parent, {:ready, self(), backend()})
              receive do: (:go -> callback.(hash))
            after
              Sandbox.checkin(TestRepo)
            end
          end)
        end

      assert_receive {:ready, first, first_backend}, 5_000
      assert_receive {:ready, second, second_backend}, 5_000
      refute first_backend == second_backend
      send(first, :go)
      send(second, :go)
      results = Task.await_many(tasks)
      assert Enum.count(results, &(match?(:ok, &1) or match?({:ok, _}, &1))) == 1
    end
  end

  test "a new replay marker is honored by old finalization" do
    code = issue(Old, "provenance")
    hash = Secret.hash(code)
    assert {:ok, _} = Old.take(hash)
    assert {:error, :invalid_grant} = another_connection(fn -> AuthorizationCode.redeem(New, code, @params) end)

    assert {:ok, issued} =
             Attesto.RefreshToken.issue(
               EctoRefreshStore,
               %{client_id: "rolling-client", subject: "rolling-subject", scope: [], resource: []}
             )

    Config.with_request_config(config(), fn ->
      :ok = Old.mark_consumed(hash, redemption(issued.family_id))
    end)

    assert {:error, _} = Attesto.RefreshToken.rotate(EctoRefreshStore, issued.token, client_id: "rolling-client")
    assert {:ok, %{state: :redeemed, data: %{family_id: "provenance"}}} = New.read(hash)
  end

  test "an old replay marker is honored by new finish and refresh composition" do
    code = issue(New)
    {:ok, grant} = AuthorizationCode.redeem(New, code, @params)
    assert :error = another_connection(fn -> Old.take(Secret.hash(code)) end)
    assert {:ok, %{revoked: true}} = New.read(Secret.hash(code))

    assert {:ok, issued} =
             AuthorizationCode.issue_refresh_and_finalize(New, code, grant, EctoRefreshStore, %{
               client_id: "rolling-client",
               subject: "rolling-subject",
               scope: [],
               resource: []
             })

    assert {:error, _} = Attesto.RefreshToken.rotate(EctoRefreshStore, issued.token, client_id: "rolling-client")
    assert {:ok, %{data: %{family_id: nil}}} = New.read(Secret.hash(code))
  end

  test "old redeemed bindings are compared before new replay handling without a writing read" do
    code = issue(Old, "original")
    hash = Secret.hash(code)
    {:ok, _} = Old.take(hash)
    :ok = Old.mark_consumed(hash, redemption("issued"))
    before = TestRepo.get!(Authorization, hash)
    assert before.authorization_family_id == nil

    assert {:error, :client_mismatch} =
             another_connection(fn ->
               AuthorizationCode.redeem(New, code, %{@params | client_id: "other"})
             end)

    assert {:error, {:reuse, %{family_id: "issued"}}} =
             another_connection(fn ->
               AuthorizationCode.redeem(New, code, @params, now: System.system_time(:second) + 700)
             end)

    assert before == TestRepo.get!(Authorization, hash)
    assert {:ok, %{data: %{family_id: nil}}} = New.read(hash)

    :ok = New.record_access_token_for_code(hash, hash, System.system_time(:second) + 600)
    :ok = New.revoke_access_token_for_code(hash)
    assert {:ok, %{data: %{family_id: nil}, revoked: false}} = New.read(hash)
    assert TestRepo.get!(Authorization, hash).authorization_family_id == nil
  end

  test "new redemption is understood by old replay handling and preserves nil provenance" do
    for provenance <- [nil, "original"] do
      code = issue(New, provenance)
      hash = Secret.hash(code)
      :ok = New.claim(hash)
      {:ok, _} = New.finish(hash, redemption("issued"))
      assert {:error, :consumed, %{family_id: "issued"}} = another_connection(fn -> Old.take(hash) end)
      assert {:ok, %{data: %{family_id: ^provenance}}} = New.read(hash)
    end
  end

  test "new writes copy old provenance and preserve legacy cutoff markers" do
    code = issue(Old, "original")
    hash = Secret.hash(code)
    {:ok, _} = Old.take(hash)
    {:ok, 0} = another_connection(fn -> Old.delete_unconsumed(client_id: "rolling-client") end)
    :ok = New.record_access_token_for_code(hash, hash, System.system_time(:second) + 600)
    assert {:ok, true} = New.finish(hash, redemption("issued"))
    assert {:ok, %{data: %{family_id: "original"}}} = New.read(hash)
  end

  test "both sweepers preserve current claims and live access links across writers" do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    for writer <- [Old, New] do
      code = issue(writer)
      hash = Secret.hash(code)
      if writer == Old, do: Old.take(hash), else: New.claim(hash)

      TestRepo.update_all(from(a in Authorization, where: a.code_hash == ^hash),
        set: [expires_at: DateTime.add(now, -1)]
      )

      another_connection(fn -> OldSweeper.sweep_once(config(), now) end)
      another_connection(fn -> Sweeper.sweep_once(config(), now) end)
      assert {:ok, %{state: :claimed}} = New.read(hash)
      New.record_access_token_for_code(hash, hash, DateTime.to_unix(now) + 600)
      if writer == Old, do: Old.mark_consumed(hash, redemption()), else: New.finish(hash, redemption())
      another_connection(fn -> OldSweeper.sweep_once(config(), now) end)
      another_connection(fn -> Sweeper.sweep_once(config(), now) end)
      assert {:ok, %{state: :redeemed}} = New.read(hash)
    end
  end

  test "both sweepers retire abandoned claims after the reservation and finish returns an error" do
    for sweeper <- [OldSweeper, Sweeper] do
      code = issue(New)
      {:ok, grant} = AuthorizationCode.redeem(New, code, @params)
      hash = Secret.hash(code)
      later = DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.add(700)
      another_connection(fn -> sweeper.sweep_once(config(), later) end)
      assert :error = New.read(hash)
      assert {:error, :invalid_grant} = AuthorizationCode.redeem(New, code, @params)
      assert {:error, :invalid_grant} = AuthorizationCode.finalize(New, code, grant)
    end
  end

  test "both sweepers retire redeemed families with no remaining refresh member" do
    for sweeper <- [OldSweeper, Sweeper] do
      code = issue(New)
      hash = Secret.hash(code)
      :ok = New.claim(hash)
      {:ok, _} = New.finish(hash, redemption("unbounded-family"))
      later = DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.add(700)
      another_connection(fn -> sweeper.sweep_once(config(), later) end)
      assert :error = New.read(hash)
    end
  end
end
