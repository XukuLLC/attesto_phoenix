defmodule AttestoPhoenix.Store.EctoCodeBindingTest do
  use ExUnit.Case, async: false

  import Ecto.Query, only: [from: 2]

  alias Attesto.AuthorizationCode
  alias Attesto.RefreshToken
  alias Attesto.Secret
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Schema.Authorization
  alias AttestoPhoenix.Store.EctoCodeStore, as: ETS
  alias AttestoPhoenix.Store.EctoRefreshStore, as: RefreshStore
  alias AttestoPhoenix.TestRepo
  alias Ecto.Adapters.SQL.Sandbox

  @verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  @challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
  @jkt Base.url_encode64(:crypto.hash(:sha256, "key"), padding: false)
  @params %{client_id: "client", redirect_uri: "https://client.example/cb", code_verifier: @verifier, dpop_jkt: @jkt}
  @attrs %{
    client_id: "client",
    redirect_uri: "https://client.example/cb",
    code_challenge: @challenge,
    dpop_jkt: @jkt,
    subject: "subject",
    scope: [],
    resource: []
  }

  @moduletag :ecto

  setup do
    owner = Sandbox.start_owner!(TestRepo, sandbox: false)

    config =
      struct!(Config,
        issuer: "https://issuer.example",
        keystore: __MODULE__,
        repo: TestRepo,
        refresh_store: RefreshStore
      )

    Process.put(:binding_test_config, config)

    on_exit(fn ->
      :ok = Sandbox.allow(TestRepo, owner, self())
      TestRepo.delete_all(from a in Authorization, where: a.client_id == "client")
      TestRepo.delete_all(from r in AttestoPhoenix.Schema.RefreshToken, where: r.client_id == "client")
      Sandbox.stop_owner(owner)
    end)

    :ok
  end

  for {field, value, reason} <- [
        {:client_id, "other", :client_mismatch},
        {:redirect_uri, "https://other.example/cb", :redirect_uri_mismatch},
        {:code_verifier, String.duplicate("x", 43), :pkce_failed},
        {:dpop_jkt, Base.url_encode64(:crypto.hash(:sha256, "other"), padding: false), :dpop_binding_mismatch}
      ] do
    test "a wrong #{field} leaves a live code redeemable" do
      {:ok, code} = AuthorizationCode.issue(ETS, @attrs)
      hash = Secret.hash(code)
      before = ETS.read(hash)

      assert {:error, unquote(reason)} =
               AuthorizationCode.redeem(ETS, code, Map.put(@params, unquote(field), unquote(value)))

      assert ETS.read(hash) == before
      assert {:ok, _} = AuthorizationCode.redeem(ETS, code, @params)
    end

    test "a wrong #{field} cannot contain a pending or finalized redemption" do
      for phase <- [:pending, :finalized] do
        {:ok, code} = AuthorizationCode.issue(ETS, @attrs)
        {:ok, grant} = AuthorizationCode.redeem(ETS, code, @params)
        hash = Secret.hash(code)
        jti = Secret.generate()
        :ok = ETS.record_access_token_for_code(hash, jti, System.system_time(:second) + 600)
        issued = if phase == :finalized, do: finalize(code, grant)
        before = ETS.read(hash)

        assert {:error, unquote(reason)} =
                 AuthorizationCode.redeem(ETS, code, Map.put(@params, unquote(field), unquote(value)))

        assert ETS.read(hash) == before
        refute TestRepo.get_by!(Authorization, code_hash: hash).access_token_revoked_at
        issued = issued || finalize(code, grant)
        refute ETS.access_token_revoked?(jti)
        assert {:ok, _} = RefreshToken.rotate(RefreshStore, issued.token, client_id: "client")
      end
    end
  end

  test "a matching pending replay contains the family created at finalization" do
    {:ok, code} = AuthorizationCode.issue(ETS, @attrs)
    {:ok, grant} = AuthorizationCode.redeem(ETS, code, @params)
    hash = Secret.hash(code)
    :ok = ETS.record_access_token_for_code(hash, "matching-jti", System.system_time(:second) + 600)
    assert {:error, :invalid_grant} = AuthorizationCode.redeem(ETS, code, @params)
    issued = finalize(code, grant)
    assert ETS.access_token_revoked?("matching-jti")
    assert {:error, _} = RefreshToken.rotate(RefreshStore, issued.token, client_id: "client")
  end

  test "reads and failed claims do not flag a replay" do
    {:ok, code} = AuthorizationCode.issue(ETS, @attrs)
    {:ok, _} = AuthorizationCode.redeem(ETS, code, @params)
    hash = Secret.hash(code)
    assert {:ok, %{state: :claimed, data: data, revoked: false}} = ETS.read(hash)
    assert Map.take(data, Map.keys(@attrs)) == @attrs
    assert :error = ETS.claim(hash)
    assert {:ok, %{revoked: false}} = ETS.read(hash)
  end

  test "a replay flag losing to finish rereads the redemption" do
    {:ok, code} = AuthorizationCode.issue(ETS, @attrs)
    {:ok, grant} = AuthorizationCode.redeem(ETS, code, @params)
    issued = finalize(code, grant)
    assert :error = ETS.flag_replay(Secret.hash(code))
    family = issued.family_id
    assert {:error, {:reuse, %{family_id: ^family}}} = AuthorizationCode.redeem(ETS, code, @params)
    assert {:error, {:reuse, _}} = AuthorizationCode.redeem(ETS, code, @params, now: System.system_time(:second) + 600)
  end

  test "an unchallenged consumed code compares client and redirect without a verifier" do
    {:ok, code} = AuthorizationCode.issue(ETS, %{@attrs | code_challenge: nil, dpop_jkt: nil})
    {:ok, grant} = AuthorizationCode.redeem(ETS, code, Map.drop(@params, [:code_verifier, :dpop_jkt]))
    :ok = AuthorizationCode.finalize(ETS, code, grant)
    assert {:error, {:reuse, _}} = AuthorizationCode.redeem(ETS, code, Map.delete(@params, :code_verifier))
    assert {:error, :client_mismatch} = AuthorizationCode.redeem(ETS, code, %{@params | client_id: "other"})
  end

  test "racing presentations redeem once and a wrong client cannot win" do
    for second <- [@params, %{@params | client_id: "other"}] do
      {:ok, code} = AuthorizationCode.issue(ETS, @attrs)
      parent = self()

      tasks =
        for params <- [@params, second] do
          Task.async(fn ->
            :ok = Sandbox.checkout(TestRepo, sandbox: false)

            try do
              %{rows: [[backend]]} = TestRepo.query!("SELECT pg_backend_pid()")
              send(parent, {:ready, self(), backend})

              receive do
                :go -> AuthorizationCode.redeem(ETS, code, params)
              end
            after
              Sandbox.checkin(TestRepo)
            end
          end)
        end

      assert_receive {:ready, first, first_backend}, 5_000
      assert_receive {:ready, second_pid, second_backend}, 5_000
      refute first_backend == second_backend
      send(first, :go)
      send(second_pid, :go)
      results = Task.await_many(tasks)
      assert Enum.count(results, &match?({:ok, _}, &1)) == 1
      if second.client_id == "other", do: assert(match?({:ok, _}, hd(results)))
    end
  end

  test "expiry refuses only live codes and failed comparisons remain non-writing after expiry" do
    now = System.system_time(:second)

    for phase <- [:live, :claimed, :redeemed] do
      {:ok, code} = AuthorizationCode.issue(ETS, @attrs, now: now, ttl: 1)

      if phase != :live do
        {:ok, grant} = AuthorizationCode.redeem(ETS, code, @params, now: now)
        if phase == :redeemed, do: AuthorizationCode.finalize(ETS, code, grant)
      end

      hash = Secret.hash(code)
      before = ETS.read(hash)

      assert {:error, :client_mismatch} =
               AuthorizationCode.redeem(ETS, code, %{@params | client_id: "other"}, now: now + 2)

      assert ETS.read(hash) == before

      case phase do
        :live ->
          assert {:error, :expired} = AuthorizationCode.redeem(ETS, code, @params, now: now + 2)
          assert ETS.read(hash) == before

        :claimed ->
          assert {:error, :invalid_grant} = AuthorizationCode.redeem(ETS, code, @params, now: now + 2)
          assert {:ok, %{revoked: true}} = ETS.read(hash)

        :redeemed ->
          assert {:error, {:reuse, _}} = AuthorizationCode.redeem(ETS, code, @params, now: now + 2)
      end
    end
  end

  defp finalize(code, grant) do
    Config.with_request_config(Process.get(:binding_test_config), fn ->
      assert {:ok, issued} =
               AuthorizationCode.issue_refresh_and_finalize(ETS, code, grant, RefreshStore, %{
                 client_id: "client",
                 subject: "subject",
                 scope: [],
                 resource: []
               })

      issued
    end)
  end
end
