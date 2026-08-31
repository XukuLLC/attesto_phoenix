defmodule AttestoPhoenix.Store.EctoRefreshStoreTest do
  @moduledoc """
  Direct conformance tests for the atomic Ecto refresh-token store.

  These tests run against PostgreSQL because advisory locks, row locks,
  transaction rollback, JSONB successor state, and prefix routing are all
  part of the storage contract.
  """

  use AttestoPhoenix.DataCase, async: false

  import Ecto.Query
  import ExUnit.CaptureLog

  alias Attesto.RefreshToken, as: CoreRefreshToken
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.RefreshSuccessorCipher
  alias AttestoPhoenix.Schema.RefreshFamilyRevocation
  alias AttestoPhoenix.Schema.RefreshToken
  alias AttestoPhoenix.Store.EctoRefreshStore
  alias AttestoPhoenix.Store.Sweeper
  alias Ecto.Adapters.SQL.Sandbox

  @moduletag :ecto

  defmodule Keystore do
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem, do: "refresh-prefix-test"

    @impl true
    def verification_pems, do: [signing_pem()]
  end

  defmodule FailingRepo do
    @moduledoc false

    def transaction(_fun), do: {:error, :store_unavailable}
    def transaction(_fun, _opts), do: {:error, :store_unavailable}
  end

  # Behaviour-style store calls do not receive a Config argument. Install a
  # complete host config for those calls so direct reads and rotations resolve
  # the same validated defaults as a deployed host, even when another test
  # leaves the library's otp_app pointer set.
  setup do
    previous_otp_app = Application.get_env(:attesto_phoenix, :otp_app, :missing)
    previous_config = Application.get_env(__MODULE__, Config, :missing)

    Application.put_env(:attesto_phoenix, :otp_app, __MODULE__)
    Application.put_env(__MODULE__, Config, prefix_config(nil))

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

    :ok
  end

  defp entry(attrs \\ %{}) do
    Map.merge(
      %{
        token_hash: "hash-#{System.unique_integer([:positive])}",
        family_id: "fam-#{System.unique_integer([:positive])}",
        generation: 0,
        data: %{
          subject: "sub-1",
          scope: ["read"],
          resource: [],
          acr: nil,
          auth_time: nil,
          client_id: "client-1",
          dpop_jkt: nil,
          claims: %{"k" => "v"}
        },
        expires_at: 1_900_000_100,
        consumed: false
      },
      attrs
    )
  end

  defp child(parent, token, attrs \\ %{}) do
    Map.merge(
      entry(%{
        token_hash: Attesto.Secret.hash(token),
        family_id: parent.family_id,
        generation: parent.generation + 1,
        data: parent.data,
        expires_at: parent.expires_at,
        consumed_at: nil,
        successor: nil
      }),
      attrs
    )
  end

  defp successor(child, token, retry_until, attrs \\ %{}) do
    Map.merge(
      %{
        token: token,
        generation: child.generation,
        context: child.data,
        retry_until: retry_until
      },
      attrs
    )
  end

  defp prefix_config(prefix) do
    Config.new(
      issuer: "https://issuer.example",
      audience: "https://resource.example",
      keystore: Keystore,
      repo: TestRepo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      schema_prefix: prefix
    )
  end

  defp assert_parent_unchanged(parent) do
    assert {:ok, stored} = EctoRefreshStore.get(parent.token_hash)
    assert stored.consumed == false
    assert stored.successor == nil
  end

  defp assert_refresh_sensitive_queries_suppressed(ref) do
    events = AttestoPhoenix.TestTelemetryCapture.collect(ref)

    refute Enum.any?(events, fn {_event_name, _measurements, metadata} ->
             String.contains?(metadata.query, "SELECT a0.\"id\"") or
               String.contains?(metadata.query, "SET \"successor\"")
           end)
  end

  describe "insert/1 and get/1" do
    test "refresh writes and full-row reads emit no telemetry or sensitive logs" do
      capture = AttestoPhoenix.TestTelemetryCapture.attach(TestRepo)
      on_exit(fn -> AttestoPhoenix.TestTelemetryCapture.detach(capture) end)
      {_id, ref} = capture

      assert is_integer(TestRepo.aggregate(RefreshToken, :count, :id))
      assert AttestoPhoenix.TestTelemetryCapture.collect(ref) != []

      parent =
        entry(%{
          token_hash: "refresh-hash-telemetry-sentinel",
          family_id: "refresh-family-telemetry-sentinel",
          data: %{
            subject: "refresh-subject-telemetry-sentinel",
            scope: ["read"],
            resource: [],
            acr: nil,
            auth_time: nil,
            client_id: "refresh-client-telemetry-sentinel",
            dpop_jkt: nil,
            claims: %{"secret" => "refresh-claims-telemetry-sentinel"}
          }
        })

      child_token = "refresh-token-telemetry-sentinel"
      child = child(parent, child_token)
      retry_state = successor(child, child_token, 1_900_000_010)

      log =
        capture_log([level: :debug], fn ->
          assert :ok = EctoRefreshStore.insert(parent)
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []

          assert {:ok, loaded} = EctoRefreshStore.get(parent.token_hash)
          assert loaded.token_hash == parent.token_hash
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []

          assert {:ok, _committed_parent, _committed_child} =
                   EctoRefreshStore.rotate(
                     parent.token_hash,
                     child,
                     retry_state,
                     now: 1_900_000_001
                   )

          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []

          assert :ok = EctoRefreshStore.revoke_family(parent.family_id)
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
        end)

      for sentinel <- [
            parent.token_hash,
            parent.family_id,
            parent.data.subject,
            parent.data.client_id,
            "refresh-claims-telemetry-sentinel",
            child_token
          ] do
        refute log =~ sentinel
      end
    end

    test "rotation suppresses telemetry for full-row phases and successor lineage reads" do
      capture = AttestoPhoenix.TestTelemetryCapture.attach(TestRepo)
      on_exit(fn -> AttestoPhoenix.TestTelemetryCapture.detach(capture) end)
      {_id, ref} = capture

      assert is_integer(TestRepo.aggregate(RefreshToken, :count, :id))
      assert AttestoPhoenix.TestTelemetryCapture.collect(ref) != []

      parent = entry()
      token = "telemetry-successor-#{System.unique_integer([:positive])}"
      child = child(parent, token)
      retry_state = successor(child, token, 1_900_000_010)
      assert :ok = EctoRefreshStore.insert(parent)
      assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []

      assert {:ok, _committed_parent, _committed_child} =
               EctoRefreshStore.rotate(parent.token_hash, child, retry_state, now: 1_900_000_001)

      assert_refresh_sensitive_queries_suppressed(ref)

      assert {:ok, loaded} = EctoRefreshStore.get(parent.token_hash)
      assert loaded.successor == retry_state
      assert_refresh_sensitive_queries_suppressed(ref)

      assert {:reuse, reused} =
               EctoRefreshStore.rotate(parent.token_hash, child, retry_state, now: 1_900_000_002)

      assert reused.successor == retry_state
      assert_refresh_sensitive_queries_suppressed(ref)
    end

    test "pins a core-issued record through the real Ecto round trip" do
      context = %{
        subject: "sub-1",
        scope: ["read", "read", "write"],
        resource: [],
        acr: nil,
        auth_time: nil,
        client_id: nil,
        dpop_jkt: nil,
        claims: %{"issuer" => "test"}
      }

      assert {:ok, issued} =
               CoreRefreshToken.issue(EctoRefreshStore, context, now: 1_900_000_000, ttl: 100)

      assert {:ok, persisted} = EctoRefreshStore.get(Attesto.Secret.hash(issued.token))
      assert persisted.generation == 0
      assert persisted.data == context
    end

    test "round-trips nested portable claims exactly through JSONB" do
      claims = %{
        "nested" => %{
          "values" => [nil, true, 42, %{"leaf" => "value"}]
        }
      }

      e = entry()
      e = %{e | data: Map.put(e.data, :claims, claims)}
      assert :ok = EctoRefreshStore.insert(e)
      assert {:ok, persisted} = EctoRefreshStore.get(e.token_hash)
      assert persisted.data.claims == claims
    end

    test "rejects noncanonical data before touching Ecto with a fixed diagnostic" do
      e = entry()

      for key <- Map.keys(e.data) do
        bad = Map.put(e, :data, Map.delete(e.data, key))

        error =
          assert_raise ArgumentError,
                       "refresh token record violates the canonical store contract",
                       fn ->
                         EctoRefreshStore.insert(bad)
                       end

        refute Exception.message(error) =~ "sub-1"
      end

      bad = Map.put(e, :data, Map.put(e.data, :unexpected, "private-refresh-context"))

      error =
        assert_raise ArgumentError,
                     "refresh token record violates the canonical store contract",
                     fn ->
                       EctoRefreshStore.insert(bad)
                     end

      refute Exception.message(error) =~ "private-refresh-context"
    end

    test "rejects malformed canonical values rather than letting Ecto defaults widen them" do
      e = entry()

      for {key, value} <- [
            {:subject, ""},
            {:scope, nil},
            {:resource, nil},
            {:client_id, ""},
            {:acr, ""},
            {:auth_time, -1},
            {:claims, nil},
            {:dpop_jkt, "not-a-thumbprint"}
          ] do
        bad = Map.put(e, :data, Map.put(e.data, key, value))

        assert_raise ArgumentError,
                     "refresh token record violates the canonical store contract",
                     fn ->
                       EctoRefreshStore.insert(bad)
                     end
      end
    end

    test "round-trips an entry and uses the primary configured prefix" do
      e = entry()

      assert :ok = EctoRefreshStore.insert(e)
      assert {:ok, got} = EctoRefreshStore.get(e.token_hash)
      assert got.token_hash == e.token_hash
      assert got.family_id == e.family_id
      assert got.generation == e.generation
      assert got.expires_at == e.expires_at
      assert got.data == e.data

      assert TestRepo.one(from(r in RefreshToken, where: r.token_hash == ^e.token_hash))
    end

    test "rejects duplicate token hashes and duplicate family generations" do
      e = entry()
      assert :ok = EctoRefreshStore.insert(e)

      assert {:error, :conflict} =
               EctoRefreshStore.insert(entry(%{token_hash: e.token_hash, family_id: "other-family"}))

      assert {:error, :conflict} =
               EctoRefreshStore.insert(entry(%{family_id: e.family_id, generation: e.generation}))
    end

    test "sticky family revocation rejects later inserts" do
      e = entry()
      assert :ok = EctoRefreshStore.insert(e)
      assert :ok = EctoRefreshStore.revoke_family(e.family_id)
      assert {:error, :family_revoked} = EctoRefreshStore.insert(entry(%{family_id: e.family_id}))
      assert :error = EctoRefreshStore.get(e.token_hash)

      assert TestRepo.aggregate(
               from(r in RefreshToken, where: r.family_id == ^e.family_id),
               :count,
               :id
             ) == 0
    end

    test "get hides a residual row when the durable family marker exists" do
      e = entry()
      assert :ok = EctoRefreshStore.insert(e)

      assert {:ok, _marker} =
               TestRepo.insert(%RefreshFamilyRevocation{
                 family_id: e.family_id,
                 revoked_at: ~U[2030-01-01 00:00:00Z]
               })

      assert :error = EctoRefreshStore.get(e.token_hash)
      assert %RefreshToken{} = TestRepo.get_by(RefreshToken, token_hash: e.token_hash)
    end

    test "revoking an unknown family creates a tombstone before its first insert" do
      family_id = "unknown-revoked-family-#{System.unique_integer([:positive])}"

      assert :ok = EctoRefreshStore.revoke_family(family_id)
      assert {:error, :family_revoked} = EctoRefreshStore.insert(entry(%{family_id: family_id}))

      assert %RefreshFamilyRevocation{family_id: ^family_id} =
               TestRepo.get(RefreshFamilyRevocation, family_id)
    end

    test "revocation remains sticky after the sweeper removes every expired family row" do
      family_id = "swept-family-#{System.unique_integer([:positive])}"
      expired = System.system_time(:second) - 60
      e = entry(%{family_id: family_id, expires_at: expired})
      assert :ok = EctoRefreshStore.insert(e)
      assert :ok = EctoRefreshStore.revoke_family(family_id)

      config = %{prefix_config(nil) | sweep_interval_ms: 60_000}
      {:ok, sweeper} = Sweeper.start_link(config: config, name: nil)
      Sandbox.allow(TestRepo, self(), sweeper)
      on_exit(fn -> if Process.alive?(sweeper), do: GenServer.stop(sweeper) end)

      assert Sweeper.sweep_now(sweeper)["attesto_refresh_tokens"] == 0

      assert TestRepo.aggregate(
               from(r in RefreshToken, where: r.family_id == ^family_id),
               :count,
               :id
             ) == 0

      assert {:error, :family_revoked} = EctoRefreshStore.insert(entry(%{family_id: family_id}))
    end

    test "sweeper removes an expired parent despite a later encrypted retry deadline" do
      now = System.system_time(:second)
      parent = entry(%{expires_at: now - 1})
      token = "sweeper-parent-expiry-#{System.unique_integer([:positive])}"
      child = child(parent, token, %{expires_at: now + 100})
      assert :ok = EctoRefreshStore.insert(parent)

      assert {:ok, _, _} =
               EctoRefreshStore.rotate(
                 parent.token_hash,
                 child,
                 successor(child, token, now + 60),
                 now: now - 2
               )

      config = %{prefix_config(nil) | sweep_interval_ms: 60_000}
      {:ok, sweeper} = Sweeper.start_link(config: config, name: nil)
      Sandbox.allow(TestRepo, self(), sweeper)
      on_exit(fn -> if Process.alive?(sweeper), do: GenServer.stop(sweeper) end)

      assert Sweeper.sweep_now(sweeper)["attesto_refresh_tokens"] == 1
      assert TestRepo.get_by(RefreshToken, token_hash: parent.token_hash) == nil
    end
  end

  describe "rotate/4" do
    test "never writes successor credentials or ciphertext to Ecto query logs" do
      parent = entry()
      token = "log-secret-successor-#{System.unique_integer([:positive])}"
      child = child(parent, token)
      retry_until = 1_900_000_010
      retry_state = successor(child, token, retry_until)
      assert :ok = EctoRefreshStore.insert(parent)
      test_pid = self()

      log =
        capture_log([level: :debug], fn ->
          result =
            EctoRefreshStore.rotate(parent.token_hash, child, retry_state, now: 1_900_000_001)

          send(test_pid, {:rotation_result, result})
        end)

      assert_receive {:rotation_result, {:ok, _committed_parent, _committed_child}}

      ciphertext =
        RefreshToken
        |> TestRepo.get_by!(token_hash: parent.token_hash)
        |> Map.fetch!(:successor)
        |> Map.fetch!("ciphertext")

      refute log =~ "attesto_refresh_tokens"
      refute log =~ token
      refute log =~ ciphertext
    end

    test "commits the parent and child atomically and returns both snapshots" do
      parent = entry()
      token = "successor-#{System.unique_integer([:positive])}"
      child = child(parent, token)
      retry_until = 1_900_000_010
      successor = successor(child, token, retry_until)

      assert :ok = EctoRefreshStore.insert(parent)

      assert {:ok, committed_parent, committed_child} =
               EctoRefreshStore.rotate(parent.token_hash, child, successor, now: 1_900_000_001)

      assert committed_parent.consumed
      assert committed_parent.consumed_at == 1_900_000_001
      assert committed_parent.successor == successor
      assert committed_child == child

      assert {:ok, stored_parent} = EctoRefreshStore.get(parent.token_hash)
      assert stored_parent == committed_parent
      assert {:ok, stored_child} = EctoRefreshStore.get(child.token_hash)
      assert stored_child == committed_child
    end

    test "a replay returns the complete committed parent and never inserts the candidate" do
      parent = entry()
      winner_token = "winner-#{System.unique_integer([:positive])}"
      winner_child = child(parent, winner_token)
      winner_successor = successor(winner_child, winner_token, 1_900_000_010)
      assert :ok = EctoRefreshStore.insert(parent)

      assert {:ok, _, _} =
               EctoRefreshStore.rotate(parent.token_hash, winner_child, winner_successor, now: 1_900_000_001)

      loser_token = "loser-#{System.unique_integer([:positive])}"
      loser_child = child(parent, loser_token)
      loser_successor = successor(loser_child, loser_token, 1_900_000_020)

      assert {:reuse, reused} =
               EctoRefreshStore.rotate(parent.token_hash, loser_child, loser_successor, now: 1_900_000_002)

      assert reused.consumed
      assert reused.successor == winner_successor
      assert :error = EctoRefreshStore.get(loser_child.token_hash)
    end

    test "strict mode persists an exact tombstone without a secret" do
      parent = entry()
      token = "strict-#{System.unique_integer([:positive])}"
      child = child(parent, token)
      assert :ok = EctoRefreshStore.insert(parent)

      original = Application.get_env(:attesto_phoenix, :refresh_successor_secret)
      Application.delete_env(:attesto_phoenix, :refresh_successor_secret)

      on_exit(fn ->
        Application.put_env(:attesto_phoenix, :refresh_successor_secret, original)
      end)

      assert {:ok, committed_parent, committed_child} =
               EctoRefreshStore.rotate(
                 parent.token_hash,
                 child,
                 %{retry_until: 1_900_000_001, recoverable: false},
                 now: 1_900_000_001
               )

      assert committed_parent.successor == %{retry_until: 1_900_000_001, recoverable: false}
      assert committed_child == child

      row = TestRepo.get_by!(RefreshToken, token_hash: parent.token_hash)
      assert row.successor == %{"v" => 1, "retry_until" => 1_900_000_001, "recoverable" => false}
    end

    test "missing positive-state secret returns retry_state_unavailable with zero mutation" do
      parent = entry()
      token = "secret-failure-#{System.unique_integer([:positive])}"
      child = child(parent, token)
      assert :ok = EctoRefreshStore.insert(parent)

      original = Application.get_env(:attesto_phoenix, :refresh_successor_secret)
      Application.delete_env(:attesto_phoenix, :refresh_successor_secret)

      on_exit(fn ->
        Application.put_env(:attesto_phoenix, :refresh_successor_secret, original)
      end)

      assert {:error, :retry_state_unavailable} =
               EctoRefreshStore.rotate(
                 parent.token_hash,
                 child,
                 successor(child, token, 1_900_000_010),
                 now: 1_900_000_001
               )

      assert_parent_unchanged(parent)
      assert :error = EctoRefreshStore.get(child.token_hash)
    end

    test "rejects an expired parent without consuming it" do
      parent = entry(%{expires_at: 1_900_000_001})
      token = "expired-#{System.unique_integer([:positive])}"
      child = child(parent, token, %{expires_at: 1_900_000_100})
      assert :ok = EctoRefreshStore.insert(parent)

      assert {:error, :expired} =
               EctoRefreshStore.rotate(
                 parent.token_hash,
                 child,
                 successor(child, token, 1_900_000_010),
                 now: 1_900_000_001
               )

      assert_parent_unchanged(parent)
    end

    test "rejects a malformed rotation without consuming the parent" do
      parent = entry()
      token = "invalid-#{System.unique_integer([:positive])}"
      child = child(parent, token)
      assert :ok = EctoRefreshStore.insert(parent)

      assert {:error, :invalid_rotation} =
               EctoRefreshStore.rotate(
                 parent.token_hash,
                 child,
                 successor(child, token, 1_900_000_010, %{context: %{subject: "wrong"}}),
                 now: 1_900_000_001
               )

      assert_parent_unchanged(parent)
    end

    test "rejects extra successor members before persistence" do
      parent = entry()
      token = "extra-successor-#{System.unique_integer([:positive])}"
      child = child(parent, token)
      assert :ok = EctoRefreshStore.insert(parent)

      bad_successor = Map.put(successor(child, token, 1_900_000_010), :unexpected, "private")

      assert {:error, :invalid_rotation} =
               EctoRefreshStore.rotate(parent.token_hash, child, bad_successor, now: 1_900_000_001)

      assert_parent_unchanged(parent)
      assert :error = EctoRefreshStore.get(child.token_hash)
    end

    test "rejects malformed child maps without raising or mutating" do
      parent = entry()
      assert :ok = EctoRefreshStore.insert(parent)

      child = %{token_hash: "not-a-complete-entry"}
      successor = %{token: "ignored", generation: 1, context: %{}, retry_until: 1_900_000_010}

      assert {:error, :invalid_rotation} =
               EctoRefreshStore.rotate(parent.token_hash, child, successor, now: 1_900_000_001)

      assert_parent_unchanged(parent)
    end

    test "a child cannot redirect rotation locking to its caller-provided family" do
      parent = entry()
      token = "wrong-family-#{System.unique_integer([:positive])}"
      malicious_child = child(parent, token, %{family_id: "attacker-family"})
      assert :ok = EctoRefreshStore.insert(parent)

      assert {:error, :invalid_rotation} =
               EctoRefreshStore.rotate(
                 parent.token_hash,
                 malicious_child,
                 successor(malicious_child, token, 1_900_000_010),
                 now: 1_900_000_001
               )

      assert_parent_unchanged(parent)
      refute TestRepo.get(RefreshFamilyRevocation, "attacker-family")
    end

    test "token collision returns token_conflict without consuming the parent" do
      parent = entry()
      collision_token = "collision-#{System.unique_integer([:positive])}"
      collision = entry(%{token_hash: Attesto.Secret.hash(collision_token)})
      candidate = child(parent, collision_token)
      assert :ok = EctoRefreshStore.insert(parent)
      assert :ok = EctoRefreshStore.insert(collision)

      assert {:error, :token_conflict} =
               EctoRefreshStore.rotate(
                 parent.token_hash,
                 candidate,
                 successor(candidate, collision_token, 1_900_000_010),
                 now: 1_900_000_001
               )

      assert_parent_unchanged(parent)
    end

    test "a preexisting sibling generation revokes the family and returns family_integrity_error" do
      parent = entry()
      sibling_token = "sibling-#{System.unique_integer([:positive])}"
      sibling = child(parent, sibling_token)
      candidate_token = "candidate-#{System.unique_integer([:positive])}"
      candidate = child(parent, candidate_token)
      assert :ok = EctoRefreshStore.insert(parent)
      assert :ok = EctoRefreshStore.insert(sibling)

      assert {:error, :family_integrity_error} =
               EctoRefreshStore.rotate(
                 parent.token_hash,
                 candidate,
                 successor(candidate, candidate_token, 1_900_000_010),
                 now: 1_900_000_001
               )

      assert TestRepo.aggregate(
               from(r in RefreshToken, where: r.family_id == ^parent.family_id),
               :count,
               :id
             ) == 0

      assert %RefreshFamilyRevocation{family_id: marker_family_id} =
               TestRepo.get(RefreshFamilyRevocation, parent.family_id)

      assert marker_family_id == parent.family_id

      TestRepo.delete_all(from(r in RefreshToken, where: r.family_id == ^parent.family_id))

      assert {:error, :family_revoked} =
               EctoRefreshStore.insert(entry(%{family_id: parent.family_id}))
    end

    test "unknown parent returns :error and does not insert the child" do
      parent = entry()
      token = "unknown-#{System.unique_integer([:positive])}"
      child = child(parent, token)

      assert :error =
               EctoRefreshStore.rotate(
                 parent.token_hash,
                 child,
                 successor(child, token, 1_900_000_010),
                 now: 1_900_000_001
               )

      assert :error = EctoRefreshStore.get(child.token_hash)
    end

    test "stopped-cutover v1 ciphertext copied across families is never recovered or issued" do
      parent_a_token = "legacy-family-a-parent-#{System.unique_integer([:positive])}"
      parent_a = entry(%{token_hash: Attesto.Secret.hash(parent_a_token)})
      token_a = "legacy-family-a-child-#{System.unique_integer([:positive])}"
      child_a = child(parent_a, token_a)
      assert :ok = EctoRefreshStore.insert(parent_a)

      assert {:ok, _, _} =
               EctoRefreshStore.rotate(
                 parent_a.token_hash,
                 child_a,
                 successor(child_a, token_a, 1_900_000_010),
                 now: 1_900_000_001
               )

      {:ok, ciphertext} =
        RefreshSuccessorCipher.encrypt(Map.delete(successor(child_a, token_a, 1_900_000_010), :retry_until))

      TestRepo.get_by!(RefreshToken, token_hash: parent_a.token_hash)
      |> Ecto.Changeset.change(successor: %{"v" => 1, "ciphertext" => ciphertext})
      |> TestRepo.update!()

      parent_b_token = "legacy-family-b-parent-#{System.unique_integer([:positive])}"
      parent_b = entry(%{token_hash: Attesto.Secret.hash(parent_b_token)})
      token_b = "legacy-family-b-child-#{System.unique_integer([:positive])}"
      child_b = child(parent_b, token_b)
      assert :ok = EctoRefreshStore.insert(parent_b)

      assert {:ok, _, _} =
               EctoRefreshStore.rotate(
                 parent_b.token_hash,
                 child_b,
                 successor(child_b, token_b, 1_900_000_010),
                 now: 1_900_000_001
               )

      TestRepo.get_by!(RefreshToken, token_hash: parent_b.token_hash)
      |> Ecto.Changeset.change(successor: %{"v" => 1, "ciphertext" => ciphertext})
      |> TestRepo.update!()

      assert {:ok, loaded} = EctoRefreshStore.get(parent_b.token_hash)
      assert loaded.successor == nil

      assert {:error, :grant_revoked} =
               CoreRefreshToken.rotate(EctoRefreshStore, parent_b_token,
                 client_id: "client-1",
                 rotation_grace_seconds: 60,
                 ttl: 60,
                 now: 1_900_000_002
               )

      assert :error = EctoRefreshStore.get(parent_b.token_hash)
      assert :error = EctoRefreshStore.get(child_b.token_hash)

      family_id_b = parent_b.family_id

      assert %RefreshFamilyRevocation{family_id: ^family_id_b} =
               TestRepo.get(RefreshFamilyRevocation, parent_b.family_id)
    end

    test "ciphertext, deadline, child binding, and parent binding tampering fail closed" do
      parent = entry()
      token = "tamper-#{System.unique_integer([:positive])}"
      child = child(parent, token)
      assert :ok = EctoRefreshStore.insert(parent)

      assert {:ok, _, _} =
               EctoRefreshStore.rotate(
                 parent.token_hash,
                 child,
                 successor(child, token, 1_900_000_010),
                 now: 1_900_000_001
               )

      row = TestRepo.get_by!(RefreshToken, token_hash: parent.token_hash)

      for mutate <- [
            fn wrapper -> Map.update!(wrapper, "ciphertext", &(&1 <> "tampered")) end,
            fn wrapper -> Map.put(wrapper, "retry_until", 1_900_000_011) end,
            fn wrapper -> Map.put(wrapper, "child_hash", "wrong-child-hash") end
          ] do
        row
        |> Ecto.Changeset.change(successor: mutate.(row.successor))
        |> TestRepo.update!()

        assert {:ok, loaded} = EctoRefreshStore.get(parent.token_hash)
        assert loaded.successor == nil

        row
        |> Ecto.Changeset.change(successor: row.successor)
        |> TestRepo.update!()
      end

      altered_parent = Map.put(row, :token_hash, "wrong-parent-hash")
      assert RefreshToken.to_store_record(altered_parent).successor == nil
    end

    test "modern encrypted successors reject missing or extra context members" do
      parent = entry()
      token = "context-tamper-#{System.unique_integer([:positive])}"
      child = child(parent, token)
      retry_until = 1_900_000_010
      assert :ok = EctoRefreshStore.insert(parent)

      assert {:ok, _, _} =
               EctoRefreshStore.rotate(
                 parent.token_hash,
                 child,
                 successor(child, token, retry_until),
                 now: 1_900_000_001
               )

      row = TestRepo.get_by!(RefreshToken, token_hash: parent.token_hash)

      aad =
        RefreshSuccessorCipher.binding_aad(
          parent.token_hash,
          parent.family_id,
          parent.generation,
          child.token_hash,
          retry_until
        )

      assert {:ok, decoded} = RefreshSuccessorCipher.decrypt(row.successor["ciphertext"], aad)

      for context <- [
            Map.delete(child.data, :resource),
            Map.put(child.data, :unexpected, "private")
          ] do
        tampered = Map.put(decoded, :context, context)
        assert {:ok, ciphertext} = RefreshSuccessorCipher.encrypt(tampered, aad)

        row
        |> Ecto.Changeset.change(successor: Map.put(row.successor, "ciphertext", ciphertext))
        |> TestRepo.update!()

        assert {:ok, loaded} = EctoRefreshStore.get(parent.token_hash)
        assert loaded.successor == nil
      end
    end
  end

  describe "concurrency and revocation" do
    test "does not report success when the revocation transaction rolls back" do
      Application.put_env(__MODULE__, Config, Map.put(prefix_config(nil), :repo, FailingRepo))

      assert_raise RuntimeError, ~r/revoke_family\/1 transaction failed/, fn ->
        EctoRefreshStore.revoke_family("family-with-store-failure")
      end
    end

    test "concurrent insert and revoke of an unknown family leaves a sticky marker" do
      family_id = "concurrent-unknown-family-#{System.unique_integer([:positive])}"
      candidate = entry(%{family_id: family_id})
      owner = self()

      tasks = [
        Task.async(fn ->
          Sandbox.allow(TestRepo, owner, self())
          EctoRefreshStore.insert(candidate)
        end),
        Task.async(fn ->
          Sandbox.allow(TestRepo, owner, self())
          EctoRefreshStore.revoke_family(family_id)
        end)
      ]

      results = Enum.map(tasks, &Task.await(&1, 15_000))
      assert Enum.all?(results, &(&1 in [:ok, {:error, :family_revoked}]))

      assert %RefreshFamilyRevocation{family_id: ^family_id} =
               TestRepo.get(RefreshFamilyRevocation, family_id)

      assert {:error, :family_revoked} = EctoRefreshStore.insert(entry(%{family_id: family_id}))
    end

    test "concurrent malformed child rotations serialize on the actual parent family" do
      parent = entry()
      token = "wrong-family-race-#{System.unique_integer([:positive])}"
      malicious_child = child(parent, token, %{family_id: "attacker-family"})
      malicious_successor = successor(malicious_child, token, 1_900_000_010)
      assert :ok = EctoRefreshStore.insert(parent)
      owner = self()

      tasks =
        Enum.map(1..8, fn _ ->
          Task.async(fn ->
            Sandbox.allow(TestRepo, owner, self())

            EctoRefreshStore.rotate(
              parent.token_hash,
              malicious_child,
              malicious_successor,
              now: 1_900_000_001
            )
          end)
        end) ++
          [
            Task.async(fn ->
              Sandbox.allow(TestRepo, owner, self())
              EctoRefreshStore.revoke_family(parent.family_id)
            end)
          ]

      results = Enum.map(tasks, &Task.await(&1, 15_000))

      assert Enum.all?(results, fn
               :ok -> true
               {:error, :invalid_rotation} -> true
               {:error, :family_revoked} -> true
               :error -> true
               _ -> false
             end)

      assert %RefreshFamilyRevocation{family_id: marker_family_id} =
               TestRepo.get(RefreshFamilyRevocation, parent.family_id)

      assert marker_family_id == parent.family_id

      assert :error = EctoRefreshStore.get(parent.token_hash)
      assert :error = EctoRefreshStore.get(malicious_child.token_hash)

      assert {:error, :family_revoked} =
               EctoRefreshStore.insert(entry(%{family_id: parent.family_id}))
    end

    test "concurrent matching rotations coalesce to one child" do
      parent = entry()
      token = "concurrent-#{System.unique_integer([:positive])}"
      child = child(parent, token)
      successor = successor(child, token, 1_900_000_010)
      assert :ok = EctoRefreshStore.insert(parent)
      owner = self()

      results =
        1..8
        |> Task.async_stream(
          fn _ ->
            Sandbox.allow(TestRepo, owner, self())
            EctoRefreshStore.rotate(parent.token_hash, child, successor, now: 1_900_000_001)
          end,
          max_concurrency: 8,
          timeout: 15_000
        )
        |> Enum.map(fn {:ok, result} -> result end)

      assert Enum.count(results, &match?({:ok, _, _}, &1)) == 1
      assert Enum.count(results, &match?({:reuse, _}, &1)) == 7

      assert TestRepo.aggregate(
               from(r in RefreshToken, where: r.family_id == ^parent.family_id),
               :count,
               :id
             ) == 2
    end

    test "revoke_family serializes with rotation and leaves no live family rows" do
      parent = entry()
      token = "revoke-race-#{System.unique_integer([:positive])}"
      child = child(parent, token)
      successor = successor(child, token, 1_900_000_010)
      assert :ok = EctoRefreshStore.insert(parent)
      owner = self()

      tasks = [
        Task.async(fn ->
          Sandbox.allow(TestRepo, owner, self())
          EctoRefreshStore.rotate(parent.token_hash, child, successor, now: 1_900_000_001)
        end),
        Task.async(fn ->
          Sandbox.allow(TestRepo, owner, self())
          EctoRefreshStore.revoke_family(parent.family_id)
        end)
      ]

      results = Enum.map(tasks, &Task.await(&1, 15_000))
      assert Enum.any?(results, &(&1 == :ok))

      assert TestRepo.aggregate(
               from(r in RefreshToken, where: r.family_id == ^parent.family_id),
               :count,
               :id
             ) == 0
    end
  end

  describe "prefix routing and housekeeping" do
    test "all refresh operations honor schema_prefix" do
      TestRepo.query!("CREATE SCHEMA IF NOT EXISTS auth_refresh_test")

      TestRepo.query!(
        "CREATE TABLE auth_refresh_test.attesto_refresh_tokens (LIKE public.attesto_refresh_tokens INCLUDING ALL)"
      )

      TestRepo.query!(
        "CREATE TABLE auth_refresh_test.attesto_refresh_family_revocations (LIKE public.attesto_refresh_family_revocations INCLUDING ALL)"
      )

      on_exit(fn ->
        TestRepo.query!("DROP SCHEMA IF EXISTS auth_refresh_test CASCADE")
      end)

      Config.with_request_config(prefix_config("auth_refresh_test"), fn ->
        parent = entry()
        token = "prefix-#{System.unique_integer([:positive])}"
        child = child(parent, token)
        assert :ok = EctoRefreshStore.insert(parent)

        assert {:ok, _, _} =
                 EctoRefreshStore.rotate(
                   parent.token_hash,
                   child,
                   successor(child, token, 1_900_000_010),
                   now: 1_900_000_001
                 )

        assert {:ok, _} = EctoRefreshStore.get(child.token_hash)
        assert :ok = EctoRefreshStore.revoke_family(parent.family_id)
        assert EctoRefreshStore.get(child.token_hash) == :error

        assert TestRepo.aggregate(
                 from(r in RefreshToken, where: r.family_id == ^parent.family_id),
                 :count,
                 :id
               ) == 0

        assert nil ==
                 TestRepo.one(from(r in RefreshToken, where: r.token_hash == ^parent.token_hash),
                   prefix: "auth_refresh_test"
                 )

        assert %RefreshFamilyRevocation{family_id: marker_family_id} =
                 TestRepo.get(RefreshFamilyRevocation, parent.family_id, prefix: "auth_refresh_test")

        assert marker_family_id == parent.family_id

        refute TestRepo.one(from(r in RefreshToken, where: r.token_hash == ^parent.token_hash),
                 prefix: nil
               )
      end)
    end

    test "redaction produces a tombstone with recoverable false" do
      parent = entry()
      token = "redact-#{System.unique_integer([:positive])}"
      child = child(parent, token)
      assert :ok = EctoRefreshStore.insert(parent)

      assert {:ok, _, _} =
               EctoRefreshStore.rotate(
                 parent.token_hash,
                 child,
                 successor(child, token, 1_900_000_010),
                 now: 1_900_000_001
               )

      assert 1 ==
               EctoRefreshStore.redact_expired_successors(
                 TestRepo,
                 DateTime.from_unix!(1_900_000_011),
                 legacy_grace_seconds: 0
               )

      row = TestRepo.get_by!(RefreshToken, token_hash: parent.token_hash)
      assert row.successor == %{"v" => 1, "retry_until" => 1_900_000_010, "recoverable" => false}
      assert {:ok, loaded} = EctoRefreshStore.get(parent.token_hash)
      assert loaded.successor == %{retry_until: 1_900_000_010, recoverable: false}
    end

    test "redaction never retains a successor past the consumed parent expiry" do
      parent = entry(%{expires_at: 1_900_000_005})
      token = "parent-expiry-redaction-#{System.unique_integer([:positive])}"
      child = child(parent, token, %{expires_at: 1_900_000_020})
      assert :ok = EctoRefreshStore.insert(parent)

      assert {:ok, _, _} =
               EctoRefreshStore.rotate(
                 parent.token_hash,
                 child,
                 successor(child, token, 1_900_000_010),
                 now: 1_900_000_001
               )

      encrypted_successor =
        TestRepo.get_by!(RefreshToken, token_hash: parent.token_hash).successor

      assert 1 ==
               EctoRefreshStore.redact_expired_successors(
                 TestRepo,
                 DateTime.from_unix!(1_900_000_005),
                 legacy_grace_seconds: 0
               )

      assert TestRepo.get_by!(RefreshToken, token_hash: parent.token_hash).successor == %{
               "v" => 1,
               "retry_until" => 1_900_000_004,
               "recoverable" => false
             }

      TestRepo.get_by!(RefreshToken, token_hash: parent.token_hash)
      |> Ecto.Changeset.change(successor: encrypted_successor)
      |> TestRepo.update!()

      assert 1 ==
               EctoRefreshStore.redact_expired_successors(
                 TestRepo,
                 DateTime.from_unix!(1_900_000_006),
                 legacy_grace_seconds: 0
               )

      assert TestRepo.get_by!(RefreshToken, token_hash: parent.token_hash).successor == %{
               "v" => 1,
               "retry_until" => 1_900_000_004,
               "recoverable" => false
             }
    end

    test "malformed retry deadline is redacted without a casting error" do
      parent = entry()
      token = "malformed-deadline-#{System.unique_integer([:positive])}"
      child = child(parent, token)
      assert :ok = EctoRefreshStore.insert(parent)

      assert {:ok, _, _} =
               EctoRefreshStore.rotate(
                 parent.token_hash,
                 child,
                 successor(child, token, 1_900_000_010),
                 now: 1_900_000_001
               )

      row = TestRepo.get_by!(RefreshToken, token_hash: parent.token_hash)

      row
      |> Ecto.Changeset.change(successor: Map.put(row.successor, "retry_until", "not-a-number"))
      |> TestRepo.update!()

      assert 1 ==
               EctoRefreshStore.redact_expired_successors(
                 TestRepo,
                 DateTime.from_unix!(1_900_000_011),
                 legacy_grace_seconds: 0
               )

      assert TestRepo.get_by!(RefreshToken, token_hash: parent.token_hash).successor == %{
               "v" => 1,
               "retry_until" => 1_900_000_001,
               "recoverable" => false
             }
    end

    test "adversarial retry deadlines redact encrypted state without bigint casts" do
      parent = entry()
      token = "adversarial-deadline-#{System.unique_integer([:positive])}"
      child = child(parent, token)
      assert :ok = EctoRefreshStore.insert(parent)

      assert {:ok, _, _} =
               EctoRefreshStore.rotate(
                 parent.token_hash,
                 child,
                 successor(child, token, 1_900_000_010),
                 now: 1_900_000_001
               )

      row = TestRepo.get_by!(RefreshToken, token_hash: parent.token_hash)
      wrapper = row.successor

      for bad_deadline <- [
            nil,
            Decimal.new("1.5"),
            "1900000010",
            -1,
            9_223_372_036_854_775_808,
            1.5
          ] do
        row
        |> Ecto.Changeset.change(successor: Map.put(wrapper, "retry_until", bad_deadline))
        |> TestRepo.update!()

        assert 1 ==
                 EctoRefreshStore.redact_expired_successors(
                   TestRepo,
                   DateTime.from_unix!(1_900_000_011),
                   legacy_grace_seconds: 60
                 )

        refute Map.has_key?(
                 TestRepo.get_by!(RefreshToken, token_hash: parent.token_hash).successor,
                 "ciphertext"
               )
      end
    end

    test "legacy v1 ciphertext without a deadline is redacted from consumed_at" do
      parent = entry()
      token = "legacy-redaction-#{System.unique_integer([:positive])}"
      child = child(parent, token)
      retry_successor = successor(child, token, 1_900_000_010)
      assert :ok = EctoRefreshStore.insert(parent)

      assert {:ok, _, _} =
               EctoRefreshStore.rotate(parent.token_hash, child, retry_successor, now: 1_900_000_001)

      {:ok, legacy_ciphertext} = RefreshSuccessorCipher.encrypt(retry_successor)
      row = TestRepo.get_by!(RefreshToken, token_hash: parent.token_hash)

      row
      |> Ecto.Changeset.change(successor: %{"v" => 1, "ciphertext" => legacy_ciphertext})
      |> TestRepo.update!()

      assert 1 ==
               EctoRefreshStore.redact_expired_successors(
                 TestRepo,
                 DateTime.from_unix!(1_900_000_011),
                 legacy_grace_seconds: 0
               )

      assert TestRepo.get_by!(RefreshToken, token_hash: parent.token_hash).successor == %{
               "v" => 1,
               "retry_until" => 1_900_000_001,
               "recoverable" => false
             }
    end

    test "legacy v1 ciphertext recovers within configured grace and expires at its derived deadline" do
      parent_token = "legacy-parent-#{System.unique_integer([:positive])}"
      parent = entry(%{token_hash: Attesto.Secret.hash(parent_token)})
      token = "legacy-upgrade-#{System.unique_integer([:positive])}"
      child = child(parent, token)
      legacy_successor = successor(child, token, 1_900_000_010) |> Map.delete(:retry_until)
      assert :ok = EctoRefreshStore.insert(parent)

      assert {:ok, _, _} =
               EctoRefreshStore.rotate(
                 parent.token_hash,
                 child,
                 successor(child, token, 1_900_000_010),
                 now: 1_900_000_001
               )

      {:ok, legacy_ciphertext} = RefreshSuccessorCipher.encrypt(legacy_successor)

      TestRepo.get_by!(RefreshToken, token_hash: parent.token_hash)
      |> Ecto.Changeset.change(successor: %{"v" => 1, "ciphertext" => legacy_ciphertext})
      |> TestRepo.update!()

      config = prefix_config(nil)

      Config.with_request_config(config, fn ->
        assert {:ok, loaded} = EctoRefreshStore.get(parent.token_hash)
        assert loaded.successor.retry_until == 1_900_000_061

        assert {:ok, recovered} =
                 Attesto.RefreshToken.rotate(
                   EctoRefreshStore,
                   parent_token,
                   client_id: "client-1",
                   rotation_grace_seconds: 60,
                   ttl: 60,
                   now: 1_900_000_030
                 )

        assert recovered.token == token
        assert recovered.generation == child.generation

        assert {:error, :reuse_detected} =
                 Attesto.RefreshToken.rotate(
                   EctoRefreshStore,
                   parent_token,
                   client_id: "client-1",
                   rotation_grace_seconds: 60,
                   ttl: 60,
                   now: 1_900_000_062
                 )

        assert :error = EctoRefreshStore.get(child.token_hash)
      end)
    end

    test "legacy v1 redaction clamps the retry deadline before token expiry" do
      parent = entry(%{expires_at: 1_900_000_040})
      token = "legacy-expiry-clamp-#{System.unique_integer([:positive])}"
      child = child(parent, token)
      retry_successor = successor(child, token, 1_900_000_010)
      assert :ok = EctoRefreshStore.insert(parent)

      assert {:ok, _, _} =
               EctoRefreshStore.rotate(parent.token_hash, child, retry_successor, now: 1_900_000_001)

      {:ok, legacy_ciphertext} = RefreshSuccessorCipher.encrypt(retry_successor)

      TestRepo.get_by!(RefreshToken, token_hash: parent.token_hash)
      |> Ecto.Changeset.change(successor: %{"v" => 1, "ciphertext" => legacy_ciphertext})
      |> TestRepo.update!()

      assert 0 ==
               EctoRefreshStore.redact_expired_successors(
                 TestRepo,
                 DateTime.from_unix!(1_900_000_039),
                 legacy_grace_seconds: 60
               )

      assert 1 ==
               EctoRefreshStore.redact_expired_successors(
                 TestRepo,
                 DateTime.from_unix!(1_900_000_040),
                 legacy_grace_seconds: 60
               )

      assert TestRepo.get_by!(RefreshToken, token_hash: parent.token_hash).successor == %{
               "v" => 1,
               "retry_until" => 1_900_000_039,
               "recoverable" => false
             }
    end

    test "malformed legacy state with a pre-epoch parent gets a non-negative tombstone" do
      parent = entry()
      token = "legacy-pre-epoch-#{System.unique_integer([:positive])}"
      child = child(parent, token, %{expires_at: 1_900_000_020})
      retry_successor = successor(child, token, 1_900_000_010) |> Map.delete(:retry_until)
      assert :ok = EctoRefreshStore.insert(parent)

      {:ok, legacy_ciphertext} = RefreshSuccessorCipher.encrypt(retry_successor)

      TestRepo.get_by!(RefreshToken, token_hash: parent.token_hash)
      |> Ecto.Changeset.change(
        consumed: true,
        consumed_at: DateTime.from_unix!(0),
        expires_at: DateTime.from_unix!(-1),
        successor: %{"v" => 1, "ciphertext" => legacy_ciphertext}
      )
      |> TestRepo.update!()

      assert 1 ==
               EctoRefreshStore.redact_expired_successors(TestRepo, DateTime.from_unix!(2), legacy_grace_seconds: 60)

      assert TestRepo.get_by!(RefreshToken, token_hash: parent.token_hash).successor == %{
               "v" => 1,
               "retry_until" => 0,
               "recoverable" => false
             }
    end
  end
end
