defmodule AttestoPhoenix.Store.EctoLogoutSessionStoreTest do
  @moduledoc """
  Behaviour conformance tests for the Ecto-backed Back-Channel Logout session
  store (OpenID Connect Back-Channel Logout 1.0).

  The load-bearing properties are: `record/1` upserts on `(sid, client_id)`,
  `targets/1` scopes by sid (one session) or subject (all sessions) and drops
  expired rows, and `delete/1` clears the matched rows.

  Tagged `:ecto` so the suite runs only when a SQL backend is available.
  """

  use AttestoPhoenix.DataCase, async: false

  import ExUnit.CaptureLog

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Schema.LogoutSession
  alias AttestoPhoenix.Store.EctoLogoutSessionStore, as: Store

  @moduletag :ecto

  defmodule Keystore do
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem, do: "test-pem"

    @impl true
    def verification_pems, do: [signing_pem()]
  end

  defp record(overrides) do
    now = System.system_time(:second)

    entry =
      Map.merge(
        %{
          sid: "sid-#{System.unique_integer([:positive])}",
          subject: "usr-1",
          client_id: "cli-#{System.unique_integer([:positive])}",
          backchannel_logout_uri: "https://rp.example/bc",
          session_required: false,
          expires_at: now + 3600
        },
        overrides
      )

    :ok = Store.record(entry)
    entry
  end

  defp retry_config(initial, maximum) do
    Config.new(
      issuer: "https://issuer.example",
      audience: "https://api.example",
      keystore: Keystore,
      repo: TestRepo,
      load_client: fn _client_id -> {:error, :not_found} end,
      verify_client_secret: fn _client, _secret -> false end,
      load_principal: fn _subject -> {:error, :not_found} end,
      logout_session_store: Store,
      sweep_interval_ms: 1_000,
      terminate_session: fn conn, _context -> {:ok, conn} end,
      logout: [
        enabled: true,
        retry_initial_delay_seconds: initial,
        retry_max_delay_seconds: maximum
      ]
    )
  end

  defp row!(sid), do: TestRepo.get_by!(LogoutSession, sid: sid)

  test "record + targets by sid returns the RP" do
    e = record(%{sid: "s1", client_id: "rp-a", session_required: true})

    assert [target] = Store.targets(%{sid: "s1"})
    assert target.client_id == "rp-a"
    assert is_binary(target.delivery_id)
    assert byte_size(target.delivery_id) >= 32
    assert target.backchannel_logout_uri == e.backchannel_logout_uri
    assert target.sid == "s1"
    assert target.session_required == true
  end

  test "record is idempotent on (sid, client_id)" do
    record(%{sid: "s2", client_id: "rp-a", backchannel_logout_uri: "https://rp.example/old"})
    record(%{sid: "s2", client_id: "rp-a", backchannel_logout_uri: "https://rp.example/new"})

    assert [target] = Store.targets(%{sid: "s2"})
    assert target.backchannel_logout_uri == "https://rp.example/new"
  end

  test "round-trips the front-channel fields (Front-Channel Logout 1.0 §2)" do
    record(%{
      sid: "s-fc",
      client_id: "rp-fc",
      frontchannel_logout_uri: "https://rp.example/fc",
      frontchannel_session_required: true
    })

    assert [target] = Store.targets(%{sid: "s-fc"})
    assert target.frontchannel_logout_uri == "https://rp.example/fc"
    assert target.frontchannel_session_required == true
    assert target.backchannel_logout_uri == "https://rp.example/bc"
  end

  test "a front-channel-only record needs no backchannel_logout_uri" do
    now = System.system_time(:second)

    :ok =
      Store.record(%{
        sid: "s-fc-only",
        subject: "usr-1",
        client_id: "rp-fc-only",
        frontchannel_logout_uri: "https://rp.example/fc",
        expires_at: now + 3600
      })

    assert [target] = Store.targets(%{sid: "s-fc-only"})
    assert target.backchannel_logout_uri == nil
    assert target.frontchannel_logout_uri == "https://rp.example/fc"
    assert target.frontchannel_session_required == false
  end

  test "an upsert can drop one channel and add the other" do
    record(%{sid: "s-swap", client_id: "rp-swap"})

    now = System.system_time(:second)

    :ok =
      Store.record(%{
        sid: "s-swap",
        subject: "usr-1",
        client_id: "rp-swap",
        backchannel_logout_uri: nil,
        frontchannel_logout_uri: "https://rp.example/fc",
        expires_at: now + 3600
      })

    assert [target] = Store.targets(%{sid: "s-swap"})
    assert target.backchannel_logout_uri == nil
    assert target.frontchannel_logout_uri == "https://rp.example/fc"
  end

  test "a record with neither logout URI is refused (nothing to notify)" do
    now = System.system_time(:second)

    assert_raise Ecto.InvalidChangesetError, fn ->
      Store.record(%{
        sid: "s-none",
        subject: "usr-1",
        client_id: "rp-none",
        backchannel_logout_uri: nil,
        expires_at: now + 3600
      })
    end

    assert [] = Store.targets(%{sid: "s-none"})
  end

  test "targets by sid spans every RP holding that session" do
    record(%{sid: "s3", client_id: "rp-a"})
    record(%{sid: "s3", client_id: "rp-b"})

    targets = Store.targets(%{sid: "s3"})
    assert MapSet.new(Enum.map(targets, & &1.client_id)) == MapSet.new(["rp-a", "rp-b"])
  end

  test "targets by subject spans every session for that subject" do
    record(%{subject: "usr-multi", sid: "s4", client_id: "rp-a"})
    record(%{subject: "usr-multi", sid: "s5", client_id: "rp-b"})

    targets = Store.targets(%{subject: "usr-multi"})
    assert length(targets) == 2
  end

  test "sid takes precedence over subject when both are given" do
    record(%{subject: "usr-prec", sid: "s6", client_id: "rp-a"})
    record(%{subject: "usr-prec", sid: "s7", client_id: "rp-b"})

    # sid scopes to the one session even though the subject has two.
    assert [target] = Store.targets(%{sid: "s6", subject: "usr-prec"})
    assert target.client_id == "rp-a"
  end

  test "expired rows are not returned" do
    now = System.system_time(:second)
    record(%{sid: "s8", client_id: "rp-a", expires_at: now - 1})

    assert [] = Store.targets(%{sid: "s8"})
  end

  test "delete by sid clears the session" do
    record(%{sid: "s9", client_id: "rp-a"})
    record(%{sid: "s9", client_id: "rp-b"})

    assert :ok = Store.delete(%{sid: "s9"})
    assert [] = Store.targets(%{sid: "s9"})
  end

  test "delete by subject clears all of the subject's sessions" do
    record(%{subject: "usr-del", sid: "s10", client_id: "rp-a"})
    record(%{subject: "usr-del", sid: "s11", client_id: "rp-b"})

    assert :ok = Store.delete(%{subject: "usr-del"})
    assert [] = Store.targets(%{subject: "usr-del"})
  end

  test "empty criteria match nothing (no accidental global logout)" do
    record(%{sid: "s12", client_id: "rp-a"})

    assert [] = Store.targets(%{})
    assert :ok = Store.delete(%{})
    # the unrelated row survives
    assert [_] = Store.targets(%{sid: "s12"})
  end

  describe "take_targets/1 (atomic enumerate-and-delete)" do
    test "returns the targets AND removes them in one call" do
      record(%{sid: "t1", client_id: "rp-a"})
      record(%{sid: "t1", client_id: "rp-b"})

      taken = Store.take_targets(%{sid: "t1"})
      assert MapSet.new(Enum.map(taken, & &1.client_id)) == MapSet.new(["rp-a", "rp-b"])

      # gone after the take — a second take yields nothing (no double-delivery)
      assert [] = Store.take_targets(%{sid: "t1"})
      assert [] = Store.targets(%{sid: "t1"})
    end

    test "ignores expired rows" do
      now = System.system_time(:second)
      record(%{sid: "t2", client_id: "rp-a", expires_at: now - 1})
      assert [] = Store.take_targets(%{sid: "t2"})
    end

    test "empty criteria take nothing" do
      record(%{sid: "t3", client_id: "rp-a"})
      assert [] = Store.take_targets(%{})
      assert [_] = Store.targets(%{sid: "t3"})
    end
  end

  describe "delivery leases" do
    test "release applies bounded exponential backoff before work becomes available" do
      record(%{sid: "lease-1", client_id: "rp-a"})
      now = System.system_time(:second)
      config = retry_config(2, 4)

      assert [target] = Store.lease_targets(%{sid: "lease-1"}, "worker-a", now, now + 60)
      assert [] = Store.lease_targets(%{sid: "lease-1"}, "worker-b", now, now + 60)

      released_at = System.system_time(:second)

      assert :ok =
               Config.with_request_config(config, fn ->
                 Store.release_targets("worker-a", [target.delivery_id])
               end)

      first_release = row!("lease-1")
      first_retry_at = DateTime.to_unix(first_release.lease_expires_at)
      assert first_release.delivery_attempts == 1
      assert (first_retry_at - released_at) in 2..3
      assert [] = Store.lease_targets(%{sid: "lease-1"}, "worker-b", first_retry_at - 1, first_retry_at + 59)

      assert [retried] =
               Store.lease_targets(%{sid: "lease-1"}, "worker-b", first_retry_at, first_retry_at + 60)

      assert retried.delivery_id == target.delivery_id

      released_again_at = System.system_time(:second)

      assert :ok =
               Config.with_request_config(config, fn ->
                 Store.release_targets("worker-b", [target.delivery_id])
               end)

      second_release = row!("lease-1")
      second_retry_at = DateTime.to_unix(second_release.lease_expires_at)
      assert second_release.delivery_attempts == 2
      assert (second_retry_at - released_again_at) in 4..5

      assert [retried_again] =
               Store.lease_targets(%{sid: "lease-1"}, "worker-c", second_retry_at, second_retry_at + 60)

      capped_released_at = System.system_time(:second)

      assert :ok =
               Config.with_request_config(config, fn ->
                 Store.release_targets("worker-c", [retried_again.delivery_id])
               end)

      capped_release = row!("lease-1")
      assert capped_release.delivery_attempts == 3
      assert (DateTime.to_unix(capped_release.lease_expires_at) - capped_released_at) in 4..5

      retry_at = DateTime.to_unix(capped_release.lease_expires_at)
      assert [final] = Store.lease_targets(%{sid: "lease-1"}, "worker-final", retry_at, retry_at + 60)
      assert :ok = Store.acknowledge_targets("worker-final", [final.delivery_id])
      assert [] = Store.targets(%{sid: "lease-1"})
    end

    test "legacy list and delete callbacks cannot disturb an active lease" do
      record(%{sid: "lease-legacy", client_id: "rp-a"})
      now = System.system_time(:second)

      assert [target] = Store.lease_targets(%{sid: "lease-legacy"}, "worker-a", now, now + 60)
      assert [] = Store.targets(%{sid: "lease-legacy"})
      assert :ok = Store.delete(%{sid: "lease-legacy"})

      assert :ok = Store.acknowledge_targets("worker-a", [target.delivery_id])
      assert [] = Store.targets(%{sid: "lease-legacy"})
    end

    test "an expired lease is reclaimable and stale workers cannot delete or unlock it" do
      record(%{sid: "lease-expired", client_id: "rp-a"})

      assert [target] =
               Store.lease_targets(%{sid: "lease-expired"}, "worker-old", 1_000, 1_010)

      assert [reclaimed] =
               Store.lease_targets(%{sid: "lease-expired"}, "worker-new", 1_011, 1_071)

      assert reclaimed.delivery_id == target.delivery_id
      assert :ok = Store.acknowledge_targets("worker-old", [target.delivery_id])
      assert :ok = Store.release_targets("worker-old", [target.delivery_id])
      assert [] = Store.lease_targets(%{sid: "lease-expired"}, "worker-third", 1_012, 1_072)

      assert :ok = Store.acknowledge_targets("worker-new", [target.delivery_id])
      assert [] = Store.targets(%{sid: "lease-expired"})
    end

    test "background retry leases only previously claimed back-channel work" do
      record(%{sid: "retry-pending", subject: "retry-user", client_id: "rp-a"})
      now = System.system_time(:second)

      assert [] =
               Store.lease_retry_targets(
                 AttestoPhoenix.TestRepo,
                 nil,
                 "retry-before-logout",
                 now,
                 now + 60,
                 100
               )

      assert [leased] = Store.lease_targets(%{sid: "retry-pending"}, "worker-a", now, now + 60)
      assert :ok = Store.release_targets("worker-a", [leased.delivery_id])
      retry_now = row!("retry-pending").lease_expires_at |> DateTime.to_unix()

      assert [retried] =
               Store.lease_retry_targets(
                 AttestoPhoenix.TestRepo,
                 nil,
                 "retry-worker",
                 retry_now,
                 retry_now + 60,
                 100
               )

      assert retried.delivery_id == leased.delivery_id
      assert retried.subject == "retry-user"
    end

    test "a released marker protects work from the stale worker that released it" do
      record(%{sid: "retry-stale", client_id: "rp-a"})
      now = System.system_time(:second)

      assert [target] = Store.lease_targets(%{sid: "retry-stale"}, "worker-a", now, now + 60)
      assert :ok = Store.release_targets("worker-a", [target.delivery_id])
      assert :ok = Store.acknowledge_targets("worker-a", [target.delivery_id])
      survivor = row!("retry-stale")
      assert survivor.delivery_id == target.delivery_id
    end

    test "background retry reclaims an expired crashed-worker lease but not an active one" do
      record(%{sid: "retry-crash", client_id: "rp-a"})

      assert [target] = Store.lease_targets(%{sid: "retry-crash"}, "crashed-worker", 1_000, 1_010)

      assert [] =
               Store.lease_retry_targets(
                 AttestoPhoenix.TestRepo,
                 nil,
                 "retry-too-early",
                 1_009,
                 1_069,
                 100
               )

      assert [retried] =
               Store.lease_retry_targets(
                 AttestoPhoenix.TestRepo,
                 nil,
                 "retry-after-expiry",
                 1_011,
                 1_071,
                 100
               )

      assert retried.delivery_id == target.delivery_id
    end

    test "concurrent workers never receive the same delivery" do
      record(%{sid: "lease-race", client_id: "rp-a"})
      now = System.system_time(:second)

      results =
        1..8
        |> Task.async_stream(
          fn worker ->
            Store.lease_targets(%{sid: "lease-race"}, "worker-#{worker}", now, now + 60)
          end,
          max_concurrency: 8,
          ordered: false
        )
        |> Enum.flat_map(fn {:ok, targets} -> targets end)

      assert [target] = results
      assert is_binary(target.delivery_id)
    end

    test "upserting a leased session rotates its delivery id so a stale acknowledgement is harmless" do
      record(%{sid: "lease-upsert", client_id: "rp-a", backchannel_logout_uri: "https://rp.example/old"})
      now = System.system_time(:second)

      assert [old] = Store.lease_targets(%{sid: "lease-upsert"}, "worker-old", now, now + 60)

      record(%{sid: "lease-upsert", client_id: "rp-a", backchannel_logout_uri: "https://rp.example/new"})
      assert [fresh] = Store.lease_targets(%{sid: "lease-upsert"}, "worker-new", now, now + 60)
      refute fresh.delivery_id == old.delivery_id

      assert :ok = Store.acknowledge_targets("worker-old", [old.delivery_id])
      assert :ok = Store.release_targets("worker-new", [fresh.delivery_id])
      survivor = row!("lease-upsert")
      assert survivor.delivery_id == fresh.delivery_id
      assert survivor.backchannel_logout_uri == "https://rp.example/new"
    end
  end

  test "query telemetry is suppressed for session identifiers and logout targets" do
    capture = AttestoPhoenix.TestTelemetryCapture.attach(TestRepo)
    on_exit(fn -> AttestoPhoenix.TestTelemetryCapture.detach(capture) end)
    {_id, ref} = capture

    e = %{
      sid: "private-session-id",
      subject: "private-subject",
      client_id: "private-client-id",
      backchannel_logout_uri: "https://private.example/logout",
      session_required: false,
      expires_at: System.system_time(:second) + 3600
    }

    log =
      capture_log([level: :debug], fn ->
        assert :ok = Store.record(e)
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
        assert [target] = Store.targets(%{sid: e.sid})
        assert target.sid == e.sid
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
        assert :ok = Store.delete(%{sid: e.sid})
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
      end)

    refute log =~ e.sid
    refute log =~ e.subject
    refute log =~ e.client_id
    refute log =~ e.backchannel_logout_uri
  end
end
