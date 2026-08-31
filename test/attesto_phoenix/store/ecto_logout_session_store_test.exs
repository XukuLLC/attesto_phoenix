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

  alias AttestoPhoenix.Store.EctoLogoutSessionStore, as: Store

  @moduletag :ecto

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

  test "record + targets by sid returns the RP" do
    e = record(%{sid: "s1", client_id: "rp-a", session_required: true})

    assert [target] = Store.targets(%{sid: "s1"})
    assert target.client_id == "rp-a"
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
