defmodule AttestoPhoenix.Store.EctoCIBAStoreTest do
  @moduledoc """
  Behaviour-conformance tests for the Ecto-backed CIBA authentication-request
  store (OpenID Connect CIBA Core 1.0), mirroring the device-code store tests:
  each state transition is a single guarded atomic statement, so approve/deny
  land exactly once, consume is single-use, and poll enforces the per-row §7.3
  interval.
  """

  use AttestoPhoenix.DataCase, async: false

  import ExUnit.CaptureLog

  alias Attesto.CIBA
  alias Attesto.CIBA.Grant
  alias Attesto.CIBA.Request
  alias AttestoPhoenix.Schema.CIBARequest
  alias AttestoPhoenix.Store.EctoCIBAStore, as: Store

  @moduletag :ecto

  defp put(overrides \\ %{}) do
    now = System.system_time(:second)

    record =
      Map.merge(
        %{
          auth_req_id_hash: "arh-#{System.unique_integer([:positive])}",
          data: %{
            acr_values: [],
            binding_message: nil,
            client_id: "cli-1",
            client_notification_token: nil,
            delivery_mode: :poll,
            dpop_jkt: nil,
            resource: [],
            scope: ["openid"],
            subject: "user:alice"
          },
          status: :pending,
          interval: 0,
          expires_at: now + 120,
          last_polled_at: nil
        },
        overrides
      )

    :ok = Store.put(record)
    record
  end

  defp nested_claims(0), do: %{}
  defp nested_claims(depth), do: %{"nested" => nested_claims(depth - 1)}

  test "put + lookup returns the pending entry with the frozen data" do
    r = put(%{data: put_data(scope: ["openid", "profile"], delivery_mode: :ping, client_notification_token: "cnt")})

    assert {:ok, entry} = Store.lookup(r.auth_req_id_hash)
    assert entry.status == :pending
    assert entry.data.client_id == "cli-1"
    assert entry.data.scope == ["openid", "profile"]
    assert entry.data.delivery_mode == :ping
    assert entry.data.client_notification_token == "cnt"
    assert entry.data.subject == "user:alice"
  end

  test "core issue, approve, and redeem round-trip through the Ecto read bridge" do
    now = System.system_time(:second)

    request = %Request{
      client_id: "cli-1",
      delivery_mode: :poll,
      hint: {:login_hint, "user:alice"},
      scope: ["openid"]
    }

    assert {:ok, %{auth_req_id: auth_req_id}} =
             CIBA.issue(Store, request, %{subject: "user:alice"}, now: now, interval: 1)

    assert {:ok, _decision} = CIBA.approve(Store, auth_req_id, %{subject: "user:alice"}, now: now)

    assert {:ok, %Grant{client_id: "cli-1", subject: "user:alice", scope: ["openid"]}} =
             CIBA.redeem(Store, auth_req_id, %{client_id: "cli-1"}, now: now)
  end

  test "put rejects an extra canonical data key before database projection" do
    assert_raise ArgumentError, "CIBA request has invalid canonical data", fn ->
      record = put_record()
      Store.put(Map.put(record, :data, Map.put(Map.fetch!(record, :data), :adapter_metadata, "not protocol data")))
    end
  end

  test "lookup of an unknown hash is :error" do
    assert :error = Store.lookup("nope")
  end

  test "approve transitions pending->approved exactly once, binding the auth context" do
    r = put()
    now = System.system_time(:second)

    assert {:ok, entry} =
             Store.approve(
               r.auth_req_id_hash,
               %{
                 subject: "user:alice",
                 acr: "silver",
                 auth_time: now,
                 granted_scope: ["openid"],
                 granted_claims: %{"k" => "v"}
               },
               %{now: now}
             )

    assert entry.status == :approved
    assert entry.subject == "user:alice"
    assert entry.acr == "silver"
    assert entry.granted_scope == ["openid"]
    assert entry.granted_claims == %{"k" => "v"}

    assert {:error, :already_decided} = Store.approve(r.auth_req_id_hash, %{subject: "user:alice"}, %{})
    assert {:error, :already_decided} = Store.deny(r.auth_req_id_hash, %{})
  end

  test "approve preserves portable nested claims at the JSON boundary" do
    r = put()

    claims = %{
      "nested" => %{
        "minimum" => -9_007_199_254_740_991,
        "maximum" => 9_007_199_254_740_991,
        "values" => [nil, false, "text", %{"leaf" => 42}]
      }
    }

    assert {:ok, approved} =
             Store.approve(
               r.auth_req_id_hash,
               %{
                 subject: "user:alice",
                 acr: "silver",
                 auth_time: System.system_time(:second),
                 granted_scope: ["openid"],
                 granted_claims: claims
               },
               %{now: System.system_time(:second)}
             )

    assert approved.status == :approved
    assert approved.granted_claims == claims
    assert {:ok, loaded} = Store.lookup(r.auth_req_id_hash)
    assert loaded.granted_claims == claims
  end

  test "approve rejects non-portable claims before updating the pending row" do
    invalid_claims = [
      %{atom_key: "value"},
      %{"nested" => %{atom_key: "value"}},
      %{"float" => 1.5},
      %{"nul" => "a\0b"},
      %{"large" => 9_007_199_254_740_992},
      nested_claims(64)
    ]

    Enum.each(invalid_claims, fn claims ->
      r = put()

      assert_raise ArgumentError, "CIBA approval has invalid granted claims", fn ->
        Store.approve(
          r.auth_req_id_hash,
          %{subject: "user:alice", granted_claims: claims},
          %{now: System.system_time(:second)}
        )
      end

      assert {:ok, entry} = Store.lookup(r.auth_req_id_hash)
      assert entry.status == :pending
      assert entry.subject == nil
      assert entry.granted_claims == nil
    end)
  end

  test "deny transitions pending->denied" do
    r = put()
    assert {:ok, entry} = Store.deny(r.auth_req_id_hash, %{})
    assert entry.status == :denied
  end

  test "an unknown hash is not_found on approve/deny" do
    assert {:error, :not_found} = Store.approve("nope", %{subject: "user:alice"}, %{})
    assert {:error, :not_found} = Store.deny("nope", %{})
  end

  test "a decision on an expired pending request is refused as :expired" do
    now = System.system_time(:second)
    r = put(%{expires_at: now - 1})

    assert {:error, :expired} = Store.approve(r.auth_req_id_hash, %{subject: "user:alice"}, %{now: now})
    assert {:error, :expired} = Store.deny(r.auth_req_id_hash, %{now: now})
  end

  test "consume transitions approved->consumed exactly once" do
    r = put()
    now = System.system_time(:second)
    {:ok, _} = Store.approve(r.auth_req_id_hash, %{subject: "user:alice"}, %{now: now})

    assert {:ok, entry} = Store.consume(r.auth_req_id_hash, %{now: now})
    assert entry.status == :consumed
    assert :error = Store.consume(r.auth_req_id_hash, %{now: now})
  end

  test "consume refuses a non-approved request" do
    r = put()
    assert :error = Store.consume(r.auth_req_id_hash, %{now: System.system_time(:second)})
  end

  test "poll enforces the per-row §7.3 interval and distinguishes unknown from slow_down" do
    now = System.system_time(:second)
    r = put(%{interval: 5, last_polled_at: nil})

    assert {:ok, _} = Store.poll(r.auth_req_id_hash, %{now: now})
    assert {:error, :slow_down} = Store.poll(r.auth_req_id_hash, %{now: now + 1})
    assert {:ok, _} = Store.poll(r.auth_req_id_hash, %{now: now + 6})
    assert :error = Store.poll("never-issued", %{now: now})
  end

  test "poll with interval 0 accepts every poll" do
    now = System.system_time(:second)
    r = put(%{interval: 0})

    assert {:ok, _} = Store.poll(r.auth_req_id_hash, %{now: now})
    assert {:ok, _} = Store.poll(r.auth_req_id_hash, %{now: now})
  end

  test "query telemetry is suppressed for notification-token writes and full-row transitions" do
    capture = AttestoPhoenix.TestTelemetryCapture.attach(TestRepo)
    on_exit(fn -> AttestoPhoenix.TestTelemetryCapture.detach(capture) end)
    {_id, ref} = capture

    assert is_integer(TestRepo.aggregate(CIBARequest, :count, :auth_req_id_hash))
    assert AttestoPhoenix.TestTelemetryCapture.collect(ref) != []

    now = System.system_time(:second)

    r = %{
      auth_req_id_hash: "telemetry-ciba-#{System.unique_integer([:positive])}",
      data: put_data(delivery_mode: :ping, client_notification_token: "notification-token-secret"),
      status: :pending,
      interval: 5,
      expires_at: now + 120,
      last_polled_at: nil
    }

    log =
      capture_log([level: :debug], fn ->
        assert :ok = Store.put(r)
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
        assert {:ok, _} = Store.lookup(r.auth_req_id_hash)
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
        assert {:ok, _} = Store.poll(r.auth_req_id_hash, %{now: now})
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
        assert {:error, :slow_down} = Store.poll(r.auth_req_id_hash, %{now: now + 1})
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
        assert :error = Store.poll("telemetry-ciba-missing", %{now: now})
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
        assert {:ok, _} = Store.approve(r.auth_req_id_hash, %{subject: "user:alice"}, %{now: now})
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
        assert {:error, :already_decided} = Store.deny(r.auth_req_id_hash, %{now: now})
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
        assert {:ok, _} = Store.consume(r.auth_req_id_hash, %{now: now})
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
      end)

    refute log =~ "notification-token-secret"
  end

  defp put_data(overrides) do
    Map.merge(
      %{
        acr_values: [],
        binding_message: nil,
        client_id: "cli-1",
        client_notification_token: nil,
        delivery_mode: :poll,
        dpop_jkt: nil,
        resource: [],
        scope: ["openid"],
        subject: "user:alice"
      },
      Map.new(overrides)
    )
  end

  defp put_record do
    %{
      auth_req_id_hash: "arh-#{System.unique_integer([:positive])}",
      data: put_data(%{}),
      status: :pending,
      interval: 0,
      expires_at: System.system_time(:second) + 120,
      last_polled_at: nil
    }
  end
end
