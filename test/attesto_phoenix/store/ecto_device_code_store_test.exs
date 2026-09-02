defmodule AttestoPhoenix.Store.EctoDeviceCodeStoreTest do
  @moduledoc """
  Behaviour conformance tests for the Ecto-backed device-code store (RFC 8628).

  The load-bearing properties are the atomic, state-guarded transitions: a
  pending code is approved/denied exactly once, an approved code is consumed
  exactly once, and the §3.5 poll interval is enforced in one statement.

  Tagged `:ecto` so the suite runs only when a SQL backend is available.
  """

  use AttestoPhoenix.DataCase, async: false

  import ExUnit.CaptureLog

  alias Attesto.DeviceCode
  alias Attesto.DeviceCode.Grant
  alias AttestoPhoenix.Store.EctoDeviceCodeStore, as: Store

  @moduletag :ecto
  @user_code_alphabet ~c"BCDFGHJKLMNPQRSTVWXZ"

  defp put(overrides \\ %{}) do
    now = System.system_time(:second)

    record =
      Map.merge(
        %{
          device_code_hash: "dch-#{System.unique_integer([:positive])}",
          user_code: unique_user_code(),
          data: %{client_id: "cli-1", scope: ["read"], resource: [], dpop_jkt: nil},
          status: :pending,
          expires_at: now + 600,
          last_polled_at: nil
        },
        overrides
      )

    :ok = Store.put(record)
    record
  end

  defp nested_claims(0), do: %{}
  defp nested_claims(depth), do: %{"nested" => nested_claims(depth - 1)}

  defp unique_user_code do
    System.unique_integer([:positive, :monotonic])
    |> user_code_for()
  end

  defp user_code_for(value) do
    value
    |> Integer.digits(20)
    |> Enum.map(fn digit -> Enum.at(@user_code_alphabet, digit) end)
    |> to_string()
    |> String.pad_leading(8, "B")
  end

  test "test user codes are unique and use the database-safe alphabet" do
    codes = Enum.map(1..1_000, &user_code_for/1)

    assert length(codes) == length(Enum.uniq(codes))

    assert Enum.all?(codes, fn code ->
             String.length(code) >= 8 and
               Enum.all?(String.to_charlist(code), &(&1 in @user_code_alphabet))
           end)
  end

  test "put + lookup_user_code returns the full entry" do
    r = put(%{data: %{client_id: "cli-1", scope: ["a", "b"], resource: ["https://x/r"], dpop_jkt: nil}})
    assert {:ok, entry} = Store.lookup_user_code(r.user_code)
    assert entry.device_code_hash == r.device_code_hash
    assert entry.user_code == r.user_code
    assert entry.data.client_id == "cli-1"
    assert entry.data.scope == ["a", "b"]
    assert entry.data.resource == ["https://x/r"]
    assert entry.status == :pending
    assert {:ok, ^entry} = Store.get(r.device_code_hash)
  end

  test "core issue, approve, and redeem round-trip through the Ecto read bridge" do
    now = System.system_time(:second)

    assert {:ok, %{device_code: device_code, user_code: user_code}} =
             DeviceCode.issue(Store, %{client_id: "cli-1", scope: ["read"]}, now: now, ttl: 600)

    assert {:ok, _view} = DeviceCode.lookup(Store, user_code)

    assert :ok =
             DeviceCode.approve(
               Store,
               user_code,
               %{subject: "user:alice", scope: ["read"], claims: %{}},
               now: now
             )

    assert {:ok, %Grant{client_id: "cli-1", subject: "user:alice", scope: ["read"]}} =
             DeviceCode.redeem(Store, device_code, %{client_id: "cli-1"}, now: now, interval: 0)
  end

  test "put rejects an extra canonical data key before database projection" do
    assert_raise ArgumentError, "device code has invalid canonical data", fn ->
      put(%{
        data: %{client_id: "cli-1", scope: ["read"], resource: [], dpop_jkt: nil, adapter_metadata: "not protocol data"}
      })
    end
  end

  test "approve transitions pending->approved exactly once" do
    r = put()
    now = System.system_time(:second)

    assert {:ok, approved} =
             Store.approve(
               r.user_code,
               %{subject: "usr_1", granted_scope: ["read"], granted_claims: %{"k" => "v"}},
               %{now: now}
             )

    assert approved.status == :approved
    assert approved.subject == "usr_1"
    assert approved.granted_scope == ["read"]
    assert approved.granted_claims == %{"k" => "v"}
    # A second decision is refused.
    assert {:error, :already_decided} = Store.approve(r.user_code, %{subject: "usr_2"}, %{now: now})
    assert {:error, :already_decided} = Store.deny(r.user_code, %{now: now})

    {:ok, entry} = Store.poll(r.device_code_hash, %{now: now, interval: 0})
    assert entry.status == :approved
    assert entry.subject == "usr_1"
    assert entry.granted_scope == ["read"]
    assert entry.granted_claims == %{"k" => "v"}
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
               r.user_code,
               %{subject: "usr_1", granted_scope: ["read"], granted_claims: claims},
               %{now: System.system_time(:second)}
             )

    assert approved.status == :approved
    assert approved.granted_claims == claims
    assert {:ok, loaded} = Store.lookup_user_code(r.user_code)
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

      assert_raise ArgumentError, "device-code approval has invalid granted claims", fn ->
        Store.approve(
          r.user_code,
          %{subject: "usr_1", granted_scope: ["read"], granted_claims: claims},
          %{now: System.system_time(:second)}
        )
      end

      assert {:ok, entry} = Store.lookup_user_code(r.user_code)
      assert entry.status == :pending
      assert entry.subject == nil
      assert entry.granted_claims == nil
    end)
  end

  test "deny transitions pending->denied" do
    r = put()
    now = System.system_time(:second)
    assert {:ok, denied} = Store.deny(r.user_code, %{now: now})
    assert denied.status == :denied
    {:ok, entry} = Store.poll(r.device_code_hash, %{now: now, interval: 0})
    assert entry.status == :denied
  end

  test "an unknown user_code is not_found" do
    assert {:error, :not_found} = Store.approve("NOSUCH", %{subject: "usr_1"}, %{now: System.system_time(:second)})
  end

  test "approve refuses an expired pending code" do
    r = put(%{expires_at: System.system_time(:second) - 1})

    assert {:error, :expired} =
             Store.approve(r.user_code, %{subject: "usr_1"}, %{now: System.system_time(:second)})

    assert {:error, :expired} = Store.deny(r.user_code, %{now: System.system_time(:second)})
  end

  test "consume transitions approved->consumed exactly once" do
    r = put()
    assert {:ok, _approved} = Store.approve(r.user_code, %{subject: "usr_1"}, %{now: System.system_time(:second)})

    assert {:ok, entry} = Store.consume(r.device_code_hash, %{})
    assert entry.status == :consumed
    # Second consume loses.
    assert :error = Store.consume(r.device_code_hash, %{})
  end

  test "consume refuses a non-approved code" do
    r = put()
    assert :error = Store.consume(r.device_code_hash, %{})
  end

  test "poll enforces the §3.5 interval and distinguishes unknown from slow_down" do
    now = System.system_time(:second)
    r = put(%{last_polled_at: nil})

    # First poll accepted (nil last_polled_at).
    assert {:ok, _} = Store.poll(r.device_code_hash, %{now: now, interval: 5})
    # Within the interval → slow_down.
    assert {:error, :slow_down} = Store.poll(r.device_code_hash, %{now: now + 1, interval: 5})
    # After the interval → accepted.
    assert {:ok, _} = Store.poll(r.device_code_hash, %{now: now + 6, interval: 5})
    # Unknown device code → :error (not slow_down).
    assert :error = Store.poll("never-issued", %{now: now, interval: 5})
  end

  test "query telemetry is suppressed for device user-code and full-row operations" do
    capture = AttestoPhoenix.TestTelemetryCapture.attach(TestRepo)
    on_exit(fn -> AttestoPhoenix.TestTelemetryCapture.detach(capture) end)
    {_id, ref} = capture

    assert is_integer(TestRepo.aggregate(AttestoPhoenix.Schema.DeviceCode, :count, :device_code_hash))
    assert AttestoPhoenix.TestTelemetryCapture.collect(ref) != []

    now = System.system_time(:second)

    r = %{
      device_code_hash: "telemetry-device-#{System.unique_integer([:positive])}",
      user_code: unique_user_code(),
      data: %{client_id: "cli-1", scope: ["read"], resource: [], dpop_jkt: nil},
      status: :pending,
      expires_at: now + 600,
      last_polled_at: nil
    }

    log =
      capture_log([level: :debug], fn ->
        assert :ok = Store.put(r)
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
        assert {:ok, _} = Store.lookup_user_code(r.user_code)
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
        assert {:ok, _} = Store.get(r.device_code_hash)
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
        assert {:ok, _} = Store.poll(r.device_code_hash, %{now: now, interval: 0})
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
        assert {:error, :slow_down} = Store.poll(r.device_code_hash, %{now: now + 1, interval: 5})
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
        assert :error = Store.poll("telemetry-device-missing", %{now: now, interval: 5})
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []

        assert {:ok, _} =
                 Store.approve(
                   r.user_code,
                   %{subject: "user:alice", granted_scope: ["read"], granted_claims: %{}},
                   %{now: now}
                 )

        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
        assert {:error, :already_decided} = Store.deny(r.user_code, %{now: now})
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
        assert {:ok, _} = Store.consume(r.device_code_hash, %{now: now})
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
      end)

    refute log =~ r.user_code
  end
end
