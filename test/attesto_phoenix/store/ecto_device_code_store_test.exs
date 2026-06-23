defmodule AttestoPhoenix.Store.EctoDeviceCodeStoreTest do
  @moduledoc """
  Behaviour conformance tests for the Ecto-backed device-code store (RFC 8628).

  The load-bearing properties are the atomic, state-guarded transitions: a
  pending code is approved/denied exactly once, an approved code is consumed
  exactly once, and the §3.5 poll interval is enforced in one statement.

  Tagged `:ecto` so the suite runs only when a SQL backend is available.
  """

  use AttestoPhoenix.DataCase, async: true

  alias AttestoPhoenix.Store.EctoDeviceCodeStore, as: Store

  @moduletag :ecto

  defp put(overrides \\ %{}) do
    now = System.system_time(:second)

    record =
      Map.merge(
        %{
          device_code_hash: "dch-#{System.unique_integer([:positive])}",
          user_code: "UC#{System.unique_integer([:positive])}",
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

  test "put + lookup_user_code returns the pending view" do
    r = put(%{data: %{client_id: "cli-1", scope: ["a", "b"], resource: ["https://x/r"], dpop_jkt: nil}})
    assert {:ok, view} = Store.lookup_user_code(r.user_code)
    assert view.client_id == "cli-1"
    assert view.scope == ["a", "b"]
    assert view.resource == ["https://x/r"]
    assert view.status == :pending
  end

  test "approve transitions pending->approved exactly once" do
    r = put()
    assert :ok = Store.approve(r.user_code, %{subject: "usr_1", granted_scope: ["read"], granted_claims: %{"k" => "v"}})
    # A second decision is refused.
    assert {:error, :already_decided} = Store.approve(r.user_code, %{subject: "usr_2"})
    assert {:error, :already_decided} = Store.deny(r.user_code)

    {:ok, entry} = Store.poll(r.device_code_hash, %{now: System.system_time(:second), interval: 0})
    assert entry.status == :approved
    assert entry.subject == "usr_1"
    assert entry.granted_scope == ["read"]
    assert entry.granted_claims == %{"k" => "v"}
  end

  test "deny transitions pending->denied" do
    r = put()
    assert :ok = Store.deny(r.user_code)
    {:ok, entry} = Store.poll(r.device_code_hash, %{now: System.system_time(:second), interval: 0})
    assert entry.status == :denied
  end

  test "an unknown user_code is not_found" do
    assert {:error, :not_found} = Store.approve("NOSUCH", %{subject: "usr_1"})
  end

  test "consume transitions approved->consumed exactly once" do
    r = put()
    :ok = Store.approve(r.user_code, %{subject: "usr_1"})

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
end
