defmodule AttestoPhoenix.Schema.DeviceCodeTest do
  use ExUnit.Case, async: true

  alias AttestoPhoenix.Schema.DeviceCode

  @expires_at 1_704_067_260

  defp data(overrides \\ %{}) do
    Map.merge(
      %{client_id: "client-1", dpop_jkt: nil, resource: [], scope: ["read"]},
      overrides
    )
  end

  defp record(data_overrides \\ %{}) do
    %{
      device_code_hash: "hash-1",
      user_code: "BCDFGHJK",
      data: data(data_overrides),
      status: :pending,
      expires_at: @expires_at,
      last_polled_at: nil
    }
  end

  test "preserves a valid core-issued entry through the row bridge" do
    row = DeviceCode.from_record(record()) |> Ecto.Changeset.apply_changes()

    assert row.device_code_hash == "hash-1"
    assert row.client_id == "client-1"
    assert row.scope == ["read"]
    assert DeviceCode.to_entry(row).data == data()
  end

  test "accepts normalized base-20 user codes at configurable lengths from 8 through 64" do
    Enum.each([8, 12, 64], fn length ->
      user_code = String.duplicate("B", length)
      row = DeviceCode.from_record(%{record() | user_code: user_code}) |> Ecto.Changeset.apply_changes()

      assert row.user_code == user_code
    end)
  end

  test "rejects short, long, lowercase, separated, and disallowed user codes" do
    invalid_codes = [
      String.duplicate("B", 7),
      String.duplicate("B", 65),
      "bcdfghjk",
      "BCDF-GHJK",
      "BCDFGHJY"
    ]

    Enum.each(invalid_codes, fn user_code ->
      assert_raise ArgumentError, "device code has invalid canonical data", fn ->
        DeviceCode.from_record(%{record() | user_code: user_code})
      end
    end)
  end

  test "rejects an extra issue-time data key before projection" do
    assert_raise ArgumentError, "device code has invalid canonical data", fn ->
      DeviceCode.from_record(record(%{adapter_metadata: "not protocol data"}))
    end
  end

  test "rejects a missing issue-time data key before projecting a default" do
    assert_raise ArgumentError, "device code has invalid canonical data", fn ->
      DeviceCode.from_record(%{record() | data: Map.delete(data(), :scope)})
    end
  end

  test "preserves malformed loaded NULLs for core read validation" do
    entry = DeviceCode.to_entry(%DeviceCode{scope: nil, resource: nil})

    assert entry.data.scope == nil
    assert entry.data.resource == nil
  end
end
