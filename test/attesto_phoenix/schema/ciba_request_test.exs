defmodule AttestoPhoenix.Schema.CIBARequestTest do
  use ExUnit.Case, async: true

  alias AttestoPhoenix.Schema.CIBARequest

  @expires_at 1_704_067_260

  defp data(overrides \\ %{}) do
    Map.merge(
      %{
        acr_values: [],
        binding_message: nil,
        client_id: "client-1",
        client_notification_token: nil,
        delivery_mode: :poll,
        dpop_jkt: nil,
        resource: [],
        scope: ["openid"],
        subject: "user-1"
      },
      overrides
    )
  end

  defp record(data_overrides \\ %{}) do
    %{
      auth_req_id_hash: "hash-1",
      data: data(data_overrides),
      status: :pending,
      interval: 5,
      expires_at: @expires_at,
      last_polled_at: nil
    }
  end

  test "preserves a valid core-issued entry through the row bridge" do
    row = CIBARequest.from_record(record())

    assert row.auth_req_id_hash == "hash-1"
    assert row.client_id == "client-1"
    assert row.scope == ["openid"]
    assert row.hint_subject == "user-1"
    assert row.interval == 5
    assert CIBARequest.to_entry(row).data == data()
  end

  test "rejects an extra issue-time data key before projection" do
    assert_raise ArgumentError, "CIBA request has invalid canonical data", fn ->
      CIBARequest.from_record(record(%{adapter_metadata: "not protocol data"}))
    end
  end

  test "rejects a missing issue-time data key before projecting a default" do
    assert_raise ArgumentError, "CIBA request has invalid canonical data", fn ->
      CIBARequest.from_record(%{record() | data: Map.delete(data(), :scope)})
    end
  end

  test "preserves malformed loaded NULLs for core read validation" do
    entry =
      CIBARequest.to_entry(%CIBARequest{
        acr_values: nil,
        scope: nil,
        resource: nil,
        interval: nil
      })

    assert entry.data.acr_values == nil
    assert entry.data.scope == nil
    assert entry.data.resource == nil
    assert entry.interval == nil
  end
end
