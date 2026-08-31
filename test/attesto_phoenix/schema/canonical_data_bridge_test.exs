defmodule AttestoPhoenix.Schema.CanonicalDataBridgeTest do
  use ExUnit.Case, async: true

  alias AttestoPhoenix.Schema.Authorization
  alias AttestoPhoenix.Schema.CIBARequest
  alias AttestoPhoenix.Schema.DeviceCode

  @authorization_data %{
    client_id: "client-1",
    code_challenge: nil,
    claims: %{},
    dpop_jkt: nil,
    family_id: nil,
    redirect_uri: "https://rp.example/cb",
    resource: [],
    scope: ["openid"],
    subject: "user-1"
  }

  @ciba_data %{
    acr_values: [],
    binding_message: nil,
    client_id: "client-1",
    client_notification_token: nil,
    delivery_mode: :poll,
    dpop_jkt: nil,
    resource: [],
    scope: ["openid"],
    subject: "user-1"
  }

  @device_data %{client_id: "client-1", dpop_jkt: nil, resource: [], scope: ["read"]}

  test "all NON-REFRESH write bridges reject malformed canonical values uniformly" do
    cases = [
      {
        Authorization,
        %{code_hash: "hash", data: Map.put(@authorization_data, :dpop_jkt, "bad"), expires_at: 1_704_067_260},
        "authorization code record has invalid canonical data"
      },
      {
        CIBARequest,
        %{
          auth_req_id_hash: "hash",
          data: Map.put(@ciba_data, :scope, nil),
          status: :pending,
          interval: 0,
          expires_at: 1_704_067_260
        },
        "CIBA request has invalid canonical data"
      },
      {
        CIBARequest,
        %{
          auth_req_id_hash: "hash",
          data: @ciba_data,
          status: :approved,
          interval: 0,
          expires_at: 1_704_067_260
        },
        "CIBA request has invalid canonical data"
      },
      {
        CIBARequest,
        %{
          auth_req_id_hash: "hash",
          data: @ciba_data,
          status: :pending,
          subject: "user-1",
          interval: 0,
          expires_at: 1_704_067_260
        },
        "CIBA request has invalid canonical data"
      },
      {
        CIBARequest,
        %{
          auth_req_id_hash: "hash",
          data: Map.put(@ciba_data, :delivery_mode, "poll"),
          status: :pending,
          interval: 0,
          expires_at: 1_704_067_260
        },
        "CIBA request has invalid canonical data"
      },
      {
        DeviceCode,
        %{
          device_code_hash: "hash",
          user_code: "BCDFGHJK",
          data: Map.put(@device_data, :resource, [nil]),
          status: :pending,
          expires_at: 1_704_067_260
        },
        "device code has invalid canonical data"
      },
      {
        DeviceCode,
        %{
          device_code_hash: "hash",
          user_code: "BCDFGHJK",
          data: @device_data,
          status: :pending,
          subject: "user-1",
          expires_at: 1_704_067_260
        },
        "device code has invalid canonical data"
      },
      {
        DeviceCode,
        %{
          device_code_hash: "hash",
          user_code: "BCDFGHJK",
          data: @device_data,
          status: "pending",
          expires_at: 1_704_067_260
        },
        "device code has invalid canonical data"
      }
    ]

    Enum.each(cases, fn {module, record, message} ->
      assert_raise ArgumentError, message, fn -> module.from_record(record) end
    end)
  end
end
