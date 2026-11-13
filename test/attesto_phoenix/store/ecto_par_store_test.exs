defmodule AttestoPhoenix.Store.EctoPARStoreTest do
  @moduledoc """
  Behaviour-conformance tests for the Postgres-backed Pushed Authorization
  Request store (RFC 9126): cross-node resolution, TTL expiry on read,
  non-consuming `fetch/1`, atomic single-use `take/1`, and string-keyed jsonb
  round-trip.

  The store reads its repo from the `:attesto_phoenix` application environment,
  which `AttestoPhoenix.DataCase` points at the sandboxed test repo.
  """

  use AttestoPhoenix.DataCase, async: false

  import ExUnit.CaptureLog

  alias AttestoPhoenix.Schema.PushedAuthorizationRequest
  alias AttestoPhoenix.Store.EctoPARStore
  alias AttestoPhoenix.TestRepo

  @moduletag :ecto

  @request_uri "urn:ietf:params:oauth:request_uri:" <> "abc123def456"
  @params %{
    "client_id" => "client-1",
    "response_type" => "code",
    "scope" => "openid profile",
    "redirect_uri" => "https://rp.example/cb",
    "dpop_jkt" => "request-parameter-secret",
    "authorization_details" => [%{"amount" => 1.25}]
  }

  test "put then fetch round-trips the params verbatim (string-keyed jsonb)" do
    assert :ok = EctoPARStore.put(@request_uri, @params, 90)

    assert {:ok, fetched} = EctoPARStore.fetch(@request_uri)
    assert fetched == @params
  end

  test "fetch does NOT consume - a request_uri resolves repeatedly across a consent detour" do
    :ok = EctoPARStore.put(@request_uri, @params, 90)

    assert {:ok, _} = EctoPARStore.fetch(@request_uri)
    assert {:ok, _} = EctoPARStore.fetch(@request_uri)
    # Still present in the shared store; resolution did not spend it.
    assert TestRepo.get(PushedAuthorizationRequest, @request_uri)
  end

  test "fetch is :error for an unknown request_uri" do
    assert :error = EctoPARStore.fetch("urn:ietf:params:oauth:request_uri:nope")
  end

  test "an expired reference is not honored on read and yields :error" do
    # A past TTL would be rejected by the positive-ttl guard, so insert directly
    # with an expiry in the past to exercise the read-time freshness check.
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    %{request_uri: @request_uri, params: @params, expires_at: DateTime.add(now, -1, :second), inserted_at: now}
    |> PushedAuthorizationRequest.put_changeset()
    |> TestRepo.insert!()

    assert :error = EctoPARStore.fetch(@request_uri)
  end

  test "take atomically resolves and deletes a live reference" do
    :ok = EctoPARStore.put(@request_uri, @params, 90)

    assert {:ok, taken} = EctoPARStore.take(@request_uri)
    assert taken == @params
    # Single-use: the row is gone, so a second take (or fetch) finds nothing.
    assert :error = EctoPARStore.take(@request_uri)
    assert :error = EctoPARStore.fetch(@request_uri)
    refute TestRepo.get(PushedAuthorizationRequest, @request_uri)
  end

  test "take is :error for an expired reference and leaves no row to honor" do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    %{request_uri: @request_uri, params: @params, expires_at: DateTime.add(now, -1, :second), inserted_at: now}
    |> PushedAuthorizationRequest.put_changeset()
    |> TestRepo.insert!()

    assert :error = EctoPARStore.take(@request_uri)
  end

  test "replace changes only a live value and never resurrects a taken entry" do
    assert :ok = EctoPARStore.put(@request_uri, @params, 90)
    original = TestRepo.get!(PushedAuthorizationRequest, @request_uri)
    updated = Map.put(@params, "consent_decision", "allow")
    assert :ok = EctoPARStore.replace(@request_uri, updated)
    assert {:ok, ^updated} = EctoPARStore.fetch(@request_uri)
    row = TestRepo.get!(PushedAuthorizationRequest, @request_uri)
    assert row.expires_at == original.expires_at
    assert row.inserted_at == original.inserted_at
    assert {:ok, ^updated} = EctoPARStore.take(@request_uri)
    assert :error = EctoPARStore.replace(@request_uri, @params)
    refute TestRepo.get(PushedAuthorizationRequest, @request_uri)
    assert :error = EctoPARStore.replace("unknown", @params)
  end

  test "replace refuses an expired entry without changing it" do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    original =
      %{request_uri: @request_uri, params: @params, expires_at: DateTime.add(now, -1, :second), inserted_at: now}
      |> PushedAuthorizationRequest.put_changeset()
      |> TestRepo.insert!()

    assert :error = EctoPARStore.replace(@request_uri, %{"consent_decision" => "allow"})
    assert TestRepo.get!(PushedAuthorizationRequest, @request_uri) == original
    assert :error = EctoPARStore.take(@request_uri)
  end

  test "replace refuses invalid PostgreSQL text without changing the entry" do
    assert :ok = EctoPARStore.put(@request_uri, @params, 90)

    for key <- [@request_uri <> <<0>>, @request_uri <> <<0xFF>>] do
      assert :error = EctoPARStore.replace(key, @params)
    end

    assert :error = EctoPARStore.replace(@request_uri, %{"subject" => "bad\0subject"})
    assert {:ok, @params} = EctoPARStore.fetch(@request_uri)
  end

  test "put rejects a duplicate request_uri rather than overwriting" do
    :ok = EctoPARStore.put(@request_uri, @params, 90)

    assert {:error, _changeset} = EctoPARStore.put(@request_uri, %{"client_id" => "other"}, 90)
    # The original reference is intact.
    assert {:ok, %{"client_id" => "client-1"}} = EctoPARStore.fetch(@request_uri)
  end

  test "put rejects NUL bytes before PostgreSQL encoding" do
    params = Map.put(@params, "claims", %{"userinfo" => %{"name" => "before\0after"}})

    assert {:error, :invalid_text} = EctoPARStore.put(@request_uri, params, 90)
    refute TestRepo.get(PushedAuthorizationRequest, @request_uri)
  end

  test "put rejects a request_uri PostgreSQL text cannot hold" do
    assert {:error, :invalid_text} = EctoPARStore.put(@request_uri <> <<0>>, @params, 90)
    assert {:error, :invalid_text} = EctoPARStore.put(@request_uri <> <<0xFF>>, @params, 90)
  end

  test "fetch and take answer :error for a request_uri PostgreSQL text cannot hold" do
    :ok = EctoPARStore.put(@request_uri, @params, 90)

    for request_uri <- [@request_uri <> <<0>>, <<0>>, "x" <> <<0>>, @request_uri <> <<0xFF>>] do
      assert :error = EctoPARStore.fetch(request_uri)
      assert :error = EctoPARStore.take(request_uri)
    end

    assert {:ok, @params} = EctoPARStore.fetch(@request_uri)
  end

  test "query telemetry is suppressed for request_uri writes, reads, and deletes" do
    capture = AttestoPhoenix.TestTelemetryCapture.attach(TestRepo)
    on_exit(fn -> AttestoPhoenix.TestTelemetryCapture.detach(capture) end)
    {_id, ref} = capture

    assert is_integer(TestRepo.aggregate(PushedAuthorizationRequest, :count, :request_uri))
    assert AttestoPhoenix.TestTelemetryCapture.collect(ref) != []

    log =
      capture_log([level: :debug], fn ->
        assert :ok = EctoPARStore.put(@request_uri, @params, 90)
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
        assert {:ok, _} = EctoPARStore.fetch(@request_uri)
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
        assert :ok = EctoPARStore.replace(@request_uri, Map.put(@params, "consent_decision", "allow"))
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
        assert {:ok, _} = EctoPARStore.take(@request_uri)
        assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
      end)

    refute log =~ @request_uri
    refute log =~ @params["dpop_jkt"]
  end
end
