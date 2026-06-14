defmodule AttestoPhoenix.Store.EctoPARStoreTest do
  @moduledoc """
  Behaviour-conformance tests for the Postgres-backed Pushed Authorization
  Request store (RFC 9126): cross-node resolution, TTL expiry on read,
  non-consuming `fetch/1`, atomic single-use `take/1`, and string-keyed jsonb
  round-trip.

  The store reads its repo from the `:attesto_phoenix` application environment,
  which `AttestoPhoenix.DataCase` points at the sandboxed test repo.
  """

  use AttestoPhoenix.DataCase, async: true

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
    "dpop_jkt" => "thumbprint-xyz"
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

  test "put rejects a duplicate request_uri rather than overwriting" do
    :ok = EctoPARStore.put(@request_uri, @params, 90)

    assert {:error, _changeset} = EctoPARStore.put(@request_uri, %{"client_id" => "other"}, 90)
    # The original reference is intact.
    assert {:ok, %{"client_id" => "client-1"}} = EctoPARStore.fetch(@request_uri)
  end
end
