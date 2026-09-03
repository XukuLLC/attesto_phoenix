defmodule AttestoPhoenix.Store.EctoCodeStoreTelemetryTest do
  @moduledoc """
  Query-observability contract for the Ecto authorization-code store.

  The `claims` column carries the authentication context and, for a host using
  `:authorization_code_private_context`, that host's private authorization
  state. Ecto SQL query telemetry publishes params, cast params, and the
  decoded result, so an operation that binds or returns the whole row would
  hand that state to every attached APM handler - and `redact: true` does not
  help, because telemetry carries the raw row rather than the struct.

  `EctoCodeStoreTest` already pins that every store operation is silent. These
  tests add the content check that a silence-only assertion cannot make: each
  one plants a unique sentinel inside the private context and fails if that
  sentinel reaches telemetry metadata or the SQL log by any route, so a future
  change that re-enables observability on a claims-bearing query is caught by
  what it discloses rather than only by whether it emitted.

  `async: false`, deliberately: each test attaches a handler to the repo's
  global `[:query]` telemetry event and asserts on which events arrive, so a
  concurrent test issuing any query against the same repo would break it.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias AttestoPhoenix.AuthorizationCodePrivateContext, as: PrivateContext
  alias AttestoPhoenix.Schema.Authorization
  alias AttestoPhoenix.Store.EctoCodeStore
  alias AttestoPhoenix.TestRepo
  alias Ecto.Adapters.SQL.Sandbox

  @moduletag :ecto

  # Deliberately NOT `AttestoPhoenix.DataCase`. That template derives its
  # sandbox mode from the async flag (`shared: not tags[:async]`), so a
  # synchronous case would take the connection in SHARED mode and collide with
  # the unboxed owner `AuthorizationCodeCompletionTest` starts. These tests need
  # serial execution for telemetry isolation, not a shared connection, so the
  # owner is started explicitly with `shared: false`.
  setup do
    pid = Sandbox.start_owner!(TestRepo, shared: false)

    previous_otp_app = Application.fetch_env(:attesto_phoenix, :otp_app)
    Application.delete_env(:attesto_phoenix, :otp_app)
    Application.put_env(:attesto_phoenix, :repo, TestRepo)

    on_exit(fn ->
      Sandbox.stop_owner(pid)

      # Restore only what this case changed, and leave `:repo` pointing at the
      # test repo the way `test_helper.exs` established it globally - restoring
      # a captured `:error` here would delete it for every later test.
      case previous_otp_app do
        {:ok, value} -> Application.put_env(:attesto_phoenix, :otp_app, value)
        :error -> Application.delete_env(:attesto_phoenix, :otp_app)
      end

      Application.put_env(:attesto_phoenix, :repo, TestRepo)
    end)

    :ok
  end

  @future_seconds System.system_time(:second) + 600

  describe "query observability for claims-bearing operations" do
    test "put/1 emits neither query telemetry nor SQL logs" do
      {private_data, sentinel} = private_grant_data()

      assert_private_query_suppressed(sentinel, fn ->
        assert :ok = EctoCodeStore.put(entry("hash-private-put", private_data))
      end)

      row = TestRepo.get_by!(Authorization, code_hash: "hash-private-put")
      assert row.claims[PrivateContext.claims_key()] == %{"nested" => %{"sentinel" => sentinel}}
    end

    test "get/1 emits neither query telemetry nor SQL logs" do
      {private_data, sentinel} = private_grant_data()
      assert :ok = EctoCodeStore.put(entry("hash-private-get", private_data))

      assert_private_query_suppressed(sentinel, fn ->
        assert {:ok, %{data: %{claims: claims}}} = EctoCodeStore.get("hash-private-get")
        assert claims[PrivateContext.claims_key()] == %{"nested" => %{"sentinel" => sentinel}}
      end)
    end

    test "a successful take/1 emits neither query telemetry nor SQL logs" do
      {private_data, sentinel} = private_grant_data()
      assert :ok = EctoCodeStore.put(entry("hash-private-take", private_data))

      assert_private_query_suppressed(sentinel, fn ->
        assert {:ok, %{data: %{claims: claims}}} = EctoCodeStore.take("hash-private-take")
        assert claims[PrivateContext.claims_key()] == %{"nested" => %{"sentinel" => sentinel}}
      end)
    end

    test "a consumed take/1 fallback emits neither query telemetry nor SQL logs" do
      {private_data, sentinel} = private_grant_data(%{family_id: "fam-private-replay"})
      assert :ok = EctoCodeStore.put(entry("hash-private-replay", private_data))
      assert {:ok, _record} = EctoCodeStore.take("hash-private-replay")
      # A real redemption binds the refresh family it issued; `%{}` would clear
      # the family as an explicit no-refresh marker and report nil on replay.
      assert :ok = EctoCodeStore.mark_consumed("hash-private-replay", %{family_id: "fam-private-replay"})

      # The replay read binds the code hash and returns the subject and family
      # ID, so it is suppressed like every other authorization-row query. The
      # narrow select additionally keeps `claims` out of the decoded row.
      assert_private_query_suppressed(sentinel, fn ->
        assert {:error, :consumed, %{family_id: "fam-private-replay", subject: "subject-1"}} =
                 EctoCodeStore.take("hash-private-replay")
      end)
    end

    test "the revocation linkage fallback emits neither query telemetry nor SQL logs" do
      {private_data, sentinel} = private_grant_data(%{family_id: "fam-private-revoke"})
      assert :ok = EctoCodeStore.put(entry("hash-private-revoke", private_data))
      assert {:ok, _record} = EctoCodeStore.take("hash-private-revoke")

      # No access-token linkage was ever recorded, so revocation takes the
      # `legacy_or_missing_revoke/2` path - which reads the row by code hash and
      # returns the access-token JTI.
      assert_private_query_suppressed(sentinel, fn ->
        assert :ok = EctoCodeStore.revoke_access_token_for_code("hash-private-revoke")
      end)
    end

    test "the lifecycle update on a private-context row stays suppressed" do
      {private_data, sentinel} = private_grant_data(%{family_id: "fam-private-consume"})
      assert :ok = EctoCodeStore.put(entry("hash-private-consume", private_data))
      assert {:ok, _record} = EctoCodeStore.take("hash-private-consume")

      assert_private_query_suppressed(sentinel, fn ->
        assert :ok = EctoCodeStore.mark_consumed("hash-private-consume", %{family_id: "fam-private-consume"})
      end)
    end
  end

  defp grant_data(overrides) do
    Map.merge(
      %{
        client_id: "client-abc",
        subject: "subject-1",
        scope: ["openid", "profile"],
        resource: [],
        redirect_uri: "https://rp.example/cb",
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        dpop_jkt: nil,
        family_id: "fam-1",
        claims: %{"acr" => "urn:mace:incommon:iap:silver", "nonce" => "request-nonce"}
      },
      overrides
    )
  end

  defp entry(code_hash, data, expires_at \\ @future_seconds) do
    %{code_hash: code_hash, data: data, expires_at: expires_at}
  end

  defp private_grant_data(overrides \\ %{}) do
    sentinel = "private-context-sentinel-#{System.unique_integer([:positive, :monotonic])}"

    data =
      grant_data(
        Map.merge(
          %{
            claims: %{
              "nonce" => "request-nonce",
              PrivateContext.claims_key() => %{"nested" => %{"sentinel" => sentinel}}
            }
          },
          overrides
        )
      )

    {data, sentinel}
  end

  defp assert_private_query_suppressed(sentinel, operation) do
    {handler_id, event_ref} = attach_query_handler()

    try do
      log = capture_log([level: :debug], operation)

      refute_received {:ecto_code_store_query, ^event_ref, _metadata}

      if String.contains?(log, sentinel) do
        flunk("private context appeared in SQL Logger output")
      end

      if log != "" do
        flunk("protected EctoCodeStore operation emitted SQL Logger output")
      end
    after
      :telemetry.detach(handler_id)
    end
  end

  defp attach_query_handler do
    handler_id = {__MODULE__, make_ref()}
    event_ref = make_ref()
    event = Keyword.fetch!(TestRepo.config(), :telemetry_prefix) ++ [:query]

    :ok =
      :telemetry.attach(
        handler_id,
        event,
        &__MODULE__.forward_query_event/4,
        {self(), event_ref}
      )

    {handler_id, event_ref}
  end

  @doc false
  def forward_query_event(_event, _measurements, metadata, {test_pid, event_ref}) do
    send(test_pid, {:ecto_code_store_query, event_ref, metadata})
  end
end
