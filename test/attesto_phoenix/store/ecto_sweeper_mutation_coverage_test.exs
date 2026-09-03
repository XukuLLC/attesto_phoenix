defmodule AttestoPhoenix.Store.EctoSweeperMutationCoverageTest do
  @moduledoc """
  Focused coverage for the missing-sweeper signal at each bundled Ecto store's
  database-mutation entry point.

  These tests deliberately run with no cleanup worker for the test repository.
  The stores must still complete their operation, while the asynchronous
  `:sweeper_unsupervised` signal identifies the exact repository and prefix.
  """

  use AttestoPhoenix.DataCase, async: false

  alias AttestoPhoenix.ClientIdMetadata.Cache.Ecto, as: ClientIdMetadataCache
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Schema.RefreshToken
  alias AttestoPhoenix.Store.EctoCIBAStore
  alias AttestoPhoenix.Store.EctoCodeStore
  alias AttestoPhoenix.Store.EctoConsentGrantStore
  alias AttestoPhoenix.Store.EctoDeviceCodeStore
  alias AttestoPhoenix.Store.EctoLogoutSessionStore
  alias AttestoPhoenix.Store.EctoNonceStore
  alias AttestoPhoenix.Store.EctoPARStore
  alias AttestoPhoenix.Store.EctoRefreshStore
  alias AttestoPhoenix.Store.EctoReplayCheck
  alias AttestoPhoenix.Store.Sweeper
  alias AttestoPhoenix.Store.Sweeper.Signal

  @moduletag :ecto
  @user_code_alphabet ~c"BCDFGHJKLMNPQRSTVWXZ"

  defmodule Keystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem, do: "sweeper-mutation-coverage"

    @impl true
    def verification_pems, do: [signing_pem()]
  end

  setup do
    :ok = reset_missing_sweeper()
    :ok
  end

  test "authorization-code insertion signals when the sweeper is absent" do
    assert_missing_signal(fn -> EctoCodeStore.put(code_record()) end)
  end

  test "authorization-code consume update signals when the sweeper is absent" do
    record = code_record()
    prepare_with_worker(fn -> EctoCodeStore.put(record) end)

    assert {:ok, _entry} = assert_missing_signal(fn -> EctoCodeStore.take(record.code_hash) end)
  end

  test "authorization-code lifecycle updates signal when the sweeper is absent" do
    record = code_record()
    prepare_with_worker(fn -> EctoCodeStore.put(record) end)

    assert :ok =
             assert_missing_signal(fn ->
               EctoCodeStore.mark_consumed(record.code_hash, %{family_id: record.data.family_id})
             end)

    assert :ok =
             assert_missing_signal(fn ->
               EctoCodeStore.record_access_token_for_code(record.code_hash, unique("jti"), unix_now() + 60)
             end)

    assert :ok = assert_missing_signal(fn -> EctoCodeStore.revoke_access_token_for_code(record.code_hash) end)
  end

  test "authorization-code family lifecycle updates signal when the sweeper is absent" do
    record = code_record()
    prepare_with_worker(fn -> EctoCodeStore.put(record) end)

    assert :ok =
             assert_missing_signal(fn ->
               EctoCodeStore.record_access_token(record.data.family_id, unique("jti"), unix_now() + 60)
             end)

    assert :ok = assert_missing_signal(fn -> EctoCodeStore.revoke_family_access_tokens(record.data.family_id) end)
  end

  test "device-code insertion signals when the sweeper is absent" do
    assert_missing_signal(fn -> EctoDeviceCodeStore.put(device_code_record()) end)
  end

  test "device-code approval, denial, and consumption signal when the sweeper is absent" do
    approved = device_code_record()
    prepare_with_worker(fn -> EctoDeviceCodeStore.put(approved) end)

    assert {:ok, _entry} =
             assert_missing_signal(fn ->
               EctoDeviceCodeStore.approve(approved.user_code, %{subject: "coverage-subject"}, %{now: unix_now()})
             end)

    denied = device_code_record()
    prepare_with_worker(fn -> EctoDeviceCodeStore.put(denied) end)

    assert {:ok, _entry} =
             assert_missing_signal(fn -> EctoDeviceCodeStore.deny(denied.user_code, %{now: unix_now()}) end)

    consumed = device_code_record()

    prepare_with_worker(fn ->
      :ok = EctoDeviceCodeStore.put(consumed)

      {:ok, _entry} =
        EctoDeviceCodeStore.approve(consumed.user_code, %{subject: "coverage-subject"}, %{now: unix_now()})
    end)

    assert {:ok, _entry} =
             assert_missing_signal(fn -> EctoDeviceCodeStore.consume(consumed.device_code_hash, %{now: unix_now()}) end)
  end

  test "CIBA-request insertion signals when the sweeper is absent" do
    assert_missing_signal(fn -> EctoCIBAStore.put(ciba_record()) end)
  end

  test "CIBA approval, denial, and consumption signal when the sweeper is absent" do
    approved = ciba_record()
    prepare_with_worker(fn -> EctoCIBAStore.put(approved) end)

    assert {:ok, _entry} =
             assert_missing_signal(fn ->
               EctoCIBAStore.approve(approved.auth_req_id_hash, %{subject: "coverage-subject"}, %{now: unix_now()})
             end)

    denied = ciba_record()
    prepare_with_worker(fn -> EctoCIBAStore.put(denied) end)

    assert {:ok, _entry} =
             assert_missing_signal(fn -> EctoCIBAStore.deny(denied.auth_req_id_hash, %{now: unix_now()}) end)

    consumed = ciba_record()

    prepare_with_worker(fn ->
      :ok = EctoCIBAStore.put(consumed)

      {:ok, _entry} =
        EctoCIBAStore.approve(consumed.auth_req_id_hash, %{subject: "coverage-subject"}, %{now: unix_now()})
    end)

    assert {:ok, _entry} =
             assert_missing_signal(fn -> EctoCIBAStore.consume(consumed.auth_req_id_hash, %{now: unix_now()}) end)
  end

  test "logout-session insertion signals when the sweeper is absent" do
    assert_missing_signal(fn -> EctoLogoutSessionStore.record(logout_record()) end)
  end

  test "logout-session deletion and take signal when the sweeper is absent" do
    deleted = logout_record()
    prepare_with_worker(fn -> EctoLogoutSessionStore.record(deleted) end)
    assert :ok = assert_missing_signal(fn -> EctoLogoutSessionStore.delete(%{sid: deleted.sid}) end)

    taken = logout_record()
    prepare_with_worker(fn -> EctoLogoutSessionStore.record(taken) end)
    assert [_target] = assert_missing_signal(fn -> EctoLogoutSessionStore.take_targets(%{sid: taken.sid}) end)
  end

  test "PAR insertion signals when the sweeper is absent" do
    assert_missing_signal(fn -> EctoPARStore.put(par_uri(), %{"client_id" => "coverage-client"}, 60) end)
  end

  test "PAR take signals when the sweeper is absent" do
    request_uri = par_uri()
    prepare_with_worker(fn -> EctoPARStore.put(request_uri, %{"client_id" => "coverage-client"}, 60) end)
    assert {:ok, _params} = assert_missing_signal(fn -> EctoPARStore.take(request_uri) end)
  end

  test "consent-grant insertion signals when the sweeper is absent" do
    assert_missing_signal(fn -> EctoConsentGrantStore.mint(consent_binding(), 60) end)
  end

  test "consent-grant consumption signals when the sweeper is absent" do
    binding = consent_binding()
    {:ok, token} = prepare_with_worker(fn -> EctoConsentGrantStore.mint(binding, 60) end)
    assert :ok = assert_missing_signal(fn -> EctoConsentGrantStore.consume(token, binding) end)
  end

  test "DPoP nonce insertion and atomic acceptance signal when the sweeper is absent" do
    nonce = assert_missing_signal(fn -> EctoNonceStore.issue(coverage_config(), 60) end)

    # Acceptance is a second mutation path. The worker reset in this helper
    # clears the first episode before checking the atomic UPDATE path.
    assert_missing_signal(fn -> EctoNonceStore.accept(coverage_config(), nonce, 60) end)
  end

  test "DPoP replay insertion signals when the sweeper is absent" do
    assert_missing_signal(fn -> EctoReplayCheck.check_and_record(unique("jti"), 60) end)
  end

  test "Client ID metadata insertion signals when the sweeper is absent" do
    url = "https://metadata.example/#{unique("document")}"

    assert_missing_signal(fn ->
      ClientIdMetadataCache.put(url, %{"client_id" => url}, future())
    end)
  end

  test "Client ID metadata deletion paths signal when the sweeper is absent" do
    url = "https://metadata.example/#{unique("delete")}"
    prepare_with_worker(fn -> ClientIdMetadataCache.put(url, %{"client_id" => url}, future()) end)
    assert :ok = assert_missing_signal(fn -> ClientIdMetadataCache.delete(url) end)

    url = "https://metadata.example/#{unique("delete-all")}"
    prepare_with_worker(fn -> ClientIdMetadataCache.put(url, %{"client_id" => url}, future()) end)
    assert :ok = assert_missing_signal(fn -> ClientIdMetadataCache.delete_all() end)
  end

  test "refresh insertion signals with zero retry grace" do
    config = coverage_config(refresh_token_rotation_grace_seconds: 0)

    assert_missing_signal(fn ->
      Config.with_request_config(config, fn -> EctoRefreshStore.insert(refresh_record()) end)
    end)
  end

  test "refresh rotation signals when the sweeper is absent" do
    config = coverage_config()
    parent = refresh_record()

    parent_row =
      %RefreshToken{}
      |> RefreshToken.insert_changeset(RefreshToken.from_store_record(parent))

    assert {:ok, _row} = TestRepo.insert(parent_row, log: false, telemetry_event: nil)

    child_token = unique("refresh-child")
    child = refresh_child(parent, child_token)
    successor = %{token: child_token, generation: child.generation, context: child.data, retry_until: unix_now() + 30}

    assert {:ok, _child, _successor} =
             assert_missing_signal(fn ->
               Config.with_request_config(config, fn ->
                 EctoRefreshStore.rotate(parent.token_hash, child, successor, now: unix_now())
               end)
             end)
  end

  test "refresh-family revocation signals when the sweeper is absent" do
    config = coverage_config()

    assert_missing_signal(fn ->
      Config.with_request_config(config, fn -> EctoRefreshStore.revoke_family(unique("family")) end)
    end)
  end

  defp assert_missing_signal(fun) when is_function(fun, 0) do
    # Each invocation exercises a separate mutation path. Registering and
    # retiring a short-lived worker clears Lifecycle's one-hour suppression
    # episode before the operation under test runs.
    :ok = reset_missing_sweeper()

    ref = make_ref()
    handler_id = {__MODULE__, :mutation_signal, ref}

    :telemetry.attach(
      handler_id,
      [:attesto_phoenix, :store, :sweeper_unsupervised],
      &__MODULE__.handle_telemetry/4,
      {self(), ref}
    )

    try do
      result = fun.()

      assert_receive {
                       :sweeper_mutation_signal,
                       ^ref,
                       %{count: 1},
                       %{repo: TestRepo, schema_prefix: nil}
                     },
                     2_000

      await_signal_idle()
      result
    after
      :telemetry.detach(handler_id)
    end
  end

  def handle_telemetry(_event, measurements, metadata, {owner, ref}) do
    send(owner, {:sweeper_mutation_signal, ref, measurements, metadata})
  end

  defp reset_missing_sweeper do
    target = {TestRepo, nil}
    worker = spawn(fn -> Process.sleep(:infinity) end)
    :ok = Sweeper.register_cleanup_worker(target, worker)
    Process.exit(worker, :kill)

    eventually(fn -> refute Sweeper.running?(target) end)
    await_signal_idle()
    :ok
  end

  defp prepare_with_worker(fun) when is_function(fun, 0) do
    target = {TestRepo, nil}
    worker = spawn(fn -> Process.sleep(:infinity) end)
    :ok = Sweeper.register_cleanup_worker(target, worker)

    try do
      fun.()
    after
      Process.exit(worker, :kill)
      eventually(fn -> refute Sweeper.running?(target) end)
      await_signal_idle()
    end
  end

  defp await_signal_idle do
    eventually(fn ->
      state = :sys.get_state(Signal)
      assert state.active == nil
      assert :queue.is_empty(state.queue)
      assert state.retry_ref == nil
      assert state.delivery_failures == %{}
    end)
  end

  defp eventually(assertion, attempts \\ 200)
  defp eventually(assertion, 0), do: assertion.()

  defp eventually(assertion, attempts) do
    assertion.()
  rescue
    ExUnit.AssertionError ->
      Process.sleep(10)
      eventually(assertion, attempts - 1)
  end

  defp coverage_config(overrides \\ []) do
    [
      issuer: "https://issuer.example",
      audience: "https://resource.example",
      keystore: Keystore,
      repo: TestRepo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end
    ]
    |> Keyword.merge(overrides)
    |> Config.new()
  end

  defp code_record do
    %{
      code_hash: unique("code"),
      data: %{
        client_id: "coverage-client",
        subject: "coverage-subject",
        scope: ["openid"],
        resource: [],
        redirect_uri: "https://client.example/callback",
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        dpop_jkt: nil,
        family_id: unique("code-family"),
        claims: %{}
      },
      expires_at: unix_now() + 600
    }
  end

  defp device_code_record do
    %{
      device_code_hash: unique("device"),
      user_code: unique_user_code(),
      data: %{client_id: "coverage-client", scope: ["openid"], resource: [], dpop_jkt: nil},
      status: :pending,
      expires_at: unix_now() + 600,
      last_polled_at: nil
    }
  end

  defp ciba_record do
    %{
      auth_req_id_hash: unique("ciba"),
      data: %{
        acr_values: [],
        binding_message: nil,
        client_id: "coverage-client",
        client_notification_token: nil,
        delivery_mode: :poll,
        dpop_jkt: nil,
        resource: [],
        scope: ["openid"],
        subject: "coverage-subject"
      },
      status: :pending,
      interval: 0,
      expires_at: unix_now() + 600,
      last_polled_at: nil
    }
  end

  defp logout_record do
    %{
      sid: unique("sid"),
      subject: "coverage-subject",
      client_id: unique("logout-client"),
      backchannel_logout_uri: "https://client.example/backchannel-logout",
      session_required: false,
      expires_at: unix_now() + 600
    }
  end

  defp consent_binding do
    %{
      client_id: "coverage-client",
      subject: "coverage-subject",
      redirect_uri: "https://client.example/callback",
      scope: ["openid"],
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      code_challenge_method: "S256"
    }
  end

  defp refresh_record do
    %{
      token_hash: unique("refresh"),
      family_id: unique("refresh-family"),
      generation: 0,
      data: %{
        subject: "coverage-subject",
        scope: ["openid"],
        resource: [],
        acr: nil,
        auth_time: nil,
        client_id: "coverage-client",
        dpop_jkt: nil,
        claims: %{}
      },
      expires_at: unix_now() + 600,
      consumed: false,
      consumed_at: nil,
      successor: nil
    }
  end

  defp refresh_child(parent, token) do
    %{
      token_hash: Attesto.Secret.hash(token),
      family_id: parent.family_id,
      generation: parent.generation + 1,
      data: parent.data,
      expires_at: parent.expires_at,
      consumed: false,
      consumed_at: nil,
      successor: nil
    }
  end

  defp par_uri, do: "urn:ietf:params:oauth:request_uri:" <> unique("par")
  defp future, do: DateTime.add(DateTime.utc_now(), 600, :second)
  defp unix_now, do: System.system_time(:second)
  defp unique(prefix), do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"

  defp unique_user_code do
    System.unique_integer([:positive, :monotonic])
    |> Integer.digits(20)
    |> Enum.map(&Enum.at(@user_code_alphabet, &1))
    |> to_string()
    |> String.pad_leading(8, "B")
  end
end
