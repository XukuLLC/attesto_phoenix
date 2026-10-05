defmodule AttestoPhoenix.Store.RefreshIssuerMigrationTest do
  use AttestoPhoenix.DataCase, async: false

  alias Attesto.RefreshToken, as: CoreRefreshToken
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.RefreshSuccessorCipher
  alias AttestoPhoenix.Schema.RefreshToken
  alias AttestoPhoenix.Store.EctoRefreshStore
  alias AttestoPhoenix.Store.Sweeper
  alias Mix.Tasks.AttestoPhoenix.BackfillRefreshIssuer

  @issuer "https://issuer.example/authorization"
  @other_issuer "https://other-issuer.example/authorization"
  @issuer_claim "urn:attesto:refresh-token:issuer"
  @now 1_900_000_000
  @instance_key Base.url_encode64(:crypto.hash(:sha256, "verified-instance-key"), padding: false)

  defmodule Keystore do
    def signing_pem, do: "unused-store-test-key"
    def verification_pems, do: [signing_pem()]
  end

  setup do
    :ok = Sweeper.register_cleanup_worker({TestRepo, nil}, self())

    config =
      Config.new(
        issuer: @issuer,
        audience: "https://resource.example",
        keystore: Keystore,
        repo: TestRepo,
        refresh_store: EctoRefreshStore,
        sweep_interval_ms: 1_000,
        load_client: fn _ -> {:error, :not_found} end,
        verify_client_secret: fn _, _ -> false end,
        client_auth_method: fn _ -> :client_secret_post end,
        load_principal: fn _ -> {:error, :not_found} end
      )

    %{config: config}
  end

  test "default policy refuses an unbound family without consuming or revoking it", %{config: config} do
    Config.with_request_config(config, fn ->
      initial = issue_legacy()
      assert {:error, :issuer_mismatch} = rotate(initial.token)
      parent = row(initial.token)
      refute parent.consumed
      refute parent.family_revoked
      refute Map.has_key?(parent.claims, @issuer_claim)
    end)
  end

  test "compatibility telemetry reports aggregate outcomes without identifiers", %{config: config} do
    handler = {__MODULE__, self()}

    :ok =
      :telemetry.attach(
        handler,
        [:attesto_phoenix, :refresh_token, :issuer_migration],
        &__MODULE__.handle_migration/4,
        self()
      )

    on_exit(fn -> :telemetry.detach(handler) end)
    initial = Config.with_request_config(config, &issue_legacy/0)

    Config.with_request_config(%{config | bind_unbound_refresh_families: :configured_issuer}, fn ->
      assert {:ok, _record} = EctoRefreshStore.get(Attesto.Secret.hash(initial.token))
      assert_receive {:issuer_migration, %{count: 1}, %{outcome: :bound, reason: :configured_single_issuer}}
      assert {:ok, _record} = EctoRefreshStore.get(Attesto.Secret.hash(initial.token))
      refute_receive {:issuer_migration, _, _}
    end)
  end

  test "a telemetry handler failure cannot turn a committed backfill into a protocol error", %{config: config} do
    handler = {__MODULE__, self()}

    :ok =
      :telemetry.attach(
        handler,
        [:attesto_phoenix, :refresh_token, :issuer_migration],
        &__MODULE__.fail_migration_handler/4,
        nil
      )

    on_exit(fn -> :telemetry.detach(handler) end)

    Config.with_request_config(config, fn ->
      initial = issue_legacy()
      assert {:ok, %{rows_changed: 1}} = apply_backfill()
      assert {:ok, _rotated} = rotate(initial.token)
    end)
  end

  test "operator assertion is required and dry run never persists a binding", %{config: config} do
    Config.with_request_config(config, fn ->
      initial = issue_legacy()
      assert_raise ArgumentError, ~r/assert_single_issuer/, fn -> EctoRefreshStore.backfill_issuer(@issuer) end

      assert_raise ArgumentError, ~r/HTTPS issuer/, fn ->
        EctoRefreshStore.backfill_issuer("http://issuer.example", assert_single_issuer: true)
      end

      assert {:ok, %{families_changed: 1, rows_changed: 1}} =
               EctoRefreshStore.backfill_issuer(@issuer, assert_single_issuer: true, batch_size: 1)

      refute Map.has_key?(row(initial.token).claims, @issuer_claim)
      assert {:error, :issuer_mismatch} = rotate(initial.token)
    end)
  end

  test "backfill preserves a v2 lost-response retry and is byte-idempotent", %{config: config} do
    Config.with_request_config(config, fn ->
      initial = issue_legacy()

      assert {:ok, first} =
               CoreRefreshToken.rotate(EctoRefreshStore, initial.token,
                 client_id: "client-1",
                 now: @now + 1,
                 ttl: 100,
                 rotation_grace_seconds: 5
               )

      original = row(initial.token)
      assert {:ok, %{families_changed: 1, rows_changed: 2}} = apply_backfill(batch_size: 1)
      migrated = row(initial.token)
      child = row(first.token)
      assert migrated.claims[@issuer_claim] == @issuer
      assert child.claims[@issuer_claim] == @issuer
      assert migrated.successor["retry_until"] == original.successor["retry_until"]
      assert migrated.expires_at == original.expires_at
      assert migrated.consumed_at == original.consumed_at
      assert migrated.successor["ciphertext"] != original.successor["ciphertext"]
      assert {:ok, retry} = rotate(initial.token, now: @now + 2)
      assert retry.token == first.token
      assert retry.context.issuer == @issuer
      assert retry.context.claims == %{"session" => "original-session"}
      assert {:ok, %{families_changed: 0, rows_changed: 0}} = apply_backfill()
      assert row(initial.token).successor == migrated.successor
      assert {:ok, next} = rotate(first.token, now: @now + 3)
      assert next.context.issuer == @issuer
    end)
  end

  test "v1 retry migration retains its envelope and original derived deadline", %{config: config} do
    Config.with_request_config(config, fn ->
      initial = issue_legacy()
      {child, payload} = legacy_child(initial, @now + 1)
      {:ok, ciphertext} = RefreshSuccessorCipher.encrypt(Map.delete(payload, :retry_until))
      persist_old_rotation(initial, child, %{"v" => 1, "ciphertext" => ciphertext})
      assert {:ok, %{rows_changed: 2}} = apply_backfill()
      assert Map.keys(row(initial.token).successor) |> Enum.sort() == ["ciphertext", "v"]
      assert {:ok, retry} = rotate(initial.token, now: @now + 2)
      assert retry.token == child.token
      assert {:ok, loaded} = EctoRefreshStore.get(Attesto.Secret.hash(initial.token))
      assert loaded.successor.retry_until == @now + 1 + config.refresh_token_rotation_grace_seconds
    end)
  end

  test "a conflicting generation aborts the entire family without replacing any issuer", %{config: config} do
    Config.with_request_config(config, fn ->
      initial = issue_legacy()
      {child, payload} = legacy_child(initial, @now + 1)
      persist_old_rotation(initial, child, encrypted_wrapper(initial, child, payload))

      TestRepo.update!(
        Ecto.Changeset.change(row(child.token), claims: Map.put(child.record.data.claims, @issuer_claim, @other_issuer))
      )

      before = row(initial.token)
      assert {:error, _reason, %{rows_changed: 0}} = apply_backfill()
      assert row(initial.token).claims == before.claims
      assert row(initial.token).successor == before.successor
      assert row(child.token).claims[@issuer_claim] == @other_issuer
      refute row(initial.token).family_revoked
    end)
  end

  test "unreadable retry ciphertext fails the family atomically", %{config: config} do
    Config.with_request_config(config, fn ->
      initial = issue_legacy()
      {child, payload} = legacy_child(initial, @now + 1)
      persist_old_rotation(initial, child, encrypted_wrapper(initial, child, payload))

      TestRepo.update!(
        Ecto.Changeset.change(row(initial.token),
          successor: %{
            "v" => 2,
            "ciphertext" => "malformed",
            "retry_until" => payload.retry_until,
            "child_hash" => child.record.token_hash
          }
        )
      )

      assert {:error, :invalid_retry_state, %{rows_changed: 0}} = apply_backfill()
      refute Map.has_key?(row(initial.token).claims, @issuer_claim)
      refute Map.has_key?(row(child.token).claims, @issuer_claim)
    end)
  end

  test "temporary single-issuer mode binds new legacy issuance from configured provenance", %{config: config} do
    initial = Config.with_request_config(config, &issue_legacy/0)
    compatibility = %{config | bind_unbound_refresh_families: :configured_issuer}

    Config.with_request_config(compatibility, fn ->
      assert {:ok, first} = rotate(initial.token)
      assert first.context.issuer == @issuer
      assert row(initial.token).claims[@issuer_claim] == @issuer
      newly_issued = issue_legacy()
      assert row(newly_issued.token).claims[@issuer_claim] == @issuer
      assert {:ok, _rotated} = rotate(newly_issued.token)
    end)
  end

  test "rolling repair handles a stale old-node rotation after administrative backfill", %{config: config} do
    Config.with_request_config(config, fn ->
      initial = issue_legacy()
      {child, payload} = legacy_child(initial, @now + 1)
      assert {:ok, %{rows_changed: 1}} = apply_backfill()
      # An old caller read the parent before backfill. Its later transaction
      # retains the now-bound parent claims but inserts an unbound child and
      # authenticated retry context, exactly as the historical writer did.
      persist_old_rotation(initial, child, encrypted_wrapper(initial, child, payload))
      assert row(initial.token).claims[@issuer_claim] == @issuer
      refute Map.has_key?(row(child.token).claims, @issuer_claim)

      Config.with_request_config(%{config | bind_unbound_refresh_families: :configured_issuer}, fn ->
        assert {:ok, retry} = rotate(initial.token, now: @now + 2)
        assert retry.token == child.token
        assert row(child.token).claims[@issuer_claim] == @issuer
        assert row(initial.token).successor["retry_until"] == payload.retry_until
      end)

      assert {:ok, next} = rotate(child.token, now: @now + 3)
      assert next.context.issuer == @issuer
    end)
  end

  test "configured single-issuer mode never overwrites a different bound issuer", %{config: config} do
    Config.with_request_config(config, fn ->
      assert {:ok, initial} =
               CoreRefreshToken.issue(
                 EctoRefreshStore,
                 Map.put(context(), :issuer, @other_issuer),
                 now: @now,
                 ttl: 100
               )

      before = row(initial.token)

      Config.with_request_config(%{config | bind_unbound_refresh_families: :configured_issuer}, fn ->
        assert :error = EctoRefreshStore.get(Attesto.Secret.hash(initial.token))
        assert {:error, :invalid_grant} = rotate(initial.token)
      end)

      after_read = row(initial.token)
      assert after_read.claims == before.claims
      refute after_read.consumed
      refute after_read.family_revoked
    end)
  end

  test "issuer migration does not invent a missing attestation binding", %{config: config} do
    Config.with_request_config(config, fn ->
      initial = issue_legacy()
      assert {:ok, _counts} = apply_backfill()
      assert {:error, :attestation_proof_unexpected} = rotate(initial.token, attestation_jkt: @instance_key)
      assert row(initial.token).attestation_jkt == nil
      refute row(initial.token).consumed
    end)
  end

  test "issuer migration preserves absolute family expiry and persisted instance binding", %{config: config} do
    Config.with_request_config(config, fn ->
      assert {:ok, initial} =
               CoreRefreshToken.issue(
                 EctoRefreshStore,
                 Map.put(context(), :attestation_jkt, @instance_key),
                 now: @now,
                 ttl: 100,
                 family_ttl: 50
               )

      assert {:ok, _counts} = apply_backfill()
      assert row(initial.token).family_expires_at == @now + 50
      assert row(initial.token).attestation_jkt == @instance_key
      assert {:ok, next} = rotate(initial.token, attestation_jkt: @instance_key, ttl: 100)
      assert next.context.family_expires_at == @now + 50
      assert row(next.token).attestation_jkt == @instance_key
      assert DateTime.to_unix(row(next.token).expires_at) == @now + 50
    end)
  end

  test "direct rotation cannot erase a stored issuer binding", %{config: config} do
    Config.with_request_config(config, fn ->
      initial = issue_legacy()
      {child, payload} = legacy_child(initial, @now + 1)
      assert {:ok, _counts} = apply_backfill()

      assert {:error, :invalid_rotation} =
               EctoRefreshStore.rotate(
                 Attesto.Secret.hash(initial.token),
                 child.record,
                 payload,
                 now: @now + 1
               )

      refute row(initial.token).consumed
    end)
  end

  test "revoked family rows are skipped and never made usable", %{config: config} do
    Config.with_request_config(config, fn ->
      initial = issue_legacy()
      saved = row(initial.token)
      :ok = EctoRefreshStore.revoke_family(initial.family_id)
      TestRepo.insert!(%{saved | family_revoked: true})
      assert {:ok, %{families_skipped: 1, rows_changed: 0}} = apply_backfill()
      assert row(initial.token).family_revoked
      refute Map.has_key?(row(initial.token).claims, @issuer_claim)
      assert :error = EctoRefreshStore.get(Attesto.Secret.hash(initial.token))
    end)
  end

  test "administrative binding is isolated to the selected schema prefix", %{config: config} do
    TestRepo.query!("CREATE SCHEMA issuer_migration_scope")

    TestRepo.query!(
      "CREATE TABLE issuer_migration_scope.attesto_refresh_tokens (LIKE public.attesto_refresh_tokens INCLUDING ALL)"
    )

    TestRepo.query!(
      "CREATE TABLE issuer_migration_scope.attesto_refresh_family_revocations (LIKE public.attesto_refresh_family_revocations INCLUDING ALL)"
    )

    :ok = Sweeper.register_cleanup_worker({TestRepo, "issuer_migration_scope"}, self())

    try do
      public = Config.with_request_config(config, &issue_legacy/0)
      scoped = %{config | schema_prefix: "issuer_migration_scope"}

      Config.with_request_config(scoped, fn ->
        initial = issue_legacy()
        assert {:ok, %{rows_changed: 1}} = apply_backfill()
        assert {:ok, next} = rotate(initial.token)
        assert next.context.issuer == @issuer
      end)

      refute Map.has_key?(row(public.token).claims, @issuer_claim)
    after
      TestRepo.query!("DROP SCHEMA issuer_migration_scope CASCADE")
    end
  end

  test "task requires the explicit declaration, audits by default, and applies only on request", %{config: config} do
    previous = Application.fetch_env(__MODULE__, Config)
    shell = Mix.shell()
    Application.put_env(__MODULE__, Config, config)
    Mix.shell(Mix.Shell.Process)

    on_exit(fn ->
      Mix.shell(shell)

      case previous do
        {:ok, value} -> Application.put_env(__MODULE__, Config, value)
        :error -> Application.delete_env(__MODULE__, Config)
      end
    end)

    Config.with_request_config(config, fn ->
      initial = issue_legacy()
      assert_raise Mix.Error, ~r/assert-single-issuer/, fn -> BackfillRefreshIssuer.run(["--issuer", @issuer]) end
      args = ["--issuer", @issuer, "--assert-single-issuer", "--otp-app", Atom.to_string(__MODULE__)]
      BackfillRefreshIssuer.run(args)
      assert_receive {:mix_shell, :info, ["Dry run:" <> _counts]}
      refute Map.has_key?(row(initial.token).claims, @issuer_claim)
      BackfillRefreshIssuer.run(args ++ ["--apply"])
      assert_receive {:mix_shell, :info, ["Applied:" <> _counts]}
      assert row(initial.token).claims[@issuer_claim] == @issuer

      assert_raise Mix.Error, ~r/exactly match/, fn ->
        BackfillRefreshIssuer.run(List.replace_at(args, 1, @other_issuer) ++ ["--apply"])
      end
    end)
  end

  defp context do
    %{
      subject: "subject-1",
      scope: ["read"],
      resource: [],
      client_id: "client-1",
      claims: %{"session" => "original-session"}
    }
  end

  def handle_migration(_event, measurements, metadata, owner),
    do: send(owner, {:issuer_migration, measurements, metadata})

  def fail_migration_handler(_event, _measurements, _metadata, _owner), do: raise("observer failure")

  defp issue_legacy do
    {:ok, issued} = CoreRefreshToken.issue(EctoRefreshStore, context(), now: @now, ttl: 100)
    issued
  end

  defp rotate(token, opts \\ []) do
    CoreRefreshToken.rotate(
      EctoRefreshStore,
      token,
      Keyword.merge([issuer: @issuer, client_id: "client-1", now: @now + 1, ttl: 100, rotation_grace_seconds: 5], opts)
    )
  end

  defp apply_backfill(opts \\ []) do
    EctoRefreshStore.backfill_issuer(@issuer, Keyword.merge([assert_single_issuer: true, dry_run: false], opts))
  end

  defp row(token), do: TestRepo.get_by!(RefreshToken, token_hash: Attesto.Secret.hash(token))

  defp legacy_child(initial, now) do
    {:ok, parent} = EctoRefreshStore.get(Attesto.Secret.hash(initial.token))
    token = "legacy-successor-#{System.unique_integer([:positive])}"

    record = %{
      parent
      | token_hash: Attesto.Secret.hash(token),
        generation: parent.generation + 1,
        consumed: false,
        consumed_at: nil,
        successor: nil
    }

    child = %{token: token, record: record}
    payload = %{token: token, generation: record.generation, context: record.data, retry_until: now + 5}
    {child, payload}
  end

  defp encrypted_wrapper(initial, child, payload) do
    aad =
      RefreshSuccessorCipher.binding_aad(
        Attesto.Secret.hash(initial.token),
        initial.family_id,
        child.record.generation - 1,
        child.record.token_hash,
        payload.retry_until
      )

    {:ok, ciphertext} = RefreshSuccessorCipher.encrypt(payload, aad)

    %{
      "v" => 2,
      "ciphertext" => ciphertext,
      "retry_until" => payload.retry_until,
      "child_hash" => child.record.token_hash
    }
  end

  defp persist_old_rotation(initial, child, wrapper) do
    TestRepo.update!(
      Ecto.Changeset.change(row(initial.token),
        consumed: true,
        consumed_at: DateTime.from_unix!(@now + 1),
        successor: wrapper
      )
    )

    attrs = RefreshToken.from_store_record(child.record, parent_hash: Attesto.Secret.hash(initial.token))
    TestRepo.insert!(RefreshToken.insert_changeset(%RefreshToken{}, attrs))
  end
end
