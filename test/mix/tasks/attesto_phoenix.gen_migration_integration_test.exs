defmodule Mix.Tasks.AttestoPhoenix.Gen.MigrationIntegrationTest do
  @moduledoc """
  Applies the generated migration against PostgreSQL and drives every bundled
  Ecto store through the resulting non-default schema.

  The source-level generator tests catch drift in the rendered migration. This
  test catches the runtime failure that would otherwise be hidden by a table
  name prefix: Ecto's `prefix:` option must select one PostgreSQL schema for
  every store operation, including the migration's indexes and rollback.
  """

  use AttestoPhoenix.DataCase, async: false

  alias AttestoPhoenix.ClientIdMetadata.Cache.Ecto, as: ClientIdMetadataCache
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Store.EctoCIBAStore
  alias AttestoPhoenix.Store.EctoCodeStore
  alias AttestoPhoenix.Store.EctoConsentGrantStore
  alias AttestoPhoenix.Store.EctoDeviceCodeStore
  alias AttestoPhoenix.Store.EctoLogoutSessionStore
  alias AttestoPhoenix.Store.EctoNonceStore
  alias AttestoPhoenix.Store.EctoPARStore
  alias AttestoPhoenix.Store.EctoRefreshStore
  alias AttestoPhoenix.Store.EctoReplayCheck
  alias AttestoPhoenix.TestRepo
  alias Ecto.Adapters.SQL.Sandbox
  alias Mix.Tasks.AttestoPhoenix.Gen.Migration

  @moduletag :ecto
  @moduletag :tmp_dir

  defmodule Keystore do
    @moduledoc false
  end

  defp migrations_dir(tmp_dir), do: Path.join(tmp_dir, "migrations")

  defp prefix_config(prefix) do
    Config.new(
      issuer: "https://issuer.example",
      audience: "https://resource.example",
      keystore: Keystore,
      repo: TestRepo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      schema_prefix: prefix
    )
  end

  test "applies the generated schema prefix and routes every Ecto store through it", %{
    tmp_dir: tmp_dir
  } do
    prefix = "attesto_generated_#{System.unique_integer([:positive])}"

    # Ecto.Migrator runs migration callbacks in a supervised process. Let that
    # process check out its own connection; the store assertions below are
    # likewise committed and the schema is removed by the cleanup callback.
    Sandbox.mode(TestRepo, :auto)
    on_exit(fn -> Sandbox.mode(TestRepo, :manual) end)

    on_exit(fn ->
      TestRepo.query!(~s|DROP SCHEMA IF EXISTS "#{prefix}" CASCADE|)
    end)

    Migration.run([
      "--repo",
      inspect(TestRepo),
      "--migrations-path",
      migrations_dir(tmp_dir),
      "--schema-prefix",
      prefix
    ])

    [migration_file] = Path.wildcard(Path.join(migrations_dir(tmp_dir), "*.exs"))
    [{migration, _binary}] = Code.compile_file(migration_file)
    version = 9_000_000_000 + System.unique_integer([:positive])

    assert :ok = Ecto.Migrator.up(TestRepo, version, migration, log: false)

    config = prefix_config(prefix)

    Config.with_request_config(config, fn ->
      now = System.system_time(:second)

      assert :ok =
               EctoCodeStore.put(%{
                 code_hash: "generated-code-#{now}",
                 data: %{
                   client_id: "client-1",
                   subject: "subject-1",
                   scope: ["openid"],
                   resource: [],
                   redirect_uri: "https://rp.example/cb",
                   code_challenge: nil,
                   dpop_jkt: nil,
                   family_id: nil,
                   claims: %{}
                 },
                 expires_at: now + 600
               })

      assert {:ok, _} = EctoCodeStore.get("generated-code-#{now}")

      par_uri = "urn:ietf:params:oauth:request_uri:generated-#{now}"
      assert :ok = EctoPARStore.put(par_uri, %{"client_id" => "client-1"}, 600)
      assert {:ok, %{"client_id" => "client-1"}} = EctoPARStore.fetch(par_uri)

      binding = %{
        subject: "subject-1",
        client_id: "client-1",
        redirect_uri: "https://rp.example/cb",
        scope: ["openid"],
        code_challenge: nil,
        code_challenge_method: nil
      }

      assert {:ok, consent_token} = EctoConsentGrantStore.mint(binding, 600)
      assert :ok = EctoConsentGrantStore.consume(consent_token, binding)

      nonce = EctoNonceStore.issue(60)
      assert EctoNonceStore.valid?(nonce)
      assert :ok = EctoNonceStore.accept(nonce, 60)

      assert :ok = EctoReplayCheck.check_and_record("generated-jti-#{now}", 60)

      metadata_url = "https://client.example/generated-#{now}.json"

      assert :ok =
               ClientIdMetadataCache.put(
                 metadata_url,
                 %{"client_id" => metadata_url},
                 DateTime.add(DateTime.utc_now(), 600, :second)
               )

      assert {:ok, %{"client_id" => ^metadata_url}} = ClientIdMetadataCache.get(metadata_url)

      ciba = %{
        auth_req_id_hash: "generated-ciba-#{now}",
        data: %{
          acr_values: [],
          binding_message: nil,
          client_id: "client-1",
          client_notification_token: nil,
          delivery_mode: :poll,
          dpop_jkt: nil,
          resource: [],
          scope: ["openid"],
          subject: "subject-1"
        },
        status: :pending,
        interval: 0,
        expires_at: now + 600,
        last_polled_at: nil
      }

      assert :ok = EctoCIBAStore.put(ciba)
      assert {:ok, _} = EctoCIBAStore.lookup(ciba.auth_req_id_hash)

      device = %{
        device_code_hash: "generated-device-#{now}",
        user_code: "BCDFGHJK",
        data: %{client_id: "client-1", scope: ["openid"], resource: [], dpop_jkt: nil},
        status: :pending,
        expires_at: now + 600,
        last_polled_at: nil
      }

      assert :ok = EctoDeviceCodeStore.put(device)
      assert {:ok, _} = EctoDeviceCodeStore.get(device.device_code_hash)

      logout = %{
        sid: "generated-sid-#{now}",
        subject: "subject-1",
        client_id: "client-1",
        backchannel_logout_uri: "https://rp.example/logout",
        expires_at: now + 600
      }

      assert :ok = EctoLogoutSessionStore.record(logout)
      assert [%{client_id: "client-1"}] = EctoLogoutSessionStore.targets(%{sid: logout.sid})

      refresh = %{
        token_hash: "generated-refresh-#{now}",
        family_id: "generated-family-#{now}",
        generation: 0,
        data: %{
          subject: "subject-1",
          scope: ["openid"],
          resource: [],
          acr: nil,
          auth_time: nil,
          client_id: "client-1",
          dpop_jkt: nil,
          claims: %{}
        },
        expires_at: now + 600,
        consumed: false
      }

      assert :ok = EctoRefreshStore.insert(refresh)
      assert {:ok, _} = EctoRefreshStore.get(refresh.token_hash)
      assert :ok = EctoRefreshStore.revoke_family(refresh.family_id)
      assert :error = EctoRefreshStore.get(refresh.token_hash)
    end)

    assert :ok = Ecto.Migrator.down(TestRepo, version, migration, log: false)

    assert %{rows: [[true]]} =
             TestRepo.query!(
               "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)",
               [prefix]
             )

    assert %{rows: [[nil]]} =
             TestRepo.query!(
               "SELECT to_regclass($1)",
               ["#{prefix}.attesto_authorization_codes"]
             )
  end
end
