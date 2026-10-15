defmodule AttestoPhoenix.Store.EctoSweeperTest do
  use AttestoPhoenix.DataCase, async: false

  import Ecto.Query

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Schema.Authorization
  alias AttestoPhoenix.Schema.RefreshToken
  alias AttestoPhoenix.Store.EctoCodeStore
  alias AttestoPhoenix.Store.Sweeper
  alias Ecto.Adapters.SQL.Sandbox

  @swept_tables [
    "attesto_authorization_codes",
    "attesto_refresh_tokens",
    "attesto_device_codes",
    "attesto_ciba_requests",
    "attesto_logout_sessions",
    "dpop_nonces",
    "dpop_replays",
    "attesto_pushed_authorization_requests",
    "attesto_client_id_metadata",
    "attesto_consent_grants"
  ]

  defmodule FakeKeystore do
    @moduledoc false
  end

  test "expires unlinked and malformed codes but preserves every live token link" do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    expired = DateTime.add(now, -60, :second)
    token_expired = DateTime.add(now, -1, :second)
    token_live = DateTime.add(now, 300, :second)

    rows = [
      authorization("unlinked", expired),
      authorization("empty-jti", expired, access_token_jti: "", access_token_expires_at: token_live),
      authorization("malformed", expired, access_token_jti: "malformed", access_token_expires_at: nil),
      authorization("expired-token", expired,
        access_token_jti: "expired-token-jti",
        access_token_expires_at: token_expired
      ),
      authorization("live-token", expired,
        access_token_jti: "live-token-jti",
        access_token_expires_at: token_live
      ),
      authorization("revoked-live-token", expired,
        access_token_jti: "revoked-live-token-jti",
        access_token_expires_at: token_live,
        access_token_revoked_at: now
      )
    ]

    Enum.each(rows, &TestRepo.insert!/1)

    sweeper = start_sweeper()
    assert Sweeper.sweep_now(sweeper)["attesto_authorization_codes"] == 4

    assert TestRepo.get_by(Authorization, code_hash: "unlinked") == nil
    assert TestRepo.get_by(Authorization, code_hash: "empty-jti") == nil
    assert TestRepo.get_by(Authorization, code_hash: "malformed") == nil
    assert TestRepo.get_by(Authorization, code_hash: "expired-token") == nil
    assert %Authorization{} = live = TestRepo.get_by(Authorization, code_hash: "live-token")
    assert %Authorization{} = revoked = TestRepo.get_by(Authorization, code_hash: "revoked-live-token")
    assert revoked.access_token_revoked_at == now

    # The retained row remains the replay/revocation record until its linked
    # token expires. A replay can therefore still revoke that token after the
    # authorization code itself has expired.
    assert :ok = EctoCodeStore.revoke_access_token_for_code(live.code_hash)
    assert EctoCodeStore.access_token_revoked?("live-token-jti")

    assert {1, nil} =
             TestRepo.update_all(
               from(a in Authorization, where: a.code_hash == ^live.code_hash),
               set: [access_token_expires_at: DateTime.add(now, -1, :second)]
             )

    assert Sweeper.sweep_now(sweeper)["attesto_authorization_codes"] == 1
    assert TestRepo.get_by(Authorization, code_hash: "live-token") == nil
    assert %Authorization{} = TestRepo.get_by(Authorization, code_hash: "revoked-live-token")

    assert {1, nil} =
             TestRepo.update_all(
               from(a in Authorization, where: a.code_hash == ^revoked.code_hash),
               set: [access_token_expires_at: DateTime.add(now, -1, :second)]
             )

    assert Sweeper.sweep_now(sweeper)["attesto_authorization_codes"] == 1
    assert TestRepo.get_by(Authorization, code_hash: "revoked-live-token") == nil
  end

  test "applies code and linked-token expiry cutoffs" do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    code_boundary = authorization("code-boundary", now)

    code_after_boundary =
      authorization("code-after-boundary", DateTime.add(now, 2, :second),
        access_token_jti: "code-boundary-jti",
        access_token_expires_at: DateTime.add(now, 2, :second)
      )

    token_boundary =
      authorization("token-boundary", DateTime.add(now, -60, :second),
        access_token_jti: "token-boundary-jti",
        access_token_expires_at: now
      )

    TestRepo.insert!(code_boundary)
    TestRepo.insert!(code_after_boundary)
    TestRepo.insert!(token_boundary)

    sweeper = start_sweeper()
    result = Sweeper.sweep_now(sweeper)

    # The sweep instant occurs after the test's truncated second, so the first
    # code and the linked token are expired. A code after that second remains.
    assert result["attesto_authorization_codes"] == 2
    assert TestRepo.get_by(Authorization, code_hash: "code-boundary") == nil
    assert %Authorization{} = TestRepo.get_by(Authorization, code_hash: "code-after-boundary")
    assert TestRepo.get_by(Authorization, code_hash: "token-boundary") == nil
  end

  test "preserves claimed rows through finalization and family markers while a refresh descendant is live" do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    expired = DateTime.add(now, -60, :second)
    past = DateTime.add(now, -1, :second)
    future = DateTime.add(now, 300, :second)

    rows = [
      authorization("finalizing", expired,
        consumed_at: expired,
        consumed_success: false,
        replay_retain_until: future
      ),
      authorization("finalization-ended", expired,
        consumed_at: expired,
        consumed_success: false,
        replay_retain_until: past
      ),
      authorization("bounded-family", expired,
        consumed_at: expired,
        consumed_success: true,
        family_id: "bounded",
        replay_retain_until: future
      ),
      authorization("ended-family", expired,
        consumed_at: expired,
        consumed_success: true,
        family_id: "ended",
        replay_retain_until: past
      ),
      authorization("unbounded-family", expired,
        consumed_at: expired,
        consumed_success: true,
        family_id: "unbounded",
        replay_retain_until: nil
      ),
      authorization("no-refresh", expired,
        consumed_at: expired,
        consumed_success: true,
        family_id: nil,
        replay_retain_until: nil
      )
    ]

    Enum.each(rows, &TestRepo.insert!/1)

    TestRepo.insert!(refresh_token("bounded-live", "bounded", 0, future))
    TestRepo.insert!(refresh_token("unbounded-live", "unbounded", 0, future))

    sweeper = start_sweeper()
    assert Sweeper.sweep_now(sweeper)["attesto_authorization_codes"] == 3

    assert %Authorization{} = TestRepo.get_by(Authorization, code_hash: "finalizing")
    assert %Authorization{} = TestRepo.get_by(Authorization, code_hash: "bounded-family")
    assert %Authorization{} = TestRepo.get_by(Authorization, code_hash: "unbounded-family")
    assert TestRepo.get_by(Authorization, code_hash: "finalization-ended") == nil
    assert TestRepo.get_by(Authorization, code_hash: "ended-family") == nil
    assert TestRepo.get_by(Authorization, code_hash: "no-refresh") == nil
  end

  test "retires successful and legacy NULL family markers after the last refresh descendant expires" do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    expired = DateTime.add(now, -60, :second)
    past = DateTime.add(now, -1, :second)
    future = DateTime.add(now, 300, :second)

    rows = [
      authorization("legacy-live", expired,
        consumed_at: expired,
        consumed_success: true,
        family_id: "legacy-live-family",
        replay_retain_until: nil
      ),
      authorization("legacy-ended", expired,
        consumed_at: expired,
        consumed_success: true,
        family_id: "legacy-ended-family",
        replay_retain_until: nil
      ),
      authorization("bounded-ended", expired,
        consumed_at: expired,
        consumed_success: true,
        family_id: "bounded-ended-family",
        replay_retain_until: future
      )
    ]

    Enum.each(rows, &TestRepo.insert!/1)
    TestRepo.insert!(refresh_token("legacy-live-token", "legacy-live-family", 0, future))
    TestRepo.insert!(refresh_token("legacy-ended-token", "legacy-ended-family", 0, past))
    TestRepo.insert!(refresh_token("bounded-ended-token", "bounded-ended-family", 0, past))

    sweeper = start_sweeper()
    result = Sweeper.sweep_now(sweeper)

    assert result["attesto_authorization_codes"] == 2
    assert result["attesto_refresh_tokens"] == 2
    assert %Authorization{} = TestRepo.get_by(Authorization, code_hash: "legacy-live")
    assert TestRepo.get_by(Authorization, code_hash: "legacy-ended") == nil
    assert TestRepo.get_by(Authorization, code_hash: "bounded-ended") == nil

    assert {1, nil} =
             TestRepo.update_all(
               from(t in RefreshToken, where: t.token_hash == "legacy-live-token"),
               set: [expires_at: past]
             )

    result = Sweeper.sweep_now(sweeper)
    assert result["attesto_authorization_codes"] == 1
    assert result["attesto_refresh_tokens"] == 1
    assert TestRepo.get_by(Authorization, code_hash: "legacy-live") == nil
  end

  test "evaluates refresh-family liveness inside the configured schema prefix" do
    prefix = "auth_sweeper_#{System.unique_integer([:positive, :monotonic])}"
    TestRepo.query!("CREATE SCHEMA #{prefix}")

    Enum.each(@swept_tables, fn table ->
      TestRepo.query!("CREATE TABLE #{prefix}.#{table} (LIKE public.#{table} INCLUDING ALL)")
    end)

    on_exit(fn -> TestRepo.query!("DROP SCHEMA IF EXISTS #{prefix} CASCADE") end)

    now = DateTime.utc_now() |> DateTime.truncate(:second)
    expired = DateTime.add(now, -60, :second)
    past = DateTime.add(now, -1, :second)
    future = DateTime.add(now, 300, :second)

    TestRepo.insert!(
      authorization("prefixed-live-family", expired,
        consumed_at: expired,
        consumed_success: true,
        family_id: "prefixed-live",
        replay_retain_until: nil
      ),
      prefix: prefix
    )

    TestRepo.insert!(
      authorization("prefixed-ended-family", expired,
        consumed_at: expired,
        consumed_success: true,
        family_id: "prefixed-ended",
        replay_retain_until: nil
      ),
      prefix: prefix
    )

    TestRepo.insert!(refresh_token("prefixed-live-token", "prefixed-live", 0, future), prefix: prefix)
    TestRepo.insert!(refresh_token("prefixed-ended-token", "prefixed-ended", 0, past), prefix: prefix)

    sweeper = start_sweeper(prefix)
    result = Sweeper.sweep_now(sweeper)

    assert result["attesto_authorization_codes"] == 1
    assert result["attesto_refresh_tokens"] == 1

    assert %Authorization{} =
             TestRepo.get_by(Authorization, [code_hash: "prefixed-live-family"], prefix: prefix)

    assert TestRepo.get_by(Authorization, [code_hash: "prefixed-ended-family"], prefix: prefix) == nil

    assert {1, nil} =
             TestRepo.update_all(
               from(t in RefreshToken, where: t.token_hash == "prefixed-live-token"),
               [set: [expires_at: past]],
               prefix: prefix
             )

    result = Sweeper.sweep_now(sweeper)
    assert result["attesto_authorization_codes"] == 1
    assert result["attesto_refresh_tokens"] == 1
    assert TestRepo.get_by(Authorization, [code_hash: "prefixed-live-family"], prefix: prefix) == nil
  end

  defp start_sweeper(schema_prefix \\ nil) do
    config =
      Config.new(
        issuer: "https://issuer.example",
        audience: "https://resource.example",
        keystore: FakeKeystore,
        repo: TestRepo,
        schema_prefix: schema_prefix,
        sweep_interval_ms: 60_000,
        load_client: fn _ -> {:error, :not_found} end,
        verify_client_secret: fn _, _ -> false end,
        load_principal: fn _ -> {:error, :not_found} end
      )

    {:ok, pid} = Sweeper.start_link(config: config, name: nil)
    Sandbox.allow(TestRepo, self(), pid)
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)
    pid
  end

  defp authorization(code_hash, expires_at, attrs \\ []) do
    struct!(
      %Authorization{
        code_hash: code_hash,
        client_id: "client",
        subject: "subject",
        scope: [],
        resource: [],
        redirect_uri: "https://client.example/callback",
        claims: %{},
        expires_at: expires_at,
        inserted_at: expires_at
      },
      attrs
    )
  end

  defp refresh_token(token_hash, family_id, generation, expires_at) do
    %RefreshToken{
      token_hash: token_hash,
      family_id: family_id,
      generation: generation,
      subject: "subject",
      scope: [],
      resource: [],
      claims: %{},
      consumed: false,
      family_revoked: false,
      expires_at: expires_at,
      inserted_at: DateTime.add(expires_at, -60, :second)
    }
  end
end
