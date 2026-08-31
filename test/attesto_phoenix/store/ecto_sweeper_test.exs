defmodule AttestoPhoenix.Store.EctoSweeperTest do
  use AttestoPhoenix.DataCase, async: false

  import Ecto.Query

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Schema.Authorization
  alias AttestoPhoenix.Store.EctoCodeStore
  alias AttestoPhoenix.Store.Sweeper
  alias Ecto.Adapters.SQL.Sandbox

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

  defp start_sweeper do
    config =
      Config.new(
        issuer: "https://issuer.example",
        audience: "https://resource.example",
        keystore: FakeKeystore,
        repo: TestRepo,
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
end
