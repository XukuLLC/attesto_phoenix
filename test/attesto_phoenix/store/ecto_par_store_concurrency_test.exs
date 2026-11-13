defmodule AttestoPhoenix.Store.EctoPARStoreConcurrencyTest do
  use ExUnit.Case, async: false

  import Ecto.Query, only: [from: 2]

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.ConsentGrant
  alias AttestoPhoenix.Interaction
  alias AttestoPhoenix.Schema.PushedAuthorizationRequest
  alias AttestoPhoenix.Store.EctoPARStore
  alias AttestoPhoenix.TestRepo
  alias Ecto.Adapters.SQL.Sandbox

  @moduletag :ecto

  setup do
    owner = Sandbox.start_owner!(TestRepo, sandbox: false)

    config =
      struct!(Config,
        issuer: "https://issuer.example",
        repo: TestRepo,
        keystore: __MODULE__.Keystore,
        par_store: EctoPARStore,
        interaction_browser_binding: fn _conn -> "browser" end
      )

    conn =
      :get
      |> Plug.Test.conn("/oauth/authorize?client_id=client")
      |> Plug.Conn.put_private(:attesto_phoenix_config, config)

    request = %Attesto.AuthorizationRequest{
      response_type: "code",
      client_id: "client",
      redirect_uri: "https://client.example/cb",
      scope: ["openid"]
    }

    assert {:ok, id} = Config.with_request_config(config, fn -> Interaction.park(conn, request, subject: "user") end)
    key = Interaction.parked_key(id, "browser")

    on_exit(fn ->
      :ok = Sandbox.allow(TestRepo, owner, self())
      TestRepo.delete_all(from p in PushedAuthorizationRequest, where: p.request_uri == ^key)
      Sandbox.stop_owner(owner)
    end)

    %{conn: conn, config: config, request: request, id: id, key: key}
  end

  test "decide and take on separate connections leave one complete result and no row", ctx do
    parent = self()

    tasks =
      for operation <- [
            fn -> Interaction.decide(ctx.conn, ctx.id, :allow, "user") end,
            fn -> Config.with_request_config(ctx.config, fn -> Interaction.take(ctx.config, ctx.conn, ctx.id) end) end
          ] do
        Task.async(fn ->
          :ok = Sandbox.checkout(TestRepo, sandbox: false)

          try do
            %{rows: [[backend]]} = TestRepo.query!("SELECT pg_backend_pid()")
            send(parent, {:ready, self(), backend})

            receive do
              :go -> operation.()
            after
              5_000 -> raise "race start timed out"
            end
          after
            Sandbox.checkin(TestRepo)
          end
        end)
      end

    assert_receive {:ready, first, first_backend}, 5_000
    assert_receive {:ready, second, second_backend}, 5_000
    refute first_backend == second_backend
    send(first, :go)
    send(second, :go)
    [decided, taken] = Task.await_many(tasks, 5_000)

    assert decided in [:ok, {:error, :invalid_resume}]
    assert {:ok, entry} = taken
    assert entry.subject == "user"
    assert entry.consent_binding == ConsentGrant.binding_hash(ConsentGrant.binding(ctx.request, "user"))
    assert entry.consent_decision in [nil, "allow"]
    if decided == :ok, do: assert(entry.consent_decision == "allow")

    Config.with_request_config(ctx.config, fn ->
      assert {:error, :invalid_resume} = Interaction.take(ctx.config, ctx.conn, ctx.id)
      assert :error = EctoPARStore.replace(ctx.key, %{"consent_decision" => "deny"})
    end)

    assert {:error, :invalid_resume} = Interaction.decide(ctx.conn, ctx.id, :deny, "user")
    refute TestRepo.get(PushedAuthorizationRequest, ctx.key)
  end
end
