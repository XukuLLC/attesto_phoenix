defmodule AttestoPhoenix.AuthorizationServer.RefreshCompletionTest do
  @moduledoc """
  Transaction-boundary coverage for `:refresh_completion`.

  Runs against the real Ecto code and refresh stores on an unboxed SQL sandbox
  connection, so the host callback's `Repo.transaction/1` is the actual
  transaction boundary: rotation happens inside the continuation and commits
  or rolls back with the host's transaction.
  """

  use ExUnit.Case, async: false

  import Ecto.Query
  import ExUnit.CaptureLog

  alias Attesto.AuthorizationCode
  alias AttestoPhoenix.AuthorizationServer.Token
  alias AttestoPhoenix.AuthorizationServer.Token.Request
  alias AttestoPhoenix.{Config, OAuthError, TestRepo}
  alias AttestoPhoenix.Schema.{Authorization, RefreshFamilyRevocation, RefreshToken}
  alias AttestoPhoenix.Store.{EctoCodeStore, EctoRefreshStore}
  alias Ecto.Adapters.SQL.Sandbox

  @moduletag :ecto

  @signing_pem JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_pem() |> elem(1)
  @code_verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  @code_challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
  @redirect_uri "https://client.example/cb"
  @client %{id: "client-1", public?: false}
  @client_kind Attesto.PrincipalKind.new("client", "oc_", required_claims: [{"client_id", :non_empty_string}])

  defmodule Keystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem do
      :attesto_phoenix
      |> Application.fetch_env!(__MODULE__)
      |> Keyword.fetch!(:signing_pem)
    end

    @impl true
    def verification_pems, do: [signing_pem()]
  end

  # A wrapper, so the bundled store's boot-time sweeper requirement does not
  # apply to these configurations.
  defmodule RefreshStore do
    @moduledoc false
    @behaviour Attesto.RefreshStore

    @impl true
    defdelegate insert(record), to: EctoRefreshStore
    @impl true
    defdelegate get(token_hash), to: EctoRefreshStore
    @impl true
    defdelegate rotate(parent_hash, child, successor, opts), to: EctoRefreshStore
    @impl true
    defdelegate revoke_family(family_id), to: EctoRefreshStore
  end

  setup do
    owner = Sandbox.start_owner!(TestRepo, sandbox: false)

    TestRepo.delete_all(RefreshToken)
    TestRepo.delete_all(Authorization)

    Application.put_env(:attesto_phoenix, __MODULE__.Keystore, signing_pem: @signing_pem)

    previous_otp_app = Application.fetch_env(:attesto_phoenix, :otp_app)
    Application.delete_env(:attesto_phoenix, :otp_app)
    Application.put_env(:attesto_phoenix, :repo, TestRepo)

    on_exit(fn ->
      :ok = Sandbox.allow(TestRepo, owner, self())
      families = TestRepo.all(from r in RefreshToken, select: r.family_id)
      TestRepo.delete_all(RefreshToken)
      TestRepo.delete_all(Authorization)
      TestRepo.delete_all(from r in RefreshFamilyRevocation, where: r.family_id in ^families)
      Sandbox.stop_owner(owner)
      Application.delete_env(:attesto_phoenix, __MODULE__.Keystore)

      case previous_otp_app do
        {:ok, value} -> Application.put_env(:attesto_phoenix, :otp_app, value)
        :error -> Application.delete_env(:attesto_phoenix, :otp_app)
      end

      Application.put_env(:attesto_phoenix, :repo, TestRepo)
    end)

    # Every test starts from a refresh token issued by a plain code redemption.
    plain = config()
    assert {:ok, initial, _events} = Token.issue(plain, code_request(plain, issue_code()))
    family_id = TestRepo.one!(from r in RefreshToken, select: r.family_id)

    %{refresh_token: initial.refresh_token, family_id: family_id}
  end

  test "with no callback the refresh rotates directly, as before", %{refresh_token: token, family_id: family_id} do
    config = config()
    assert Config.refresh_completion_fun(config) == nil

    assert {:ok, response, [%{name: :refresh_rotated}]} = Token.issue(config, refresh_request(config, token))
    assert is_binary(response.access_token)
    assert response.refresh_token != token
    assert generations(family_id) == [0, 1]
  end

  test "the callback receives a secret-free context and the rotation runs inside it", ctx do
    test_pid = self()

    callback = fn context, continuation ->
      send(test_pid, {:context, context, generations(ctx.family_id)})

      TestRepo.transaction(fn ->
        result = continuation.()
        send(test_pid, {:inside, generations(ctx.family_id)})
        result
      end)
    end

    config = config(refresh_completion: callback)

    assert {:ok, response, [%{name: :refresh_rotated}]} =
             Token.issue(config, refresh_request(config, ctx.refresh_token))

    assert is_binary(response.refresh_token)

    # Nothing was rotated when the callback was entered.
    assert_receive {:context, context, [0]}
    assert_receive {:inside, [0, 1]}

    assert context == %{
             client_id: "client-1",
             subject: "oc_user-1",
             family_id: ctx.family_id,
             scope: ["offline_access"],
             resource: [],
             auth_time: nil,
             acr: nil,
             sid: nil
           }

    refute inspect(context) =~ ctx.refresh_token
    assert generations(ctx.family_id) == [0, 1]
  end

  test "a host refusal leaves the presented token usable", ctx do
    refusing = config(refresh_completion: fn _context, _continuation -> {:error, invalid_grant()} end)

    assert {:error, %OAuthError{error: :invalid_grant}, _events} =
             issue(refusing, refresh_request(refusing, ctx.refresh_token))

    assert generations(ctx.family_id) == [0]

    plain = config()
    assert {:ok, response, _events} = Token.issue(plain, refresh_request(plain, ctx.refresh_token))
    assert is_binary(response.refresh_token)
  end

  test "a host rollback after the continuation succeeded undoes the rotation", ctx do
    callback = fn _context, continuation ->
      {:error, :subject_disabled} =
        TestRepo.transaction(fn ->
          assert {:ok, _response, _events} = continuation.()
          assert generations(ctx.family_id) == [0, 1]
          TestRepo.rollback(:subject_disabled)
        end)

      {:error, invalid_grant()}
    end

    config = config(refresh_completion: callback)

    log =
      capture_log(fn ->
        assert {:error, %OAuthError{error: :invalid_grant}, _events} =
                 issue(config, refresh_request(config, ctx.refresh_token))
      end)

    assert log =~ "refresh completion callback returned an error after the continuation succeeded"
    refute log =~ ctx.refresh_token
    assert generations(ctx.family_id) == [0]

    plain = config()
    assert {:ok, _response, _events} = Token.issue(plain, refresh_request(plain, ctx.refresh_token))
  end

  test "a raise inside the host transaction rolls the rotation back", ctx do
    callback = fn _context, continuation ->
      TestRepo.transaction(fn ->
        {:ok, _response, _events} = continuation.()
        raise "host failure after rotation"
      end)
    end

    config = config(refresh_completion: callback)

    capture_log(fn ->
      assert_raise RuntimeError, "host failure after rotation", fn ->
        Token.issue(config, refresh_request(config, ctx.refresh_token))
      end
    end)

    assert generations(ctx.family_id) == [0]

    plain = config()
    assert {:ok, _response, _events} = Token.issue(plain, refresh_request(plain, ctx.refresh_token))
  end

  test "the continuation runs once: a second call is refused and rotates nothing more", ctx do
    test_pid = self()

    callback = fn _context, continuation ->
      first = continuation.()
      send(test_pid, {:second, continuation.()})
      first
    end

    config = config(refresh_completion: callback)

    log =
      capture_log(fn ->
        assert {:ok, response, _events} = Token.issue(config, refresh_request(config, ctx.refresh_token))
        assert is_binary(response.refresh_token)
      end)

    assert_receive {:second, {:error, %OAuthError{error: :invalid_request}}}
    assert log =~ "refresh continuation was invoked more than once"
    assert generations(ctx.family_id) == [0, 1]
  end

  test "a success the host assembled without the continuation is refused", ctx do
    callback = fn _context, _continuation -> {:ok, %{access_token: "forged"}, []} end
    config = config(refresh_completion: callback)

    log =
      capture_log(fn ->
        assert {:error, %OAuthError{error: :invalid_request}, _events} =
                 issue(config, refresh_request(config, ctx.refresh_token))
      end)

    assert log =~ "refresh completion callback returned without invoking the continuation"
    assert generations(ctx.family_id) == [0]

    plain = config()
    assert {:ok, _response, _events} = Token.issue(plain, refresh_request(plain, ctx.refresh_token))
  end

  test "reuse detection survives a host that rolls back on every error", ctx do
    plain = config()
    assert {:ok, rotated, _events} = Token.issue(plain, refresh_request(plain, ctx.refresh_token))

    callback = fn _context, continuation ->
      case TestRepo.transaction(fn ->
             case continuation.() do
               {:ok, _response, _events} = ok -> ok
               error -> TestRepo.rollback(error)
             end
           end) do
        {:ok, result} -> result
        {:error, error} -> error
      end
    end

    config = config(refresh_completion: callback)

    # The already rotated token is presented again: reuse.
    assert {:error, %OAuthError{error: :invalid_grant}, events} =
             issue(config, refresh_request(config, ctx.refresh_token))

    assert Enum.any?(events, &(&1.name == :refresh_reuse_detected))

    # The host's rollback took the in-transaction revocation with it; the
    # family is revoked all the same, so the successor is dead.
    assert generations(ctx.family_id) == []

    assert {:error, %OAuthError{error: :invalid_grant}, _events} =
             issue(plain, refresh_request(plain, rotated.refresh_token))
  end

  test "a principal denial revokes the family even when the host rolls back", ctx do
    callback = fn _context, continuation ->
      case TestRepo.transaction(fn ->
             case continuation.() do
               {:ok, _response, _events} = ok -> ok
               error -> TestRepo.rollback(error)
             end
           end) do
        {:ok, result} -> result
        {:error, error} -> error
      end
    end

    config =
      config(
        refresh_completion: callback,
        build_refresh_principal: fn _client, _context -> {:error, :invalid_grant} end
      )

    assert {:error, %OAuthError{error: :invalid_grant}, _events} =
             issue(config, refresh_request(config, ctx.refresh_token))

    assert generations(ctx.family_id) == []

    plain = config()

    assert {:error, %OAuthError{error: :invalid_grant}, _events} =
             issue(plain, refresh_request(plain, ctx.refresh_token))
  end

  # `Token.issue/2` answers `{:error, error, events}`; some paths answer a
  # two-tuple. Normalize for the assertions above.
  defp issue(config, request) do
    case Token.issue(config, request) do
      {:error, error} -> {:error, error, []}
      other -> other
    end
  end

  defp invalid_grant, do: OAuthError.new(:invalid_grant, "the grant is no longer valid")

  defp generations(family_id) do
    TestRepo.all(from r in RefreshToken, where: r.family_id == ^family_id, select: r.generation, order_by: r.generation)
  end

  defp config(overrides \\ []) do
    [
      issuer: "https://issuer.example",
      audience: "https://issuer.example",
      keystore: __MODULE__.Keystore,
      repo: TestRepo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _client, _given -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      client_public?: fn client -> Map.get(client, :public?, false) end,
      client_id: fn client -> client.id end,
      authorize_scope: fn _client, requested -> {:ok, requested} end,
      principal_kinds: [@client_kind],
      build_principal: fn client, subject, scope ->
        %{kind: "client", sub: subject, scopes: scope, claims: %{"client_id" => client.id}}
      end,
      code_store: EctoCodeStore,
      refresh_store: RefreshStore,
      refresh_token_rotation_grace_seconds: 0,
      issue_refresh_token?: fn _client, _scope -> true end
    ]
    |> Keyword.merge(overrides)
    |> Config.new()
  end

  defp issue_code do
    {:ok, code} =
      AuthorizationCode.issue(
        EctoCodeStore,
        %{
          client_id: "client-1",
          redirect_uri: @redirect_uri,
          scope: ["offline_access"],
          subject: "oc_user-1",
          code_challenge: @code_challenge,
          code_challenge_method: "S256",
          family_id: "family-refresh-completion",
          claims: %{}
        },
        []
      )

    code
  end

  defp code_request(config, code) do
    request(config, "authorization_code", %{
      "code" => code,
      "code_verifier" => @code_verifier,
      "redirect_uri" => @redirect_uri
    })
  end

  defp refresh_request(config, refresh_token) do
    request(config, "refresh_token", %{"refresh_token" => refresh_token})
  end

  defp request(config, grant_type, params) do
    %Request{
      config: config,
      client: @client,
      client_auth_method: :client_secret_basic,
      grant_type: grant_type,
      params: params,
      request_client_id: "client-1",
      sender_constraint_input: %{
        dpop_proof: nil,
        mtls_cert_der: nil,
        http_uri: "https://issuer.example/oauth/token",
        http_method: "POST"
      }
    }
  end
end
