defmodule AttestoPhoenix.AuthorizationServer.AuthorizationCodeCompletionTest do
  @moduledoc """
  Transaction-boundary coverage for authorization-code completion.

  These tests run against the package's real Ecto code and refresh stores on an
  unboxed SQL sandbox connection. That makes the host callback's
  `Repo.transaction/1` the actual transaction boundary: redemption commits
  before the callback, while every continuation write either commits together
  or rolls back together.
  """

  use ExUnit.Case, async: false

  import Ecto.Query
  import ExUnit.CaptureLog

  alias Attesto.AuthorizationCode
  alias AttestoPhoenix.AuthorizationCodePrivateContext, as: PrivateContext
  alias AttestoPhoenix.AuthorizationServer.Token
  alias AttestoPhoenix.AuthorizationServer.Token.Request
  alias AttestoPhoenix.{Config, OAuthError, TestRepo}
  alias AttestoPhoenix.Schema.{Authorization, LogoutSession, RefreshToken}
  alias AttestoPhoenix.Store.{EctoCodeStore, EctoLogoutSessionStore, EctoRefreshStore}
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

  defmodule CompletionCodeStore do
    @moduledoc false
    @behaviour Attesto.CodeStore

    @impl true
    def put(record), do: EctoCodeStore.put(record)

    @impl true
    def take(code_hash), do: EctoCodeStore.take(code_hash)

    @impl true
    def get(code_hash), do: EctoCodeStore.get(code_hash)

    @impl true
    def mark_consumed(code_hash, meta) do
      notify(:code_finalization)
      EctoCodeStore.mark_consumed(code_hash, meta)
    end

    def record_access_token_for_code(code_hash, jti, expires_at) do
      notify({:access_jti, jti, expires_at})
      EctoCodeStore.record_access_token_for_code(code_hash, jti, expires_at)
    end

    defdelegate revoke_access_token_for_code(code_hash), to: EctoCodeStore

    defdelegate revoke_family_access_tokens(family_id), to: EctoCodeStore

    defp notify(step) do
      if pid = Process.get(:authorization_code_completion_test_pid) do
        send(pid, {:completion_step, step, Process.get(:authorization_code_completion_active) == true})
      end
    end
  end

  defmodule CompletionRefreshStore do
    @moduledoc false
    @behaviour Attesto.RefreshStore

    @impl true
    def insert(record) do
      notify({:refresh_insert, record.family_id, record.generation})
      EctoRefreshStore.insert(record)
    end

    @impl true
    def get(token_hash), do: EctoRefreshStore.get(token_hash)

    @impl true
    def rotate(parent_hash, child, successor, opts), do: EctoRefreshStore.rotate(parent_hash, child, successor, opts)

    @impl true
    def revoke_family(family_id), do: EctoRefreshStore.revoke_family(family_id)

    defp notify(step) do
      if pid = Process.get(:authorization_code_completion_test_pid) do
        send(pid, {:completion_step, step, Process.get(:authorization_code_completion_active) == true})
      end
    end
  end

  defmodule FailingRefreshStore do
    @moduledoc false
    @behaviour Attesto.RefreshStore

    @impl true
    def insert(record) do
      notify({:refresh_insert_failed, record.family_id, record.generation})
      {:error, :family_revoked}
    end

    @impl true
    def get(token_hash), do: EctoRefreshStore.get(token_hash)

    @impl true
    def rotate(parent_hash, child, successor, opts), do: EctoRefreshStore.rotate(parent_hash, child, successor, opts)

    @impl true
    def revoke_family(family_id), do: EctoRefreshStore.revoke_family(family_id)

    defp notify(step) do
      if pid = Process.get(:authorization_code_completion_test_pid) do
        send(pid, {:completion_step, step, Process.get(:authorization_code_completion_active) == true})
      end
    end
  end

  defmodule FailingAccessJTIStore do
    @moduledoc false
    @behaviour Attesto.CodeStore

    @impl true
    defdelegate put(record), to: EctoCodeStore

    @impl true
    defdelegate take(code_hash), to: EctoCodeStore

    @impl true
    defdelegate get(code_hash), to: EctoCodeStore

    @impl true
    defdelegate mark_consumed(code_hash, meta), to: EctoCodeStore

    def record_access_token_for_code(_code_hash, _jti, _expires_at) do
      logout_count = TestRepo.aggregate(LogoutSession, :count)
      notify({:access_jti_failed, logout_count})
      raise "injected access JTI failure"
    end

    defdelegate revoke_access_token_for_code(code_hash), to: EctoCodeStore

    defdelegate revoke_family_access_tokens(family_id), to: EctoCodeStore

    defp notify(step) do
      if pid = Process.get(:authorization_code_completion_test_pid) do
        send(pid, {:completion_step, step, Process.get(:authorization_code_completion_active) == true})
      end
    end
  end

  defmodule FailingFinalizationCodeStore do
    @moduledoc false
    @behaviour Attesto.CodeStore

    @impl true
    defdelegate put(record), to: EctoCodeStore

    @impl true
    defdelegate take(code_hash), to: EctoCodeStore

    @impl true
    defdelegate get(code_hash), to: EctoCodeStore

    defdelegate record_access_token_for_code(code_hash, jti, expires_at), to: EctoCodeStore

    defdelegate revoke_access_token_for_code(code_hash), to: EctoCodeStore

    defdelegate revoke_family_access_tokens(family_id), to: EctoCodeStore

    @impl true
    def mark_consumed(code_hash, _meta) do
      row = TestRepo.get_by!(Authorization, code_hash: code_hash)

      notify({
        :finalization_failed,
        is_binary(row.access_token_jti),
        TestRepo.aggregate(RefreshToken, :count),
        TestRepo.aggregate(LogoutSession, :count)
      })

      raise "injected code finalization failure"
    end

    defp notify(step) do
      if pid = Process.get(:authorization_code_completion_test_pid) do
        send(pid, {:completion_step, step, Process.get(:authorization_code_completion_active) == true})
      end
    end
  end

  defmodule AgentCodeStore do
    @moduledoc false
    @behaviour Attesto.CodeStore

    def child_spec(_opts) do
      %{id: __MODULE__, start: {__MODULE__, :start_link, [[]]}}
    end

    def start_link(_opts), do: Agent.start_link(fn -> %{} end, name: __MODULE__)

    @impl true
    def put(record) do
      entry = %{record: record, consumed: false, consumed_success: false, meta: nil, access_token_jti: nil}
      Agent.update(__MODULE__, &Map.put(&1, record.code_hash, entry))
      :ok
    end

    @impl true
    def get(code_hash) do
      Agent.get(__MODULE__, fn state ->
        case Map.get(state, code_hash) do
          %{consumed: false, record: record} -> {:ok, record}
          _other -> :error
        end
      end)
    end

    @impl true
    def take(code_hash) do
      Agent.get_and_update(__MODULE__, fn state ->
        case Map.get(state, code_hash) do
          %{consumed: false, record: record} = entry ->
            {{:ok, record}, Map.put(state, code_hash, %{entry | consumed: true})}

          %{consumed_success: true, meta: meta} ->
            {{:error, :consumed, meta}, state}

          _other ->
            {:error, state}
        end
      end)
    end

    @impl true
    def mark_consumed(code_hash, meta) do
      Agent.update(__MODULE__, fn state ->
        Map.update!(state, code_hash, &%{&1 | consumed_success: true, meta: meta})
      end)

      :ok
    end

    def record_access_token_for_code(code_hash, jti, _expires_at) do
      Agent.update(__MODULE__, fn state ->
        Map.update!(state, code_hash, &%{&1 | access_token_jti: jti})
      end)

      :ok
    end

    def revoke_access_token_for_code(_code_hash), do: :ok

    def revoke_family_access_tokens(_family_id), do: :ok

    def entry(code) do
      Agent.get(__MODULE__, &Map.fetch!(&1, Attesto.Secret.hash(code)))
    end
  end

  setup do
    owner = Sandbox.start_owner!(TestRepo, sandbox: false)
    start_supervised!(AgentCodeStore)

    TestRepo.delete_all(LogoutSession)
    TestRepo.delete_all(RefreshToken)
    TestRepo.delete_all(Authorization)

    Application.put_env(:attesto_phoenix, __MODULE__.Keystore, signing_pem: @signing_pem)

    # These tests drive the bundled stores through the package-level `:repo`
    # contract. A synthetic host's `:otp_app` pointer left behind by another
    # test would send `Config.table_prefix/0` down `resolve!/0`, which builds a
    # full host config and raises on the missing `:issuer`/`:keystore`/`:repo`.
    # Pin both for the duration rather than inheriting whatever global state the
    # async phase happened to leave.
    previous_otp_app = Application.fetch_env(:attesto_phoenix, :otp_app)
    Application.delete_env(:attesto_phoenix, :otp_app)
    Application.put_env(:attesto_phoenix, :repo, TestRepo)

    Process.put(:authorization_code_completion_test_pid, self())

    on_exit(fn ->
      :ok = Sandbox.allow(TestRepo, owner, self())
      TestRepo.delete_all(LogoutSession)
      TestRepo.delete_all(RefreshToken)
      TestRepo.delete_all(Authorization)
      Sandbox.stop_owner(owner)
      Application.delete_env(:attesto_phoenix, __MODULE__.Keystore)

      case previous_otp_app do
        {:ok, value} -> Application.put_env(:attesto_phoenix, :otp_app, value)
        :error -> Application.delete_env(:attesto_phoenix, :otp_app)
      end

      Application.put_env(:attesto_phoenix, :repo, TestRepo)
    end)

    :ok
  end

  test "the absent callback preserves direct completion and all writes" do
    family_id = "family-default"
    code = issue_code(family_id)
    config = config()

    assert Config.authorization_code_completion_fun(config) == nil
    assert {:ok, response, _events} = Token.issue(config, code_request(config, code))
    assert is_binary(response.access_token)
    assert is_binary(response.refresh_token)

    row = authorization_by_code!(code)
    assert row.consumed_at
    assert row.consumed_success
    assert row.access_token_jti == claim!(response.access_token, "jti")

    # Core 2.0 mints a fresh refresh family and binds it to the row, replacing
    # the authorization provenance id.
    refresh_family = row.family_id
    assert is_binary(refresh_family)
    refute refresh_family == family_id

    assert %RefreshToken{generation: 0} =
             TestRepo.one!(from r in RefreshToken, where: r.family_id == ^refresh_family)
  end

  test "the callback receives only stable identifiers and spans every completion step" do
    test_pid = self()
    family_id = "family-transaction"
    private_context = %{"security_epoch" => 42}
    code = issue_code(family_id, ["openid", "offline_access"], private_context: private_context)

    config =
      config(
        authorization_code_completion: transactional_completion(test_pid),
        build_principal: fn client, subject, scope ->
          send(test_pid, {:completion_step, :build_principal, completion_active?()})
          principal(client, subject, scope)
        end,
        build_id_token_claims: fn _client, _subject, _scope, _requested ->
          send(test_pid, {:completion_step, :build_id_token_claims, completion_active?()})
          %{}
        end
      )

    assert {:ok, response, _events} = Token.issue(config, code_request(config, code))
    assert is_binary(response.access_token)
    assert is_binary(response.id_token)
    assert is_binary(response.refresh_token)

    assert_receive {:completion_context,
                    %{
                      client_id: "client-1",
                      subject: "oc_user-1",
                      family_id: ^family_id,
                      private_context: ^private_context
                    } = context}

    assert map_size(context) == 4
    assert_receive {:completion_step, :transaction_started, true}
    assert_receive {:completion_step, :build_principal, true}
    assert_receive {:completion_step, :build_id_token_claims, true}
    assert_receive {:completion_step, {:access_jti, jti, expires_at}, true}
    assert is_binary(jti)
    assert is_integer(expires_at)
    assert_receive {:completion_step, {:refresh_insert, refresh_family, 0}, true}
    assert is_binary(refresh_family)
    assert_receive {:completion_step, :code_finalization, true}
    assert_receive :authorization_code_completion_committed
  end

  test "an MFA completion callback receives configured extra arguments through the token path" do
    family_id = "family-mfa-completion"
    private_context = %{"security_epoch" => 43}
    code = issue_code(family_id, ["offline_access"], private_context: private_context)

    config =
      config(authorization_code_completion: {__MODULE__, :mfa_completion, [self(), :configured_marker]})

    assert {:ok, response, _events} = Token.issue(config, code_request(config, code))
    assert is_binary(response.access_token)
    assert is_binary(response.refresh_token)

    assert_receive {:mfa_completion, :configured_marker, %{family_id: ^family_id, private_context: ^private_context}}
  end

  test "a host rollback after the continuation leaves no JTI, refresh, or finalization writes" do
    family_id = "family-host-rollback"
    private_context = %{"security_epoch" => 7}
    code = issue_code(family_id, ["offline_access"], private_context: private_context)

    callback = fn context, continuation ->
      assert context.family_id == family_id
      assert context.private_context == private_context

      assert {:error, :host_policy_changed} =
               TestRepo.transaction(fn ->
                 Process.put(:authorization_code_completion_active, true)

                 try do
                   assert {:ok, _response, _events} = continuation.()

                   inside = authorization_by_code!(code)
                   assert inside.access_token_jti
                   assert inside.consumed_success

                   assert TestRepo.aggregate(
                            from(r in RefreshToken, where: r.family_id == ^inside.family_id),
                            :count
                          ) == 1

                   TestRepo.rollback(:host_policy_changed)
                 after
                   Process.delete(:authorization_code_completion_active)
                 end
               end)

      {:error, :host_policy_changed}
    end

    config = config(authorization_code_completion: callback)

    log =
      capture_log(fn ->
        assert {:error, %OAuthError{error: :invalid_request}, _events} =
                 Token.issue(config, code_request(config, code))
      end)

    assert log =~ "returned an error after the continuation succeeded"
    assert log =~ "code may already be finalized"
    assert log =~ "revoke that response's access token and refresh family"
    refute log =~ "host_policy_changed"

    assert_spent_without_completion(family_id)
  end

  test "private context is completion-only and leaves OIDC and token claims unchanged" do
    test_pid = self()
    family_id = "family-private-nondisclosure"
    private_context = %{"mobile_auth_security_epoch" => 42, "marker" => "never-token-visible"}

    code =
      issue_code(family_id, ["openid", "offline_access"],
        private_context: private_context,
        claims: %{
          "nonce" => "oidc-nonce",
          "auth_time" => 1_700_000_000,
          "acr" => "urn:example:loa:2",
          "amr" => ["pwd"]
        }
      )

    config =
      config(
        authorization_code_completion: fn context, continuation ->
          send(test_pid, {:private_context_at_completion, context.private_context})
          continuation.()
        end
      )

    assert {:ok, response, _events} = Token.issue(config, code_request(config, code))
    assert_receive {:private_context_at_completion, ^private_context}

    access_claims = claims!(response.access_token)
    id_claims = claims!(response.id_token)

    refute Map.has_key?(access_claims, "mobile_auth_security_epoch")
    refute Map.has_key?(access_claims, "marker")
    refute Map.has_key?(access_claims, "private_context")
    refute Map.has_key?(id_claims, "mobile_auth_security_epoch")
    refute Map.has_key?(id_claims, "marker")
    refute Map.has_key?(id_claims, "private_context")
    assert id_claims["nonce"] == "oidc-nonce"
    assert id_claims["auth_time"] == 1_700_000_000
    assert id_claims["acr"] == "urn:example:loa:2"
    assert id_claims["amr"] == ["pwd"]

    assert {:ok, refreshed, _events} = Token.issue(config, refresh_request(config, response.refresh_token))
    refreshed_claims = claims!(refreshed.access_token)
    refute Map.has_key?(refreshed_claims, "mobile_auth_security_epoch")
    refute Map.has_key?(refreshed_claims, "marker")
    refute Map.has_key?(refreshed_claims, "private_context")
    refute Map.has_key?(refreshed_claims, PrivateContext.claims_key())
    refute_received {:private_context_at_completion, _context}
  end

  test "continuation provenance keeps only a digest and outcome outside the mailbox" do
    test_pid = self()
    family_id = "family-digest-marker"
    code = issue_code(family_id)

    callback = fn _context, continuation ->
      {:ok, response, _events} = result = continuation.()
      keys = Process.get_keys()

      key =
        Enum.find(keys, fn
          {Token, :authorization_code_continuation, ref} when is_reference(ref) -> true
          _other -> false
        end)

      assert {digest, :succeeded} = state = Process.get(key)
      assert is_binary(digest)
      assert byte_size(digest) == 32
      refute inspect(state) =~ response.access_token

      {:messages, messages} = Process.info(self(), :messages)

      refute Enum.any?(messages, &match?({_ref, :authorization_code_continuation_produced, _, _}, &1))
      send(test_pid, {:continuation_state, key, state})
      result
    end

    config = config(authorization_code_completion: callback)
    assert {:ok, response, _events} = Token.issue(config, code_request(config, code))
    assert is_binary(response.access_token)

    assert_receive {:continuation_state, {Token, :authorization_code_continuation, ref} = key, {digest, :succeeded}}

    assert is_reference(ref)
    assert byte_size(digest) == 32
    assert Process.get(key) == nil
  end

  test "a broad receive after the continuation cannot erase its provenance" do
    family_id = "family-broad-receive"
    code = issue_code(family_id)
    test_pid = self()

    callback = fn _context, continuation ->
      # Keep the store wrappers from sending their ordinary test notifications
      # so the sentinel below is the only mailbox message. Before provenance
      # moved out of the mailbox, the marker preceded this sentinel and a broad
      # receive consumed it, falsely reporting that the continuation never ran.
      Process.delete(:authorization_code_completion_test_pid)

      try do
        result = continuation.()
        send(self(), :broad_receive_sentinel)

        receive do
          _any_message -> :ok
        after
          100 -> flunk("expected the mailbox sentinel")
        end

        result
      after
        Process.put(:authorization_code_completion_test_pid, test_pid)
      end
    end

    config = config(authorization_code_completion: callback)

    assert {:ok, response, _events} = Token.issue(config, code_request(config, code))
    assert is_binary(response.access_token)
    assert authorization_by_code!(code).consumed_success
    refute_received :broad_receive_sentinel
  end

  test "a callback refusal runs before principal construction and leaves completion empty" do
    test_pid = self()
    family_id = "family-refused"
    code = issue_code(family_id)

    config =
      config(
        authorization_code_completion: fn context, _continuation ->
          send(test_pid, {:completion_refused, context})

          {:error,
           OAuthError.new(
             :invalid_grant,
             "subject authorization is no longer valid"
           )}
        end,
        build_principal: fn client, subject, scope ->
          send(test_pid, :build_principal_invoked)
          principal(client, subject, scope)
        end
      )

    log =
      capture_log(fn ->
        assert {:error, %OAuthError{error: :invalid_grant}, _events} =
                 Token.issue(config, code_request(config, code))
      end)

    refute log =~ "authorization code completion callback failed"

    assert_receive {:completion_refused,
                    %{
                      client_id: "client-1",
                      subject: "oc_user-1",
                      family_id: ^family_id,
                      private_context: nil
                    }}

    refute_received :build_principal_invoked
    assert_spent_without_completion(family_id)
  end

  test "a downstream refresh failure rolls the earlier JTI write back and does not finalize" do
    family_id = "family-refresh-failure"
    code = issue_code(family_id)

    config =
      config(
        refresh_store: FailingRefreshStore,
        authorization_code_completion: transactional_completion(self())
      )

    capture_log(fn ->
      assert {:error, %OAuthError{error: :invalid_request}, _events} =
               Token.issue(config, code_request(config, code))
    end)

    assert_receive {:completion_step, {:access_jti, _jti, _expires_at}, true}
    assert_receive {:completion_step, {:refresh_insert_failed, _refresh_family, 0}, true}
    assert_receive :authorization_code_completion_rolled_back
    refute_received {:completion_step, :code_finalization, _active}
    assert_spent_without_completion(family_id)
  end

  test "the continuation is one-shot within the owner process" do
    family_id = "family-double-call"
    code = issue_code(family_id)
    test_pid = self()

    callback = fn _context, continuation ->
      assert {:error, {:second_call, %OAuthError{} = second_call_error}} =
               TestRepo.transaction(fn ->
                 Process.put(:authorization_code_completion_active, true)

                 try do
                   assert {:ok, _response, _events} = continuation.()
                   assert {:error, %OAuthError{} = error} = continuation.()
                   TestRepo.rollback({:second_call, error})
                 after
                   Process.delete(:authorization_code_completion_active)
                 end
               end)

      {:error, second_call_error}
    end

    config =
      config(
        authorization_code_completion: callback,
        build_principal: fn client, subject, scope ->
          send(test_pid, :guarded_build_principal)
          principal(client, subject, scope)
        end
      )

    assert {:error, %OAuthError{error: :invalid_request}, _events} =
             Token.issue(config, code_request(config, code))

    assert_receive :guarded_build_principal
    refute_receive :guarded_build_principal
    assert_receive {:completion_step, {:access_jti, _jti, _expires_at}, true}
    assert_receive {:completion_step, {:refresh_insert, refresh_family, 0}, true}
    assert is_binary(refresh_family)
    assert_receive {:completion_step, :code_finalization, true}
    assert_spent_without_completion(family_id)
  end

  test "an escaped continuation is closed when the callback returns" do
    family_id = "family-escaped"
    code = issue_code(family_id)

    config =
      config(
        authorization_code_completion: fn _context, continuation ->
          send(self(), {:escaped_continuation, continuation})
          {:error, :host_declined}
        end,
        build_principal: fn _client, _subject, _scope ->
          flunk("an escaped continuation must not build a principal")
        end
      )

    capture_log(fn ->
      assert {:error, %OAuthError{error: :invalid_request}, _events} =
               Token.issue(config, code_request(config, code))
    end)

    assert_receive {:escaped_continuation, escaped}
    assert {:error, %OAuthError{error: :invalid_request}} = escaped.()
    assert_spent_without_completion(family_id)
  end

  test "a cross-process continuation invocation is rejected before completion" do
    family_id = "family-cross-process"
    code = issue_code(family_id)

    config =
      config(
        authorization_code_completion: fn _context, continuation ->
          Task.async(continuation) |> Task.await()
        end,
        build_principal: fn _client, _subject, _scope ->
          flunk("a cross-process continuation must not build a principal")
        end
      )

    log =
      capture_log(fn ->
        assert {:error, %OAuthError{error: :invalid_request}, _events} =
                 Token.issue(config, code_request(config, code))
      end)

    assert log =~ "does not own it"
    assert_spent_without_completion(family_id)
  end

  test "an invalid callback result is normalized without completion writes" do
    family_id = "family-invalid-callback-result"
    code = issue_code(family_id)
    config = config(authorization_code_completion: fn _context, _continuation -> :invalid_result end)

    log =
      capture_log(fn ->
        assert {:error, %OAuthError{error: :invalid_request}, _events} =
                 Token.issue(config, code_request(config, code))
      end)

    assert log =~ "authorization code completion callback returned without invoking the continuation"
    refute log =~ "invalid_result"
    assert_spent_without_completion(family_id)
  end

  test "a callback that never invokes the continuation cannot fabricate a token response" do
    family_id = "family-forged-response"
    code = issue_code(family_id)

    # The continuation is the only thing that mints, records the access jti,
    # inserts generation-0 refresh, and finalizes the code. A callback that
    # assembles its own success must not be served as a token response.
    forged = %{
      access_token: "forged.access.token",
      token_type: "Bearer",
      expires_in: 900,
      scope: "offline_access"
    }

    config = config(authorization_code_completion: fn _context, _continuation -> {:ok, forged, []} end)

    log =
      capture_log(fn ->
        assert {:error, %OAuthError{error: :invalid_request}, _events} =
                 Token.issue(config, code_request(config, code))
      end)

    assert log =~ "returned without invoking the continuation"
    refute log =~ "forged.access.token"
    assert_spent_without_completion(family_id)
  end

  test "a committed Repo.transaction wrapper is unwrapped rather than failing after commit" do
    family_id = "family-transaction-wrapper"
    code = issue_code(family_id, ["offline_access"])

    # The most natural host mistake: return the `Repo.transaction/1` result
    # directly instead of the continuation's. The commit already took the mint,
    # refresh insert, and code finalization with it, so failing here would
    # finalize the code and then score the client's retry as a replay.
    callback = fn _context, continuation -> TestRepo.transaction(fn -> continuation.() end) end

    config = config(authorization_code_completion: callback)

    assert {:ok, response, _events} = Token.issue(config, code_request(config, code))
    assert is_binary(response.access_token)
    assert is_binary(response.refresh_token)

    row = authorization_by_code!(code)
    assert row.consumed_success
    assert row.access_token_jti
    assert TestRepo.aggregate(from(r in RefreshToken, where: r.family_id == ^row.family_id), :count) == 1
  end

  test "a Repo.transaction wrapper around a failed continuation is unwrapped" do
    family_id = "family-failed-transaction-wrapper"
    code = issue_code(family_id)

    callback = fn _context, continuation ->
      TestRepo.transaction(fn -> continuation.() end)
    end

    config =
      config(
        refresh_store: FailingRefreshStore,
        authorization_code_completion: callback
      )

    log =
      capture_log(fn ->
        assert {:error, %OAuthError{error: :invalid_request}, _events} =
                 Token.issue(config, code_request(config, code))
      end)

    refute log =~ "authorization code completion callback failed"
    row = authorization!(family_id)
    assert row.consumed_at
    refute row.consumed_success
    assert is_binary(row.access_token_jti)
    assert TestRepo.aggregate(RefreshToken, :count) == 0
  end

  test "nested transaction wrappers are refused and report the committed-result retry hazard" do
    family_id = "family-nested-transaction-wrapper"
    code = issue_code(family_id, ["offline_access"])

    callback = fn _context, continuation ->
      TestRepo.transaction(fn ->
        TestRepo.transaction(fn -> continuation.() end)
      end)
    end

    config = config(authorization_code_completion: callback)

    log =
      capture_log(fn ->
        assert {:error, %OAuthError{error: :invalid_request}, _events} =
                 Token.issue(config, code_request(config, code))
      end)

    assert log =~ "returned a different result after the continuation succeeded"
    assert log =~ "revoke that response's access token and refresh family"

    row = authorization_by_code!(code)
    assert row.consumed_success
    assert is_binary(row.access_token_jti)
    assert TestRepo.aggregate(from(r in RefreshToken, where: r.family_id == ^row.family_id), :count) == 1
  end

  test "a callback that substitutes a different result after running the continuation is refused" do
    family_id = "family-substituted-response"
    code = issue_code(family_id)

    callback = fn _context, continuation ->
      assert {:ok, _response, _events} = continuation.()
      {:ok, %{access_token: "substituted.access.token", token_type: "Bearer"}, []}
    end

    config = config(authorization_code_completion: callback)

    log =
      capture_log(fn ->
        assert {:error, %OAuthError{error: :invalid_request}, _events} =
                 Token.issue(config, code_request(config, code))
      end)

    assert log =~ "returned a different result after the continuation succeeded"
    assert log =~ "code may already be finalized"
    assert log =~ "revoke that response's access token and refresh family"
    refute log =~ "substituted.access.token"
  end

  test "a code carrying private context is refused when no completion callback is configured" do
    family_id = "family-context-without-callback"
    code = issue_code(family_id, ["offline_access"], private_context: %{"security_epoch" => 3})

    # Config skew (rolling deploy, behaviour module not loaded on this node).
    # The host's fail-closed completion policy cannot run, so issuing tokens
    # would silently skip it.
    config = config(authorization_code_completion: nil)

    log =
      capture_log(fn ->
        assert {:error, %OAuthError{error: :invalid_grant}, _events} =
                 Token.issue(config, code_request(config, code))
      end)

    assert log =~ "no :authorization_code_completion callback is configured"
    refute log =~ "security_epoch"
    assert_spent_without_completion(family_id)
  end

  test "callback exceptions propagate and close an escaped continuation" do
    family_id = "family-callback-exception"
    code = issue_code(family_id)

    config =
      config(
        authorization_code_completion: fn _context, continuation ->
          send(self(), {:exception_continuation, continuation})
          raise "injected host callback failure"
        end
      )

    assert_raise RuntimeError, "injected host callback failure", fn ->
      Token.issue(config, code_request(config, code))
    end

    assert_receive {:exception_continuation, escaped}
    assert {:error, %OAuthError{error: :invalid_request}} = escaped.()
    assert_spent_without_completion(family_id)
  end

  test "callback termination after a committed success logs the retry hazard and preserves the stacktrace" do
    test_pid = self()

    cases = [
      {:error, "family-post-success-raise", "private exception reason", "raised"},
      {:throw, "family-post-success-throw", {:private_throw_reason, 42}, "threw"},
      {:exit, "family-post-success-exit", {:private_exit_reason, 43}, "exited"}
    ]

    Enum.each(cases, fn {kind, family_id, reason, verb} ->
      context_sentinel = "private-context-#{kind}"
      code = issue_code(family_id, ["offline_access"], private_context: %{"marker" => context_sentinel})

      callback = fn context, continuation ->
        assert context.private_context == %{"marker" => context_sentinel}

        assert {:ok, {:ok, _response, _events}} =
                 TestRepo.transaction(fn -> continuation.() end)

        key = continuation_state_key!()
        assert {_digest, :succeeded} = Process.get(key)
        send(test_pid, {:post_success_termination_key, kind, key})

        terminate_completion_callback(kind, reason)
      end

      config = config(authorization_code_completion: callback)

      log =
        capture_log(fn ->
          caught =
            try do
              Token.issue(config, code_request(config, code))
              flunk("the callback termination must propagate")
            catch
              caught_kind, caught_reason ->
                {caught_kind, caught_reason, __STACKTRACE__}
            end

          assert {^kind, caught_reason, stacktrace} = caught

          case kind do
            :error -> assert %RuntimeError{message: ^reason} = caught_reason
            _other -> assert caught_reason == reason
          end

          assert Enum.any?(stacktrace, fn
                   {__MODULE__, :terminate_completion_callback, 2, _location} -> true
                   _frame -> false
                 end)
        end)

      assert log =~ "authorization code completion callback #{verb} after the continuation succeeded"
      assert log =~ "code may already be finalized"
      assert log =~ "client retry"
      assert log =~ "revoke that response's access token and refresh family"
      refute log =~ context_sentinel
      reason_fragment = if is_binary(reason), do: reason, else: reason |> elem(0) |> Atom.to_string()
      refute log =~ reason_fragment

      assert_receive {:post_success_termination_key, ^kind, key}
      assert Process.get(key) == nil

      row = authorization_by_code!(code)
      assert row.consumed_success
      assert is_binary(row.access_token_jti)
      assert is_binary(row.family_id)
      refute row.family_id == family_id
    end)
  end

  test "a throw or exit before continuation does not report a finalized-code retry hazard" do
    cases = [
      {:throw, "family-pre-continuation-throw", {:private_early_throw, 44}},
      {:exit, "family-pre-continuation-exit", {:private_early_exit, 45}}
    ]

    Enum.each(cases, fn {kind, family_id, reason} ->
      code = issue_code(family_id)

      config =
        config(
          authorization_code_completion: fn _context, _continuation ->
            terminate_completion_callback(kind, reason)
          end
        )

      log =
        capture_log(fn ->
          caught =
            try do
              Token.issue(config, code_request(config, code))
              flunk("the callback termination must propagate")
            catch
              caught_kind, caught_reason -> {caught_kind, caught_reason}
            end

          assert {^kind, ^reason} = caught
        end)

      refute log =~ "after the continuation succeeded"
      refute log =~ "code may already be finalized"
      reason_name = reason |> elem(0) |> Atom.to_string()
      refute log =~ reason_name
      assert_spent_without_completion(family_id)
    end)
  end

  test "a JTI-store exception rolls back an earlier logout-session write" do
    family_id = "family-jti-failure"

    code =
      issue_code(family_id, ["openid", "offline_access"],
        code_store: FailingAccessJTIStore,
        claims: %{"sid" => "sid-jti-failure"}
      )

    config = transactional_logout_config(FailingAccessJTIStore)

    assert_raise RuntimeError, "injected access JTI failure", fn ->
      Token.issue(config, code_request(config, code))
    end

    assert_receive {:completion_step, {:access_jti_failed, 1}, true}
    refute_received {:completion_step, {:refresh_insert, _refresh_family, 0}, _active}
    refute_received {:completion_step, :code_finalization, _active}
    assert_spent_without_completion(family_id)
  end

  test "a finalization exception rolls back JTI, refresh, and logout-session writes" do
    family_id = "family-finalization-failure"

    code =
      issue_code(family_id, ["openid", "offline_access"],
        code_store: FailingFinalizationCodeStore,
        claims: %{"sid" => "sid-finalization-failure"}
      )

    config = transactional_logout_config(FailingFinalizationCodeStore)

    assert_raise RuntimeError, "injected code finalization failure", fn ->
      Token.issue(config, code_request(config, code))
    end

    assert_receive {:completion_step, {:refresh_insert, refresh_family, 0}, true}
    assert is_binary(refresh_family)
    assert_receive {:completion_step, {:finalization_failed, true, 1, 1}, true}
    assert_spent_without_completion(family_id)
  end

  test "private context completes end-to-end through a custom Agent code store" do
    family_id = "family-agent-store"
    private_context = %{"security_epoch" => 91}

    code =
      issue_code(family_id, ["read"],
        code_store: AgentCodeStore,
        private_context: private_context
      )

    config =
      config(
        code_store: AgentCodeStore,
        refresh_store: nil,
        authorization_code_completion: fn context, continuation ->
          send(self(), {:agent_completion_context, context})
          continuation.()
        end
      )

    assert {:ok, response, _events} = Token.issue(config, code_request(config, code))
    assert_receive {:agent_completion_context, %{family_id: ^family_id, private_context: ^private_context}}
    refute claim!(response.access_token, "security_epoch")
    refute claim!(response.access_token, "private_context")

    entry = AgentCodeStore.entry(code)
    assert entry.consumed
    assert entry.consumed_success
    assert is_binary(entry.access_token_jti)
    assert entry.record.data.claims[PrivateContext.claims_key()] == private_context
    # The canonical grant data admits no sibling key (core enforces exactly nine).
    refute Map.has_key?(entry.record.data, :attesto_phoenix_private_context)
  end

  test "retry after a committed-success substitution revokes only that response lineage" do
    unrelated_code = issue_code("unrelated-authorization-provenance")
    unrelated_config = config()

    assert {:ok, _unrelated_response, _events} =
             Token.issue(unrelated_config, code_request(unrelated_config, unrelated_code))

    unrelated_row = authorization_by_code!(unrelated_code)
    refute EctoCodeStore.access_token_revoked?(unrelated_row.access_token_jti)
    assert TestRepo.aggregate(from(r in RefreshToken, where: r.family_id == ^unrelated_row.family_id), :count) == 1

    family_id = "family-commit-then-error"
    code = issue_code(family_id)

    # The host ran the continuation to success and then returned its own error.
    # If it committed rather than rolled back, the code is finalized and the
    # client's retry will be scored as reuse and revoke that response's access
    # token and refresh family. The library cannot see the transaction outcome,
    # so it honours the error but must say so - this was the normalizer's only
    # silent path.
    callback = fn _context, continuation ->
      assert {:ok, _response, _events} = continuation.()
      {:error, %OAuthError{error: :access_denied, error_description: "policy changed", status: 400}}
    end

    config = config(authorization_code_completion: callback)

    log =
      capture_log(fn ->
        assert {:error, %OAuthError{error: :access_denied}, _events} =
                 Token.issue(config, code_request(config, code))
      end)

    assert log =~ "returned an error after the continuation succeeded"
    assert log =~ "revoke that response's access token and refresh family"

    row = authorization_by_code!(code)
    assert row.consumed_success
    assert is_binary(row.access_token_jti)
    assert is_binary(row.family_id)
    refute row.family_id == family_id
    assert TestRepo.aggregate(from(r in RefreshToken, where: r.family_id == ^row.family_id), :count) == 1

    assert {:error, %OAuthError{error: :invalid_grant}, _events} =
             Token.issue(config, code_request(config, code))

    assert EctoCodeStore.access_token_revoked?(row.access_token_jti)
    assert TestRepo.aggregate(from(r in RefreshToken, where: r.family_id == ^row.family_id), :count) == 0
    refute EctoCodeStore.access_token_revoked?(unrelated_row.access_token_jti)
    assert TestRepo.aggregate(from(r in RefreshToken, where: r.family_id == ^unrelated_row.family_id), :count) == 1
  end

  test "a non-OAuth error after a successful continuation is normalized and names the retry hazard" do
    family_id = "family-success-then-generic-error"
    code = issue_code(family_id)
    private_reason = {:private_policy_failure, "do-not-log-this-value"}

    callback = fn _context, continuation ->
      assert {:ok, _response, _events} = continuation.()
      {:error, private_reason}
    end

    config = config(authorization_code_completion: callback)

    log =
      capture_log(fn ->
        assert {:error, %OAuthError{error: :invalid_request}, _events} =
                 Token.issue(config, code_request(config, code))
      end)

    assert log =~ "returned an error after the continuation succeeded"
    assert log =~ "code may already be finalized"
    assert log =~ "client retry"
    assert log =~ "revoke that response's access token and refresh family"
    refute log =~ "private_policy_failure"
    refute log =~ "do-not-log-this-value"

    row = authorization_by_code!(code)
    assert row.consumed_success
    assert is_binary(row.access_token_jti)
  end

  test "an arbitrary return after a successful continuation is normalized and names the retry hazard" do
    family_id = "family-success-then-arbitrary-return"
    code = issue_code(family_id)
    private_value = "arbitrary-private-value"

    callback = fn _context, continuation ->
      assert {:ok, _response, _events} = continuation.()
      {:unexpected_callback_return, private_value}
    end

    config = config(authorization_code_completion: callback)

    log =
      capture_log(fn ->
        assert {:error, %OAuthError{error: :invalid_request}, _events} =
                 Token.issue(config, code_request(config, code))
      end)

    assert log =~ "returned a different result after the continuation succeeded"
    assert log =~ "code may already be finalized"
    assert log =~ "client retry"
    assert log =~ "revoke that response's access token and refresh family"
    refute log =~ "unexpected_callback_return"
    refute log =~ private_value

    row = authorization_by_code!(code)
    assert row.consumed_success
    assert is_binary(row.access_token_jti)
  end

  test "an error remapped after a FAILED continuation is not reported as a revocation hazard" do
    family_id = "family-remapped-failure"
    code = issue_code(family_id)

    # The continuation itself failed, so nothing was minted or finalized. A host
    # remapping that reason is ordinary, and must not raise the commit-then-error
    # alarm.
    callback = fn _context, continuation ->
      assert {:error, %OAuthError{}} = continuation.()
      {:error, %OAuthError{error: :invalid_grant, error_description: "declined", status: 400}}
    end

    config =
      config(
        refresh_store: FailingRefreshStore,
        authorization_code_completion: callback
      )

    log =
      capture_log(fn ->
        assert {:error, %OAuthError{error: :invalid_grant}, _events} =
                 Token.issue(config, code_request(config, code))
      end)

    refute log =~ "returned an error after the continuation succeeded"

    # This callback runs no transaction of its own, so the JTI write the failed
    # continuation made stands; what matters is that the code was never
    # finalized, so the client's retry is not scored as reuse.
    row = authorization!(family_id)
    assert row.consumed_at
    refute row.consumed_success
  end

  test "private context is stripped from the grant before the host sees any claims" do
    test_pid = self()
    family_id = "family-stripped-grant"
    private_context = %{"epoch" => 5, "marker" => "never-host-visible"}

    code =
      issue_code(family_id, ["openid", "offline_access"],
        private_context: private_context,
        claims: %{"claims" => %{"userinfo" => %{"email" => nil}}}
      )

    config =
      config(
        authorization_code_completion: fn _context, continuation -> continuation.() end,
        build_id_token_claims: fn _client, _subject, _scope, requested ->
          send(test_pid, {:requested_claims, requested})
          %{}
        end
      )

    assert {:ok, response, _events} = Token.issue(config, code_request(config, code))

    # The host's claims callback sees the OIDC claims request and nothing else.
    assert_receive {:requested_claims, %{"userinfo" => %{"email" => nil}} = requested}
    refute Map.has_key?(requested, PrivateContext.claims_key())
    refute Map.has_key?(requested, "marker")

    # And the reserved key reaches neither token.
    refute Map.has_key?(claims!(response.access_token), PrivateContext.claims_key())
    refute Map.has_key?(claims!(response.id_token), PrivateContext.claims_key())
  end

  test "a malformed reserved claim fails closed instead of reaching the callback" do
    test_pid = self()
    family_id = "family-malformed-context"

    # Not a map: a tampered or corrupted row, not host state.
    code = issue_code(family_id, ["offline_access"], claims: %{PrivateContext.claims_key() => "not-a-map"})

    config =
      config(
        authorization_code_completion: fn _context, continuation ->
          send(test_pid, :callback_invoked)
          continuation.()
        end
      )

    log =
      capture_log(fn ->
        assert {:error, %OAuthError{error: :invalid_grant}, _events} =
                 Token.issue(config, code_request(config, code))
      end)

    assert log =~ "malformed private context"
    refute_received :callback_invoked
    assert_spent_without_completion(family_id)
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
      build_principal: &principal/3,
      code_store: CompletionCodeStore,
      refresh_store: CompletionRefreshStore,
      issue_refresh_token?: fn _client, _scope -> true end
    ]
    |> Keyword.merge(overrides)
    |> Config.new()
  end

  defp principal(client, subject, scope) do
    %{
      kind: "client",
      sub: subject,
      scopes: scope,
      claims: %{"client_id" => client.id}
    }
  end

  defp issue_code(family_id, scope \\ ["offline_access"], opts \\ []) do
    private_context = Keyword.get(opts, :private_context)
    claims = Keyword.get(opts, :claims, %{})
    code_store = Keyword.get(opts, :code_store, CompletionCodeStore)

    {:ok, claims} = PrivateContext.put(claims, private_context)

    {:ok, code} =
      AuthorizationCode.issue(
        code_store,
        %{
          client_id: "client-1",
          redirect_uri: @redirect_uri,
          scope: scope,
          subject: "oc_user-1",
          code_challenge: @code_challenge,
          code_challenge_method: "S256",
          family_id: family_id,
          claims: claims
        },
        []
      )

    code
  end

  defp transactional_logout_config(code_store) do
    config(
      code_store: code_store,
      authorization_code_completion: transactional_completion(self()),
      logout: [enabled: true],
      terminate_session: fn conn, _context -> {:ok, conn} end,
      logout_session_store: EctoLogoutSessionStore,
      client_frontchannel_logout_uri: fn _client -> "https://client.example/logout" end
    )
  end

  defp code_request(config, code) do
    %Request{
      config: config,
      client: @client,
      client_auth_method: :client_secret_basic,
      grant_type: "authorization_code",
      params: %{
        "code" => code,
        "code_verifier" => @code_verifier,
        "redirect_uri" => @redirect_uri
      },
      request_client_id: "client-1",
      sender_constraint_input: %{
        dpop_proof: nil,
        mtls_cert_der: nil,
        http_uri: "https://issuer.example/oauth/token",
        http_method: "POST"
      }
    }
  end

  defp refresh_request(config, refresh_token) do
    %Request{
      config: config,
      client: @client,
      client_auth_method: :client_secret_basic,
      grant_type: "refresh_token",
      params: %{"refresh_token" => refresh_token},
      request_client_id: "client-1",
      sender_constraint_input: %{
        dpop_proof: nil,
        mtls_cert_der: nil,
        http_uri: "https://issuer.example/oauth/token",
        http_method: "POST"
      }
    }
  end

  @doc false
  def mfa_completion(context, continuation, test_pid, marker) do
    send(test_pid, {:mfa_completion, marker, context})
    continuation.()
  end

  defp transactional_completion(test_pid) do
    fn context, continuation ->
      send(test_pid, {:completion_context, context})

      result =
        TestRepo.transaction(fn ->
          Process.put(:authorization_code_completion_active, true)
          send(test_pid, {:completion_step, :transaction_started, true})

          try do
            case continuation.() do
              {:ok, _response, _events} = success -> success
              {:error, _error} = failure -> TestRepo.rollback(failure)
            end
          after
            Process.delete(:authorization_code_completion_active)
          end
        end)

      case result do
        {:ok, success} ->
          send(test_pid, :authorization_code_completion_committed)
          success

        {:error, {:error, _error} = failure} ->
          send(test_pid, :authorization_code_completion_rolled_back)
          failure

        {:error, reason} ->
          send(test_pid, :authorization_code_completion_rolled_back)
          {:error, reason}
      end
    end
  end

  defp authorization!(family_id), do: TestRepo.get_by!(Authorization, family_id: family_id)

  # After a successful `issue_refresh_and_finalize/6` the row's `family_id` is
  # the freshly generated REFRESH family, not the authorization provenance id
  # the code was issued under, so a successful redemption is looked up by code.
  defp authorization_by_code!(code), do: TestRepo.get_by!(Authorization, code_hash: Attesto.Secret.hash(code))

  defp assert_spent_without_completion(family_id) do
    row = authorization!(family_id)
    assert row.consumed_at
    refute row.consumed_success
    refute row.access_token_jti
    # Table-wide, not `where: family_id == ^family_id`: core 2.0 mints a FRESH
    # refresh family on finalization, so filtering by the authorization
    # provenance id would count zero whether or not a refresh row was written -
    # an assertion that cannot fail. `setup` truncates the table.
    assert TestRepo.aggregate(RefreshToken, :count) == 0
    assert TestRepo.aggregate(LogoutSession, :count) == 0
  end

  defp completion_active?, do: Process.get(:authorization_code_completion_active) == true

  defp continuation_state_key! do
    Enum.find(Process.get_keys(), fn
      {Token, :authorization_code_continuation, ref} when is_reference(ref) -> true
      _other -> false
    end) || flunk("continuation provenance state was not recorded")
  end

  defp terminate_completion_callback(:error, reason), do: raise(RuntimeError, reason)
  defp terminate_completion_callback(:throw, reason), do: throw(reason)
  defp terminate_completion_callback(:exit, reason), do: exit(reason)

  defp claim!(jwt, key) when is_binary(jwt) do
    claims!(jwt)[key]
  end

  defp claims!(jwt) when is_binary(jwt) do
    [_header, payload | _] = String.split(jwt, ".")
    {:ok, json} = Base.url_decode64(payload, padding: false)
    JSON.decode!(json)
  end
end
