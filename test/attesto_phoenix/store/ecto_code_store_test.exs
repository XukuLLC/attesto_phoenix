defmodule AttestoPhoenix.Store.EctoCodeStoreTest do
  @moduledoc """
  Behaviour conformance tests for the Ecto-backed authorization-code store.

  The load-bearing property is single use (RFC 6749 §4.1.2): a code is
  redeemable exactly once, even under concurrent redemption, because the
  code is the sole browser-deliverable secret in the PKCE-mandatory
  authorization-code flow (RFC 7636).

  Tagged `:ecto` so the suite is excluded by default and runs only when a SQL
  backend is available (see `test/test_helper.exs`).
  """

  use AttestoPhoenix.DataCase, async: false

  import ExUnit.CaptureLog

  alias AttestoPhoenix.Schema.Authorization
  alias AttestoPhoenix.Store.EctoCodeStore
  alias Ecto.Adapters.SQL.Sandbox

  @moduletag :ecto

  # take/1 does not gate on expiry; a future value keeps fixtures realistic.
  @future_seconds System.system_time(:second) + 600

  # The canonical grant context the protocol layer round-trips. The schema spreads
  # these across columns, so the required authorization-request fields must
  # be present (RFC 6749 §4.1.3, RFC 7636 §4.3).
  defp grant_data(overrides \\ %{}) do
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

  defp entry(code_hash, data \\ grant_data(), expires_at \\ @future_seconds) do
    %{code_hash: code_hash, data: data, expires_at: expires_at}
  end

  defp nested_objects(1), do: %{"value" => 1}
  defp nested_objects(depth), do: %{"nested" => nested_objects(depth - 1)}

  defp nested_object_arrays(1), do: %{"value" => 1}
  defp nested_object_arrays(depth), do: %{"nested" => [nested_object_arrays(depth - 1)]}

  describe "put/1" do
    test "persists a record retrievable by its code_hash" do
      assert :ok = EctoCodeStore.put(entry("hash-1"))
      assert {:ok, %{code_hash: "hash-1"}} = EctoCodeStore.take("hash-1")
    end

    test "round-trips the grant context through the column bridge" do
      assert :ok = EctoCodeStore.put(entry("hash-rt"))
      assert {:ok, %{data: data}} = EctoCodeStore.take("hash-rt")

      assert data.client_id == "client-abc"
      assert data.subject == "subject-1"
      assert data.scope == ["openid", "profile"]
      assert data.redirect_uri == "https://rp.example/cb"
      assert data.code_challenge == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
      assert data.family_id == "fam-1"
      assert data.claims["nonce"] == "request-nonce"

      assert Map.keys(data) |> Enum.sort() ==
               [
                 :claims,
                 :client_id,
                 :code_challenge,
                 :dpop_jkt,
                 :family_id,
                 :redirect_uri,
                 :resource,
                 :scope,
                 :subject
               ]
    end

    test "round-trips portable nested claims through Postgres JSONB" do
      claims = %{
        "nested" => %{
          "minimum" => -9_007_199_254_740_991,
          "maximum" => 9_007_199_254_740_991,
          "values" => [nil, false, true, "text", %{"leaf" => 42}]
        }
      }

      assert :ok = EctoCodeStore.put(entry("hash-jsonb-claims", grant_data(%{claims: claims})))
      assert {:ok, %{data: %{claims: ^claims}}} = EctoCodeStore.take("hash-jsonb-claims")
    end

    test "accepts the portable depth-64 boundary and alternating object/array boundary" do
      assert %Ecto.Changeset{valid?: true} =
               Authorization.from_record(entry("hash-depth-64", grant_data(%{claims: nested_objects(64)})))

      assert %Ecto.Changeset{valid?: true} =
               Authorization.from_record(entry("hash-alternating-32", grant_data(%{claims: nested_object_arrays(32)})))

      assert_raise ArgumentError, "authorization code record has invalid canonical data", fn ->
        Authorization.from_record(entry("hash-depth-65", grant_data(%{claims: nested_objects(65)})))
      end

      assert_raise ArgumentError, "authorization code record has invalid canonical data", fn ->
        Authorization.from_record(entry("hash-alternating-33", grant_data(%{claims: nested_object_arrays(33)})))
      end
    end

    test "preserves expires_at as absolute unix seconds across storage" do
      assert :ok = EctoCodeStore.put(entry("hash-exp"))
      assert {:ok, %{expires_at: @future_seconds}} = EctoCodeStore.take("hash-exp")
    end

    test "rejects a duplicate code_hash rather than overwriting" do
      assert :ok = EctoCodeStore.put(entry("hash-dup", grant_data(%{subject: "first"})))

      # A repeated primary key is a caller bug; the unique constraint must
      # surface, never a silent upsert that could replace an issued code.
      # `insert!/1` maps the constraint onto the changeset and raises.
      assert_raise Ecto.InvalidChangesetError, fn ->
        EctoCodeStore.put(entry("hash-dup", grant_data(%{subject: "second"})))
      end

      # The original row is untouched.
      assert {:ok, %{data: %{subject: "first"}}} = EctoCodeStore.take("hash-dup")
    end

    test "fails closed when a required canonical grant key is missing" do
      # The bridge rejects an incomplete canonical map before projection, so it
      # cannot be stored as a half-formed, unredeemable code.
      bad = entry("hash-bad", Map.delete(grant_data(), :redirect_uri))

      assert_raise ArgumentError, "authorization code record has invalid canonical data", fn ->
        EctoCodeStore.put(bad)
      end
    end

    test "rejects an extra canonical data key before database projection" do
      assert_raise ArgumentError, "authorization code record has invalid canonical data", fn ->
        EctoCodeStore.put(entry("hash-extra", grant_data(%{adapter_metadata: "not protocol data"})))
      end
    end
  end

  describe "take/1" do
    test "returns the record and claims it so a code is redeemable once" do
      assert :ok = EctoCodeStore.put(entry("hash-once"))

      assert {:ok, %{code_hash: "hash-once"}} = EctoCodeStore.take("hash-once")
      # The first presentation has only claimed the row. Until the protocol
      # layer reports successful redemption, a second presentation is not
      # replay evidence and fails closed as an unknown/invalid grant.
      assert :error = EctoCodeStore.take("hash-once")
    end

    test "clears authorization provenance when no refresh family is finalized" do
      assert :ok = EctoCodeStore.put(entry("hash-consumed", grant_data(%{family_id: "fam-ok"})))

      assert {:ok, %{code_hash: "hash-consumed"}} = EctoCodeStore.take("hash-consumed")
      assert :ok = EctoCodeStore.mark_consumed("hash-consumed", %{})

      assert {:error, :consumed, %{family_id: nil, subject: "subject-1"}} =
               EctoCodeStore.take("hash-consumed")
    end

    test "an explicit nil family clears authorization provenance" do
      assert :ok = EctoCodeStore.put(entry("hash-consumed-nil", grant_data(%{family_id: "fam-ok"})))

      assert {:ok, %{code_hash: "hash-consumed-nil"}} = EctoCodeStore.take("hash-consumed-nil")
      assert :ok = EctoCodeStore.mark_consumed("hash-consumed-nil", %{family_id: nil})

      assert {:error, :consumed, %{family_id: nil, subject: "subject-1"}} =
               EctoCodeStore.take("hash-consumed-nil")
    end

    test "binds a finalized refresh family to the consumed authorization row" do
      assert :ok = EctoCodeStore.put(entry("hash-finalized", grant_data(%{family_id: "fam-origin"})))

      assert {:ok, %{code_hash: "hash-finalized"}} = EctoCodeStore.take("hash-finalized")
      assert :ok = EctoCodeStore.mark_consumed("hash-finalized", %{family_id: "fam-issued"})

      assert {:error, :consumed, %{family_id: "fam-issued", subject: "subject-1"}} =
               EctoCodeStore.take("hash-finalized")
    end

    test "records an access token by code hash before family rebinding" do
      expires_at = System.system_time(:second) + 600

      assert :ok = EctoCodeStore.put(entry("hash-access-code", grant_data(%{family_id: nil})))
      assert {:ok, %{code_hash: "hash-access-code"}} = EctoCodeStore.take("hash-access-code")

      assert :ok =
               EctoCodeStore.record_access_token_for_code(
                 "hash-access-code",
                 "jti-code",
                 expires_at
               )

      assert %Authorization{access_token_jti: "jti-code"} =
               TestRepo.get_by!(Authorization, code_hash: "hash-access-code")
    end

    test "returns :error for an absent code_hash" do
      assert :error = EctoCodeStore.take("hash-missing")
    end

    test "legacy consumed rows without an access-token JTI are a replay no-op" do
      # 2.14.x could leave a successful consumed marker without either a
      # refresh-family ID or access-token linkage. Reuse containment must still
      # return :ok for that row instead of raising on a zero-row UPDATE.
      assert :ok = EctoCodeStore.put(entry("hash-legacy", grant_data(%{family_id: nil})))
      assert {:ok, %{code_hash: "hash-legacy"}} = EctoCodeStore.take("hash-legacy")
      assert :ok = EctoCodeStore.mark_consumed("hash-legacy", %{family_id: nil})

      assert :ok = EctoCodeStore.revoke_access_token_for_code("hash-legacy")

      row = TestRepo.get_by!(Authorization, code_hash: "hash-legacy")
      assert is_nil(row.family_id)
      assert is_nil(row.access_token_jti)
      assert is_nil(row.access_token_revoked_at)
    end

    test "replay revocation is idempotent when the authorization row is gone" do
      assert :ok = EctoCodeStore.revoke_access_token_for_code("hash-missing")
    end

    test "mark_consumed fails loudly when no authorization row exists" do
      assert_raise RuntimeError, ~r/mark_consumed failed to update exactly one authorization record/, fn ->
        EctoCodeStore.mark_consumed("hash-missing", %{})
      end
    end

    test "consumes the row regardless of expiry" do
      stale = entry("hash-stale", grant_data(), System.system_time(:second) - 1)
      assert :ok = EctoCodeStore.put(stale)

      # take/1 does not gate on expiry; the caller re-checks. The row is still
      # spent on first presentation, denying replayed validation attempts.
      assert {:ok, %{code_hash: "hash-stale"}} = EctoCodeStore.take("hash-stale")
      assert :error = EctoCodeStore.take("hash-stale")
    end

    test "only one of two concurrent redemptions wins" do
      assert :ok = EctoCodeStore.put(entry("hash-race"))
      owner = self()

      results =
        ["hash-race", "hash-race"]
        |> Task.async_stream(
          fn h ->
            # Each task runs in its own process; grant it the test's sandboxed
            # connection so both takes hit the same transaction state.
            Sandbox.allow(TestRepo, owner, self())
            EctoCodeStore.take(h)
          end,
          max_concurrency: 2
        )
        |> Enum.map(fn {:ok, result} -> result end)

      # The atomic UPDATE ... RETURNING serialises on the row: exactly one
      # winner claims the record, the other gets :error.
      assert Enum.count(results, &match?({:ok, _}, &1)) == 1
      assert Enum.count(results, &(&1 == :error)) == 1
    end
  end

  describe "access-token revocation after authorization-code reuse" do
    test "records, revokes, and checks the access token issued from a code family" do
      expires_at = System.system_time(:second) + 600

      assert :ok = EctoCodeStore.put(entry("hash-access", grant_data(%{family_id: "fam-access"})))
      assert {:ok, %{code_hash: "hash-access"}} = EctoCodeStore.take("hash-access")

      assert :ok = EctoCodeStore.record_access_token("fam-access", "jti-1", expires_at)
      refute EctoCodeStore.access_token_revoked?("jti-1")

      assert :ok = EctoCodeStore.revoke_family_access_tokens("fam-access")
      assert EctoCodeStore.access_token_revoked?("jti-1")
    end

    test "expired revoked access tokens are ignored" do
      expires_at = System.system_time(:second) - 1

      assert :ok =
               EctoCodeStore.put(entry("hash-expired-token", grant_data(%{family_id: "fam-exp"})))

      assert {:ok, %{code_hash: "hash-expired-token"}} = EctoCodeStore.take("hash-expired-token")

      assert :ok = EctoCodeStore.record_access_token("fam-exp", "jti-expired", expires_at)
      assert :ok = EctoCodeStore.revoke_family_access_tokens("fam-exp")

      refute EctoCodeStore.access_token_revoked?("jti-expired")
    end

    test "record_access_token fails loudly when the family row is absent" do
      expires_at = System.system_time(:second) + 600

      assert_raise RuntimeError, ~r/record_access_token failed to update exactly one authorization record/, fn ->
        EctoCodeStore.record_access_token("fam-missing", "jti-missing", expires_at)
      end
    end
  end

  describe "query observability" do
    test "sensitive operations emit no query telemetry or debug SQL" do
      capture = AttestoPhoenix.TestTelemetryCapture.attach(TestRepo)
      on_exit(fn -> AttestoPhoenix.TestTelemetryCapture.detach(capture) end)
      {_id, ref} = capture

      assert is_integer(TestRepo.aggregate(Authorization, :count, :code_hash))
      assert AttestoPhoenix.TestTelemetryCapture.collect(ref) != []

      now = System.system_time(:second)
      code_hash = "telemetry-code-#{System.unique_integer([:positive])}"
      family_id = "telemetry-family-#{System.unique_integer([:positive])}"
      code_jti = "telemetry-code-jti-#{System.unique_integer([:positive])}"
      family_jti = "telemetry-family-jti-#{System.unique_integer([:positive])}"
      expires_at = now + 600

      log =
        capture_log([level: :debug], fn ->
          assert :ok = EctoCodeStore.put(entry(code_hash, grant_data(%{family_id: nil}), expires_at))
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
          assert {:ok, _} = EctoCodeStore.get(code_hash)
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
          assert {:ok, _} = EctoCodeStore.take(code_hash)
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
          assert :ok = EctoCodeStore.mark_consumed(code_hash, %{family_id: family_id})
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []

          assert :ok = EctoCodeStore.record_access_token_for_code(code_hash, code_jti, expires_at)
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
          assert :ok = EctoCodeStore.record_access_token(family_id, family_jti, expires_at)
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
          assert :ok = EctoCodeStore.revoke_family_access_tokens(family_id)
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
          assert EctoCodeStore.access_token_revoked?(family_jti)
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
          assert :ok = EctoCodeStore.revoke_access_token_for_code(code_hash)
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
          assert :ok = EctoCodeStore.revoke_access_token_for_code("telemetry-code-missing")
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
          assert {:error, :consumed, _} = EctoCodeStore.take(code_hash)
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
          assert :error = EctoCodeStore.get("telemetry-code-missing")
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
          assert :error = EctoCodeStore.take("telemetry-code-missing")
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
        end)

      for sentinel <- [code_hash, family_id, code_jti, family_jti] do
        refute log =~ sentinel
      end
    end
  end
end
