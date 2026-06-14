defmodule AttestoPhoenix.Store.EctoCodeStoreAtomicityTest do
  @moduledoc """
  Integration coverage for the redeem/finalize atomicity contract against the
  REAL Ecto-backed code store.

  `Attesto.AuthorizationCode.redeem/4` claims and validates a code, but the
  reuse marker (`consumed_success`) is recorded only by `finalize/3`, which the
  token endpoint runs after the full response is built. So a code whose
  redemption validated but whose downstream issuance then failed (a mint fault,
  a refresh-store error, a host `build_principal` callback returning the subject
  under the wrong key) is left consumed-but-unfinalized: a replay is
  `invalid_grant`, NOT a false reuse attack that would revoke the family. This
  exercises that against the actual `EctoCodeStore` + schema, the gap that let a
  host integration burn a code with no token issued.

  Tagged `:ecto`; runs only when a SQL backend is available.
  """
  use AttestoPhoenix.DataCase, async: true

  alias Attesto.AuthorizationCode
  alias Attesto.Secret
  alias AttestoPhoenix.Schema.Authorization
  alias AttestoPhoenix.Store.EctoCodeStore
  alias AttestoPhoenix.TestRepo

  @moduletag :ecto

  # RFC 7636 §4 example verifier/challenge pair (S256).
  @verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  @challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

  defp put_code(overrides \\ %{}) do
    code = Secret.generate()

    data =
      Map.merge(
        %{
          client_id: "client-1",
          subject: "subject-1",
          scope: ["openid"],
          redirect_uri: "https://rp.example/cb",
          code_challenge: @challenge,
          code_challenge_method: Authorization.code_challenge_method(),
          family_id: "fam-1"
        },
        overrides
      )

    :ok =
      EctoCodeStore.put(%{
        code_hash: Secret.hash(code),
        data: data,
        expires_at: System.system_time(:second) + 600
      })

    code
  end

  defp redeem_params do
    %{redirect_uri: "https://rp.example/cb", client_id: "client-1", code_verifier: @verifier}
  end

  defp row(code) do
    TestRepo.get_by!(Authorization, code_hash: Secret.hash(code))
  end

  test "a validated-but-unfinalized redemption leaves consumed_success false; a replay is invalid_grant" do
    code = put_code()

    # Redemption fully validates and returns the grant ...
    assert {:ok, grant} = AuthorizationCode.redeem(EctoCodeStore, code, redeem_params())
    assert grant.family_id == "fam-1"

    # ... but the caller's downstream token issuance fails, so finalize/3 never
    # runs. The code is single-use-spent (consumed_at set) but NOT reuse-flagged.
    spent = row(code)
    refute is_nil(spent.consumed_at)
    refute spent.consumed_success

    # A replay (e.g. the client retrying a transient failure) is a clean
    # invalid_grant, NOT a reuse attack that would revoke the family.
    assert {:error, :invalid_grant} = AuthorizationCode.redeem(EctoCodeStore, code, redeem_params())
  end

  test "finalize records the reuse marker so a post-issuance replay is reuse" do
    code = put_code()
    assert {:ok, grant} = AuthorizationCode.redeem(EctoCodeStore, code, redeem_params())

    # The token endpoint finalizes only after the full response is built.
    assert :ok = AuthorizationCode.finalize(EctoCodeStore, code, grant)
    assert row(code).consumed_success

    assert {:error, {:reuse, %{family_id: "fam-1", subject: "subject-1"}}} =
             AuthorizationCode.redeem(EctoCodeStore, code, redeem_params())
  end
end
