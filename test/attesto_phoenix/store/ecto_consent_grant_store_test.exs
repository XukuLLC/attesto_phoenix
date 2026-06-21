defmodule AttestoPhoenix.Store.EctoConsentGrantStoreTest do
  @moduledoc """
  Behaviour-conformance tests for the Postgres-backed consent-grant store
  (RFC 6749 §4.1.1): single use, request binding (order-agnostic scope set,
  mismatch on a differing client/redirect/scope/challenge/method), TTL expiry,
  and double-consume.

  The store reads its repo from the `:attesto_phoenix` application environment,
  which `AttestoPhoenix.DataCase` points at the sandboxed test repo.
  """

  use AttestoPhoenix.DataCase, async: true

  alias AttestoPhoenix.ConsentGrant
  alias AttestoPhoenix.Schema.ConsentGrant, as: Grant
  alias AttestoPhoenix.Store.EctoConsentGrantStore, as: Store
  alias AttestoPhoenix.TestRepo

  @moduletag :ecto

  @ttl 300

  defp request(overrides \\ []) do
    base = %Attesto.AuthorizationRequest{
      response_type: "code",
      client_id: "client-1",
      redirect_uri: "https://rp.example/cb",
      scope: ["openid", "profile"],
      code_challenge: "challenge-xyz",
      code_challenge_method: "S256"
    }

    struct!(base, overrides)
  end

  defp cg_binding(overrides \\ []), do: ConsentGrant.binding(request(overrides), "sub-123")

  describe "mint/2" do
    test "returns an opaque, url-safe token and persists one row" do
      assert {:ok, token} = Store.mint(cg_binding(), @ttl)

      assert is_binary(token)
      assert token =~ ~r/\A[A-Za-z0-9_-]+\z/

      row = TestRepo.get(Grant, token)
      assert row.subject == "sub-123"
      assert row.binding_hash == ConsentGrant.binding_hash(cg_binding())
      assert row.consumed_at == nil
      assert DateTime.after?(row.expires_at, DateTime.utc_now())
    end

    test "two mints yield distinct tokens" do
      assert {:ok, t1} = Store.mint(cg_binding(), @ttl)
      assert {:ok, t2} = Store.mint(cg_binding(), @ttl)
      refute t1 == t2
    end
  end

  describe "consume/2 - happy path and single use" do
    test "consumes a matching grant exactly once" do
      {:ok, token} = Store.mint(cg_binding(), @ttl)

      assert :ok = Store.consume(token, cg_binding())
      # The row is marked consumed, not deleted, so a replay is detectable.
      assert %Grant{consumed_at: consumed} = TestRepo.get(Grant, token)
      assert consumed != nil
    end

    test "a second consume of the same token is refused as :consumed" do
      {:ok, token} = Store.mint(cg_binding(), @ttl)

      assert :ok = Store.consume(token, cg_binding())
      assert {:error, :consumed} = Store.consume(token, cg_binding())
    end
  end

  describe "consume/2 - request binding" do
    test "scope order is NOT significant: a reordered scope set still consumes" do
      {:ok, token} = Store.mint(cg_binding(scope: ["openid", "profile", "email"]), @ttl)

      # Same set, different order — RFC 6749 §3.3.
      assert :ok = Store.consume(token, cg_binding(scope: ["email", "profile", "openid"]))
    end

    test "a differing scope SET is a binding mismatch" do
      {:ok, token} = Store.mint(cg_binding(scope: ["openid", "profile"]), @ttl)

      assert {:error, :binding_mismatch} = Store.consume(token, cg_binding(scope: ["openid", "profile", "email"]))
      # The grant was NOT spent by a failed consume; it is still claimable for the
      # request it was actually minted for.
      assert :ok = Store.consume(token, cg_binding(scope: ["openid", "profile"]))
    end

    test "a differing client_id is a binding mismatch" do
      {:ok, token} = Store.mint(cg_binding(client_id: "client-1"), @ttl)
      assert {:error, :binding_mismatch} = Store.consume(token, cg_binding(client_id: "client-2"))
    end

    test "a differing redirect_uri is a binding mismatch" do
      {:ok, token} = Store.mint(cg_binding(redirect_uri: "https://rp.example/cb"), @ttl)
      assert {:error, :binding_mismatch} = Store.consume(token, cg_binding(redirect_uri: "https://evil.example/cb"))
    end

    test "a differing code_challenge is a binding mismatch" do
      {:ok, token} = Store.mint(cg_binding(code_challenge: "challenge-xyz"), @ttl)
      assert {:error, :binding_mismatch} = Store.consume(token, cg_binding(code_challenge: "challenge-other"))
    end

    test "a S256 grant is refused against an otherwise identical plain request" do
      {:ok, token} = Store.mint(cg_binding(code_challenge: "same-challenge", code_challenge_method: "S256"), @ttl)

      assert {:error, :binding_mismatch} =
               Store.consume(token, cg_binding(code_challenge: "same-challenge", code_challenge_method: "plain"))

      assert :ok = Store.consume(token, cg_binding(code_challenge: "same-challenge", code_challenge_method: "S256"))
    end

    test "a plain grant is refused against an otherwise identical S256 request" do
      {:ok, token} = Store.mint(cg_binding(code_challenge: "same-challenge", code_challenge_method: "plain"), @ttl)

      assert {:error, :binding_mismatch} =
               Store.consume(token, cg_binding(code_challenge: "same-challenge", code_challenge_method: "S256"))

      assert :ok = Store.consume(token, cg_binding(code_challenge: "same-challenge", code_challenge_method: "plain"))
    end

    test "a request with no PKCE challenge still consumes when both PKCE fields are absent" do
      binding = cg_binding(code_challenge: nil, code_challenge_method: nil)
      {:ok, token} = Store.mint(binding, @ttl)

      assert :ok = Store.consume(token, binding)
    end

    test "a differing subject is a binding mismatch" do
      {:ok, token} = Store.mint(ConsentGrant.binding(request(), "sub-123"), @ttl)
      assert {:error, :binding_mismatch} = Store.consume(token, ConsentGrant.binding(request(), "sub-456"))
    end
  end

  describe "consume/2 - not found" do
    test "an unknown token is :not_found" do
      assert {:error, :not_found} = Store.consume("never-minted", cg_binding())
    end

    test "a nil token is :not_found without touching the database" do
      assert {:error, :not_found} = Store.consume(nil, cg_binding())
    end

    test "a blank token is :not_found" do
      assert {:error, :not_found} = Store.consume("", cg_binding())
    end
  end

  describe "consume/2 - expiry" do
    test "an expired grant is refused as :expired even with a matching binding" do
      # Insert directly with an expiry in the past (mint/2's positive-ttl guard
      # forbids minting an already-expired grant), to exercise the read-time
      # freshness check.
      token = "expired-token"
      now = DateTime.utc_now()

      %{
        token: token,
        binding_hash: ConsentGrant.binding_hash(cg_binding()),
        subject: "sub-123",
        expires_at: DateTime.add(now, -1, :second)
      }
      |> Grant.changeset()
      |> TestRepo.insert!()

      assert {:error, :expired} = Store.consume(token, cg_binding())
    end

    test "an expired grant whose binding ALSO mismatches is reported :binding_mismatch" do
      # The disambiguation order checks the hash before expiry, so a wrong-request
      # presentation is named as the mismatch it is, not masked by the stale TTL.
      token = "expired-mismatch-token"
      now = DateTime.utc_now()

      %{
        token: token,
        binding_hash: ConsentGrant.binding_hash(cg_binding(client_id: "client-1")),
        subject: "sub-123",
        expires_at: DateTime.add(now, -1, :second)
      }
      |> Grant.changeset()
      |> TestRepo.insert!()

      assert {:error, :binding_mismatch} = Store.consume(token, cg_binding(client_id: "client-2"))
    end
  end
end
