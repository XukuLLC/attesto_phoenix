defmodule AttestoPhoenix.AuthorizationServer.SubjectIdentifierTest do
  use ExUnit.Case, async: true

  alias Attesto.PairwiseSubject
  alias AttestoPhoenix.AuthorizationServer.SubjectIdentifier
  alias AttestoPhoenix.AuthorizationServer.Userinfo
  alias AttestoPhoenix.Config

  @salt String.duplicate("k", 32)

  @clients %{
    "public-rp" => %{id: "public-rp", subject_type: "public", redirect_uris: ["https://public.example/cb"]},
    "pairwise-rp" => %{
      id: "pairwise-rp",
      subject_type: "pairwise",
      redirect_uris: ["https://rp.example/cb", "https://rp.example/other"]
    },
    "spread-rp" => %{
      id: "spread-rp",
      subject_type: "pairwise",
      redirect_uris: ["https://a.example/cb", "https://b.example/cb"]
    }
  }

  defmodule Keystore do
    @moduledoc false
  end

  defp config(overrides \\ []) do
    Config.new(
      Keyword.merge(
        [
          issuer: "https://issuer.example",
          audience: "https://api.example.com",
          keystore: Keystore,
          repo: __MODULE__.Repo,
          load_client: fn id -> with :error <- Map.fetch(@clients, id), do: {:error, :not_found} end,
          verify_client_secret: fn _client, _secret -> false end,
          load_principal: fn _sub -> {:error, :not_found} end,
          client_redirect_uris: fn client -> client.redirect_uris end,
          client_subject_type: fn client -> client.subject_type end,
          pairwise_subject_salt: @salt,
          build_userinfo_claims: fn subject, _scopes, _requested -> %{"name" => "seen:" <> subject} end
        ],
        overrides
      )
    )
  end

  defp pairwise(subject), do: PairwiseSubject.derive("rp.example", subject, @salt)

  describe "for_client/3" do
    test "a public client sees the host subject, a pairwise client the derived one" do
      assert {:ok, "usr_1"} = SubjectIdentifier.for_client(config(), @clients["public-rp"], "usr_1")
      assert SubjectIdentifier.for_client(config(), @clients["pairwise-rp"], "usr_1") == {:ok, pairwise("usr_1")}
      refute pairwise("usr_1") == pairwise("usr_2")
    end

    test "a pairwise client whose redirect URIs span hosts has no sub" do
      assert {:error, :multiple_hosts} = SubjectIdentifier.for_client(config(), @clients["spread-rp"], "usr_1")
    end

    test "with no :client_subject_type every client is public and no client is loaded" do
      config = config(client_subject_type: nil, pairwise_subject_salt: nil, load_client: fn _ -> raise "not loaded" end)

      refute SubjectIdentifier.pairwise_possible?(config)
      assert SubjectIdentifier.subject_types_supported(config) == ["public"]
      assert {:ok, "usr_1"} = SubjectIdentifier.for_client(config, @clients["pairwise-rp"], "usr_1")
      assert {:ok, "usr_1"} = SubjectIdentifier.for_client_id(config, "pairwise-rp", "usr_1")
    end

    test "a callback result outside the contract raises" do
      config = config(client_subject_type: fn _client -> "ephemeral" end)

      assert_raise RuntimeError, ~r/:client_subject_type callback violated its return contract/, fn ->
        SubjectIdentifier.for_client(config, @clients["public-rp"], "usr_1")
      end
    end
  end

  describe "for_client_id/3" do
    test "loads the client and applies its subject type" do
      assert SubjectIdentifier.subject_types_supported(config()) == ["public", "pairwise"]
      assert {:ok, "usr_1"} = SubjectIdentifier.for_client_id(config(), "public-rp", "usr_1")
      assert SubjectIdentifier.for_client_id(config(), "pairwise-rp", "usr_1") == {:ok, pairwise("usr_1")}
    end

    test "an unknown or absent client is an error, never the host subject" do
      assert {:error, :client_unavailable} = SubjectIdentifier.for_client_id(config(), "gone", "usr_1")
      assert {:error, :client_unavailable} = SubjectIdentifier.for_client_id(config(), nil, "usr_1")
    end
  end

  describe "configuration" do
    test "a salt is required once a client can be pairwise, and must be long enough" do
      assert_raise ArgumentError, ~r/:client_subject_type is configured.*:pairwise_subject_salt/s, fn ->
        config(pairwise_subject_salt: nil)
      end

      for salt <- [String.duplicate("k", 31), :atom, 32] do
        assert_raise ArgumentError, ~r/:pairwise_subject_salt must be a binary of at least 32 bytes/, fn ->
          config(pairwise_subject_salt: salt)
        end
      end

      assert %Config{} = config(client_subject_type: nil)
    end
  end

  describe "UserInfo (OIDC Core §5.3.2)" do
    defp token_claims(client_id), do: %{"sub" => "usr_1", "scope" => "openid profile", "client_id" => client_id}

    test "a pairwise client's sub is the derived one; the host callback still gets the host subject" do
      assert {:ok, userinfo} = Userinfo.resolve_claims(config(), token_claims("pairwise-rp"))
      assert userinfo == %{"sub" => pairwise("usr_1"), "name" => "seen:usr_1"}

      assert {:ok, %{"sub" => "usr_1"}} = Userinfo.resolve_claims(config(), token_claims("public-rp"))
    end

    test "a token whose client cannot be given a sub is refused" do
      assert {:error, :invalid_token} = Userinfo.resolve_claims(config(), token_claims("spread-rp"))
      assert {:error, :invalid_token} = Userinfo.resolve_claims(config(), token_claims("gone"))
    end
  end
end
