defmodule AttestoPhoenix.AuthorizationServer.UserinfoTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias AttestoPhoenix.AuthorizationServer.Userinfo
  alias AttestoPhoenix.Config

  defmodule StubKeystore do
    @moduledoc false
  end

  defmodule StubRepo do
    @moduledoc false
  end

  defp build_config(overrides \\ []) do
    base = [
      issuer: "https://issuer.example",
      audience: "https://api.example.com",
      keystore: StubKeystore,
      repo: StubRepo,
      load_client: fn _id -> {:error, :not_found} end,
      verify_client_secret: fn _client, _secret -> false end,
      load_principal: fn _sub -> {:error, :not_found} end,
      build_userinfo_claims: fn _sub, _scopes, _requested ->
        %{
          "name" => "Ada Lovelace",
          "email" => "ada@example.com",
          "email_verified" => true,
          "phone_number" => "+15550100",
          "custom_claim" => "requested-value",
          "unrequested_claim" => "hidden"
        }
      end
    ]

    Config.new(Keyword.merge(base, overrides))
  end

  describe "resolve_claims/2" do
    test "returns {:error, :insufficient_scope} when the openid scope is absent" do
      config = build_config()

      assert {:error, :insufficient_scope} =
               Userinfo.resolve_claims(config, %{"sub" => "user-1", "scope" => "profile email"})

      assert {:error, :insufficient_scope} =
               Userinfo.resolve_claims(config, %{"sub" => "user-1"})
    end

    test "shapes claims by granted scope and individually requested claims.userinfo members" do
      config = build_config(claims_parameter_supported: true)

      claims = %{
        "sub" => "user-1",
        "scope" => "openid email",
        "claims" => %{"userinfo" => %{"custom_claim" => nil}}
      }

      assert {:ok, userinfo} = Userinfo.resolve_claims(config, claims)

      assert userinfo == %{
               "sub" => "user-1",
               "email" => "ada@example.com",
               "email_verified" => true,
               "custom_claim" => "requested-value"
             }
    end

    test "ignores claims.userinfo members when the claims parameter is not supported" do
      config = build_config()

      claims = %{
        "sub" => "user-1",
        "scope" => "openid email",
        "claims" => %{"userinfo" => %{"custom_claim" => nil, "phone_number" => nil}}
      }

      assert {:ok, userinfo} = Userinfo.resolve_claims(config, claims)

      assert userinfo == %{
               "sub" => "user-1",
               "email" => "ada@example.com",
               "email_verified" => true
             }
    end

    test "always pins sub to the verified token subject even if the host callback returns another sub" do
      config =
        build_config(
          build_userinfo_claims: fn _sub, _scopes, _requested ->
            %{"sub" => "spoofed-sub", "email" => "ada@example.com"}
          end
        )

      assert {:ok, %{"sub" => "verified-sub", "email" => "ada@example.com"}} =
               Userinfo.resolve_claims(config, %{"sub" => "verified-sub", "scope" => "openid email"})
    end
  end
end
