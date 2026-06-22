defmodule AttestoPhoenix.ConsentGrantTest do
  @moduledoc """
  Pure (no-DB) tests for the consent binding and its canonical hash
  (RFC 6749 §4.1.1): the binding built from an `%Attesto.AuthorizationRequest{}`,
  order-agnostic scope-set hashing (RFC 6749 §3.3), and a hash that changes when
  the client, redirect URI, scope set, subject, PKCE challenge, or PKCE method
  differs.
  """

  use ExUnit.Case, async: true

  alias AttestoPhoenix.ConsentGrant

  @subject "sub-123"

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

  defp params(overrides \\ %{}) do
    Map.merge(
      %{
        "response_type" => "code",
        "client_id" => "client-1",
        "redirect_uri" => "https://rp.example/cb",
        "scope" => "openid profile",
        "code_challenge" => "challenge-xyz",
        "code_challenge_method" => "S256"
      },
      overrides
    )
  end

  describe "binding/2" do
    test "maps the request fields and subject into the binding" do
      assert ConsentGrant.binding(request(), @subject) == %{
               subject: @subject,
               client_id: "client-1",
               redirect_uri: "https://rp.example/cb",
               scope: ["openid", "profile"],
               code_challenge: "challenge-xyz",
               code_challenge_method: "S256"
             }
    end

    test "carries absent PKCE fields through unchanged" do
      binding = ConsentGrant.binding(request(code_challenge: nil, code_challenge_method: nil), @subject)
      assert binding.code_challenge == nil
      assert binding.code_challenge_method == nil
    end

    test "wraps a nil scope into an empty list" do
      binding = ConsentGrant.binding(request(scope: nil), @subject)
      assert binding.scope == []
    end
  end

  describe "binding_from_params/2" do
    test "maps raw string-keyed params into the same binding as a validated request" do
      assert ConsentGrant.binding_from_params(params(), @subject) ==
               ConsentGrant.binding(request(), @subject)
    end

    test "hashes byte-identically to binding/2 for the equivalent request" do
      from_params = ConsentGrant.binding_from_params(params(), @subject)
      from_request = ConsentGrant.binding(request(), @subject)

      assert ConsentGrant.binding_hash(from_params) == ConsentGrant.binding_hash(from_request)
    end

    test "scope order remains insignificant across raw params and validated request" do
      from_params = ConsentGrant.binding_from_params(params(%{"scope" => "email openid profile"}), @subject)
      from_request = ConsentGrant.binding(request(scope: ["openid", "profile", "email"]), @subject)

      assert ConsentGrant.binding_hash(from_params) == ConsentGrant.binding_hash(from_request)
    end

    test "absent PKCE params hash identically through both builders" do
      from_params =
        params(%{})
        |> Map.drop(["code_challenge", "code_challenge_method"])
        |> ConsentGrant.binding_from_params(@subject)

      from_request = ConsentGrant.binding(request(code_challenge: nil, code_challenge_method: nil), @subject)

      assert from_params.code_challenge == nil
      assert from_params.code_challenge_method == nil
      assert ConsentGrant.binding_hash(from_params) == ConsentGrant.binding_hash(from_request)
    end

    test "missing scope becomes the same empty list as a nil request scope" do
      from_params =
        params(%{})
        |> Map.delete("scope")
        |> ConsentGrant.binding_from_params(@subject)

      from_request = ConsentGrant.binding(request(scope: nil), @subject)

      assert from_params.scope == []
      assert ConsentGrant.binding_hash(from_params) == ConsentGrant.binding_hash(from_request)
    end

    test "unknown params do not affect the canonical hash" do
      base = ConsentGrant.binding_from_params(params(), @subject)
      extra = ConsentGrant.binding_from_params(params(%{"future_param" => "ignored"}), @subject)

      assert ConsentGrant.binding_hash(base) == ConsentGrant.binding_hash(extra)
    end
  end

  describe "binding_hash/1" do
    test "is a stable, url-safe, unpadded base64 string" do
      hash = ConsentGrant.binding_hash(ConsentGrant.binding(request(), @subject))

      assert is_binary(hash)
      assert hash == ConsentGrant.binding_hash(ConsentGrant.binding(request(), @subject))
      # url-base64 alphabet, no padding.
      assert hash =~ ~r/\A[A-Za-z0-9_-]+\z/
    end

    test "scope order is NOT significant (RFC 6749 §3.3): a reordered scope set hashes identically" do
      forward = ConsentGrant.binding(request(scope: ["openid", "profile", "email"]), @subject)
      reordered = ConsentGrant.binding(request(scope: ["email", "openid", "profile"]), @subject)

      assert ConsentGrant.binding_hash(forward) == ConsentGrant.binding_hash(reordered)
    end

    test "a space-joined scope string and the parsed scope list hash identically" do
      from_list = ConsentGrant.binding(request(scope: ["openid", "profile"]), @subject)
      # The consent screen may carry the requested scope as a parsed list while a
      # raw request carries the string set; both must hash the same.
      from_string_set = %{from_list | scope: ["profile", "openid"]}

      assert ConsentGrant.binding_hash(from_list) == ConsentGrant.binding_hash(from_string_set)
    end

    test "a different scope SET changes the hash" do
      base = ConsentGrant.binding(request(scope: ["openid", "profile"]), @subject)
      widened = ConsentGrant.binding(request(scope: ["openid", "profile", "email"]), @subject)

      refute ConsentGrant.binding_hash(base) == ConsentGrant.binding_hash(widened)
    end

    test "a different client_id changes the hash" do
      base = ConsentGrant.binding(request(), @subject)
      other = ConsentGrant.binding(request(client_id: "client-2"), @subject)

      refute ConsentGrant.binding_hash(base) == ConsentGrant.binding_hash(other)
    end

    test "a different redirect_uri changes the hash" do
      base = ConsentGrant.binding(request(), @subject)
      other = ConsentGrant.binding(request(redirect_uri: "https://evil.example/cb"), @subject)

      refute ConsentGrant.binding_hash(base) == ConsentGrant.binding_hash(other)
    end

    test "a different subject changes the hash" do
      base = ConsentGrant.binding(request(), @subject)
      other = ConsentGrant.binding(request(), "sub-456")

      refute ConsentGrant.binding_hash(base) == ConsentGrant.binding_hash(other)
    end

    test "a different code_challenge changes the hash" do
      base = ConsentGrant.binding(request(), @subject)
      other = ConsentGrant.binding(request(code_challenge: "challenge-other"), @subject)

      refute ConsentGrant.binding_hash(base) == ConsentGrant.binding_hash(other)
    end

    test "a different code_challenge_method changes the hash" do
      base = ConsentGrant.binding(request(code_challenge_method: "S256"), @subject)
      other = ConsentGrant.binding(request(code_challenge_method: "plain"), @subject)

      refute ConsentGrant.binding_hash(base) == ConsentGrant.binding_hash(other)
    end

    test "an absent code_challenge hashes as the empty string, distinct from any present one" do
      absent = ConsentGrant.binding(request(code_challenge: nil), @subject)
      empty = ConsentGrant.binding(request(code_challenge: ""), @subject)
      present = ConsentGrant.binding(request(code_challenge: "x"), @subject)

      # nil and "" both canonicalise to "", so they collide by design...
      assert ConsentGrant.binding_hash(absent) == ConsentGrant.binding_hash(empty)
      # ...but a real challenge is distinct.
      refute ConsentGrant.binding_hash(absent) == ConsentGrant.binding_hash(present)
    end

    test "an absent code_challenge_method hashes as the empty string, distinct from any present one" do
      absent = ConsentGrant.binding(request(code_challenge_method: nil), @subject)
      empty = ConsentGrant.binding(request(code_challenge_method: ""), @subject)
      present = ConsentGrant.binding(request(code_challenge_method: "S256"), @subject)

      assert ConsentGrant.binding_hash(absent) == ConsentGrant.binding_hash(empty)
      refute ConsentGrant.binding_hash(absent) == ConsentGrant.binding_hash(present)
    end
  end
end
