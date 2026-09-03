defmodule AttestoPhoenix.AuthorizationCodePrivateContextTest do
  @moduledoc """
  The reserved-claims transport for host-private authorization state.

  `Attesto.AuthorizationCode` admits no sibling key beside the nine canonical
  grant keys, so private context rides inside `:claims`. These tests pin the
  rules that keep that transport safe: what may be stored, how large, and that
  it comes back off the grant cleanly.
  """

  use ExUnit.Case, async: true

  alias Attesto.Claims
  alias AttestoPhoenix.AuthorizationCodePrivateContext, as: PrivateContext

  describe "put/2" do
    test "nil stores nothing and leaves the claims untouched" do
      claims = %{"nonce" => "n-1"}
      assert PrivateContext.put(claims, nil) == {:ok, claims}
      refute Map.has_key?(claims, PrivateContext.claims_key())
    end

    test "a portable JSON object is stored under the reserved key" do
      context = %{"epoch" => 3, "flags" => ["a", "b"], "nested" => %{"ok" => true, "absent" => nil}}

      assert {:ok, claims} = PrivateContext.put(%{"nonce" => "n-1"}, context)
      assert claims[PrivateContext.claims_key()] == context
      assert claims["nonce"] == "n-1"
    end

    test "atom keys are refused rather than silently stringified" do
      # The claims map round-trips a JSONB column; an atom key would not survive
      # it unchanged, so the grant would not be lossless.
      assert PrivateContext.put(%{}, %{epoch: 3}) == {:error, :invalid_private_context}
    end

    test "a float is refused because JSONB cannot round-trip it exactly" do
      assert PrivateContext.put(%{}, %{"ratio" => 1.5}) == {:error, :invalid_private_context}
    end

    test "a non-map value is refused" do
      for value <- ["string", 42, ["list"], true] do
        assert PrivateContext.put(%{}, value) == {:error, :invalid_private_context}
      end
    end

    test "ordinary Elixir structs and collection types are refused without raising" do
      for value <- [
            Date.utc_today(),
            DateTime.utc_now(),
            Decimal.new("1.25"),
            MapSet.new(["private-value"])
          ] do
        assert PrivateContext.put(%{}, value) == {:error, :invalid_private_context}
      end

      assert PrivateContext.put(%{}, %{"date" => Date.utc_today()}) ==
               {:error, :invalid_private_context}

      assert PrivateContext.put(%{}, %{"set" => MapSet.new(["private-value"])}) ==
               {:error, :invalid_private_context}
    end

    test "non-JSON nested values and invalid UTF-8 are refused before encoding" do
      assert PrivateContext.put(%{}, %{"tuple" => {:not, "json"}}) ==
               {:error, :invalid_private_context}

      assert PrivateContext.put(%{}, %{"invalid_utf8" => <<255>>}) ==
               {:error, :invalid_private_context}
    end

    test "a maximum-depth object is refused when the reserved claims key would over-nest it" do
      context =
        Enum.reduce(1..63, %{"leaf" => "value"}, fn depth, nested ->
          %{"level_#{depth}" => nested}
        end)

      assert Claims.portable_json_object?(context)
      assert PrivateContext.put(%{}, context) == {:error, :invalid_private_context}
    end

    test "a value over the encoded bound is refused rather than truncated" do
      oversized = %{"blob" => String.duplicate("x", PrivateContext.max_encoded_bytes())}

      assert PrivateContext.put(%{}, oversized) == {:error, :private_context_too_large}
    end

    test "a value just inside the encoded bound is accepted" do
      # {"blob":"xxx..."} - 11 bytes of envelope around the padding.
      padding = String.duplicate("x", PrivateContext.max_encoded_bytes() - 11)
      sized = %{"blob" => padding}

      assert byte_size(JSON.encode!(sized)) == PrivateContext.max_encoded_bytes()
      assert {:ok, claims} = PrivateContext.put(%{}, sized)
      assert claims[PrivateContext.claims_key()] == sized
    end

    test "an exactly 4097-byte encoded value is refused" do
      # {"blob":"xxx..."} contributes 11 bytes around the value.
      sized = %{"blob" => String.duplicate("x", PrivateContext.max_encoded_bytes() - 10)}

      assert byte_size(JSON.encode!(sized)) == PrivateContext.max_encoded_bytes() + 1
      assert PrivateContext.put(%{}, sized) == {:error, :private_context_too_large}
    end
  end

  describe "pop/1" do
    test "returns the context and the claims without the reserved key" do
      context = %{"epoch" => 9}
      {:ok, claims} = PrivateContext.put(%{"nonce" => "n-1"}, context)

      assert {^context, remaining} = PrivateContext.pop(claims)
      assert remaining == %{"nonce" => "n-1"}
      refute Map.has_key?(remaining, PrivateContext.claims_key())
    end

    test "claims carrying no private context are returned unchanged" do
      assert PrivateContext.pop(%{"nonce" => "n-1"}) == {nil, %{"nonce" => "n-1"}}
    end

    test "a reserved key holding a non-map or JSON null is reported invalid, not passed through" do
      # A tampered or corrupted row must fail closed at the token endpoint
      # rather than reach the completion callback as if it were host state.
      for value <- ["not-a-map", nil] do
        claims = %{PrivateContext.claims_key() => value, "nonce" => "n-1"}

        assert {:invalid, remaining} = PrivateContext.pop(claims)
        assert remaining == %{"nonce" => "n-1"}
      end
    end
  end

  describe "reserved?/1" do
    test "detects a host claims map that already carries the reserved key" do
      assert PrivateContext.reserved?(%{PrivateContext.claims_key() => %{}})
      refute PrivateContext.reserved?(%{"nonce" => "n-1"})
      refute PrivateContext.reserved?(%{})
    end
  end

  test "the reserved key is namespaced so it cannot collide with an OIDC claim" do
    key = PrivateContext.claims_key()

    assert String.starts_with?(key, "attesto_phoenix.")
    refute key in ~w(nonce auth_time acr amr sid claims sub iss aud exp iat jti azp at_hash c_hash)
  end
end
