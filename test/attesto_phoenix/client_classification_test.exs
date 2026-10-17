defmodule AttestoPhoenix.ClientClassificationTest do
  use ExUnit.Case, async: true

  alias AttestoPhoenix.{ClientClassification, Config}
  alias AttestoPhoenix.ClientIdMetadata.Client, as: CIMDClient

  defmodule StubKeystore do
    @moduledoc false
  end

  defmodule StubRepo do
    @moduledoc false
  end

  test "returns a tri-state result for registered clients" do
    client = %{id: "client-1"}

    assert ClientClassification.classify(config(nil), client) == :unknown
    assert ClientClassification.classify(config(fn _ -> true end), client) == :public
    assert ClientClassification.classify(config(fn _ -> false end), client) == :confidential
  end

  test "always classifies self-asserted metadata-document clients as public" do
    public = %CIMDClient{metadata: %{}}
    confidential = %CIMDClient{metadata: %{"token_endpoint_auth_method" => "private_key_jwt"}}

    assert ClientClassification.classify(config(fn _ -> false end), public) == :public
    assert ClientClassification.classify(config(fn _ -> true end), confidential) == :public
    assert ClientClassification.classify(config(fn _ -> true end), %CIMDClient{metadata: nil}) == :public
  end

  test "rejects a malformed host classification" do
    assert_raise ArgumentError, ~r/:client_public\? callback must return true or false/, fn ->
      ClientClassification.classify(config(fn _ -> :unknown end), %{id: "client-1"})
    end
  end

  defp config(callback) do
    %Config{
      issuer: "https://issuer.example",
      keystore: StubKeystore,
      repo: StubRepo,
      client_public?: callback
    }
  end
end
