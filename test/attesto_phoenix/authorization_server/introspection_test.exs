defmodule AttestoPhoenix.AuthorizationServer.IntrospectionTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.{JWS, PrincipalKind, Token}
  alias AttestoPhoenix.AuthorizationServer.Introspection
  alias AttestoPhoenix.{Config, OAuthError}

  defmodule TestKeystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @pem JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_pem() |> elem(1)

    @impl true
    def signing_pem, do: @pem

    @impl true
    def verification_pems, do: [@pem]
  end

  defmodule StubRepo do
    @moduledoc false
  end

  defmodule StubRefreshStore do
    @moduledoc false
    @behaviour Attesto.RefreshStore

    @impl true
    def insert(_entry), do: :ok

    @impl true
    def get(_token_hash), do: :error

    @impl true
    def rotate(_parent_hash, _child, _successor, _opts), do: :error

    @impl true
    def revoke_family(_family_id), do: :ok
  end

  defmodule RevokedAccessTokenStore do
    @moduledoc false

    def access_token_revoked?(jti), do: jti == Process.get({__MODULE__, :jti})
  end

  defp build_config(overrides \\ []) do
    base = [
      issuer: "https://issuer.example",
      audience: "https://api.example.com",
      keystore: TestKeystore,
      repo: StubRepo,
      refresh_store: StubRefreshStore,
      principal_kinds: [PrincipalKind.new("user", "usr_")],
      load_client: fn _id -> {:error, :not_found} end,
      verify_client_secret: fn _client, _secret -> false end,
      load_principal: fn sub -> {:ok, %{id: sub}} end
    ]

    Config.new(Keyword.merge(base, overrides))
  end

  defp mint_access_token(config, client_id \\ "client-1") do
    {:ok, %{access_token: jwt}} =
      Token.mint(
        Config.to_attesto_config(config),
        %{
          kind: "user",
          sub: "usr_42",
          scopes: ["openid", "profile"],
          claims: %{"client_id" => client_id}
        }
      )

    jwt
  end

  describe "fetch_token/1" do
    test "extracts a non-empty binary token and rejects missing or empty values" do
      assert {:ok, "tok-1"} = Introspection.fetch_token(%{"token" => "tok-1"})

      assert {:error, %OAuthError{error: :invalid_request, status: 400}} =
               Introspection.fetch_token(%{})

      assert {:error, %OAuthError{error: :invalid_request, status: 400}} =
               Introspection.fetch_token(%{"token" => ""})
    end
  end

  describe "introspect/4" do
    test "returns active response for a valid access token and accepts typed token_type_hint" do
      config = build_config()
      jwt = mint_access_token(config)

      response = Introspection.introspect(config, "client-1", jwt, "access_token")

      assert response["active"] == true
      assert response["sub"] == "usr_42"
      assert response["client_id"] == "client-1"
      assert response["scope"] == "openid profile"
    end

    test "without introspection_authorize, releases a token only to its client or a client in aud" do
      config = build_config()
      jwt = mint_access_token(config, "owner-client")

      assert Introspection.introspect(config, "owner-client", jwt, nil)["active"] == true
      assert Introspection.introspect(config, "https://api.example.com", jwt, nil)["active"] == true
      assert Introspection.introspect(config, "other-client", jwt, nil) == %{"active" => false}
      assert Introspection.introspect(config, nil, jwt, nil) == %{"active" => false}
    end

    test "a pairwise caller is shown its derived sub; one with no sector identifier gets inactive" do
      salt = String.duplicate("k", 32)

      clients = %{
        "client-1" => %{type: "pairwise", redirect_uris: ["https://rp.example/cb"]},
        "client-2" => %{type: "public", redirect_uris: ["https://two.example/cb"]},
        "client-3" => %{type: "pairwise", redirect_uris: ["https://a.example/cb", "https://b.example/cb"]}
      }

      config =
        build_config(
          load_client: fn id -> with :error <- Map.fetch(clients, id), do: {:error, :not_found} end,
          client_redirect_uris: fn client -> client.redirect_uris end,
          client_subject_type: fn client -> client.type end,
          pairwise_subject_salt: salt
        )

      assert %{"active" => true, "sub" => sub} =
               Introspection.introspect(config, "client-1", mint_access_token(config, "client-1"))

      assert sub == Attesto.PairwiseSubject.derive("rp.example", "usr_42", salt)

      assert %{"active" => true, "sub" => "usr_42"} =
               Introspection.introspect(config, "client-2", mint_access_token(config, "client-2"))

      assert Introspection.introspect(config, "client-3", mint_access_token(config, "client-3")) ==
               %{"active" => false}
    end

    test "downgrades to inactive when introspection_authorize denies the caller" do
      config =
        build_config(
          introspection_authorize: fn caller_client_id, token_response ->
            caller_client_id == token_response["client_id"]
          end
        )

      jwt = mint_access_token(config, "owner-client")

      assert Introspection.introspect(config, "other-client", jwt, nil) == %{"active" => false}
      assert Introspection.introspect(config, "owner-client", jwt, nil)["active"] == true
    end

    test "suppresses an access token contained in code_store.access_token_revoked?/1" do
      config = build_config(code_store: RevokedAccessTokenStore)
      jwt = mint_access_token(config)
      {:ok, payload} = JWS.peek_json(jwt, :payload)
      Process.put({RevokedAccessTokenStore, :jti}, payload["jti"])

      assert Introspection.introspect(config, "caller-client", jwt) == %{"active" => false}
    end
  end

  describe "sign_response/3" do
    test "signs an RFC 9701 token-introspection+jwt audienced to the caller client_id" do
      config = build_config()
      response = %{"active" => true, "sub" => "usr_42"}

      assert {:ok, jwt} = Introspection.sign_response(config, "caller-client", response)
      assert {:ok, %{"typ" => "token-introspection+jwt"}} = JWS.peek_json(jwt, :protected)
      assert {:ok, payload} = JWS.peek_json(jwt, :payload)
      assert payload["iss"] == "https://issuer.example"
      assert payload["aud"] == "caller-client"
      assert payload["token_introspection"] == response
    end
  end
end
