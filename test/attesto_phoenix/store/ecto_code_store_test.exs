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

  alias AttestoPhoenix.AuthorizationCodePrivateContext, as: PrivateContext
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Controller.AuthorizeController
  alias AttestoPhoenix.Schema.Authorization
  alias AttestoPhoenix.Store.EctoCodeStore
  alias AttestoPhoenix.TestRepo

  @moduletag :ecto

  # take/1 does not gate on expiry; a future value keeps fixtures realistic.
  @future_seconds System.system_time(:second) + 600

  defmodule ProbeRefreshStore do
    @behaviour Attesto.RefreshStore

    def insert(_record), do: :ok
    def get(_hash), do: :error
    def rotate(_hash, _child, _successor, _opts), do: :error

    def revoke_family(family_id) do
      send(self(), {:refresh_family_revoked, family_id})
      :ok
    end
  end

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
      assert {:ok, %{code_hash: "hash-1"}} = EctoCodeStore.read("hash-1")
    end

    test "persists a client_id, scope token, and resource longer than 255 characters" do
      # A Client ID Metadata Document client_id may be up to 2,048 bytes, and
      # neither RFC 6749 §3.3 scope tokens nor RFC 8707 resource URIs have a
      # length limit.
      client_id = "https://client.example.com/" <> String.duplicate("a", 2_021)
      scope = ["openid", String.duplicate("s", 300)]
      resource = ["https://api.example.com/" <> String.duplicate("r", 300)]
      data = grant_data(%{client_id: client_id, scope: scope, resource: resource})

      assert :ok = EctoCodeStore.put(entry("hash-long-values", data))

      assert {:ok, %{data: %{client_id: ^client_id, scope: ^scope, resource: ^resource}}} =
               EctoCodeStore.read("hash-long-values")
    end

    test "round-trips the grant context through the column bridge" do
      assert :ok = EctoCodeStore.put(entry("hash-rt"))
      assert {:ok, %{data: data}} = EctoCodeStore.read("hash-rt")

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
      assert {:ok, %{data: %{claims: ^claims}}} = EctoCodeStore.read("hash-jsonb-claims")
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
      assert {:ok, %{expires_at: @future_seconds}} = EctoCodeStore.read("hash-exp")
    end

    test "rejects a duplicate code_hash rather than overwriting" do
      assert :ok = EctoCodeStore.put(entry("hash-dup", grant_data(%{subject: "first"})))

      # A repeated primary key is a caller bug; the unique constraint must
      # surface, never a silent upsert that could replace an issued code. The
      # raised exception is rebuilt from a value-free changeset because Ecto's
      # exception formatter otherwise prints raw params despite field redaction.
      sentinel = "private-context-must-not-escape-the-insert-error"

      claims =
        grant_data().claims
        |> Map.put(PrivateContext.claims_key(), %{"marker" => sentinel})

      error =
        assert_raise Ecto.InvalidChangesetError, fn ->
          EctoCodeStore.put(entry("hash-dup", grant_data(%{subject: "second", claims: claims})))
        end

      assert error.changeset.params == nil
      assert error.changeset.changes == %{}

      assert error.changeset.errors ==
               [code_hash: {"authorization code could not be stored", []}]

      refute Exception.message(error) =~ sentinel
      refute inspect(error) =~ sentinel

      # The original row is untouched.
      assert {:ok, %{data: %{subject: "first"}}} = EctoCodeStore.read("hash-dup")
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

  describe "atomic transitions" do
    test "replay flagging reports to core and never revokes a family itself" do
      :ok = EctoCodeStore.put(entry("hash-overlap"))
      :ok = EctoCodeStore.claim("hash-overlap")
      :ok = EctoCodeStore.record_access_token_for_code("hash-overlap", "jti-overlap", @future_seconds)
      :ok = EctoCodeStore.flag_replay("hash-overlap")

      assert {:ok, true} =
               EctoCodeStore.finish("hash-overlap", %{
                 family_id: "issued",
                 subject: "subject-1",
                 replay_retain_until: nil
               })

      assert EctoCodeStore.access_token_revoked?("jti-overlap")

      assert {:ok, %{data: %{family_id: "fam-1"}, redemption: %{family_id: "issued"}}} =
               EctoCodeStore.read("hash-overlap")

      :ok = EctoCodeStore.revoke_family_access_tokens("issued")
      assert EctoCodeStore.access_token_revoked?("jti-overlap")
    end

    test "malformed redemption is rejected before writing" do
      :ok = EctoCodeStore.put(entry("hash-invalid"))
      :ok = EctoCodeStore.claim("hash-invalid")

      for redemption <- [
            %{},
            %{family_id: "fam", subject: "subject-1", replay_retain_until: "tomorrow"},
            %{family_id: nil, subject: "subject-1", replay_retain_until: @future_seconds}
          ] do
        assert_raise ArgumentError, "invalid authorization-code redemption record", fn ->
          EctoCodeStore.finish("hash-invalid", redemption)
        end
      end

      assert {:ok, %{state: :claimed}} = EctoCodeStore.read("hash-invalid")
    end

    test "missing access-token linkage fails loudly" do
      assert_raise ArgumentError, ~r/access-token linkage requires/, fn ->
        EctoCodeStore.record_access_token_for_code("missing", "jti", @future_seconds)
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
      expires_at = now + 600

      log =
        capture_log([level: :debug], fn ->
          assert :ok = EctoCodeStore.put(entry(code_hash, grant_data(%{family_id: nil}), expires_at))
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
          assert {:ok, _} = EctoCodeStore.read(code_hash)
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
          assert :ok = EctoCodeStore.claim(code_hash)
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []

          assert {:ok, _} =
                   EctoCodeStore.finish(code_hash, %{
                     family_id: family_id,
                     subject: "subject-1",
                     replay_retain_until: nil
                   })

          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []

          assert :ok = EctoCodeStore.record_access_token_for_code(code_hash, code_jti, expires_at)
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
          assert :ok = EctoCodeStore.revoke_family_access_tokens(family_id)
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
          assert EctoCodeStore.access_token_revoked?(code_jti)
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
          assert :ok = EctoCodeStore.revoke_access_token_for_code(code_hash)
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
          assert :ok = EctoCodeStore.revoke_access_token_for_code("telemetry-code-missing")
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
          assert {:ok, %{state: :redeemed}} = EctoCodeStore.read(code_hash)
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
          assert :error = EctoCodeStore.read("telemetry-code-missing")
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
          assert :error = EctoCodeStore.read("telemetry-code-missing")
          assert AttestoPhoenix.TestTelemetryCapture.collect(ref) == []
        end)

      for sentinel <- [code_hash, family_id, code_jti] do
        refute log =~ sentinel
      end
    end
  end

  describe "authorization endpoint" do
    @long_client_id "https://client.example.com/" <> String.duplicate("a", 300)
    @redirect_uri "https://client.example.com/callback"
    @code_challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

    defmodule EndpointKeystore do
      @moduledoc false
      @behaviour Attesto.Keystore

      @pem JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_pem() |> elem(1)

      @impl true
      def signing_pem, do: @pem

      @impl true
      def verification_pems, do: [@pem]
    end

    def endpoint_client(client_id), do: {:ok, %{id: client_id}}

    def endpoint_authenticate(_conn, _request, _opts),
      do: {:authenticated, %{subject: "user-42", auth_time: System.system_time(:second)}}

    defp authorize(params) do
      config =
        Config.new(
          issuer: "https://issuer.example.com",
          audience: "https://issuer.example.com",
          keystore: EndpointKeystore,
          repo: TestRepo,
          load_client: &__MODULE__.endpoint_client/1,
          verify_client_secret: fn _client, _secret -> false end,
          load_principal: fn _subject -> {:error, :not_found} end,
          client_id: fn %{id: id} -> id end,
          client_redirect_uris: fn _client -> [@redirect_uri] end,
          authenticate_resource_owner: &__MODULE__.endpoint_authenticate/3,
          # The scope policy runs at the authorization endpoint; this test
          # requests a scope outside any catalog on purpose.
          authorize_scope: fn _client, requested -> {:ok, requested} end,
          consent: fn _conn, _request, subject -> {:consented, subject} end,
          code_store: EctoCodeStore,
          principal_kinds: [Attesto.PrincipalKind.new("user", "usr_")]
        )

      Phoenix.ConnTest.build_conn()
      |> Map.put(:scheme, :https)
      |> Plug.Conn.put_private(:attesto_phoenix_config, config)
      |> AuthorizeController.authorize(
        Map.merge(
          %{
            "response_type" => "code",
            "client_id" => @long_client_id,
            "redirect_uri" => @redirect_uri,
            "scope" => "openid",
            "state" => "xyz",
            "code_challenge" => @code_challenge,
            "code_challenge_method" => "S256"
          },
          params
        )
      )
    end

    test "issues a code for a client_id and scope token longer than 255 characters" do
      long_scope = String.duplicate("s", 300)
      conn = authorize(%{"scope" => "openid " <> long_scope})

      assert conn.status == 302
      [location] = Plug.Conn.get_resp_header(conn, "location")
      assert %{"code" => code} = location |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

      assert {:ok, %{data: %{client_id: @long_client_id, scope: ["openid", ^long_scope]}}} =
               EctoCodeStore.read(Attesto.Secret.hash(code))
    end
  end
end
