defmodule AttestoPhoenix.Schema.AuthorizationTest do
  use ExUnit.Case, async: true

  alias AttestoPhoenix.Schema.Authorization

  @now ~U[2024-01-01 00:00:00Z]
  @expires_unix DateTime.to_unix(~U[2024-01-01 00:01:00Z], :second)

  defp base_data do
    %{
      client_id: "client-123",
      subject: "subject-abc",
      scope: ["read", "write"],
      resource: [],
      redirect_uri: "https://rp.example/cb",
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      dpop_jkt: nil,
      family_id: nil,
      claims: %{"acr" => "phr"}
    }
  end

  defp base_record(data_overrides \\ %{}) do
    %{
      code_hash: "hash-of-the-code",
      data: Map.merge(base_data(), data_overrides),
      expires_at: @expires_unix
    }
  end

  describe "schema contract" do
    test "code_hash is the primary key and both rolling-deploy constraints are mapped" do
      assert Authorization.__schema__(:primary_key) == [:code_hash]

      changeset = Authorization.from_record(base_record(), now: @now)

      constraint_names =
        for constraint <- changeset.constraints,
            constraint.type == :unique,
            constraint.field == :code_hash,
            do: constraint.constraint

      assert constraint_names == [
               "attesto_authorization_codes_pkey",
               "attesto_authorization_codes_code_hash_index"
             ]
    end
  end

  describe "from_record/2" do
    test "produces a valid changeset spreading grant data across columns" do
      changeset = Authorization.from_record(base_record(), now: @now)

      assert changeset.valid?
      assert Ecto.Changeset.get_change(changeset, :code_hash) == "hash-of-the-code"
      assert Ecto.Changeset.get_change(changeset, :client_id) == "client-123"
      assert Ecto.Changeset.get_change(changeset, :subject) == "subject-abc"
      assert Ecto.Changeset.get_change(changeset, :scope) == ["read", "write"]
      assert Ecto.Changeset.get_change(changeset, :redirect_uri) == "https://rp.example/cb"
      assert Ecto.Changeset.get_change(changeset, :claims) == %{"acr" => "phr"}
    end

    test "preserves portable nested claims and exact-range integer boundaries" do
      claims = %{
        "nested" => %{
          "minimum" => -9_007_199_254_740_991,
          "maximum" => 9_007_199_254_740_991,
          "values" => [nil, true, "text", %{"leaf" => 42}]
        }
      }

      changeset = Authorization.from_record(base_record(%{claims: claims}), now: @now)

      assert changeset.valid?
      assert Ecto.Changeset.get_change(changeset, :claims) == claims
    end

    test "rejects non-portable claims before Ecto projection" do
      invalid_claims = [
        %{atom_key: "value"},
        %{"nested" => %{atom_key: "value"}},
        %{"float" => 1.5},
        %{"nul" => "a\0b"},
        %{"large" => 9_007_199_254_740_992},
        nested_claims(64)
      ]

      Enum.each(invalid_claims, fn claims ->
        assert_raise ArgumentError, "authorization code record has invalid canonical data", fn ->
          Authorization.from_record(base_record(%{claims: claims}), now: @now)
        end
      end)
    end

    test "carries the grant family id for descendant revocation" do
      changeset =
        base_record(%{family_id: "fam-abc"})
        |> Authorization.from_record(now: @now)

      assert changeset.valid?
      assert Ecto.Changeset.get_change(changeset, :family_id) == "fam-abc"
    end

    test "converts the unix expiry to a utc_datetime column" do
      changeset = Authorization.from_record(base_record(), now: @now)

      assert Ecto.Changeset.get_change(changeset, :expires_at) ==
               DateTime.from_unix!(@expires_unix, :second)
    end

    test "stamps inserted_at from the :now option, truncated to the second" do
      changeset =
        Authorization.from_record(base_record(), now: ~U[2024-01-01 00:00:00.999Z])

      assert Ecto.Changeset.get_change(changeset, :inserted_at) == @now
    end

    test "promotes a flat dpop_jkt into a cnf binding map (RFC 7800 / RFC 9449)" do
      changeset =
        base_record(%{dpop_jkt: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"})
        |> Authorization.from_record(now: @now)

      assert Ecto.Changeset.get_change(changeset, :cnf) ==
               %{"jkt" => "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}
    end

    test "stores no cnf for an unbound code rather than an empty map" do
      changeset = Authorization.from_record(base_record(), now: @now)

      refute Ecto.Changeset.get_change(changeset, :cnf)
    end

    test "rejects a legacy top-level nonce in the core data map" do
      assert_raise ArgumentError, "authorization code record has invalid canonical data", fn ->
        base_record(%{nonce: "n-0S6_WzA2Mj"})
        |> Authorization.from_record(now: @now)
      end
    end

    test "applies the :prefix option to the row" do
      changeset =
        Authorization.from_record(base_record(), now: @now, prefix: "auth")

      assert Ecto.get_meta(changeset.data, :prefix) == "auth"
    end

    test "defaults to no prefix" do
      changeset = Authorization.from_record(base_record(), now: @now)

      assert Ecto.get_meta(changeset.data, :prefix) == nil
    end

    test "fails closed when the code hash is absent" do
      record = base_record() |> Map.delete(:code_hash)
      changeset = Authorization.from_record(record, now: @now)

      refute changeset.valid?
      assert %{code_hash: ["can't be blank"]} = errors_on(changeset)
    end

    test "fails closed when the client_id is absent" do
      assert_raise ArgumentError, "authorization code record has invalid canonical data", fn ->
        base_record()
        |> put_in([:data], Map.delete(base_data(), :client_id))
        |> Authorization.from_record(now: @now)
      end
    end

    test "fails closed when the redirect_uri is absent" do
      assert_raise ArgumentError, "authorization code record has invalid canonical data", fn ->
        base_record()
        |> put_in([:data], Map.delete(base_data(), :redirect_uri))
        |> Authorization.from_record(now: @now)
      end
    end

    test "accepts an absent PKCE challenge and stores no method (RFC 9700 confidential-client relaxation)" do
      # PKCE is optional at persistence: a confidential client the host exempted
      # from PKCE (Attesto.AuthorizationRequest's :require_pkce) issues a code
      # with no challenge. The changeset is valid and stores a NULL challenge AND
      # a NULL method - never a spurious "S256" for a challenge that is not there.
      data =
        base_data()
        |> Map.put(:code_challenge, nil)

      changeset =
        base_record()
        |> put_in([:data], data)
        |> Authorization.from_record(now: @now)

      assert changeset.valid?
      assert Ecto.Changeset.get_field(changeset, :code_challenge) == nil
      assert Ecto.Changeset.get_field(changeset, :code_challenge_method) == nil
    end

    test "rejects a non-S256 code-challenge method (RFC 7636 §4.3)" do
      assert_raise ArgumentError, "authorization code record has invalid canonical data", fn ->
        base_record(%{code_challenge_method: "plain"})
        |> Authorization.from_record(now: @now)
      end
    end

    test "rejects an extra canonical data key before projecting it into columns" do
      assert_raise ArgumentError, "authorization code record has invalid canonical data", fn ->
        base_record(%{adapter_metadata: "must stay opaque"})
        |> Authorization.from_record(now: @now)
      end
    end

    test "rejects a missing data map before projecting defaults" do
      assert_raise ArgumentError, "authorization code record has invalid canonical data", fn ->
        base_record() |> Map.delete(:data) |> Authorization.from_record(now: @now)
      end
    end
  end

  describe "to_record/1" do
    test "rebuilds the exact canonical grant data expected by the protocol layer" do
      row = %Authorization{
        code_hash: "hash-of-the-code",
        client_id: "client-123",
        subject: "subject-abc",
        scope: ["read", "write"],
        redirect_uri: "https://rp.example/cb",
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        code_challenge_method: "S256",
        cnf: nil,
        nonce: "n-0S6_WzA2Mj",
        claims: %{"acr" => "phr"},
        family_id: "fam-record",
        expires_at: ~U[2024-01-01 00:01:00Z]
      }

      record = Authorization.to_record(row)

      assert record.code_hash == "hash-of-the-code"
      assert record.expires_at == @expires_unix

      assert Map.keys(record.data) |> Enum.sort() ==
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

      assert record.data == %{
               client_id: "client-123",
               subject: "subject-abc",
               scope: ["read", "write"],
               resource: [],
               redirect_uri: "https://rp.example/cb",
               code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
               dpop_jkt: nil,
               claims: %{"acr" => "phr", "nonce" => "n-0S6_WzA2Mj"},
               family_id: "fam-record"
             }
    end

    test "legacy nonce overrides nil or conflicting atom and string claim keys" do
      claims_variants = [
        %{"acr" => "phr", "nonce" => nil, nonce: "claim-atom"},
        %{"acr" => "phr", "nonce" => "claim-string", nonce: nil},
        %{"acr" => "phr", "nonce" => "claim-string", nonce: "claim-atom"}
      ]

      Enum.each(claims_variants, fn claims ->
        row = %Authorization{
          code_hash: "h",
          client_id: "c",
          subject: "s",
          scope: [],
          resource: [],
          redirect_uri: "https://rp.example/cb",
          code_challenge: "chal",
          code_challenge_method: "S256",
          cnf: nil,
          nonce: "legacy-nonce",
          claims: claims,
          expires_at: ~U[2024-01-01 00:01:00Z]
        }

        assert Authorization.to_record(row).data.claims == %{"acr" => "phr", "nonce" => "legacy-nonce"}
      end)
    end

    test "preserves a canonical string nonce when the legacy nonce column is nil" do
      row = %Authorization{
        code_hash: "h",
        client_id: "c",
        subject: "s",
        scope: [],
        resource: [],
        redirect_uri: "https://rp.example/cb",
        code_challenge: "chal",
        code_challenge_method: "S256",
        cnf: nil,
        nonce: nil,
        claims: %{"nonce" => "canonical-nonce"},
        expires_at: ~U[2024-01-01 00:01:00Z]
      }

      assert Authorization.to_record(row).data.claims == %{"nonce" => "canonical-nonce"}
    end

    test "leaves atom and mixed nonce maps malformed when the legacy nonce column is nil" do
      for claims <- [%{nonce: "atom-nonce"}, %{"nonce" => "string-nonce", nonce: "atom-nonce"}] do
        row = %Authorization{
          code_hash: "h",
          client_id: "c",
          subject: "s",
          scope: [],
          resource: [],
          redirect_uri: "https://rp.example/cb",
          code_challenge: "chal",
          code_challenge_method: "S256",
          cnf: nil,
          nonce: nil,
          claims: claims,
          expires_at: ~U[2024-01-01 00:01:00Z]
        }

        assert Authorization.to_record(row).data.claims == claims
      end
    end

    test "flattens a cnf binding back to dpop_jkt" do
      row = %Authorization{
        code_hash: "h",
        client_id: "c",
        subject: "s",
        scope: [],
        redirect_uri: "https://rp.example/cb",
        code_challenge: "chal",
        code_challenge_method: "S256",
        cnf: %{"jkt" => "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"},
        claims: %{},
        expires_at: ~U[2024-01-01 00:01:00Z]
      }

      record = Authorization.to_record(row)

      assert record.data.dpop_jkt == "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
    end

    test "accepts the legacy atom-key cnf binding" do
      row = %Authorization{
        code_hash: "h",
        client_id: "c",
        subject: "s",
        scope: [],
        resource: [],
        redirect_uri: "https://rp.example/cb",
        code_challenge: "chal",
        code_challenge_method: "S256",
        cnf: %{jkt: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"},
        claims: %{},
        expires_at: ~U[2024-01-01 00:01:00Z]
      }

      assert Authorization.to_record(row).data.dpop_jkt ==
               "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
    end

    test "rejects malformed cnf instead of treating a bound code as unbound" do
      row = %Authorization{
        code_hash: "h",
        client_id: "c",
        subject: "s",
        scope: [],
        resource: [],
        redirect_uri: "https://rp.example/cb",
        code_challenge: "chal",
        code_challenge_method: "S256",
        cnf: %{"jkt" => "not-a-thumbprint"},
        claims: %{},
        expires_at: ~U[2024-01-01 00:01:00Z]
      }

      assert_raise ArgumentError, "authorization code record has invalid confirmation binding", fn ->
        Authorization.to_record(row)
      end
    end

    test "rejects cnf maps with unsupported or extra binding keys" do
      row = %Authorization{
        code_hash: "h",
        client_id: "c",
        subject: "s",
        scope: [],
        resource: [],
        redirect_uri: "https://rp.example/cb",
        code_challenge: "chal",
        code_challenge_method: "S256",
        cnf: %{"jkt" => "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I", "x5t#S256" => "x"},
        claims: %{},
        expires_at: ~U[2024-01-01 00:01:00Z]
      }

      assert_raise ArgumentError, "authorization code record has invalid confirmation binding", fn ->
        Authorization.to_record(row)
      end
    end

    test "preserves malformed nil claims for core read validation" do
      row = %Authorization{
        code_hash: "h",
        client_id: "c",
        subject: "s",
        scope: nil,
        redirect_uri: "https://rp.example/cb",
        code_challenge: "chal",
        code_challenge_method: "S256",
        cnf: nil,
        nonce: "legacy-nonce",
        claims: nil,
        expires_at: ~U[2024-01-01 00:01:00Z]
      }

      record = Authorization.to_record(row)

      assert record.data.scope == nil
      assert record.data.claims == nil
    end

    test "preserves malformed nil claims when the legacy nonce column is nil" do
      row = %Authorization{
        code_hash: "h",
        client_id: "c",
        subject: "s",
        scope: [],
        resource: [],
        redirect_uri: "https://rp.example/cb",
        code_challenge: "chal",
        code_challenge_method: "S256",
        cnf: nil,
        nonce: nil,
        claims: nil,
        expires_at: ~U[2024-01-01 00:01:00Z]
      }

      assert Authorization.to_record(row).data.claims == nil
    end
  end

  describe "from_record/2 then to_record/1 round-trip" do
    test "round-trips nested portable claims and exact-range integers unchanged" do
      claims = %{
        "nested" => %{
          "minimum" => -9_007_199_254_740_991,
          "maximum" => 9_007_199_254_740_991,
          "values" => [nil, true, "text", %{"leaf" => 42}]
        }
      }

      row =
        base_record(%{claims: claims})
        |> Authorization.from_record(now: @now)
        |> Ecto.Changeset.apply_changes()

      assert Authorization.to_record(row).data.claims == claims
    end

    test "preserves the grant context for a DPoP-bound code" do
      original =
        base_record(%{
          dpop_jkt: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
          claims: %{"acr" => "phr", "nonce" => "nn"}
        })

      row =
        original
        |> Authorization.from_record(now: @now)
        |> Ecto.Changeset.apply_changes()

      record = Authorization.to_record(row)

      assert record.code_hash == original.code_hash
      assert record.expires_at == original.expires_at
      assert record.data.client_id == original.data.client_id
      assert record.data.subject == original.data.subject
      assert record.data.scope == original.data.scope
      assert record.data.redirect_uri == original.data.redirect_uri
      assert record.data.code_challenge == original.data.code_challenge
      assert record.data.dpop_jkt == original.data.dpop_jkt
      assert record.data.family_id == Map.get(original.data, :family_id)
      assert record.data.claims == original.data.claims
    end
  end

  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Regex.replace(~r"%{(\w+)}", message, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end

  defp nested_claims(0), do: %{}
  defp nested_claims(depth), do: %{"nested" => nested_claims(depth - 1)}
end
