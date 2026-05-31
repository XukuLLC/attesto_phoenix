defmodule AttestoPhoenix.Schema.RefreshTokenTest do
  use ExUnit.Case, async: true

  alias AttestoPhoenix.Schema.RefreshToken

  @cnf_jkt "jkt"

  defp base_attrs(overrides \\ %{}) do
    Map.merge(
      %{
        token_hash: "hash-abc",
        family_id: "fam-1",
        subject: "subject-1",
        scope: ["read", "write"],
        expires_at: ~U[2030-01-01 00:00:00Z]
      },
      overrides
    )
  end

  describe "insert_changeset/2" do
    test "is valid with the required columns" do
      changeset = RefreshToken.insert_changeset(%RefreshToken{}, base_attrs())
      assert changeset.valid?
    end

    test "requires token_hash, family_id, subject, and expires_at" do
      changeset = RefreshToken.insert_changeset(%RefreshToken{}, %{})
      refute changeset.valid?

      for field <- [:token_hash, :family_id, :subject, :expires_at] do
        assert %{} = errors = errors_on(changeset)
        assert Map.has_key?(errors, field)
      end
    end

    test "defaults scope to an empty list and claims to an empty map" do
      changeset =
        RefreshToken.insert_changeset(%RefreshToken{}, base_attrs(%{scope: nil, claims: nil}))

      assert changeset.valid?
      # scope cast of nil leaves the field default; claims is forced to %{}.
      assert Ecto.Changeset.get_field(changeset, :claims) == %{}
    end

    test "deduplicates scope" do
      changeset =
        RefreshToken.insert_changeset(
          %RefreshToken{},
          base_attrs(%{scope: ["read", "read", "write"]})
        )

      assert Ecto.Changeset.get_change(changeset, :scope) == ["read", "write"]
    end

    test "refuses a record that starts consumed (RFC 6749 §6)" do
      changeset = RefreshToken.insert_changeset(%RefreshToken{}, base_attrs(%{consumed: true}))
      refute changeset.valid?
      assert Map.has_key?(errors_on(changeset), :consumed)
    end

    test "refuses a record that starts revoked" do
      changeset =
        RefreshToken.insert_changeset(%RefreshToken{}, base_attrs(%{family_revoked: true}))

      refute changeset.valid?
      assert Map.has_key?(errors_on(changeset), :family_revoked)
    end
  end

  describe "claim_changeset/1" do
    test "marks an unconsumed record consumed" do
      record = %RefreshToken{token_hash: "hash-abc", consumed: false}
      changeset = RefreshToken.claim_changeset(record, ~U[2030-01-01 00:00:00Z])
      assert Ecto.Changeset.get_change(changeset, :consumed) == true
      assert Ecto.Changeset.get_change(changeset, :consumed_at) == ~U[2030-01-01 00:00:00Z]
    end
  end

  describe "from_store_record/2" do
    test "flattens the opaque context into columns" do
      record = %{
        token_hash: "hash-abc",
        family_id: "fam-1",
        generation: 0,
        data: %{
          subject: "subject-1",
          scope: ["read"],
          client_id: "client-1",
          dpop_jkt: nil,
          claims: %{"k" => "v"}
        },
        expires_at: 1_900_000_000,
        consumed: false
      }

      attrs = RefreshToken.from_store_record(record)

      assert attrs.token_hash == "hash-abc"
      assert attrs.family_id == "fam-1"
      assert attrs.generation == 0
      assert attrs.subject == "subject-1"
      assert attrs.scope == ["read"]
      assert attrs.client_id == "client-1"
      assert attrs.claims == %{"k" => "v"}
      assert attrs.consumed == false
      assert attrs.consumed_at == nil
      assert attrs.successor == nil
      assert attrs.cnf == nil
      assert %DateTime{} = attrs.expires_at
      assert DateTime.to_unix(attrs.expires_at, :second) == 1_900_000_000
    end

    test "folds dpop_jkt into an RFC 7800 cnf confirmation" do
      record = %{
        token_hash: "hash-abc",
        family_id: "fam-1",
        generation: 0,
        data: %{subject: "subject-1", scope: [], dpop_jkt: "thumb-xyz", claims: %{}},
        expires_at: 1_900_000_000,
        consumed: false
      }

      attrs = RefreshToken.from_store_record(record)
      assert attrs.cnf == %{@cnf_jkt => "thumb-xyz"}
    end

    test "carries parent_hash from opts" do
      record = %{
        token_hash: "hash-child",
        family_id: "fam-1",
        generation: 1,
        data: %{subject: "subject-1", scope: [], claims: %{}},
        expires_at: 1_900_000_000,
        consumed: false
      }

      attrs = RefreshToken.from_store_record(record, parent_hash: "hash-parent")
      assert attrs.parent_hash == "hash-parent"
    end
  end

  describe "to_store_record/1" do
    test "rebuilds the contract record shape" do
      row = %RefreshToken{
        token_hash: "hash-abc",
        family_id: "fam-1",
        generation: 2,
        subject: "subject-1",
        scope: ["read", "write"],
        client_id: "client-1",
        cnf: nil,
        claims: %{"k" => "v"},
        consumed: false,
        consumed_at: nil,
        successor: nil,
        expires_at: ~U[2030-01-01 00:00:00Z]
      }

      record = RefreshToken.to_store_record(row)

      assert record.token_hash == "hash-abc"
      assert record.family_id == "fam-1"
      assert record.generation == 2
      assert record.consumed == false
      assert record.consumed_at == nil
      assert record.successor == nil
      assert is_integer(record.expires_at)

      assert record.data == %{
               subject: "subject-1",
               scope: ["read", "write"],
               client_id: "client-1",
               dpop_jkt: nil,
               claims: %{"k" => "v"}
             }
    end

    test "unfolds a cnf confirmation back into dpop_jkt" do
      row = %RefreshToken{
        token_hash: "hash-abc",
        family_id: "fam-1",
        subject: "subject-1",
        scope: [],
        cnf: %{@cnf_jkt => "thumb-xyz"},
        claims: %{},
        consumed: false,
        expires_at: ~U[2030-01-01 00:00:00Z]
      }

      record = RefreshToken.to_store_record(row)
      assert record.data.dpop_jkt == "thumb-xyz"
    end

    test "normalizes persisted successor keys back to the core contract shape" do
      row = %RefreshToken{
        token_hash: "hash-parent",
        family_id: "fam-1",
        generation: 0,
        subject: "subject-1",
        scope: ["read"],
        claims: %{},
        consumed: true,
        consumed_at: ~U[2030-01-01 00:00:00Z],
        successor: %{
          "token" => "successor-plaintext",
          "generation" => 1,
          "context" => %{
            "subject" => "subject-1",
            "scope" => ["read"],
            "client_id" => "client-1",
            "dpop_jkt" => "thumb-xyz",
            "claims" => %{"tenant" => "t1"}
          }
        },
        expires_at: ~U[2030-01-01 00:00:00Z]
      }

      record = RefreshToken.to_store_record(row)

      assert record.consumed_at == DateTime.to_unix(~U[2030-01-01 00:00:00Z], :second)

      assert record.successor == %{
               token: "successor-plaintext",
               generation: 1,
               context: %{
                 subject: "subject-1",
                 scope: ["read"],
                 client_id: "client-1",
                 dpop_jkt: "thumb-xyz",
                 claims: %{"tenant" => "t1"}
               }
             }
    end
  end

  describe "round trip" do
    test "from_store_record |> insert |> to_store_record preserves the context" do
      original = %{
        token_hash: "hash-abc",
        family_id: "fam-1",
        generation: 3,
        data: %{
          subject: "subject-1",
          scope: ["read", "write"],
          client_id: "client-1",
          dpop_jkt: "thumb-xyz",
          claims: %{"tenant" => "t1"}
        },
        expires_at: 1_900_000_000,
        consumed: false,
        consumed_at: nil,
        successor: nil
      }

      attrs = RefreshToken.from_store_record(original)

      row =
        %RefreshToken{}
        |> RefreshToken.insert_changeset(attrs)
        |> Ecto.Changeset.apply_changes()

      rebuilt = RefreshToken.to_store_record(row)

      assert rebuilt.token_hash == original.token_hash
      assert rebuilt.family_id == original.family_id
      assert rebuilt.generation == original.generation
      assert rebuilt.consumed == original.consumed
      assert rebuilt.consumed_at == original.consumed_at
      assert rebuilt.successor == original.successor
      assert rebuilt.expires_at == original.expires_at
      assert rebuilt.data == original.data
    end
  end

  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
