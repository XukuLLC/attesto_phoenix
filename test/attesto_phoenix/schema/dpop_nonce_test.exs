defmodule AttestoPhoenix.Schema.DPoPNonceTest do
  use ExUnit.Case, async: true

  alias AttestoPhoenix.Schema.DPoPNonce

  describe "schema definition" do
    test "persists to the nonce table" do
      assert DPoPNonce.__schema__(:source) == "dpop_nonces"
    end

    test "carries the issued-nonce columns" do
      assert DPoPNonce.__schema__(:fields) == [:id, :nonce, :issued_at, :expires_at, :used_at]
    end

    test "uses a binary_id primary key" do
      assert DPoPNonce.__schema__(:type, :id) == :binary_id
    end

    test "the issue, expiry, and consumption instants are UTC second-resolution" do
      assert DPoPNonce.__schema__(:type, :issued_at) == :utc_datetime
      assert DPoPNonce.__schema__(:type, :expires_at) == :utc_datetime
      assert DPoPNonce.__schema__(:type, :used_at) == :utc_datetime
    end

    test "has no updated_at column (a nonce is never mutated except to consume)" do
      refute :updated_at in DPoPNonce.__schema__(:fields)
    end
  end

  describe "issue_changeset/2" do
    test "accepts an opaque nonce with its issue and expiry instants" do
      issued_at = ~U[2026-01-01 00:00:00Z]
      expires_at = ~U[2026-01-01 00:05:00Z]

      changeset =
        DPoPNonce.issue_changeset(%{
          nonce: "opaque-server-value",
          issued_at: issued_at,
          expires_at: expires_at
        })

      assert changeset.valid?
      assert Ecto.Changeset.get_change(changeset, :nonce) == "opaque-server-value"
      assert Ecto.Changeset.get_change(changeset, :issued_at) == issued_at
      assert Ecto.Changeset.get_change(changeset, :expires_at) == expires_at
    end

    test "leaves a freshly issued nonce unused" do
      changeset =
        DPoPNonce.issue_changeset(%{
          nonce: "opaque-server-value",
          issued_at: ~U[2026-01-01 00:00:00Z],
          expires_at: ~U[2026-01-01 00:05:00Z]
        })

      assert Ecto.Changeset.get_field(changeset, :used_at) == nil
    end

    test "fails closed when the expiry is missing" do
      changeset =
        DPoPNonce.issue_changeset(%{
          nonce: "opaque-server-value",
          issued_at: ~U[2026-01-01 00:00:00Z]
        })

      refute changeset.valid?
      assert %{expires_at: ["can't be blank"]} = errors(changeset)
    end

    test "rejects a nonce with no opaque value" do
      changeset =
        DPoPNonce.issue_changeset(%{
          issued_at: ~U[2026-01-01 00:00:00Z],
          expires_at: ~U[2026-01-01 00:05:00Z]
        })

      refute changeset.valid?
      assert %{nonce: ["can't be blank"]} = errors(changeset)
    end

    test "registers a unique constraint so duplicate issuance is a single-use violation" do
      changeset =
        DPoPNonce.issue_changeset(%{
          nonce: "opaque-server-value",
          issued_at: ~U[2026-01-01 00:00:00Z],
          expires_at: ~U[2026-01-01 00:05:00Z]
        })

      assert Enum.any?(changeset.constraints, fn constraint ->
               constraint.type == :unique and constraint.field == :nonce
             end)
    end
  end

  describe "consume_changeset/2" do
    test "stamps the consumption instant" do
      used_at = ~U[2026-01-01 00:01:00Z]
      changeset = DPoPNonce.consume_changeset(%DPoPNonce{}, used_at)

      assert changeset.valid?
      assert Ecto.Changeset.get_change(changeset, :used_at) == used_at
    end
  end

  defp errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, _opts} -> msg end)
  end
end
