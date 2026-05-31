defmodule AttestoPhoenix.Schema.DPoPReplayTest do
  use ExUnit.Case, async: true

  import Ecto.Changeset

  alias AttestoPhoenix.Schema.DPoPReplay

  @valid_attrs %{
    jti: "0123456789abcdef0123456789abcdef",
    expires_at: ~U[2026-01-01 00:01:00.000000Z]
  }

  describe "schema shape" do
    test "jti is the string primary key, not an integer surrogate" do
      # RFC 9449 §4.2 / RFC 7519 §4.1.7: the jti is the opaque token itself.
      assert DPoPReplay.__schema__(:primary_key) == [:jti]
      assert DPoPReplay.__schema__(:type, :jti) == :string
    end

    test "persists to the neutral dpop_replays source" do
      assert DPoPReplay.__schema__(:source) == "dpop_replays"
    end

    test "carries expires_at and inserted_at with microsecond precision" do
      assert DPoPReplay.__schema__(:type, :expires_at) == :utc_datetime_usec
      assert DPoPReplay.__schema__(:type, :inserted_at) == :utc_datetime_usec
    end

    test "has no updated_at: a recorded jti is never mutated" do
      refute :updated_at in DPoPReplay.__schema__(:fields)
    end
  end

  describe "changeset/2" do
    test "accepts a jti with a freshness horizon" do
      changeset = DPoPReplay.changeset(%DPoPReplay{}, @valid_attrs)

      assert changeset.valid?
      assert get_change(changeset, :jti) == @valid_attrs.jti
      assert get_change(changeset, :expires_at) == @valid_attrs.expires_at
    end

    test "fails closed when jti is missing" do
      attrs = Map.delete(@valid_attrs, :jti)
      changeset = DPoPReplay.changeset(%DPoPReplay{}, attrs)

      refute changeset.valid?
      assert %{jti: ["can't be blank"]} = errors_on(changeset)
    end

    test "fails closed when expires_at is missing" do
      # A row with no freshness horizon could never be pruned; reject it
      # rather than persisting an unusable record.
      attrs = Map.delete(@valid_attrs, :expires_at)
      changeset = DPoPReplay.changeset(%DPoPReplay{}, attrs)

      refute changeset.valid?
      assert %{expires_at: ["can't be blank"]} = errors_on(changeset)
    end

    test "declares the jti unique constraint for atomic record-and-check" do
      changeset = DPoPReplay.changeset(%DPoPReplay{}, @valid_attrs)

      assert Enum.any?(changeset.constraints, fn constraint ->
               constraint.type == :unique and constraint.field == :jti
             end)
    end
  end

  # Local copy of the conventional Ecto.Changeset error extractor so the test
  # does not depend on a host application's data case.
  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Regex.replace(~r"%{(\w+)}", message, fn _whole, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
