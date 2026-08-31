defmodule AttestoPhoenix.AuthorizationCodePrivateContext do
  @moduledoc """
  Transport for the host-private authorization state carried by an
  authorization code.

  `Attesto.AuthorizationCode` fixes the canonical grant `:data` map at exactly
  nine keys and rejects a persisted record carrying any sibling key, so
  host-specific values belong inside `:claims`. This module owns the single
  reserved claims key that carries the host's `:authorization_code_private_context`
  value from the authorization endpoint to the token endpoint, and the rules
  that keep it from escaping.

  The value is:

    * validated as a portable JSON object (`Attesto.Claims.portable_json_object?/1`),
      because the claims map round-trips a JSONB column and must survive it
      unchanged;
    * bounded at #{4 * 1024} bytes once encoded, so a host cannot grow an
      authorization code without limit;
    * removed from the redeemed grant's claims by `pop/1` before principal
      construction, so it can never be read as an OIDC claim or minted into a
      token.

  The reserved key is namespaced and is refused as host input: a host that
  stashes its own value under it at the authorization endpoint would otherwise
  be able to forge private context for the completion callback.
  """

  alias Attesto.Claims

  # Namespaced so it cannot collide with an OIDC claim (OIDC Core §5.1) or a
  # host claim. Dotted rather than underscored to match the convention already
  # used by the refresh provenance marker in the token endpoint.
  @claims_key "attesto_phoenix.private_context"

  # A bound, not a tuning knob: the authorization code's claims travel through a
  # JSONB column on every issuance and redemption. 4 KiB is generous for policy
  # state while keeping a hostile or buggy callback from bloating the row.
  @max_encoded_bytes 4 * 1024

  @typedoc "The host's private authorization state."
  @type t :: map()

  @doc "The reserved claims key carrying private context."
  @spec claims_key() :: String.t()
  def claims_key, do: @claims_key

  @doc "The maximum encoded size, in bytes, of a private-context value."
  @spec max_encoded_bytes() :: pos_integer()
  def max_encoded_bytes, do: @max_encoded_bytes

  @doc """
  Folds `private_context` into `claims` under the reserved key.

  `nil` stores nothing, leaving `claims` untouched. A value that is not a
  portable JSON object, or that exceeds `max_encoded_bytes/0` once encoded, is
  rejected rather than truncated or silently dropped — a host that cannot
  persist its policy state must not get a code that looks like it carries it.
  """
  @spec put(map(), t() | nil) :: {:ok, map()} | {:error, :invalid_private_context | :private_context_too_large}
  def put(claims, nil) when is_map(claims), do: {:ok, claims}

  def put(claims, private_context) when is_map(claims) and is_map(private_context) do
    cond do
      not Claims.portable_json_object?(private_context) ->
        {:error, :invalid_private_context}

      encoded_size(private_context) > @max_encoded_bytes ->
        {:error, :private_context_too_large}

      true ->
        {:ok, Map.put(claims, @claims_key, private_context)}
    end
  end

  def put(claims, _private_context) when is_map(claims), do: {:error, :invalid_private_context}

  @doc """
  Removes the reserved key from `claims`, returning the private context and the
  cleaned claims.

  Returns `{nil, claims}` when the code carries none. A value stored under the
  reserved key that is not a map is reported as `:invalid`, so a tampered or
  malformed row fails closed at the token endpoint instead of being handed to
  the completion callback as valid state.
  """
  @spec pop(map()) :: {t() | nil | :invalid, map()}
  def pop(claims) when is_map(claims) do
    case Map.pop(claims, @claims_key) do
      {nil, rest} -> {nil, rest}
      {value, rest} when is_map(value) -> {value, rest}
      {_value, rest} -> {:invalid, rest}
    end
  end

  @doc """
  Rejects a host-supplied claims map that already carries the reserved key.

  Called on the authorization endpoint's claims before private context is
  folded in, so the reserved key is only ever written by this library.
  """
  @spec reserved?(map()) :: boolean()
  def reserved?(claims) when is_map(claims), do: Map.has_key?(claims, @claims_key)

  defp encoded_size(private_context) do
    private_context |> JSON.encode!() |> byte_size()
  rescue
    _ -> @max_encoded_bytes + 1
  end
end
