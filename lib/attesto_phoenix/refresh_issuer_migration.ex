defmodule AttestoPhoenix.RefreshIssuerMigration do
  @moduledoc false

  alias Attesto.RefreshToken, as: CoreRefreshToken
  alias AttestoPhoenix.RefreshSuccessorCipher
  alias AttestoPhoenix.Schema.RefreshToken

  @issuer_claim "urn:attesto:refresh-token:issuer"

  def validate_issuer!(issuer) do
    if !CoreRefreshToken.valid_issuer_binding?(%{claims: %{@issuer_claim => issuer}}) do
      raise ArgumentError, "issuer must be a valid authorization-server HTTPS issuer"
    end

    :ok
  end

  def issuer_binding(claims) when is_map(claims), do: Map.fetch(claims, @issuer_claim)
  def issuer_binding(_claims), do: :invalid

  def bind_record(%{data: %{claims: claims} = data} = record, issuer) do
    with {:ok, claims} <- bind_claims(claims, issuer) do
      {:ok, %{record | data: %{data | claims: claims}}}
    end
  end

  def bind_record(_record, _issuer), do: {:error, :invalid_record}

  def bind_successor(%{context: context} = successor, issuer) do
    with {:ok, %{data: context}} <- bind_record(%{data: context}, issuer) do
      {:ok, %{successor | context: context}}
    end
  end

  def bind_successor(%{recoverable: false} = successor, _issuer), do: {:ok, successor}
  def bind_successor(_successor, _issuer), do: {:error, :invalid_retry_state}

  # Prepare every update before the first write. A family with an existing
  # conflicting issuer or an unreadable retry bundle is never partially bound.
  def prepare_rows(rows, issuer, grace) do
    records = Map.new(rows, &{&1.token_hash, RefreshToken.to_store_record(&1, legacy_grace_seconds: grace)})
    lineage = Map.new(rows, &{&1.token_hash, &1.parent_hash})

    Enum.reduce_while(rows, {:ok, []}, fn row, {:ok, updates} ->
      with {:ok, bound} <- bind_record(Map.fetch!(records, row.token_hash), issuer),
           true <- RefreshToken.valid_store_record?(bound),
           {:ok, successor} <- prepare_successor(row, records, lineage, issuer) do
        attrs = %{claims: bound.data.claims, successor: successor}
        {:cont, {:ok, [{row, attrs} | updates]}}
      else
        false -> {:halt, {:error, :invalid_record}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  rescue
    ArgumentError -> {:error, :invalid_record}
  end

  defp bind_claims(claims, issuer) do
    case issuer_binding(claims) do
      :error -> {:ok, Map.put(claims, @issuer_claim, issuer)}
      {:ok, ^issuer} -> {:ok, claims}
      {:ok, _other} -> {:error, :issuer_mismatch}
      :invalid -> {:error, :invalid_record}
    end
  end

  defp prepare_successor(%{successor: nil}, _records, _lineage, _issuer), do: {:ok, nil}

  defp prepare_successor(row, records, lineage, issuer) do
    case Map.fetch!(records, row.token_hash).successor do
      %{recoverable: false} ->
        {:ok, row.successor}

      %{context: _context} = successor ->
        prepare_recoverable_successor(row, successor, records, lineage, issuer)

      _unreadable ->
        {:error, :invalid_retry_state}
    end
  end

  defp prepare_recoverable_successor(row, successor, records, lineage, issuer) do
    with :ok <- validate_child(row, successor, records, lineage),
         {:ok, bound} <- bind_successor(successor, issuer) do
      if bound.context == successor.context, do: {:ok, row.successor}, else: rewrite_ciphertext(row, bound.context)
    end
  end

  defp validate_child(row, %{token: token, generation: generation, context: context}, records, lineage) do
    with true <- is_binary(token) and token != "",
         %{family_id: family, generation: ^generation, data: ^context} <- Map.get(records, Attesto.Secret.hash(token)),
         true <- family == row.family_id and generation == row.generation + 1,
         true <- valid_lineage?(row, Map.fetch!(lineage, Attesto.Secret.hash(token))) do
      :ok
    else
      _invalid -> {:error, :invalid_retry_state}
    end
  end

  defp valid_lineage?(row, parent_hash) do
    parent_hash == row.token_hash or (value(row.successor, :v) == 1 and is_nil(parent_hash))
  end

  defp rewrite_ciphertext(row, context) do
    wrapper = row.successor
    aad = successor_aad(row, wrapper)

    with {:ok, payload} <- RefreshSuccessorCipher.decrypt(value(wrapper, :ciphertext), aad),
         {:ok, ciphertext} <- RefreshSuccessorCipher.encrypt(put_context(payload, context), aad) do
      {:ok, put_ciphertext(wrapper, ciphertext)}
    else
      _unavailable -> {:error, :invalid_retry_state}
    end
  end

  defp successor_aad(row, wrapper) do
    if value(wrapper, :v) == 2 do
      RefreshSuccessorCipher.binding_aad(
        row.token_hash,
        row.family_id,
        row.generation,
        value(wrapper, :child_hash),
        value(wrapper, :retry_until)
      )
    else
      "attesto_phoenix:refresh_successor:v1"
    end
  end

  defp put_context(payload, context) do
    key = if Map.has_key?(payload, :context), do: :context, else: "context"
    Map.put(payload, key, context)
  end

  defp put_ciphertext(wrapper, ciphertext) do
    key = if Map.has_key?(wrapper, :ciphertext), do: :ciphertext, else: "ciphertext"
    Map.put(wrapper, key, ciphertext)
  end

  defp value(map, key), do: Map.get(map, key, Map.get(map, Atom.to_string(key)))
end
