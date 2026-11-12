defmodule AttestoPhoenix.Store.Ecto do
  @moduledoc false

  import Ecto.Query, only: [from: 2]

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Store.Sweeper

  @type mutation_context :: {module(), String.t() | nil}

  @spec mutation_context() :: mutation_context()
  def mutation_context do
    prefix = Config.table_prefix()
    repo = Config.ecto_repo!()
    Sweeper.check_running_for_store(repo, prefix)
    {repo, prefix}
  end

  @doc """
  Narrow `query` to the rows that match validated revocation criteria
  (`Attesto.RevocationCriteria.new!/1`).

  The authorization-code and refresh-token tables both carry `subject` and
  `client_id` columns and a JSONB `claims` column, so one definition serves
  both stores and stays the SQL counterpart of
  `Attesto.RevocationCriteria.match?/2`. The session identifier is not a
  column: it is matched inside `claims` under the criteria's `:sid_claim` key
  (`claims->>key = sid`), so no migration is needed to select by session.

  Returns `:none` when a criterion cannot be bound as PostgreSQL `text`; such a
  value cannot equal any stored one.
  """
  @spec where_criteria(Ecto.Queryable.t(), Attesto.RevocationCriteria.t()) :: Ecto.Query.t() | :none
  def where_criteria(query, %{subject: subject, client_id: client_id, sid: sid, sid_claim: sid_claim}) do
    if Enum.all?([subject, client_id, sid, sid_claim], &(is_nil(&1) or text_value?(&1))) do
      query
      |> where_column(:subject, subject)
      |> where_column(:client_id, client_id)
      |> where_session(sid, sid_claim)
    else
      :none
    end
  end

  defp where_column(query, _column, nil), do: query
  defp where_column(query, column, value), do: from(r in query, where: field(r, ^column) == ^value)

  defp where_session(query, nil, _sid_claim), do: query

  defp where_session(query, sid, sid_claim) do
    from(r in query, where: fragment("?->>? = ?", r.claims, ^sid_claim, ^sid))
  end

  @doc """
  Whether `value` can be bound as a PostgreSQL `text` parameter: valid UTF-8
  with no NUL byte. PostgreSQL rejects any other string with error 22021, so a
  lookup key that fails this check cannot match a stored row.
  """
  @spec text_value?(term()) :: boolean()
  def text_value?(value) when is_binary(value), do: String.valid?(value) and not String.contains?(value, <<0>>)
  def text_value?(_value), do: false
end
