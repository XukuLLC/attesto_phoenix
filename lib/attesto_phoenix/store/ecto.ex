defmodule AttestoPhoenix.Store.Ecto do
  @moduledoc false

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
  Whether `value` can be bound as a PostgreSQL `text` parameter: valid UTF-8
  with no NUL byte. PostgreSQL rejects any other string with error 22021, so a
  lookup key that fails this check cannot match a stored row.
  """
  @spec text_value?(term()) :: boolean()
  def text_value?(value) when is_binary(value), do: String.valid?(value) and not String.contains?(value, <<0>>)
  def text_value?(_value), do: false
end
