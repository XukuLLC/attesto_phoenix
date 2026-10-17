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
end
