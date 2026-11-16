defmodule AttestoPhoenix.LogMetadata do
  @moduledoc false

  # Logger's default formatter prints a metadata value that is an atom or a
  # string and drops a tuple, a map or a list. A failure reason from a store
  # or a host callback can be any term, so the others are rendered here.
  @spec term(term()) :: atom() | String.t()
  def term(term) when is_atom(term), do: term
  def term(term) when is_binary(term), do: if(String.valid?(term), do: term, else: inspect(term))
  def term(term), do: inspect(term)
end
