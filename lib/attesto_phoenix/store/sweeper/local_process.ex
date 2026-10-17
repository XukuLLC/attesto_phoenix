defmodule AttestoPhoenix.Store.Sweeper.LocalProcess do
  @moduledoc false

  @spec alive?(term()) :: boolean()
  def alive?(pid) when is_pid(pid), do: node(pid) == node() and Process.alive?(pid)
  def alive?(_other), do: false
end
