defmodule AttestoPhoenix.Store.ETSOwner do
  @moduledoc """
  Lazily creates and owns the library's named ETS tables.

  The owner is intentionally started without a link to its first caller. A
  request process must not be able to take down the owner and discard a table
  shared by all callers on the node.
  """

  use GenServer

  @owner_start_attempts 5

  @doc """
  Ensures that the named `table` exists with the caller-supplied `options`.

  Table creation runs in this singleton owner, so concurrent callers are
  serialized before `:ets.new/2`. The options remain with each store because
  they are part of that store's table contract.
  """
  @spec ensure(atom(), [term()]) :: atom()
  def ensure(table, options) when is_atom(table) and is_list(options) do
    ensure_owner()
    GenServer.call(__MODULE__, {:ensure, table, options})
  end

  @impl true
  def init(state), do: {:ok, state}

  @impl true
  def handle_call({:ensure, table, options}, _from, state) do
    table =
      case :ets.whereis(table) do
        :undefined -> :ets.new(table, options)
        _tid -> table
      end

    {:reply, table, state}
  end

  # `GenServer.start/3`, NOT `start_link/3`: the owner holds the ETS tables,
  # and whichever process happens to touch a store first is an ordinary
  # request process. Linking the owner to it means that when that request
  # terminates abnormally, the exit signal propagates and kills the owner,
  # destroying every table with it.
  #
  # Starting unlinked gives the owner no parent to be killed by. It is a
  # singleton table holder with no supervision tree available (this library
  # installs no application callback module), so a deliberate orphan is the
  # correct lifetime for these tables.
  #
  # The `:already_started` pid is checked for liveness because a registered
  # name can briefly outlive its process. Treating that window as success is
  # what produces `GenServer.call` crashing with "no process" a moment later.
  defp ensure_owner(attempts \\ @owner_start_attempts) do
    case GenServer.start(__MODULE__, %{}, name: __MODULE__) do
      {:ok, _pid} ->
        :ok

      {:error, {:already_started, pid}} ->
        cond do
          Process.alive?(pid) -> :ok
          attempts > 1 -> retry_owner(attempts)
          true -> raise "#{inspect(__MODULE__)} is registered but not alive"
        end
    end
  end

  defp retry_owner(attempts) do
    Process.sleep(10)
    ensure_owner(attempts - 1)
  end
end
