defmodule AttestoPhoenix.DiagnosticsSupervisor do
  @moduledoc false

  use Supervisor

  alias AttestoPhoenix.Store.Sweeper.Lifecycle
  alias AttestoPhoenix.Store.Sweeper.Registration
  alias AttestoPhoenix.Store.Sweeper.Signal

  def start_link(opts \\ []) do
    Supervisor.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    children = [
      {Task.Supervisor, name: Signal.task_supervisor()},
      Lifecycle,
      Signal,
      Registration
    ]

    Supervisor.init(children,
      strategy: :one_for_one,
      max_restarts: 3,
      max_seconds: 5
    )
  end
end
