defmodule AttestoPhoenix.Application do
  @moduledoc false

  use Application

  alias AttestoPhoenix.Store.Sweeper.Liveness

  @impl true
  def start(_type, _args) do
    children = [
      # Liveness lookups for the public API come from this registry so
      # a diagnostics outage cannot change their answers.
      Liveness,
      Supervisor.child_spec(
        {AttestoPhoenix.DiagnosticsSupervisor, []},
        # Diagnostics must never take down the package or a dependent host.
        # A child crash is handled inside this nested supervisor; if that
        # supervisor exhausts its restart intensity, leave it stopped until the
        # package application is restarted instead of creating a second restart
        # storm at the package root.
        restart: :temporary
      )
    ]

    Supervisor.start_link(children,
      strategy: :one_for_one,
      name: AttestoPhoenix.Supervisor
    )
  end
end
