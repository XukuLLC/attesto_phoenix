defmodule AttestoPhoenix.TestTelemetryCapture do
  @moduledoc false

  @doc "Attach a per-owner collector to an Ecto repository's query event."
  def attach(repo) do
    event = repo.config() |> Keyword.fetch!(:telemetry_prefix) |> Kernel.++([:query])
    ref = make_ref()
    id = {__MODULE__, ref}
    owner = self()

    :telemetry.attach(
      id,
      event,
      &__MODULE__.handle_event/4,
      {owner, ref}
    )

    {id, ref}
  end

  def detach({id, _ref}), do: :telemetry.detach(id)

  def handle_event(event_name, measurements, metadata, {owner, ref}) do
    send(owner, {:repo_query, ref, event_name, measurements, metadata})
  end

  @doc "Collect this handler's events without consuming other handlers' messages."
  def collect(ref, acc \\ []) do
    receive do
      {:repo_query, ^ref, event_name, measurements, metadata} ->
        collect(ref, [{event_name, measurements, metadata} | acc])
    after
      25 -> Enum.reverse(acc)
    end
  end
end
