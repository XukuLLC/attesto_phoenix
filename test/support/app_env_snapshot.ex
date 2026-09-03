# Captures and restores application environment configuration for test isolation.
#
# Igniter evaluates in-memory project configurations during file updates and restores
# prior settings using Application.put_all_env/2. Because Application.put_all_env/2
# overwrites existing keys but does not delete keys introduced during evaluation,
# evaluated fixtures can leave residual configuration in the Erlang VM.
#
# This module provides exact snapshots and teardown restoration, deleting any keys
# added after the snapshot was taken, as well as tripwire checks to detect leaked
# application environment keys.
defmodule AttestoPhoenix.AppEnvSnapshot do
  @moduledoc false

  @spec snapshot([atom()]) :: %{atom() => keyword()}
  def snapshot(apps) do
    Map.new(apps, fn app -> {app, Application.get_all_env(app)} end)
  end

  @spec restore(%{atom() => keyword()}) :: :ok
  def restore(snapshot) do
    Enum.each(snapshot, fn {app, snapshotted_env} ->
      restore_app(app, snapshotted_env)
    end)

    :ok
  end

  defp restore_app(app, snapshotted_env) do
    current_env = Application.get_all_env(app)
    current_keys = Keyword.keys(current_env)
    snapshotted_keys = Keyword.keys(snapshotted_env)

    for key <- current_keys, key not in snapshotted_keys do
      Application.delete_env(app, key)
    end

    for {key, val} <- snapshotted_env do
      Application.put_env(app, key, val)
    end
  end

  @spec isolate([atom()], (-> result)) :: result when result: var
  def isolate(apps, fun) when is_function(fun, 0) do
    snapshot = snapshot(apps)

    try do
      fun.()
    after
      restore(snapshot)
    end
  end

  @spec ensure_unset!([{atom(), atom()}]) :: :ok
  def ensure_unset!(pairs) do
    set_pairs =
      Enum.flat_map(pairs, fn {app, key} ->
        case Application.fetch_env(app, key) do
          {:ok, value} -> [{app, key, value}]
          :error -> []
        end
      end)

    if set_pairs != [] do
      details =
        Enum.map_join(set_pairs, "\n", fn {app, key, value} ->
          "  * {#{inspect(app)}, #{inspect(key)}} => #{inspect(value)}"
        end)

      raise ArgumentError,
            "A previous test left configuration in the application environment:\n" <>
              details <>
              "\nExpected these application environment keys to be unset."
    end

    :ok
  end
end
