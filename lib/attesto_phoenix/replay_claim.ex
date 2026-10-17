defmodule AttestoPhoenix.ReplayClaim do
  @moduledoc false

  alias AttestoPhoenix.Callback

  @spec commit(Callback.callback(), String.t(), pos_integer()) :: :ok | {:error, :replay}
  def commit(callback, key, ttl) when is_binary(key) and key != "" and is_integer(ttl) and ttl > 0 do
    case Callback.invoke(callback, [key, ttl]) do
      :ok ->
        :ok

      {:error, :replay} ->
        {:error, :replay}

      _other ->
        raise ArgumentError,
              "#{inspect(__MODULE__)}: :replay_check must return :ok or {:error, :replay}"
    end
  end
end
