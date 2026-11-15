defmodule AttestoPhoenix.Schema.Canonical do
  @moduledoc false

  @spec canonical_data!(map(), [atom()], String.t(), (map() -> boolean())) :: map()
  def canonical_data!(record, required_keys, error_message, validator)
      when is_map(record) and is_list(required_keys) and is_binary(error_message) and is_function(validator, 1) do
    data = Map.get(record, :data)

    if is_map(data) and
         map_size(data) == length(required_keys) and
         Enum.all?(required_keys, &Map.has_key?(data, &1)) and
         validator.(data) do
      data
    else
      raise ArgumentError, error_message
    end
  end
end
