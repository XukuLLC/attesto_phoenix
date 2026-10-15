defmodule AttestoPhoenix.HTTPResponse do
  @moduledoc false

  @spec discard_body_collector() :: function()
  def discard_body_collector do
    fn {:data, _data}, {request, response} ->
      {:halt, {request, %{response | body: ""}}}
    end
  end
end
