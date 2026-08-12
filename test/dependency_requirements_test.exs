defmodule AttestoPhoenix.DependencyRequirementsTest do
  use ExUnit.Case, async: true

  test "Attesto and test-only Postgrex reject their affected predecessors" do
    case dependency!(:attesto) do
      {:attesto, requirement} when is_binary(requirement) ->
        assert Version.match?("1.12.2", requirement)
        refute Version.match?("1.12.1", requirement)

      {:attesto, opts} when is_list(opts) ->
        assert opts[:path], "expected the explicit ATTESTO_PATH development dependency"
    end

    {:postgrex, requirement, _opts} = dependency!(:postgrex)
    assert Version.match?("0.22.4", requirement)
    refute Version.match?("0.22.3", requirement)
  end

  defp dependency!(app) do
    AttestoPhoenix.MixProject.project()
    |> Keyword.fetch!(:deps)
    |> Enum.find(&(elem(&1, 0) == app))
  end
end
