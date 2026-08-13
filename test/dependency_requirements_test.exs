defmodule AttestoPhoenix.DependencyRequirementsTest do
  use ExUnit.Case, async: true

  test "Attesto and test-only Postgrex reject their affected predecessors" do
    case dependency!(:attesto) do
      {:attesto, requirement} when is_binary(requirement) ->
        assert Version.match?("1.15.0", requirement)
        # 1.14.0 predates the RFC 8705 §2 certificate matcher and the external
        # signer dispatch this package invokes directly.
        refute Version.match?("1.14.0", requirement)
        # 1.12.2 rejects neither an ID-JAG `authorization_details` claim nor a
        # malformed signed constraint, and this package has no equivalent check
        # on the JWT-bearer path — resolving it would silently reinstate the
        # widening that 2.12.0 closes.
        refute Version.match?("1.12.2", requirement)

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
