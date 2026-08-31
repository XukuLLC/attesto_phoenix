defmodule AttestoPhoenix.DependencyRequirementsTest do
  use ExUnit.Case, async: false

  test "Attesto and test-only Postgrex reject their affected predecessors" do
    case dependency!(:attesto) do
      {:attesto, requirement} when is_binary(requirement) ->
        # Phoenix 3 directly needs Attesto 2's `AuthorizationCode.issue_refresh_and_finalize/6`
        # and `RefreshStore.rotate/4` contracts; Attesto 1.15 lacks both.
        assert Version.match?("2.0.0", requirement)
        refute Version.match?("1.15.0", requirement)

      {:attesto, opts} when is_list(opts) ->
        source_path = Keyword.fetch!(opts, :path)
        assert File.dir?(source_path)
        assert File.regular?(Path.join(source_path, "mix.exs"))

        assert File.dir?(Path.join(source_path, ".git")) or
                 File.regular?(Path.join(source_path, ".git"))
    end

    {:postgrex, requirement, _opts} = dependency!(:postgrex)
    assert Version.match?("0.22.4", requirement)
    refute Version.match?("0.22.3", requirement)
  end

  test "explicit source path selects a validated checkout" do
    source_path = Path.join(System.tmp_dir!(), "attesto-source-#{System.unique_integer([:positive])}")
    File.mkdir_p!(Path.join(source_path, ".git"))
    File.write!(Path.join(source_path, "mix.exs"), "defmodule Attesto.MixProject do\nend\n")

    on_exit(fn -> File.rm_rf!(source_path) end)

    with_environment(%{"ATTESTO_SOURCE_PATH" => source_path, "ATTESTO_PATH" => nil}, fn ->
      assert {:attesto, path: ^source_path} = dependency!(:attesto)
    end)
  end

  test "an explicit source path must be a real checkout" do
    source_path = Path.join(System.tmp_dir!(), "not-an-attesto-source-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf!(source_path) end)

    with_environment(%{"ATTESTO_SOURCE_PATH" => source_path, "ATTESTO_PATH" => nil}, fn ->
      assert_raise Mix.Error, ~r/must point to a Git checkout containing mix\.exs/, fn ->
        dependency!(:attesto)
      end
    end)
  end

  test "an empty source path selects the released requirement" do
    with_environment(%{"ATTESTO_SOURCE_PATH" => "", "ATTESTO_PATH" => nil}, fn ->
      assert {:attesto, requirement} = dependency!(:attesto)
      assert Version.match?("2.0.0", requirement)
      refute Version.match?("1.15.0", requirement)
    end)
  end

  test "Hex package metadata ignores inherited source opt-ins" do
    output_path =
      Path.join(System.tmp_dir!(), "attesto-phoenix-hex-guard-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(output_path) end)

    {output, exit_code} =
      System.cmd(
        System.find_executable("mix"),
        ["hex.build", "--unpack", "--output", output_path],
        env: [
          {"MIX_ENV", "dev"},
          {"ATTESTO_PATH", "1"},
          {"ATTESTO_SOURCE_PATH", "/missing/attesto-source"}
        ],
        stderr_to_stdout: true
      )

    assert exit_code == 0, output

    metadata = File.read!(Path.join(output_path, "hex_metadata.config"))
    assert metadata =~ ~s(<<"name">>,<<"attesto">>)
    assert metadata =~ ~s(<<"requirement">>,<<">= 2.0.0 and < 3.0.0">>)
  end

  defp with_environment(values, fun) do
    previous = Map.new(values, fn {key, _value} -> {key, System.get_env(key)} end)

    Enum.each(values, fn
      {key, nil} -> System.delete_env(key)
      {key, value} -> System.put_env(key, value)
    end)

    try do
      fun.()
    after
      Enum.each(previous, fn
        {key, nil} -> System.delete_env(key)
        {key, value} -> System.put_env(key, value)
      end)
    end
  end

  defp dependency!(app) do
    AttestoPhoenix.MixProject.project()
    |> Keyword.fetch!(:deps)
    |> Enum.find(&(elem(&1, 0) == app))
  end
end
