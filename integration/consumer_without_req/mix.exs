defmodule AttestoPhoenix.ConsumerWithoutReq.MixProject do
  use Mix.Project

  def project do
    [
      app: :attesto_phoenix_consumer_without_req,
      version: "0.0.0",
      elixir: "~> 1.18",
      deps: deps()
    ]
  end

  def application, do: [extra_applications: [:logger]]

  defp deps do
    [
      {:attesto_phoenix, path: "../.."},
      attesto_dep(),
      {:phoenix, "== 1.7.24", override: true},
      {:plug, "== 1.16.6", override: true}
    ]
  end

  defp attesto_dep do
    case System.get_env("ATTESTO_SOURCE_PATH") do
      path when is_binary(path) and path != "" -> {:attesto, path: Path.expand(path), override: true}
      _unset -> {:attesto, "== 2.0.0", override: true}
    end
  end
end
