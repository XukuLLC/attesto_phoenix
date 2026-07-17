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
      {:attesto, "== 1.2.5", override: true},
      {:phoenix, "== 1.7.24", override: true},
      {:plug, "== 1.16.6", override: true}
    ]
  end
end
