defmodule AttestoPhoenix.TestRepo do
  @moduledoc """
  Ecto repository used only by the test suite to exercise the Ecto-backed
  stores against a real SQL backend.
  """

  use Ecto.Repo,
    otp_app: :attesto_phoenix,
    adapter: Ecto.Adapters.Postgres
end
