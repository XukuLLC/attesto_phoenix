defmodule AttestoPhoenix.DataCase do
  @moduledoc """
  Test case template for tests that touch the SQL-backed test repository.

  Wraps each test in a sandboxed transaction and points the library's `:repo`
  configuration at `AttestoPhoenix.TestRepo` for the duration of the test,
  restoring any prior value afterwards.
  """

  use ExUnit.CaseTemplate

  alias Ecto.Adapters.SQL.Sandbox

  using do
    quote do
      # Every case that touches the database is tagged so a default run
      # (no SQL backend) excludes it via `ExUnit.configure(exclude: [:ecto])`
      # in test_helper.exs. Run them with `mix test --include ecto`.
      alias AttestoPhoenix.TestRepo

      @moduletag :ecto
    end
  end

  setup tags do
    pid =
      Sandbox.start_owner!(AttestoPhoenix.TestRepo, shared: not tags[:async])

    previous_repo = Application.fetch_env(:attesto_phoenix, :repo)
    previous_otp_app = Application.fetch_env(:attesto_phoenix, :otp_app)

    # Store conformance tests exercise the package-level repo contract. A
    # synthetic host application's otp_app pointer from another test must not
    # redirect these bare-store calls to that host's (possibly nonexistent)
    # repository.
    Application.delete_env(:attesto_phoenix, :otp_app)
    Application.put_env(:attesto_phoenix, :repo, AttestoPhoenix.TestRepo)

    on_exit(fn ->
      Sandbox.stop_owner(pid)

      case previous_otp_app do
        {:ok, value} -> Application.put_env(:attesto_phoenix, :otp_app, value)
        :error -> Application.delete_env(:attesto_phoenix, :otp_app)
      end

      case previous_repo do
        {:ok, value} -> Application.put_env(:attesto_phoenix, :repo, value)
        :error -> Application.delete_env(:attesto_phoenix, :repo)
      end
    end)

    :ok
  end
end
