# Test bootstrap for the Ecto-backed store suite.
#
# Store tests are tagged `:ecto` and excluded by default; they run only when a
# SQL backend is available (e.g. `mix test --include ecto`). The database is
# provisioned only when those tests are actually included, so the default run
# needs no running SQL server. Each table has its own migration file under
# test/support/migrations, one migration module per file.

alias AttestoPhoenix.TestRepo

# Diagnostics under test (missing-sweeper warnings, logout and credential
# refusals) log on purpose. Capture every test's log output and show it only
# when that test fails; capture_log/1 inside a test still sees its messages.
ExUnit.configure(exclude: [:ecto], capture_log: true)

# Installer tests evaluate fixture config files that define helper modules, and
# Igniter evaluates them again on every file update. Those redefinitions are
# expected and must not print a warning per evaluation.
Code.put_compiler_option(:ignore_module_conflict, true)

# The default Config uses a non-zero refresh-rotation retry window. Keep one
# stable test-only secret available for every test that selects the bundled
# Ecto refresh store; focused fail-fast tests temporarily remove or replace it.
Application.put_env(
  :attesto_phoenix,
  :refresh_successor_secret,
  String.duplicate("test-refresh-successor-", 4)
)

ecto_included? =
  ExUnit.configuration()
  |> Keyword.get(:include, [])
  |> Enum.any?(&(&1 == :ecto or match?({:ecto, _}, &1)))

if ecto_included? do
  Application.put_env(:attesto_phoenix, TestRepo,
    username: System.get_env("POSTGRES_USER", "postgres"),
    password: System.get_env("POSTGRES_PASSWORD", "postgres"),
    hostname: System.get_env("POSTGRES_HOST", "localhost"),
    database: System.get_env("POSTGRES_DB", "attesto_phoenix_test"),
    pool: Ecto.Adapters.SQL.Sandbox,
    pool_size: 10
  )

  {:ok, _} = Application.ensure_all_started(:ecto_sql)

  _ = TestRepo.__adapter__().storage_up(TestRepo.config())

  {:ok, _pid} = TestRepo.start_link()

  # Point the library's runtime `:repo` at the test repo once, globally, so the
  # store functions that resolve their repo from the application environment
  # (rather than from an explicit `AttestoPhoenix.Config`) find it. Set here
  # rather than per test so concurrent `async: true` tests never race on it.
  Application.put_env(:attesto_phoenix, :repo, TestRepo)

  migrations_dir = Path.join(__DIR__, "support/migrations")

  # Each file under support/migrations defines exactly one migration module.
  migrations =
    migrations_dir
    |> File.ls!()
    |> Enum.filter(&String.ends_with?(&1, ".exs"))
    |> Enum.sort()
    |> Enum.with_index(fn file, index ->
      [{module, _bin} | _] = Code.compile_file(Path.join(migrations_dir, file))
      {index, module}
    end)

  Ecto.Migrator.run(TestRepo, migrations, :up, all: true, log: false)

  Ecto.Adapters.SQL.Sandbox.mode(TestRepo, :manual)
end

{:ok, _started} = Application.ensure_all_started(:bandit)

# The back-channel-logout / CIBA-ping deliverers SSRF-screen and IP-pin their
# targets, which blocks loopback in production. The suite delivers to local
# Bandit servers on 127.0.0.1, so enable the documented dev/test escape hatch
# globally here (off by default everywhere else).
Application.put_env(:attesto_phoenix, :allow_loopback_delivery, true)

ExUnit.start()
