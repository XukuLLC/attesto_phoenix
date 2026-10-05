defmodule Mix.Tasks.AttestoPhoenix.BackfillRefreshIssuer do
  @shortdoc "Audits or binds refresh families for an asserted single-issuer store"

  @moduledoc """
  Administratively binds legacy refresh families in the bundled Ecto store.

      mix attesto_phoenix.backfill_refresh_issuer \\
        --issuer https://issuer.example --assert-single-issuer

  The default is a dry run. Add `--apply` to persist changes. The issuer must
  exactly match the configured issuer; `--assert-single-issuer` declares that
  the complete selected repo/schema prefix has always belonged to that issuer.
  Do not make that assertion for a store shared by different issuers.

  Existing different bindings or invalid retry state abort the affected family
  without changes. Family updates are serialized with rotation and revocation;
  authenticated retry bundles are rewritten without changing their deadlines.
  No client-instance key is inferred and no expiry or revocation is reset.
  The operation is idempotent and emits aggregate counts, never credentials.

  Options: `--repo` (repeatable), `--schema-prefix`, `--otp-app`, and
  `--batch-size` (1..1,000, default 100). Otherwise the host's configured repo,
  prefix, and application are used. The host application and repos are started
  using their existing configuration, including the stable successor secret.

  A wrapping refresh store must explicitly declare
  `refresh_store_backend: AttestoPhoenix.Store.EctoRefreshStore`. The task
  updates that backing store; protocol operations continue through the
  configured wrapper and its policy checks.

  A one-time backfill requires quiescent token writers. For a rolling deployment,
  explicitly enable `bind_unbound_refresh_families: :configured_issuer` on the
  new nodes for the single-issuer migration window; backfill before and after
  old writers drain, then deploy the default `:reject` policy everywhere.
  That setting cannot make old nodes enforce issuer or client-instance bindings.
  """

  use Mix.Task

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.RefreshIssuerMigration
  alias AttestoPhoenix.Store.EctoRefreshStore

  @switches [
    issuer: :string,
    assert_single_issuer: :boolean,
    apply: :boolean,
    repo: [:keep],
    schema_prefix: :string,
    otp_app: :string,
    batch_size: :integer
  ]

  @impl Mix.Task
  def run(args) do
    {opts, positional, invalid} = OptionParser.parse(args, strict: @switches)
    validate_arguments!(opts, positional, invalid)
    Mix.Task.run("app.start")
    config = Config.from_otp_app(otp_app(opts))
    validate_store!(config, opts[:issuer])
    repos = if Keyword.has_key?(opts, :repo), do: Mix.Ecto.parse_repo(args), else: [config.repo]

    Enum.each(repos, fn repo -> run_for_repo(repo, config, opts) end)
  end

  defp validate_arguments!(opts, positional, invalid) do
    if !(positional == [] and invalid == []), do: Mix.raise("invalid refresh issuer migration arguments")
    if opts[:assert_single_issuer] != true, do: Mix.raise("--assert-single-issuer is required")
    if !is_binary(opts[:issuer]), do: Mix.raise("--issuer is required")
    RefreshIssuerMigration.validate_issuer!(opts[:issuer])
  end

  defp validate_store!(config, issuer) do
    if config.issuer != issuer, do: Mix.raise("--issuer must exactly match the configured issuer")

    if Config.refresh_store_backend(config) != EctoRefreshStore do
      Mix.raise("the configured refresh store must declare EctoRefreshStore as its backend")
    end

    if !(is_atom(config.repo) and not is_nil(config.repo)), do: Mix.raise("a configured Ecto repo is required")
  end

  defp otp_app(opts) do
    case opts[:otp_app] do
      nil -> Application.get_env(:attesto_phoenix, :otp_app) || Mix.Project.config()[:app]
      name -> String.to_existing_atom(name)
    end
  end

  defp run_for_repo(repo, config, opts) do
    config = %{config | repo: repo, schema_prefix: Keyword.get(opts, :schema_prefix, config.schema_prefix)}

    migration_opts = [
      assert_single_issuer: true,
      dry_run: !opts[:apply],
      batch_size: Keyword.get(opts, :batch_size, 100)
    ]

    result =
      Ecto.Migrator.with_repo(repo, fn repo ->
        Config.with_request_config(%{config | repo: repo}, fn ->
          EctoRefreshStore.backfill_issuer(opts[:issuer], migration_opts)
        end)
      end)

    report_result(result, migration_opts[:dry_run])
  end

  defp report_result({:ok, {:ok, counts}, _apps}, dry_run) do
    mode = if dry_run, do: "Dry run", else: "Applied"

    Mix.shell().info(
      "#{mode}: #{counts.families_scanned} families checked, #{counts.families_changed} families / #{counts.rows_changed} rows to bind, #{counts.families_skipped} revoked families skipped"
    )
  end

  defp report_result({:ok, {:error, reason, counts}, _apps}, _dry_run) do
    Mix.raise(
      "refresh issuer migration stopped (#{reason}); #{counts.families_scanned} families completed; rerun after resolving the conflicting or invalid family"
    )
  end

  defp report_result(_failure, _dry_run), do: Mix.raise("refresh issuer migration could not start the configured repo")
end
