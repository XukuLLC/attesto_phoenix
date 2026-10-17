defmodule AttestoPhoenix.MixTaskSupport do
  @moduledoc false

  @max_schema_prefix_bytes 63

  @spec parse_options!(
          [String.t()],
          keyword(),
          keyword()
        ) :: {:help, keyword()} | {:ok, keyword()}
  def parse_options!(args, switches, options) do
    aliases = Keyword.get(options, :aliases, [])
    {parsed, positional, invalid} = OptionParser.parse(args, strict: switches, aliases: aliases)

    if !Keyword.get(parsed, :help, false) do
      before_invalid_args = Keyword.get(options, :before_invalid_args, fn -> :ok end)
      before_invalid_args.()
    end

    reject_invalid_args!(
      positional,
      invalid,
      Keyword.fetch!(options, :error_subject),
      Keyword.fetch!(options, :accepted_options)
    )

    if Keyword.get(parsed, :help, false) do
      Mix.shell().info(Keyword.fetch!(options, :help))
      {:help, parsed}
    else
      {:ok, parsed}
    end
  end

  @spec validate_schema_prefix!(nil | String.t()) :: nil | String.t()
  def validate_schema_prefix!(nil), do: nil

  def validate_schema_prefix!(prefix) when is_binary(prefix) do
    cond do
      prefix == "" ->
        Mix.raise("invalid --schema-prefix: expected a non-empty lowercase PostgreSQL schema identifier")

      byte_size(prefix) > @max_schema_prefix_bytes ->
        Mix.raise("invalid --schema-prefix: expected at most 63 bytes")

      prefix == "information_schema" or String.starts_with?(prefix, "pg_") ->
        Mix.raise(
          "invalid --schema-prefix: #{inspect(prefix)} is a reserved PostgreSQL " <>
            "system schema; choose an application-owned schema"
        )

      Regex.match?(~r/\A[a-z_][a-z0-9_]*\z/, prefix) ->
        prefix

      true ->
        Mix.raise("invalid --schema-prefix: expected a lowercase PostgreSQL schema identifier")
    end
  end

  def validate_schema_prefix!(_other) do
    Mix.raise("invalid --schema-prefix: expected nil or a lowercase PostgreSQL schema identifier")
  end

  defp reject_invalid_args!([], [], _error_subject, _accepted_options), do: :ok

  defp reject_invalid_args!(positional, invalid, error_subject, accepted_options) do
    Mix.raise(
      "invalid #{error_subject} arguments. Accepted options: " <>
        Enum.join(accepted_options, ", ") <>
        ". Unexpected positional arguments: #{inspect(positional)}; " <>
        "invalid options: #{inspect(invalid)}"
    )
  end
end
