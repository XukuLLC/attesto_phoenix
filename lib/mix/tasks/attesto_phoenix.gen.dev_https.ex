defmodule Mix.Tasks.AttestoPhoenix.Gen.DevHttps do
  @shortdoc "Generates a locally-trusted (mkcert) TLS certificate for local https development"

  @moduledoc """
  Sets up a locally-trusted TLS certificate so a dev endpoint can serve
  `https://localhost` with no tunnel and no downgrade.

  attesto requires an **https** issuer (RFC 8414 §2), so a plain `http://localhost`
  dev server cannot drive the OAuth / MCP flow. This task generates a certificate
  from a local certificate authority — [mkcert](https://github.com/FiloSottile/mkcert) —
  that your machine already trusts, so `https://localhost` works everywhere with
  no `-k` and no self-signed warnings.

  The task:

    1. checks `mkcert` is on your `PATH` (printing install guidance if not),
    2. creates the cert directory (default `priv/cert`),
    3. runs `mkcert -install` (idempotent — trusts the local CA on this machine),
    4. writes `localhost.pem` + `localhost-key.pem` for the requested hosts,
    5. ensures the cert directory is git-ignored, and
    6. prints the exact `config/dev.exs` one-liner to wire it up.

  Re-running regenerates cleanly.

  ## Example

  ```sh
  mix attesto_phoenix.gen.dev_https
  ```

  Then wire it into `config/dev.exs` (the task prints this):

  ```elixir
  config :my_app, MyAppWeb.Endpoint, https: AttestoPhoenix.DevTLS.https_opts(port: 4443)
  ```

  and make sure your MCP / OAuth issuer is `https://localhost:4443`.

  ## Options

    * `--host` - the space-separated host list the certificate is valid for.
      Defaults to `localhost 127.0.0.1 ::1`.
    * `--dir` - the directory the cert/key are written to. Defaults to
      `priv/cert`.

  ## Production

  mkcert is a **local dev** CA. Never run `mkcert -install` or use these
  certificates on a server or in CI — production terminates TLS at the load
  balancer / ingress with a real CA certificate.
  """

  use Mix.Task

  @default_hosts "localhost 127.0.0.1 ::1"
  @default_dir "priv/cert"
  @cert_basename "localhost.pem"
  @key_basename "localhost-key.pem"
  @default_port 4443

  @switches [host: :string, dir: :string]

  @impl Mix.Task
  def run(args) do
    {opts, _argv, _invalid} = OptionParser.parse(args, switches: @switches)

    dir = Keyword.get(opts, :dir, @default_dir)
    hosts = Keyword.get(opts, :host, @default_hosts)

    if mkcert_available?() do
      generate(dir, hosts)
      ensure_gitignored(dir)
      Mix.shell().info(next_steps(dir))
    else
      Mix.shell().error(mkcert_install_guidance())
    end
  end

  # --- generation (guarded behind the mkcert-availability seam above) ---

  defp generate(dir, hosts) do
    File.mkdir_p!(dir)

    certfile = Path.join(dir, @cert_basename)
    keyfile = Path.join(dir, @key_basename)

    Mix.shell().info("Installing the local mkcert CA (idempotent)…")
    mkcert(["-install"])

    Mix.shell().info("Writing #{certfile} + #{keyfile} for: #{hosts}")
    mkcert(["-cert-file", certfile, "-key-file", keyfile | String.split(hosts, " ", trim: true)])
  end

  # The single seam every mkcert invocation flows through. Tests stub
  # `mkcert_available?/0` to false (exercising the guidance branch) or drive the
  # pure helpers directly, so no test ever shells out to mkcert.
  defp mkcert_available? do
    System.find_executable("mkcert") != nil
  end

  defp mkcert(args) do
    case Mix.shell().cmd("mkcert " <> Enum.map_join(args, " ", &shell_escape/1)) do
      0 -> :ok
      status -> Mix.raise("mkcert exited with status #{status}. Args: #{inspect(args)}")
    end
  end

  # mkcert args here are cert paths and host tokens; quote each so a path with a
  # space survives the shell.
  defp shell_escape(arg), do: "'" <> String.replace(arg, "'", "'\\''") <> "'"

  # --- git-ignore handling (pure, testable) ---

  @doc false
  # Ensures `<dir>/` is git-ignored, appending a single entry to `.gitignore`
  # (creating it if absent) without duplicating one already present. Returns
  # `:already` when the pattern was present, `:appended` when it was added.
  @spec ensure_gitignored(String.t(), String.t()) :: :already | :appended
  def ensure_gitignored(dir, gitignore_path \\ ".gitignore") do
    pattern = gitignore_pattern(dir)
    existing = if File.exists?(gitignore_path), do: File.read!(gitignore_path), else: ""

    if gitignore_has_pattern?(existing, pattern) do
      :already
    else
      prefix = if existing == "" or String.ends_with?(existing, "\n"), do: "", else: "\n"

      block =
        prefix <>
          "\n# Locally-trusted mkcert dev certificate (mix attesto_phoenix.gen.dev_https).\n" <>
          pattern <> "\n"

      File.write!(gitignore_path, existing <> block)
      :appended
    end
  end

  # The ignore pattern for the cert dir: a leading-slash, trailing-slash form so
  # it matches the directory anywhere it sits relative to .gitignore.
  @doc false
  @spec gitignore_pattern(String.t()) :: String.t()
  def gitignore_pattern(dir) do
    "/" <> (dir |> Path.relative_to_cwd() |> String.trim_leading("/") |> String.trim_trailing("/")) <> "/"
  end

  # True when the .gitignore already ignores this dir, tolerating the with/without
  # leading- and trailing-slash spellings a dev may already have.
  defp gitignore_has_pattern?(contents, pattern) do
    bare = pattern |> String.trim_leading("/") |> String.trim_trailing("/")

    accepted =
      MapSet.new([pattern, bare, bare <> "/", "/" <> bare, "/" <> bare <> "/"])

    contents
    |> String.split("\n")
    |> Enum.map(&String.trim/1)
    |> Enum.any?(&MapSet.member?(accepted, &1))
  end

  # --- instruction rendering (pure, testable) ---

  @doc false
  @spec next_steps(String.t()) :: String.t()
  def next_steps(dir) do
    certfile = Path.join(dir, @cert_basename)
    keyfile = Path.join(dir, @key_basename)

    """

    Locally-trusted certificate ready:
      #{certfile}
      #{keyfile}

    1. Wire it into config/dev.exs (one line):

        config :my_app, MyAppWeb.Endpoint,
          https: AttestoPhoenix.DevTLS.https_opts(port: #{@default_port})

    2. Point your MCP / OAuth issuer at the https port:

        https://localhost:#{@default_port}

       attesto requires an https issuer (RFC 8414 §2); serving this locally-trusted
       cert is the tunnel-free way to satisfy it — no downgrade, no `-k`.

    3. Start the server and verify:

        mix phx.server
        curl https://localhost:#{@default_port}/.well-known/oauth-authorization-server

    Note: mkcert is a local dev CA. Never use it on a server or in CI; production
    terminates TLS with a real certificate at the load balancer / ingress.
    """
  end

  @doc false
  @spec mkcert_install_guidance() :: String.t()
  def mkcert_install_guidance do
    """
    mkcert was not found on your PATH.

    mkcert generates a locally-trusted certificate so `https://localhost` works
    with no tunnel and no self-signed warnings. Install it, then re-run this task:

      macOS:   brew install mkcert nss     # nss adds Firefox trust
      Linux:   see https://github.com/FiloSottile/mkcert#installation
      Windows: choco install mkcert

    Then:

      mix attesto_phoenix.gen.dev_https
    """
  end
end
