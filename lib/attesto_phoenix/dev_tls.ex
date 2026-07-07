defmodule AttestoPhoenix.DevTLS do
  @moduledoc """
  A one-line, dev-only helper that wires a locally-trusted TLS certificate into a
  Phoenix endpoint's `https:` listener.

  attesto requires an **https** issuer (RFC 8414 §2: the issuer identifier MUST be
  an `https` URL) — the discovery documents, DPoP `htu`, and RFC 9728 resource
  identifiers are all https by spec, and attesto enforces that at config-build
  time. So a plain `http://localhost` dev server can't drive the OAuth / MCP flow.

  Rather than adding an https-disable switch (there is deliberately none in a
  security library), this helper makes the RIGHT path frictionless: serve a
  certificate from a local certificate authority — [mkcert](https://github.com/FiloSottile/mkcert) —
  so `https://localhost` is trusted with no tunnel and no downgrade.

  Generate the certificate once with `mix attesto_phoenix.gen.dev_https`, then in
  `config/dev.exs`:

      config :my_app, MyAppWeb.Endpoint, https: AttestoPhoenix.DevTLS.https_opts(port: 4443)

  The MCP / OAuth issuer then becomes `https://localhost:4443`, so discovery,
  DPoP, and the RFC 8707 resource identifiers all line up automatically.

  ## This is a dev-only convenience

  It does **not** weaken any https requirement and it is not for production. In
  production, TLS is terminated at the load balancer / ingress with a real CA
  certificate, and the endpoint's `https:` listener (if any) uses that
  certificate — never an mkcert one. `mix mkcert -install` trusts a CA on the
  local machine only; never run it on a server or in CI.

  This helper only wires a locally-trusted certificate into the dev endpoint. It
  never touches the issuer/audience validation, and attesto's https-only
  guarantee stays fully intact.
  """

  # The conventional dev certificate location, matching what
  # `mix attesto_phoenix.gen.dev_https` writes and what this helper loads.
  @default_certfile "priv/cert/localhost.pem"
  @default_keyfile "priv/cert/localhost-key.pem"

  # The default mkcert https port. 4443 keeps the standard Phoenix dev http
  # listener on 4000 free and needs no privileged bind.
  @default_port 4443

  # Bandit/Plug default per-header cap is ~10KB; large `Cookie`/`Authorization`
  # (DPoP proofs, long access tokens) headers can exceed it. Raise it in dev so a
  # request never 431s underfoot. Overridable via `:max_header_length`.
  @default_max_header_length 65_536

  @doc """
  Returns the Phoenix endpoint `https:` keyword list for a locally-trusted
  mkcert certificate.

  ## Options

    * `:port` - the TLS port to listen on. Defaults to `#{@default_port}`.
    * `:certfile` - path to the certificate. Defaults to the conventional
      `#{@default_certfile}` resolved against the caller's app (see below).
    * `:keyfile` - path to the private key. Defaults to the conventional
      `#{@default_keyfile}` resolved against the caller's app.
    * `:otp_app` - when given, the default cert/key paths resolve via
      `Application.app_dir/2` (release-safe). When omitted, they resolve relative
      to `File.cwd!/0` — the app root when running `mix phx.server`, which is the
      idiomatic Phoenix-dev spelling (`phx.gen.cert` emits the same bare relative
      paths).
    * `:max_header_length` - the Bandit `http_1_options` max header length.
      Defaults to `#{@default_max_header_length}`.

  Returns:

      [
        port: 4443,
        cipher_suite: :strong,
        certfile: "…/priv/cert/localhost.pem",
        keyfile: "…/priv/cert/localhost-key.pem",
        http_1_options: [max_header_length: 65_536]
      ]

  Raises `ArgumentError` if the certificate or key is missing, pointing you at
  `mix attesto_phoenix.gen.dev_https`. It NEVER silently falls back to http.

  ## Examples

      # config/dev.exs
      config :my_app, MyAppWeb.Endpoint,
        https: AttestoPhoenix.DevTLS.https_opts(port: 4443)

      # release-safe path resolution
      config :my_app, MyAppWeb.Endpoint,
        https: AttestoPhoenix.DevTLS.https_opts(port: 4443, otp_app: :my_app)
  """
  @spec https_opts(keyword()) :: keyword()
  def https_opts(opts \\ []) when is_list(opts) do
    port = Keyword.get(opts, :port, @default_port)
    max_header_length = Keyword.get(opts, :max_header_length, @default_max_header_length)
    certfile = resolve_path(opts, :certfile, @default_certfile)
    keyfile = resolve_path(opts, :keyfile, @default_keyfile)

    ensure_present!(certfile, keyfile)

    [
      port: port,
      cipher_suite: :strong,
      certfile: certfile,
      keyfile: keyfile,
      http_1_options: [max_header_length: max_header_length]
    ]
  end

  # An explicit `:certfile`/`:keyfile` is expanded as given (relative to cwd or
  # absolute); otherwise the conventional path is resolved against the caller's
  # app — via `Application.app_dir/2` when `:otp_app` is supplied, else relative
  # to `File.cwd!/0`.
  defp resolve_path(opts, key, default_rel) do
    case Keyword.get(opts, key) do
      nil -> default_path(opts, default_rel)
      path -> Path.expand(path)
    end
  end

  defp default_path(opts, rel) do
    case Keyword.get(opts, :otp_app) do
      nil -> Path.expand(rel, File.cwd!())
      app when is_atom(app) -> Application.app_dir(app, rel)
    end
  end

  defp ensure_present!(certfile, keyfile) do
    missing = Enum.reject([certfile, keyfile], &File.exists?/1)

    if missing != [] do
      raise ArgumentError, """
      AttestoPhoenix.DevTLS: locally-trusted certificate not found.

      Missing:
      #{Enum.map_join(missing, "\n", &"  - #{&1}")}

      Generate it once with mkcert:

          mix attesto_phoenix.gen.dev_https

      That installs the local CA (idempotent) and writes the cert/key pair the dev
      endpoint loads. Then point your MCP / OAuth issuer at https://localhost:<port>.

      This helper never falls back to plain http: attesto requires an https issuer
      (RFC 8414 §2), and serving a locally-trusted cert is the tunnel-free way to
      satisfy it.
      """
    end

    :ok
  end
end
