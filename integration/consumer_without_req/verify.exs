alias AttestoPhoenix.ConsumerWithoutReq, as: Consumer

defmodule AttestoPhoenix.ConsumerWithoutReq do
  defmodule Adapter do
    def fetch(_url, _opts), do: {:error, :not_called}
    def post(_url, _body), do: {:error, :not_called}
    def post(_url, _token, _request_id), do: {:error, :not_called}
  end

  defmodule Store do
  end

  def config(overrides \\ []) do
    base = [
      issuer: "https://issuer.example",
      keystore: __MODULE__.Keystore,
      repo: __MODULE__.Repo,
      audience: "https://api.example",
      load_client: fn _client_id -> {:error, :not_found} end,
      verify_client_secret: fn _client, _secret -> false end,
      load_principal: fn _subject -> {:error, :not_found} end
    ]

    AttestoPhoenix.Config.new(Keyword.merge(base, overrides))
  end

  def assert_req_failure!(label, config_path, overrides) do
    config(overrides)
  rescue
    error in ArgumentError ->
      message = Exception.message(error)

      if !(String.contains?(message, config_path) and
             String.contains?(message, "optional Req dependency is unavailable")) do
        raise "#{label} raised the wrong error: #{message}"
      end
  else
    _config ->
      raise "#{label} accepted a bundled Req adapter when Req is absent"
  end
end

if !Code.ensure_loaded?(AttestoPhoenix) do
  raise "attesto_phoenix did not compile"
end

for module <- [:"Elixir.Req", :"Elixir.Igniter", :"Elixir.OpenApiSpex"] do
  if Code.ensure_loaded?(module) do
    raise "the optional #{inspect(module)} dependency was unexpectedly resolved"
  end
end

for module <- [
      :"Elixir.AttestoPhoenix.BackChannelLogout",
      :"Elixir.AttestoPhoenix.CIBAPing",
      :"Elixir.AttestoPhoenix.ClientIdMetadata.Fetcher",
      # The installer deliberately retains its no-Igniter fallback task.
      :"Elixir.Mix.Tasks.AttestoPhoenix.Install",
      :"Elixir.Mix.Tasks.AttestoPhoenix.Install.Docs"
    ] do
  if !Code.ensure_loaded?(module) do
    raise "expected #{inspect(module)} to compile"
  end
end

for module <- [
      :"Elixir.AttestoPhoenix.BackChannelLogout.Req",
      :"Elixir.AttestoPhoenix.CIBAPing.Req",
      :"Elixir.AttestoPhoenix.ClientIdMetadata.Fetcher.Req",
      :"Elixir.AttestoPhoenix.OpenAPI.TokenEndpoint"
    ] do
  if Code.ensure_loaded?(module) do
    raise "expected #{inspect(module)} to be omitted with its optional dependency"
  end
end

# Every feature remains Req-free while disabled or while its outbound path is
# unused. These are real Config.new/1 calls in a dependency graph without Req.
Consumer.config()

Consumer.config(
  logout: [enabled: true],
  terminate_session: fn _conn, _params -> :ok end
)

Consumer.config(
  ciba: [enabled: true, delivery_modes: [:poll]],
  ciba_store: Consumer.Store,
  authenticate_ciba_user: fn _request -> {:error, :not_found} end
)

Consumer.config(
  jwt_bearer: [
    enabled: true,
    issuers: %{"https://assertions.example" => [jwks: %{"keys" => []}]}
  ],
  resolve_jwt_bearer_subject: fn _claims -> {:error, :not_found} end
)

Consumer.config(
  jwt_bearer: [enabled: true, jwks_resolver: fn _issuer, _opts -> {:ok, %{"keys" => []}} end],
  resolve_jwt_bearer_subject: fn _claims -> {:error, :not_found} end
)

# An active bundled adapter fails at config construction with an actionable
# error instead of waiting for the first outbound call to crash.
Consumer.assert_req_failure!(
  "Client ID Metadata",
  "client_id_metadata: [fetcher: ...]",
  client_id_metadata: [enabled: true]
)

Consumer.assert_req_failure!(
  "Back-Channel Logout",
  "logout: [http_client: ...]",
  logout: [enabled: true],
  logout_session_store: Consumer.Store,
  terminate_session: fn _conn, _params -> :ok end
)

Consumer.assert_req_failure!(
  "CIBA ping",
  "ciba_ping_http_client: ...",
  ciba: [enabled: true, delivery_modes: [:ping]],
  ciba_store: Consumer.Store,
  authenticate_ciba_user: fn _request -> {:error, :not_found} end
)

Consumer.assert_req_failure!(
  "JWT bearer remote JWKS",
  "jwt_bearer: [jwks_fetcher: ...]",
  jwt_bearer: [
    enabled: true,
    issuers: %{"https://assertions.example" => [jwks_uri: "https://assertions.example/jwks"]}
  ],
  resolve_jwt_bearer_subject: fn _claims -> {:error, :not_found} end
)

# A host-supplied adapter keeps all four enabled call paths independent of Req.
Consumer.config(
  client_id_metadata: [enabled: true, fetcher: Consumer.Adapter],
  logout: [enabled: true, http_client: Consumer.Adapter],
  logout_session_store: Consumer.Store,
  terminate_session: fn _conn, _params -> :ok end,
  ciba: [enabled: true, delivery_modes: [:ping]],
  ciba_store: Consumer.Store,
  ciba_ping_http_client: Consumer.Adapter,
  authenticate_ciba_user: fn _request -> {:error, :not_found} end,
  jwt_bearer: [
    enabled: true,
    jwks_fetcher: Consumer.Adapter,
    issuers: %{"https://assertions.example" => [jwks_uri: "https://assertions.example/jwks"]}
  ],
  resolve_jwt_bearer_subject: fn _claims -> {:error, :not_found} end
)

IO.puts("attesto_phoenix compiled and validated optional paths without Req")
