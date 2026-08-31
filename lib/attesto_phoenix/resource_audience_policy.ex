defmodule AttestoPhoenix.ResourceAudiencePolicy do
  @moduledoc """
  Resolves the trusted RFC 8707 audience set for an Attesto access token.

  Static resource identifiers are grant-agnostic and require no client lookup.
  When a token carries an audience outside that static set, the signed
  `client_id` selects the original OAuth client and its
  `resource_indicators[:allowed_resources_for]` policy. The client that calls
  introspection or token exchange never supplies this issuance policy.

  `resolver/1` is intended for `Attesto.Token.verify/3`'s
  `:trusted_audiences` option. The core invokes it only after every other token
  check succeeds and converts resolver failures into `:invalid_audience`.

  A dynamic audience on a CIMD client may consult the bounded, SSRF-guarded
  client-metadata resolver. Successful documents are cached; a fetch failure is
  deliberately not cached under the CIMD/RFC 9111 rules and makes that token
  inactive. Static audiences bypass client resolution and all network work.
  """

  alias AttestoPhoenix.{ClientAuthentication, Config}

  require Logger

  @doc "Returns a verifier callback bound to the given authorization-server configuration."
  @spec resolver(Config.t()) :: (map() -> [String.t()])
  def resolver(%Config{} = config) do
    fn claims -> resolve_trusted_audiences(config, claims) end
  end

  @doc "Resolves the static and, when needed, original-client resource allowlist."
  @spec trusted_audiences(Config.t(), map()) :: [String.t()]
  def trusted_audiences(%Config{} = config, claims) when is_map(claims) do
    static = Config.static_allowed_resources(config)

    if audience_covered?(Map.get(claims, "aud"), static) do
      static
    else
      original_client_audiences(config, claims, static)
    end
  end

  defp original_client_audiences(config, %{"client_id" => client_id}, static)
       when is_binary(client_id) and client_id != "" do
    case ClientAuthentication.resolve_client(config, client_id) do
      {:ok, token_client} -> Config.allowed_resources(config, token_client)
      {:error, :not_found} -> static
    end
  end

  defp original_client_audiences(_config, _claims, static), do: static

  # Attesto's verifier deliberately converts resolver failures to
  # `:invalid_audience` so no host fault crosses the token boundary. Report the
  # integration failure here, before re-raising into that privacy-preserving
  # boundary, without logging the callback value, client identifier, or token
  # claims.
  defp resolve_trusted_audiences(config, claims) do
    trusted_audiences(config, claims)
  rescue
    exception ->
      Logger.warning("AttestoPhoenix dynamic audience resolver failed; token treated as untrusted")
      reraise exception, __STACKTRACE__
  catch
    kind, reason ->
      Logger.warning("AttestoPhoenix dynamic audience resolver failed; token treated as untrusted")
      :erlang.raise(kind, reason, __STACKTRACE__)
  end

  defp audience_covered?(audience, static) when is_binary(audience), do: audience in static

  defp audience_covered?(audiences, static) when is_list(audiences) do
    audiences != [] and Enum.all?(audiences, &(&1 in static))
  end

  defp audience_covered?(_audience, _static), do: false
end
