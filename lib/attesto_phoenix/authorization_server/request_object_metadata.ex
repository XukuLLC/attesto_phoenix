defmodule AttestoPhoenix.AuthorizationServer.RequestObjectMetadata do
  @moduledoc """
  Conn-free derivation of the signed-request-object (JAR / RFC 9101 §10.5)
  discovery metadata shared by the OpenID Provider Metadata document (OpenID
  Connect Discovery) and the OAuth 2.0 Authorization Server Metadata document
  (RFC 8414).

  Both documents describe the same authorization endpoint, so the JAR capability
  they advertise is derived here once - from `%AttestoPhoenix.Config{}` - rather
  than assembled separately in each controller, where it has drifted apart
  before. This module reads only data and carries no transport concern.
  """

  alias Attesto.RequestObject.Policy
  alias Attesto.SigningAlg
  alias AttestoPhoenix.Config

  @doc """
  Whether the authorization endpoint can verify a signed request object.

  JAR support exists only when the host can resolve a client's trusted JWKS -
  a flat `:client_jwks` callback or an installed `:client_store` behaviour
  (the config resolves either). Absent that, no client can use a
  request object, so the capability is not advertised.
  """
  @spec supported?(Config.t()) :: boolean()
  def supported?(%Config{} = config), do: not is_nil(Config.client_jwks_fun(config))

  @doc """
  The JWS algorithms the authorization endpoint accepts on a signed request
  object (RFC 9101 §10.5 `request_object_signing_alg_values_supported`), or `nil`
  when request objects are not supported (so the core builder drops the member).

  Mirrors the configured `request_object_policy` accepted algorithms, falling
  back to the verifier default (`Attesto.SigningAlg.fapi_algs/0`: PS256, ES256,
  EdDSA) when the policy leaves it unset.
  """
  @spec signing_alg_values(Config.t()) :: [String.t()] | nil
  def signing_alg_values(%Config{} = config) do
    if supported?(config), do: accepted_algs(config)
  end

  @doc """
  `true` when the configured policy mandates a signed request object (RFC 9101
  §10.5 `require_signed_request_object` / FAPI 2.0 Message Signing §5.3.1),
  otherwise `nil` (the member's default is false, so the builder omits it).

  A required-request-object policy is only constructible alongside JAR support
  (`AttestoPhoenix.Config` rejects it otherwise at boot), so `require_signed/1`
  never contradicts `supported?/1`.
  """
  @spec require_signed(Config.t()) :: true | nil
  def require_signed(%Config{} = config) do
    if Policy.require_request_object?(policy(config)), do: true
  end

  defp accepted_algs(%Config{} = config) do
    case policy(config).accepted_algs do
      algs when is_list(algs) and algs != [] -> algs
      _ -> SigningAlg.fapi_algs()
    end
  end

  defp policy(%Config{request_object_policy: %Policy{} = policy}), do: policy
  defp policy(%Config{}), do: %Policy{}
end
