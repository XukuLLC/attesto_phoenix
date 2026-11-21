defmodule AttestoPhoenix.AuthorizationServer.Metadata do
  @moduledoc """
  Shared host metadata for the RFC 8414 and OpenID Provider documents.

  The core `Attesto.Discovery` and `Attesto.OpenIDDiscovery` builders remain
  separate because their required fields differ. This module owns the
  Phoenix-side capability and endpoint values that both documents advertise,
  so those values have one source of truth. Endpoint authentication metadata
  is derived from the same configured method and algorithm catalogs used by
  the corresponding endpoint policies.
  """

  alias Attesto.{MapParams, SigningAlg}
  alias AttestoPhoenix.AuthorizationServer.RequestObjectMetadata
  alias AttestoPhoenix.Config

  @response_types_supported ["code"]
  @grant_jwt_bearer "urn:ietf:params:oauth:grant-type:jwt-bearer"
  @id_jag_profile "urn:ietf:params:oauth:grant-profile:id-jag"

  @doc """
  The OAuth response types the authorization endpoint supports (RFC 8414 §2
  `response_types_supported`). Dynamic registration validates a client's
  `response_types` against this list.
  """
  @spec response_types_supported() :: [String.t()]
  def response_types_supported, do: @response_types_supported

  @wallet_attestation_auth_method "attest_jwt_client_auth"

  @doc """
  Add the metadata fields shared by both discovery documents.

  The optional `:signing_alg_values` option is available for a caller whose
  base document derives its own signing-algorithm list. When omitted, the
  OpenID base map is preferred, then the configured keystore is consulted;
  this preserves the distinct fallback behavior of the two core builders.
  """
  @spec enrich_common(map(), Config.t()) :: map()
  def enrich_common(metadata, %Config{} = config), do: enrich_common(metadata, config, [])

  @spec enrich_common(map(), Config.t(), keyword()) :: map()
  def enrich_common(metadata, %Config{} = config, opts) when is_map(metadata) do
    signing_alg_values = signing_alg_values(metadata, config, opts)

    metadata
    |> Map.merge(RequestObjectMetadata.parameter_support(config))
    |> Map.merge(%{
      "authorization_endpoint" => config.authorization_endpoint || Config.authorize_endpoint_url(config),
      "response_types_supported" => @response_types_supported,
      "response_modes_supported" => config.response_modes_supported,
      "grant_types_supported" => Config.grant_types_supported(config),
      "token_endpoint_auth_methods_supported" => Config.token_endpoint_auth_methods_supported(config),
      "token_endpoint_auth_signing_alg_values_supported" => config.client_auth_signing_algs,
      "introspection_endpoint" => Config.introspection_endpoint_url(config),
      "introspection_endpoint_auth_methods_supported" => introspection_auth_methods(config),
      "revocation_endpoint" => Config.revocation_endpoint_url(config),
      "revocation_endpoint_auth_methods_supported" => revocation_auth_methods(config),
      "pushed_authorization_request_endpoint" => Config.par_endpoint_url(config)
    })
    |> MapParams.put_optional("authorization_grant_profiles_supported", authorization_grant_profiles_supported(config))
    |> MapParams.put_optional("require_pushed_authorization_requests", require_pushed_authorization_requests(config))
    |> MapParams.put_optional("device_authorization_endpoint", device_authorization_endpoint(config))
    |> MapParams.put_optional("backchannel_authentication_endpoint", backchannel_authentication_endpoint(config))
    |> MapParams.put_optional(
      "backchannel_token_delivery_modes_supported",
      backchannel_token_delivery_modes_supported(config)
    )
    |> MapParams.put_optional(
      "backchannel_authentication_request_signing_alg_values_supported",
      backchannel_authentication_request_signing_alg_values_supported(config)
    )
    |> MapParams.put_optional(
      "backchannel_user_code_parameter_supported",
      backchannel_user_code_parameter_supported(config)
    )
    |> MapParams.put_optional("end_session_endpoint", end_session_endpoint(config))
    |> MapParams.put_optional("backchannel_logout_supported", backchannel_logout_supported(config))
    |> MapParams.put_optional("backchannel_logout_session_supported", backchannel_logout_session_supported(config))
    |> MapParams.put_optional("registration_endpoint", registration_endpoint(config))
    |> MapParams.put_optional(
      "request_object_signing_alg_values_supported",
      RequestObjectMetadata.signing_alg_values(config)
    )
    |> MapParams.put_optional("require_signed_request_object", RequestObjectMetadata.require_signed(config))
    |> MapParams.put_optional("client_id_metadata_document_supported", client_id_metadata_document_supported(config))
    |> MapParams.put_optional("refresh_token_expiration_types_supported", refresh_expiration_types(config))
    |> MapParams.put_optional(
      "authorization_details_types_supported",
      authorization_details_types_supported(config)
    )
    |> MapParams.put_optional(
      "client_attestation_signing_alg_values_supported",
      client_attestation_alg_values_supported(config)
    )
    |> MapParams.put_optional(
      "client_attestation_pop_signing_alg_values_supported",
      client_attestation_alg_values_supported(config)
    )
    |> MapParams.put_optional(
      "authorization_response_iss_parameter_supported",
      authorization_response_iss_parameter_supported(config)
    )
    |> MapParams.put_optional(
      "identity_chaining_requested_token_types_supported",
      identity_chaining_requested_token_types_supported(config)
    )
    |> MapParams.put_optional(
      "tls_client_certificate_bound_access_tokens",
      tls_client_certificate_bound_access_tokens(config)
    )
    |> MapParams.put_optional("mtls_endpoint_aliases", config.mtls_endpoint_aliases)
    |> put_signing_alg_metadata(signing_alg_values)
    |> put_introspection_auth_signing_alg_values_supported(config)
    |> put_revocation_auth_signing_alg_values_supported(config)
  end

  defp signing_alg_values(metadata, config, opts) do
    Keyword.get(opts, :signing_alg_values) ||
      Map.get(metadata, "id_token_signing_alg_values_supported") ||
      SigningAlg.keystore_algs(config.keystore)
  end

  defp refresh_expiration_types(%Config{refresh_token_expiration_metadata: true}), do: ["token_timeout"]
  defp refresh_expiration_types(_config), do: nil

  defp put_signing_alg_metadata(metadata, []), do: metadata

  defp put_signing_alg_metadata(metadata, algs) do
    metadata
    |> Map.put("authorization_signing_alg_values_supported", algs)
    |> Map.put("introspection_signing_alg_values_supported", algs)
  end

  defp put_introspection_auth_signing_alg_values_supported(metadata, %Config{} = config) do
    if "private_key_jwt" in introspection_auth_methods(config) do
      Map.put(
        metadata,
        "introspection_endpoint_auth_signing_alg_values_supported",
        config.client_auth_signing_algs
      )
    else
      metadata
    end
  end

  defp put_revocation_auth_signing_alg_values_supported(metadata, %Config{} = config) do
    if "private_key_jwt" in revocation_auth_methods(config) do
      Map.put(
        metadata,
        "revocation_endpoint_auth_signing_alg_values_supported",
        config.client_auth_signing_algs
      )
    else
      metadata
    end
  end

  defp introspection_auth_methods(config) do
    Enum.reject(
      Config.token_endpoint_auth_methods_supported(config),
      &(&1 in ["none", @wallet_attestation_auth_method])
    )
  end

  defp revocation_auth_methods(config), do: Config.token_endpoint_auth_methods_supported(config)

  defp require_pushed_authorization_requests(%Config{require_pushed_authorization_requests: true}), do: true
  defp require_pushed_authorization_requests(%Config{}), do: nil

  defp device_authorization_endpoint(%Config{} = config) do
    if Config.device_authorization_enabled?(config), do: Config.device_authorization_endpoint_url(config)
  end

  defp backchannel_authentication_endpoint(%Config{} = config) do
    if Config.ciba_enabled?(config), do: Config.backchannel_authentication_endpoint_url(config)
  end

  defp backchannel_token_delivery_modes_supported(%Config{} = config) do
    if Config.ciba_enabled?(config), do: Enum.map(Config.ciba_delivery_modes(config), &Atom.to_string/1)
  end

  defp backchannel_authentication_request_signing_alg_values_supported(%Config{} = config) do
    if Config.ciba_enabled?(config), do: Keyword.get(Config.ciba(config), :request_signing_algs)
  end

  defp backchannel_user_code_parameter_supported(%Config{} = config) do
    if Config.ciba_enabled?(config), do: Keyword.get(Config.ciba(config), :user_code_parameter_supported, false)
  end

  defp end_session_endpoint(%Config{} = config) do
    if Config.logout_enabled?(config), do: Config.end_session_endpoint_url(config)
  end

  defp backchannel_logout_supported(%Config{} = config) do
    if Config.backchannel_logout_supported?(config), do: true
  end

  defp backchannel_logout_session_supported(%Config{} = config) do
    if Config.backchannel_logout_session_supported?(config), do: true
  end

  defp registration_endpoint(%Config{registration_enabled: true} = config), do: Config.registration_endpoint_url(config)
  defp registration_endpoint(%Config{registration_enabled: false}), do: nil

  defp client_id_metadata_document_supported(%Config{} = config) do
    if Config.client_id_metadata_enabled?(config), do: true
  end

  # ID-JAG draft -06 §7.2 pairs the profile with the JWT-bearer grant type.
  defp authorization_grant_profiles_supported(%Config{} = config) do
    if Config.jwt_bearer_enabled?(config) and @grant_jwt_bearer in Config.grant_types_supported(config),
      do: [@id_jag_profile]
  end

  # RFC 9396 §11 / OID4VCI §11.2.3: an OP that issues credentials advertises the
  # `openid_credential` authorization_details type on its AS metadata so a wallet
  # requesting a scope-less credential configuration via `authorization_details`
  # can discover support. Derived from the issuer being configured (a non-empty
  # `credential_configurations_supported`) rather than a separate knob.
  defp authorization_details_types_supported(%Config{} = config) do
    types = Config.jwt_bearer_authorization_details_types(config)

    case Config.credential_configurations_supported(config) do
      map when is_map(map) and map_size(map) > 0 -> Enum.uniq(["openid_credential" | types])
      _other when types == [] -> nil
      _other -> Enum.uniq(types)
    end
  end

  # draft-ietf-oauth-attestation-based-client-auth: when `attest_jwt_client_auth`
  # is advertised, the AS MUST publish the attestation and PoP signing algorithm
  # values it accepts. These mirror the client-authentication signing algs.
  defp client_attestation_alg_values_supported(%Config{} = config) do
    # Config.token_endpoint_auth_methods_supported/1 always returns a list.
    if "attest_jwt_client_auth" in Config.token_endpoint_auth_methods_supported(config) do
      config.client_auth_signing_algs
    end
  end

  defp authorization_response_iss_parameter_supported(%Config{authorization_response_iss: true}), do: true
  defp authorization_response_iss_parameter_supported(%Config{}), do: nil

  defp identity_chaining_requested_token_types_supported(%Config{} = config) do
    if Config.identity_chaining_enabled?(config) do
      config |> Config.identity_chaining() |> Keyword.fetch!(:requested_token_types)
    end
  end

  defp tls_client_certificate_bound_access_tokens(%Config{mtls_enabled: true}), do: true
  defp tls_client_certificate_bound_access_tokens(%Config{}), do: nil
end
