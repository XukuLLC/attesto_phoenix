defmodule AttestoPhoenix.AuthorizationServer.Metadata do
  @moduledoc """
  Shared host metadata for the RFC 8414 and OpenID Provider documents.

  The core `Attesto.Discovery` and `Attesto.OpenIDDiscovery` builders remain
  separate because their required fields differ. This module owns the
  Phoenix-side capability and endpoint values that both documents advertise,
  so those values have one source of truth.
  """

  alias Attesto.AuthorizationRequest
  alias Attesto.SigningAlg
  alias AttestoPhoenix.AuthorizationServer.RequestObjectMetadata
  alias AttestoPhoenix.Config

  @response_types_supported ["code"]
  @response_modes_supported AuthorizationRequest.supported_response_modes()

  @token_endpoint_auth_methods_supported [
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt",
    "none"
  ]
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
    |> Map.merge(%{
      "authorization_endpoint" => config.authorization_endpoint || Config.authorize_endpoint_url(config),
      "response_types_supported" => @response_types_supported,
      "response_modes_supported" => @response_modes_supported,
      "grant_types_supported" => Config.grant_types_supported(config),
      "token_endpoint_auth_methods_supported" => token_endpoint_auth_methods_supported(config),
      "token_endpoint_auth_signing_alg_values_supported" => config.client_auth_signing_algs,
      "introspection_endpoint" => Config.introspection_endpoint_url(config),
      "introspection_endpoint_auth_methods_supported" => introspection_auth_methods(config),
      "pushed_authorization_request_endpoint" => Config.par_endpoint_url(config)
    })
    |> put_if_present("require_pushed_authorization_requests", require_pushed_authorization_requests(config))
    |> put_if_present("device_authorization_endpoint", device_authorization_endpoint(config))
    |> put_if_present("backchannel_authentication_endpoint", backchannel_authentication_endpoint(config))
    |> put_if_present("backchannel_token_delivery_modes_supported", backchannel_token_delivery_modes_supported(config))
    |> put_if_present(
      "backchannel_authentication_request_signing_alg_values_supported",
      backchannel_authentication_request_signing_alg_values_supported(config)
    )
    |> put_if_present("backchannel_user_code_parameter_supported", backchannel_user_code_parameter_supported(config))
    |> put_if_present("end_session_endpoint", end_session_endpoint(config))
    |> put_if_present("backchannel_logout_supported", backchannel_logout_supported(config))
    |> put_if_present("backchannel_logout_session_supported", backchannel_logout_session_supported(config))
    |> put_if_present("registration_endpoint", registration_endpoint(config))
    |> put_if_present("request_object_signing_alg_values_supported", RequestObjectMetadata.signing_alg_values(config))
    |> put_if_present("require_signed_request_object", RequestObjectMetadata.require_signed(config))
    |> put_if_present("client_id_metadata_document_supported", client_id_metadata_document_supported(config))
    |> put_if_present(
      "authorization_response_iss_parameter_supported",
      authorization_response_iss_parameter_supported(config)
    )
    |> put_signing_alg_metadata(signing_alg_values)
    |> put_introspection_auth_signing_alg_values_supported(config)
  end

  defp signing_alg_values(metadata, config, opts) do
    Keyword.get(opts, :signing_alg_values) ||
      Map.get(metadata, "id_token_signing_alg_values_supported") ||
      SigningAlg.keystore_algs(config.keystore)
  end

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

  defp put_if_present(metadata, _key, nil), do: metadata
  defp put_if_present(metadata, key, value), do: Map.put(metadata, key, value)

  defp token_endpoint_auth_methods_supported(%Config{token_endpoint_auth_methods_supported: methods} = config)
       when is_list(methods) and methods != [] do
    maybe_enable_wallet_attestation(methods, config, false)
  end

  defp token_endpoint_auth_methods_supported(%Config{} = config) do
    maybe_enable_wallet_attestation(@token_endpoint_auth_methods_supported, config, true)
  end

  defp maybe_enable_wallet_attestation(methods, config, add_when_configured?) do
    case Config.trusted_wallet_provider_jwks(config) do
      nil -> Enum.reject(methods, &(&1 == @wallet_attestation_auth_method))
      _jwks when add_when_configured? -> methods ++ [@wallet_attestation_auth_method]
      _jwks -> methods
    end
  end

  defp introspection_auth_methods(config) do
    Enum.reject(
      token_endpoint_auth_methods_supported(config),
      &(&1 in ["none", @wallet_attestation_auth_method])
    )
  end

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

  defp authorization_response_iss_parameter_supported(%Config{authorization_response_iss: true}), do: true
  defp authorization_response_iss_parameter_supported(%Config{}), do: nil
end
