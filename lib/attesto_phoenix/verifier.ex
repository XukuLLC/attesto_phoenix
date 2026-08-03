defmodule AttestoPhoenix.Verifier do
  @moduledoc """
  Host-facing OID4VP verifier API.

  Presentation requests are persisted before their signed request object is
  published. Wallet responses are verified by the public direct-post
  controller, and hosts poll the completed result through
  `presentation_result/2`.
  """

  alias Attesto.{JWS, PresentationRequest, PresentationSession}
  alias AttestoPhoenix.Config

  @presentation_ttl_seconds 300
  @self_issued_audience "https://self-issued.me/v2"
  @request_object_type "oauth-authz-req+jwt"
  @encrypted_response_alg "ECDH-ES"
  @encrypted_response_enc "A128GCM"

  @type create_attrs :: %{
          required(:dcql_query) => map(),
          required(:expected_query_ids) => [String.t()],
          required(:issuer_trust) => PresentationSession.issuer_trust()
        }

  @type create_result :: %{
          id: String.t(),
          nonce: String.t(),
          request_uri: String.t()
        }

  @doc """
  Create a verifier presentation session and its signed request object.

  The returned `id` is the OID4VP `state`; the absolute `request_uri` serves
  the request object from the convention-derived verifier endpoint.
  """
  @spec create_presentation_request(Config.t(), create_attrs()) ::
          {:ok, create_result()} | {:error, term()}
  def create_presentation_request(%Config{} = config, %{
        dcql_query: dcql_query,
        expected_query_ids: expected_query_ids,
        issuer_trust: issuer_trust
      })
      when is_map(dcql_query) do
    with {:ok, store} <- presentation_session_store(config),
         {:ok, client_id} <- verifier_client_id(config),
         {:ok, session} <-
           create_session(store, client_id, expected_query_ids, issuer_trust),
         {:ok, jar} <- sign_request_object(config, client_id, session, dcql_query),
         :ok <- PresentationSession.attach_request_object(store, session.id, jar) do
      {:ok,
       %{
         id: session.id,
         nonce: session.nonce,
         request_uri: request_uri(config, session.id)
       }}
    end
  end

  def create_presentation_request(%Config{}, _attrs), do: {:error, :invalid_attrs}

  @doc "Read the verified result of a completed presentation session."
  @spec presentation_result(Config.t(), String.t()) :: {:ok, map()} | :error
  def presentation_result(%Config{} = config, id) when is_binary(id) do
    case Config.presentation_session_store(config) do
      store when is_atom(store) and not is_nil(store) -> PresentationSession.result(store, id)
      _ -> :error
    end
  end

  def presentation_result(%Config{}, _id), do: :error

  defp create_session(store, client_id, expected_query_ids, issuer_trust) do
    PresentationSession.create(
      store,
      %{
        audience: client_id,
        expected_query_ids: expected_query_ids,
        issuer_trust: issuer_trust
      },
      ttl: @presentation_ttl_seconds
    )
  end

  defp sign_request_object(config, client_id, session, dcql_query) do
    request_options = [
      client_id: client_id,
      nonce: session.nonce,
      response_uri: Config.presentation_response_endpoint_url(config),
      dcql_query: dcql_query,
      state: session.id
    ]

    request = PresentationRequest.build(response_options(config, request_options))

    claims =
      Map.merge(request, %{
        "iss" => client_id,
        "aud" => @self_issued_audience,
        "exp" => System.system_time(:second) + @presentation_ttl_seconds
      })

    {:ok, JWS.sign_current(config.keystore, claims, typ: @request_object_type)}
  rescue
    ArgumentError -> {:error, :invalid_attrs}
  end

  defp response_options(config, options) do
    case Config.presentation_response_mode(config) do
      "direct_post" ->
        options

      "direct_post.jwt" ->
        Keyword.merge(options,
          response_mode: "direct_post.jwt",
          client_metadata: encrypted_response_metadata(config)
        )
    end
  end

  defp encrypted_response_metadata(config) do
    private_jwk = JOSE.JWK.from_pem(config.keystore.signing_pem())
    {_kty, public_jwk} = JOSE.JWK.to_public_map(private_jwk)

    encryption_jwk =
      Map.merge(public_jwk, %{
        "use" => "enc",
        "alg" => @encrypted_response_alg
      })

    %{
      "jwks" => %{"keys" => [encryption_jwk]},
      "authorization_encrypted_response_alg" => @encrypted_response_alg,
      "authorization_encrypted_response_enc" => @encrypted_response_enc
    }
  end

  defp presentation_session_store(config) do
    case Config.presentation_session_store(config) do
      store when is_atom(store) and not is_nil(store) -> {:ok, store}
      _ -> {:error, :presentation_session_store_required}
    end
  end

  defp verifier_client_id(config) do
    case Config.verifier_client_id(config) do
      client_id when is_binary(client_id) and client_id != "" -> {:ok, client_id}
      _ -> {:error, :verifier_client_id_required}
    end
  end

  defp request_uri(config, id) do
    Config.presentation_request_endpoint_url(config) <>
      "/" <>
      URI.encode(id, &URI.char_unreserved?/1)
  end
end
