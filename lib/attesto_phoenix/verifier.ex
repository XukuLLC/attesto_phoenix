defmodule AttestoPhoenix.Verifier do
  @moduledoc """
  Host-facing OID4VP verifier API.

  Presentation requests are persisted before their signed request object is
  published. Wallet responses are verified by the public direct-post
  controller, and hosts read the completed result once through
  `presentation_result/2` (single-use: the read consumes the session).

  Request objects continue to use the main `AttestoPhoenix.Config.keystore/1`; their protected
  `alg` is derived from that key by `Attesto.JWS.sign_current`. The separate
  verifier-encryption keystore is only an ECDH-ES recipient key and never
  changes request-object signing policy.
  """

  alias Attesto.{JWS, PresentationRequest, PresentationSession, VpToken}
  alias AttestoPhoenix.Config

  @presentation_ttl_seconds 300
  @self_issued_audience "https://self-issued.me/v2"
  @request_object_type "oauth-authz-req+jwt"
  @encrypted_response_alg "ECDH-ES"
  # HAIP §5 requires the verifier to advertise both A128GCM and A256GCM content
  # encryption.
  @encrypted_response_enc_values ["A128GCM", "A256GCM"]

  @type create_attrs :: %{
          required(:dcql_query) => map(),
          required(:expected_query_ids) => [String.t()],
          required(:issuer_trust) => PresentationSession.issuer_trust(),
          optional(:response_mode) => String.t(),
          optional(:client_id_scheme) => String.t()
        }

  @type create_result :: %{
          id: String.t(),
          nonce: String.t(),
          client_id: String.t(),
          request_uri: String.t()
        }

  @doc """
  Create a verifier presentation session and its signed request object.

  The returned `id` is the OID4VP `state`; the absolute `request_uri` serves
  the request object from the convention-derived verifier endpoint.
  """
  @spec create_presentation_request(Config.t(), create_attrs()) ::
          {:ok, create_result()} | {:error, term()}
  def create_presentation_request(
        %Config{} = config,
        %{dcql_query: dcql_query, expected_query_ids: expected_query_ids, issuer_trust: issuer_trust} = attrs
      )
      when is_map(dcql_query) do
    response_mode = Map.get(attrs, :response_mode) || Config.presentation_response_mode(config)
    scheme = Map.get(attrs, :client_id_scheme) || Config.verifier_client_id_scheme(config)

    with {:ok, store} <- presentation_session_store(config),
         {:ok, client_id} <- verifier_client_id(config, scheme),
         {:ok, session} <-
           create_session(store, config, client_id, expected_query_ids, issuer_trust, dcql_query),
         {:ok, response_options} <- response_options(store, session, response_mode),
         {:ok, jar} <-
           sign_request_object(config, client_id, session, dcql_query, response_options, scheme),
         :ok <- PresentationSession.attach_request_object(store, session.id, jar) do
      {:ok,
       %{
         id: session.id,
         nonce: session.nonce,
         client_id: client_id,
         request_uri: request_uri(config, session.id)
       }}
    end
  end

  def create_presentation_request(%Config{}, _attrs), do: {:error, :invalid_attrs}

  @doc """
  Read and consume the verified result of a completed presentation session.

  Single-use: the completed session is removed on read, so the `response_code`
  the browser carries to the completion page cannot be replayed to re-read the
  presented claims. Returns `:error` on a second read, or an unknown, pending,
  or expired session.
  """
  @spec presentation_result(Config.t(), String.t()) :: {:ok, map()} | :error
  def presentation_result(%Config{} = config, id) when is_binary(id) do
    case Config.presentation_session_store(config) do
      store when is_atom(store) and not is_nil(store) -> PresentationSession.result(store, id)
      _ -> :error
    end
  end

  def presentation_result(%Config{}, _id), do: :error

  defp create_session(store, config, client_id, expected_query_ids, issuer_trust, dcql_query) do
    PresentationSession.create(
      store,
      %{
        audience: client_id,
        expected_query_ids: expected_query_ids,
        issuer_trust: issuer_trust,
        # The response_uri the wallet's mdoc DeviceResponse binds to via its
        # OpenID4VPHandover SessionTranscript; harmless (unused) for SD-JWT VC.
        response_uri: Config.presentation_response_endpoint_url(config),
        # Bind each presentation to its DCQL query's type/claim-value constraints
        # (enforced by VpToken after signature + holder binding), so a
        # validly-signed wrong-type credential cannot satisfy the request.
        query_constraints: VpToken.constraints_from_dcql(dcql_query)
      },
      ttl: @presentation_ttl_seconds
    )
  end

  defp sign_request_object(config, client_id, session, dcql_query, response_options, scheme) do
    request_options = [
      client_id: client_id,
      nonce: session.nonce,
      response_uri: Config.presentation_response_endpoint_url(config),
      dcql_query: dcql_query,
      state: session.id
    ]

    request = PresentationRequest.build(Keyword.merge(request_options, response_options))

    claims =
      Map.merge(request, %{
        "iss" => client_id,
        "aud" => @self_issued_audience,
        "exp" => System.system_time(:second) + @presentation_ttl_seconds
      })

    {:ok, JWS.sign_current(config.keystore, claims, signing_options(config, scheme))}
  rescue
    ArgumentError -> {:error, :invalid_attrs}
  end

  defp signing_options(config, scheme) do
    options = [typ: @request_object_type]

    case scheme do
      s when s in ["x509_san_dns", "x509_hash"] ->
        x5c = Enum.map(Config.verifier_x5c(config), &Base.encode64/1)
        Keyword.put(options, :extra_protected, %{"x5c" => x5c})

      _default_scheme ->
        options
    end
  end

  defp response_options(store, session, response_mode) do
    case response_mode do
      "direct_post" ->
        {:ok, [client_metadata: base_client_metadata()]}

      "direct_post.jwt" ->
        with {:ok, metadata} <- encrypted_response_metadata(store, session) do
          {:ok,
           [
             response_mode: "direct_post.jwt",
             client_metadata: Map.merge(base_client_metadata(), metadata)
           ]}
        end
    end
  end

  # OID4VP 1.0 final §5.1: the request's `client_metadata` MUST advertise the
  # verifier's supported presentation formats via `vp_formats_supported`. The
  # algorithm sub-arrays are what this verifier accepts (ES256 SD-JWT VC issuer
  # and KB-JWT signatures; COSE ES256 (-7) for mdoc).
  defp base_client_metadata do
    %{
      "vp_formats_supported" => %{
        "dc+sd-jwt" => %{
          "sd-jwt_alg_values" => ["ES256"],
          "kb-jwt_alg_values" => ["ES256"]
        },
        "mso_mdoc" => %{
          "issuerauth_alg_values" => [-7],
          "deviceauth_alg_values" => [-7]
        }
      }
    }
  end

  # OID4VP 1.0 final / HAIP §5: the verifier MUST supply a fresh (ephemeral)
  # response-encryption key per Authorization Request. Generate an EC P-256 key
  # keyed by the session id, persist its private half on the session for the
  # direct-post endpoint to decrypt with, and advertise its public half.
  defp encrypted_response_metadata(store, session) do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    {_modules, public_map} = JOSE.JWK.to_public_map(jwk)
    {_modules, private_map} = JOSE.JWK.to_map(jwk)
    kid = session.id

    with :ok <-
           PresentationSession.attach_response_encryption_jwk(
             store,
             session.id,
             Map.put(private_map, "kid", kid)
           ) do
      encryption_jwk =
        Map.merge(public_map, %{"use" => "enc", "alg" => @encrypted_response_alg, "kid" => kid})

      {:ok,
       %{
         "jwks" => %{"keys" => [encryption_jwk]},
         # OID4VP 1.0 final client_metadata for encryption is `jwks` +
         # `encrypted_response_enc_values_supported` (the content-encryption algs);
         # the key-agreement alg travels in the JWK's `alg`.
         "encrypted_response_enc_values_supported" => @encrypted_response_enc_values
       }}
    end
  end

  defp presentation_session_store(config) do
    case Config.presentation_session_store(config) do
      store when is_atom(store) and not is_nil(store) -> {:ok, store}
      _ -> {:error, :presentation_session_store_required}
    end
  end

  defp verifier_client_id(config, scheme) do
    case scheme do
      s when s in [nil, "redirect_uri"] -> configured_verifier_client_id(config)
      "x509_san_dns" -> x509_verifier_client_id(config)
      "x509_hash" -> x509_hash_verifier_client_id(config)
    end
  end

  # OID4VP `x509_hash` client-id scheme: the identifier is the base64url SHA-256
  # of the verifier's leaf certificate DER; the wallet recomputes it from the
  # request object's x5c and compares.
  defp x509_hash_verifier_client_id(config) do
    x5c = Config.verifier_x5c(config)

    if valid_x5c?(x5c) do
      leaf = hd(x5c)
      hash = :crypto.hash(:sha256, leaf) |> Base.url_encode64(padding: false)
      {:ok, "x509_hash:" <> hash}
    else
      {:error, :x509_config_required}
    end
  end

  defp configured_verifier_client_id(config) do
    case Config.verifier_client_id(config) do
      client_id when is_binary(client_id) and client_id != "" -> {:ok, client_id}
      _ -> {:error, :verifier_client_id_required}
    end
  end

  defp x509_verifier_client_id(config) do
    dns = Config.verifier_dns(config)
    x5c = Config.verifier_x5c(config)

    if is_binary(dns) and dns != "" and valid_x5c?(x5c) do
      {:ok, "x509_san_dns:" <> dns}
    else
      {:error, :x509_config_required}
    end
  end

  defp valid_x5c?(x5c) when is_list(x5c) and x5c != [], do: Enum.all?(x5c, &(is_binary(&1) and &1 != ""))

  defp valid_x5c?(_x5c), do: false

  defp request_uri(config, id) do
    Config.presentation_request_endpoint_url(config) <>
      "/" <>
      URI.encode(id, &URI.char_unreserved?/1)
  end
end
