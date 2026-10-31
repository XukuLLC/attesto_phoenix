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

  alias Attesto.{
    JWE,
    JWS,
    Key,
    PresentationRequest,
    PresentationSession,
    Secret,
    SigningAlg,
    StrictJSON,
    VpToken
  }

  alias AttestoPhoenix.Config

  defmodule PresentationResponse do
    @moduledoc """
    Normalized OID4VP direct-post presentation response (`direct_post` or
    `direct_post.jwt`).
    """

    alias Attesto.StrictJSON

    @enforce_keys [:mode]
    defstruct [:mode, :response, :state, :vp_token]

    @type t ::
            %__MODULE__{
              mode: :encrypted,
              response: String.t(),
              state: nil,
              vp_token: nil
            }
            | %__MODULE__{
                mode: :plaintext,
                response: nil,
                state: String.t(),
                vp_token: map()
              }

    @doc """
    Normalize a direct-post request body map into a typed
    `%PresentationResponse{}` struct.
    """
    @spec from_params(term()) :: {:ok, t()} | {:error, :malformed}
    def from_params(params) when is_map(params) and not is_struct(params) do
      case fetch_param(params, "response") do
        {:ok, encrypted_response} when is_binary(encrypted_response) ->
          {:ok, %__MODULE__{mode: :encrypted, response: encrypted_response}}

        {:ok, _non_binary} ->
          {:error, :malformed}

        :error ->
          with state when is_binary(state) and state != "" <- param(params, "state"),
               {:ok, vp_token} <- decode_vp_token(param(params, "vp_token")) do
            {:ok, %__MODULE__{mode: :plaintext, state: state, vp_token: vp_token}}
          else
            _ -> {:error, :malformed}
          end
      end
    end

    def from_params(_params), do: {:error, :malformed}

    defp decode_vp_token(%{} = vp_token), do: {:ok, vp_token}

    defp decode_vp_token(vp_token) when is_binary(vp_token) do
      case StrictJSON.decode(vp_token) do
        {:ok, %{} = decoded} -> {:ok, decoded}
        _ -> {:error, :malformed}
      end
    end

    defp decode_vp_token(_vp_token), do: {:error, :malformed}

    defp param(params, key), do: Map.get(params, key) || Map.get(params, String.to_existing_atom(key))

    defp fetch_param(params, name) do
      case Map.fetch(params, name) do
        {:ok, value} -> {:ok, value}
        :error -> Map.fetch(params, String.to_existing_atom(name))
      end
    end
  end

  @presentation_ttl_seconds 300
  @self_issued_audience "https://self-issued.me/v2"
  @request_object_type "oauth-authz-req+jwt"
  @response_code_type "oid4vp-response-code+jwt"
  # A response code carries a session identifier and registered claims only
  # and is read before any authentication.
  @max_response_code_bytes 16 * 1_024
  # `response` is attacker-controlled input at a public endpoint. Bound it and
  # parse at most four separators before JOSE performs Base64URL decoding or
  # authenticated decryption. Presentations may be substantially larger than
  # ordinary JWTs, so the ciphertext receives a 16 MiB total envelope while the
  # protected header retains the hardened 256 KiB JOSE ceiling.
  @max_compact_jwe_bytes 16 * 1_024 * 1_024
  @max_protected_segment_bytes 256 * 1_024
  @encrypted_response_alg "ECDH-ES"
  # HAIP §5 requires the verifier to advertise both A128GCM and A256GCM content
  # encryption.
  @encrypted_response_enc_values ["A128GCM", "A256GCM"]
  # Validate the JWE alg/enc from the compact response's protected header — the
  # first segment is base64url-encoded JSON — before decrypting, rather than
  # introspecting the decoded %JOSE.JWE{} struct.
  @accepted_response_encs ~w(A128GCM A256GCM)

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
    Config.with_request_config(config, fn ->
      do_create_presentation_request(config, attrs, dcql_query, expected_query_ids, issuer_trust)
    end)
  end

  def create_presentation_request(%Config{}, _attrs), do: {:error, :invalid_attrs}

  defp do_create_presentation_request(config, attrs, dcql_query, expected_query_ids, issuer_trust) do
    response_mode = Map.get(attrs, :response_mode) || Config.presentation_response_mode(config)
    scheme = Map.get(attrs, :client_id_scheme) || Config.verifier_client_id_scheme(config)

    with {:ok, store} <- presentation_session_store(config),
         :ok <- validate_response_mode(response_mode),
         {:ok, client_id} <- verifier_client_id(config, scheme),
         {:ok, session} <-
           create_session(store, config, client_id, expected_query_ids, issuer_trust, dcql_query) do
      finish_presentation_request(store, config, client_id, session, dcql_query, response_mode, scheme)
    end
  end

  defp finish_presentation_request(store, config, client_id, session, dcql_query, response_mode, scheme) do
    result =
      with {:ok, response_options} <- response_options(store, session, response_mode),
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

    case result do
      {:ok, _presentation} = ok -> ok
      error -> discard_session(store, session.id, error)
    end
  end

  @doc """
  Read and consume the verified result of a completed presentation session.

  Single-use: the completed session is removed on read, so the `response_code`
  the browser carries to the completion page cannot be replayed to re-read the
  presented claims. Returns `:error` on a second read, or an unknown, pending,
  or expired session.
  """
  @spec presentation_result(Config.t(), String.t()) :: {:ok, map()} | :error
  def presentation_result(%Config{} = config, response_code) when is_binary(response_code) do
    Config.with_request_config(config, fn -> do_presentation_result(config, response_code) end)
  end

  def presentation_result(%Config{}, _id), do: :error

  @doc """
  Verify and atomically complete an OID4VP direct-post presentation response,
  returning `{:ok, %{"redirect_uri" => redirect_uri}}` or `{:error, reason}`.
  """
  @spec complete_presentation_response(Config.t(), PresentationResponse.t() | map()) ::
          {:ok, %{required(String.t()) => String.t()}} | {:error, :invalid_request | :misconfigured}
  def complete_presentation_response(%Config{} = config, %PresentationResponse{} = response) do
    with {:ok, store} <- response_session_store(config),
         {:ok, state, vp_token} <- resolve_presentation_response(response, config, store),
         {:ok, _request_object} <- PresentationSession.request_object(store, state),
         {:ok, _results} <- verify_presentation_response(store, state, vp_token),
         {:ok, response_code} <- issue_presentation_response_code(config, state) do
      # OID4VP §8.2 permits, and HAIP §5.1 requires, a `redirect_uri` carrying a
      # `response_code` so the wallet returns the user to the verifier front-end,
      # which then retrieves the completed presentation result. That read is
      # single-use (`AttestoPhoenix.Verifier.presentation_result/2` consumes the
      # session), so this browser-borne `response_code` cannot be replayed from
      # history/logs to re-read the presented claims.
      {:ok, %{"redirect_uri" => presentation_complete_redirect_uri(config, response_code)}}
    else
      {:error, :misconfigured} = error -> error
      _ -> {:error, :invalid_request}
    end
  end

  def complete_presentation_response(%Config{} = config, params) when is_map(params) and not is_struct(params) do
    case PresentationResponse.from_params(params) do
      {:ok, response} -> complete_presentation_response(config, response)
      _ -> {:error, :invalid_request}
    end
  end

  def complete_presentation_response(%Config{}, _params), do: {:error, :invalid_request}

  defp do_presentation_result(config, response_code) do
    with {:ok, session_id} <- verify_response_code(config, response_code),
         store when is_atom(store) and not is_nil(store) <- Config.presentation_session_store(config) do
      PresentationSession.result(store, session_id)
    else
      _ -> :error
    end
  rescue
    _error -> :error
  catch
    _kind, _reason -> :error
  end

  @doc false
  @spec issue_presentation_response_code(Config.t(), String.t()) ::
          {:ok, String.t()} | {:error, :invalid_response_code}
  def issue_presentation_response_code(%Config{} = config, session_id)
      when is_binary(session_id) and session_id != "" do
    now = System.system_time(:second)

    claims = %{
      "iss" => config.issuer,
      "aud" => config.issuer,
      "iat" => now,
      "exp" => now + @presentation_ttl_seconds,
      "jti" => Secret.generate(),
      "sid" => session_id
    }

    {:ok, JWS.sign_current(config.keystore, claims, typ: @response_code_type)}
  rescue
    _error -> {:error, :invalid_response_code}
  catch
    _kind, _reason -> {:error, :invalid_response_code}
  end

  def issue_presentation_response_code(%Config{}, _session_id), do: {:error, :invalid_response_code}

  defp verify_response_code(config, response_code) do
    now = System.system_time(:second)

    with {:ok, %{"typ" => @response_code_type} = header} <-
           JWS.peek_json(response_code, :protected, max_compact_bytes: @max_response_code_bytes),
         :ok <- JWS.reject_unsupported_crit(header, supported: []),
         candidates when candidates != [] <- response_code_candidates(config, header["kid"]),
         {:ok, claims} <-
           JWS.verify_strict(response_code, candidates,
             claims_map?: true,
             terminal_error: :invalid_response_code,
             malformed_result: :halt,
             malformed_error: :invalid_response_code
           ),
         :ok <- validate_response_code_claims(claims, config.issuer, now) do
      {:ok, claims["sid"]}
    else
      _ -> {:error, :invalid_response_code}
    end
  end

  defp response_code_candidates(config, header_kid) do
    JWS.verification_candidates(config.keystore.verification_pems(),
      kid: header_kid,
      malformed_key: :raise,
      candidate_builder: fn pem ->
        {Key.kid(pem), SigningAlg.for_key(config.keystore, pem), Key.jwk(pem)}
      end
    )
  end

  defp validate_response_code_claims(
         %{
           "iss" => issuer,
           "aud" => audience,
           "iat" => issued_at,
           "exp" => expires_at,
           "jti" => jti,
           "sid" => session_id
         },
         issuer,
         now
       ) do
    with :ok <- validate_response_code_issuer(audience, issuer),
         :ok <- validate_response_code_identifier(jti),
         :ok <- validate_response_code_identifier(session_id) do
      validate_response_code_times(issued_at, expires_at, now)
    end
  end

  defp validate_response_code_claims(_claims, _issuer, _now), do: {:error, :invalid_response_code}

  defp validate_response_code_issuer(issuer, issuer), do: :ok
  defp validate_response_code_issuer(_audience, _issuer), do: {:error, :invalid_response_code}

  defp validate_response_code_identifier(value) when is_binary(value) and value != "", do: :ok
  defp validate_response_code_identifier(_value), do: {:error, :invalid_response_code}

  defp validate_response_code_times(issued_at, expires_at, now)
       when is_integer(issued_at) and is_integer(expires_at) and issued_at <= now + 60 and expires_at > now and
              expires_at >= issued_at and expires_at - issued_at <= @presentation_ttl_seconds, do: :ok

  defp validate_response_code_times(_issued_at, _expires_at, _now), do: {:error, :invalid_response_code}

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

      _unsupported ->
        {:error, :invalid_attrs}
    end
  end

  defp validate_response_mode(mode) when mode in ["direct_post", "direct_post.jwt"], do: :ok
  defp validate_response_mode(_mode), do: {:error, :invalid_attrs}

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
      _unsupported -> {:error, :invalid_attrs}
    end
  end

  defp discard_session(store, id, error) do
    # The store contract intentionally permits `take/1` only for completed
    # entries. Move this failed, still-pending construction through a private
    # terminal result and immediately consume it so signing/attachment failures
    # cannot leave a usable orphan behind.
    with :ok <- store.complete(id, %{cancelled: true}) do
      _ = store.take(id)
    end

    error
  rescue
    _error -> error
  catch
    _kind, _reason -> error
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

  defp presentation_complete_redirect_uri(config, response_code) do
    config.issuer <> "/presentation/complete?response_code=" <> URI.encode_www_form(response_code)
  end

  defp response_session_store(config) do
    case Config.presentation_session_store(config) do
      store when is_atom(store) and not is_nil(store) -> {:ok, store}
      _ -> {:error, :misconfigured}
    end
  end

  defp resolve_presentation_response(
         %PresentationResponse{mode: :encrypted, response: encrypted_response},
         _config,
         store
       ) do
    decrypt_presentation_response(encrypted_response, store)
  end

  defp resolve_presentation_response(
         %PresentationResponse{mode: :plaintext, state: state, vp_token: vp_token},
         config,
         store
       ) do
    plaintext_presentation_response(state, vp_token, config, store)
  end

  defp plaintext_presentation_response(state, vp_token, config, store) do
    # A session created with a per-session `direct_post.jwt` override (via
    # AttestoPhoenix.Verifier's `response_mode` attr) has an ephemeral
    # response-encryption key attached to it even when the GLOBAL config mode
    # is "direct_post". Accepting a plaintext submission for such a session
    # would let a wallet (or attacker) silently downgrade that session's
    # confidentiality requirement, so a session with an encryption key MUST
    # reject plaintext, regardless of the global mode. `decoded_response/1`
    # must run first to recover `state` before this lookup is possible.
    with "direct_post" <- Config.presentation_response_mode(config),
         :error <- PresentationSession.response_encryption_jwk(store, state) do
      {:ok, state, vp_token}
    else
      _ -> {:error, :malformed}
    end
  end

  defp decrypt_presentation_response(encrypted_response, store) when is_binary(encrypted_response) do
    # The JWE `kid` is the presentation session id (the verifier advertised a
    # fresh, per-request encryption key keyed by it); recover that session's
    # private key to decrypt. `Attesto.JWE` admits only a public P-256 `epk`
    # before JOSE sees the header: the wallet chooses that key, and JOSE before
    # 1.11.13 looped forever on a key of another type.
    with {:ok, segments} <- compact_jwe(encrypted_response),
         {:ok, header} <- protected_jwe_header(segments.protected),
         :ok <- encrypted_response_algorithms(header),
         :ok <- encrypted_response_parameters(segments),
         {:ok, kid} <- jwe_kid(header),
         {:ok, jwk_map} <- PresentationSession.response_encryption_jwk(store, kid),
         {:ok, plaintext, _header} <-
           JWE.decrypt(jwk_map, encrypted_response,
             max_compact_bytes: @max_compact_jwe_bytes,
             max_plaintext_bytes: @max_compact_jwe_bytes
           ),
         {:ok, params} <- decode_json_map(plaintext),
         {:ok, state, vp_token} <- decoded_presentation_response(params),
         true <- state == kid do
      {:ok, state, vp_token}
    else
      _ -> {:error, :malformed}
    end
  rescue
    _error -> {:error, :malformed}
  catch
    _kind, _reason -> {:error, :malformed}
  end

  defp decrypt_presentation_response(_encrypted_response, _store), do: {:error, :malformed}

  defp jwe_kid(%{"kid" => kid}) when is_binary(kid) and kid != "", do: {:ok, kid}
  defp jwe_kid(_header), do: {:error, :malformed}

  defp protected_jwe_header(encoded) do
    with {:ok, json} <- decode64(encoded),
         {:ok, header} <- decode_json_map(json) do
      {:ok, header}
    else
      _ -> {:error, :malformed}
    end
  end

  defp decode_json_map(bytes) do
    case StrictJSON.decode(bytes) do
      {:ok, %{} = map} -> {:ok, map}
      _other -> {:error, :malformed}
    end
  end

  defp decode64(encoded) do
    with {:ok, decoded} <- Base.url_decode64(encoded, padding: false),
         true <- Base.url_encode64(decoded, padding: false) == encoded do
      {:ok, decoded}
    else
      _other -> {:error, :malformed}
    end
  end

  defp decoded_presentation_response(%{"state" => state, "vp_token" => raw_vp_token})
       when is_binary(state) and state != "" do
    with {:ok, vp_token} <- decode_vp_token(raw_vp_token) do
      {:ok, state, vp_token}
    end
  end

  defp decoded_presentation_response(_params), do: {:error, :malformed}

  defp compact_jwe(encrypted_response) when byte_size(encrypted_response) <= @max_compact_jwe_bytes do
    with [protected, rest] <- :binary.split(encrypted_response, "."),
         [encrypted_key, rest] <- :binary.split(rest, "."),
         [iv, rest] <- :binary.split(rest, "."),
         [ciphertext, tag] <- :binary.split(rest, "."),
         :nomatch <- :binary.match(tag, "."),
         true <- protected != "" and byte_size(protected) <= @max_protected_segment_bytes do
      {:ok,
       %{
         protected: protected,
         encrypted_key: encrypted_key,
         iv: iv,
         ciphertext: ciphertext,
         tag: tag
       }}
    else
      _parts -> {:error, :malformed}
    end
  end

  defp compact_jwe(_encrypted_response), do: {:error, :malformed}

  defp encrypted_response_algorithms(header) do
    with %{"alg" => "ECDH-ES", "enc" => enc} when enc in @accepted_response_encs <- header,
         # Reject a compressed JWE (`zip`, RFC 7516 §4.1.3) BEFORE decrypting. The
         # recipient key is the per-session key we advertise to the wallet, so
         # anyone can mint a valid `direct_post.jwt`; a `zip:"DEF"` payload would
         # have JOSE `zlib:inflate` a tiny ciphertext into hundreds of MB/GB (a
         # ~1000:1 decompression bomb) inside `block_decrypt`, before any size
         # check - an unauthenticated OOM on a public endpoint. No `zip` is used
         # on this response, so its presence is always malformed.
         false <- Map.has_key?(header, "zip") do
      :ok
    else
      _ -> {:error, :malformed}
    end
  end

  # RFC 7518 §4.6 uses direct key agreement for ECDH-ES, so the encrypted-key
  # segment is empty. AES-GCM requires a 96-bit IV and a 128-bit authentication
  # tag (§8.5). Validate those fixed boundaries before passing input to JOSE;
  # this keeps correctness independent of a dependency's permissive decoder.
  defp encrypted_response_parameters(%{encrypted_key: "", iv: iv, ciphertext: ciphertext, tag: tag})
       when byte_size(iv) == 16 and byte_size(tag) == 22 do
    with {:ok, iv} when byte_size(iv) == 12 <- decode64(iv),
         {:ok, ciphertext} when byte_size(ciphertext) > 0 <- decode64(ciphertext),
         {:ok, tag} when byte_size(tag) == 16 <- decode64(tag) do
      :ok
    else
      _other -> {:error, :malformed}
    end
  end

  defp encrypted_response_parameters(_segments), do: {:error, :malformed}

  defp decode_vp_token(%{} = vp_token), do: {:ok, vp_token}

  defp decode_vp_token(vp_token) when is_binary(vp_token) do
    case decode_json_map(vp_token) do
      {:ok, decoded} -> {:ok, decoded}
      _ -> {:error, :malformed}
    end
  end

  defp decode_vp_token(_vp_token), do: {:error, :malformed}

  defp verify_presentation_response(store, state, vp_token) do
    PresentationSession.verify_response(
      store,
      {:state, state},
      vp_token,
      now: System.system_time(:second)
    )
  rescue
    ArgumentError -> {:error, :malformed}
  end
end
