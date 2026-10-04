defmodule AttestoPhoenix.Controller.PresentationResponseController do
  @moduledoc """
  Public OID4VP direct-post response endpoint.

  The endpoint accepts either an encrypted `direct_post.jwt` `response` JWE or
  the DCQL response map directly as JSON/the JSON string carried by an
  `application/x-www-form-urlencoded` `vp_token` field. All decryption and
  verification failures use the same public error response.
  """

  use AttestoPhoenix.Controller, formats: [:json]

  alias Attesto.PresentationSession
  alias AttestoPhoenix.{Config, OAuthError, RequestContext}
  alias Plug.Conn.Unfetched

  # `response` is attacker-controlled input at a public endpoint. Bound it and
  # parse at most four separators before JOSE performs Base64URL decoding or
  # authenticated decryption. Presentations may be substantially larger than
  # ordinary JWTs, so the ciphertext receives a 16 MiB total envelope while the
  # protected header retains the hardened 256 KiB JOSE ceiling.
  @max_compact_jwe_bytes 16 * 1_024 * 1_024
  @max_protected_segment_bytes 256 * 1_024

  @doc "Verify and atomically complete an OID4VP presentation session."
  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, _params) do
    config = Config.resolve!(conn)
    conn = OAuthError.no_store(conn, config)

    with :ok <- check_https(conn, config),
         {:ok, store} <- presentation_session_store(config),
         {:ok, state, vp_token} <- response(Map.get(conn, :body_params), config, store),
         {:ok, _results} <- verify_response(store, state, vp_token) do
      # OID4VP §8.2 permits, and HAIP §5.1 requires, a `redirect_uri` carrying a
      # `response_code` so the wallet returns the user to the verifier front-end,
      # which then retrieves the completed presentation result. That read is
      # single-use (`AttestoPhoenix.Verifier.presentation_result/2` consumes the
      # session), so this browser-borne `response_code` cannot be replayed from
      # history/logs to re-read the presented claims.
      json(conn, %{"redirect_uri" => redirect_uri(config, state)})
    else
      _error -> invalid_request(conn, config)
    end
  end

  defp redirect_uri(config, state) do
    config.issuer <> "/presentation/complete?response_code=" <> URI.encode_www_form(state)
  end

  defp response(%Unfetched{}, _config, _store), do: {:error, :malformed}

  defp response(params, config, store) when is_map(params) do
    case fetch_param(params, "response") do
      {:ok, encrypted_response} -> decrypt_response(encrypted_response, store)
      :error -> plaintext_response(params, config, store)
    end
  end

  defp response(_params, _config, _store), do: {:error, :malformed}

  defp plaintext_response(params, config, store) do
    # A session created with a per-session `direct_post.jwt` override (via
    # AttestoPhoenix.Verifier's `response_mode` attr) has an ephemeral
    # response-encryption key attached to it even when the GLOBAL config mode
    # is "direct_post". Accepting a plaintext submission for such a session
    # would let a wallet (or attacker) silently downgrade that session's
    # confidentiality requirement, so a session with an encryption key MUST
    # reject plaintext, regardless of the global mode. `decoded_response/1`
    # must run first to recover `state` before this lookup is possible.
    with "direct_post" <- Config.presentation_response_mode(config),
         {:ok, state, vp_token} <- decoded_response(params),
         :error <- PresentationSession.response_encryption_jwk(store, state) do
      {:ok, state, vp_token}
    else
      _ -> {:error, :malformed}
    end
  end

  defp decrypt_response(encrypted_response, store) when is_binary(encrypted_response) do
    # The JWE `kid` is the presentation session id (the verifier advertised a
    # fresh, per-request encryption key keyed by it); recover that session's
    # private key to decrypt.
    with {:ok, segments} <- compact_jwe(encrypted_response),
         {:ok, header} <- protected_header(segments.protected),
         :ok <- encrypted_response_algorithms(header),
         :ok <- encrypted_response_parameters(segments),
         {:ok, kid} <- jwe_kid(header),
         {:ok, jwk_map} <- PresentationSession.response_encryption_jwk(store, kid),
         %JOSE.JWK{} = private_jwk <- JOSE.JWK.from_map(jwk_map),
         {plaintext, %JOSE.JWE{}} <- JOSE.JWE.block_decrypt(private_jwk, encrypted_response),
         {:ok, params} <- decode_json_map(plaintext),
         {:ok, state, vp_token} <- decoded_response(params) do
      {:ok, state, vp_token}
    else
      _ -> {:error, :malformed}
    end
  rescue
    _error -> {:error, :malformed}
  catch
    _kind, _reason -> {:error, :malformed}
  end

  defp decrypt_response(_encrypted_response, _store), do: {:error, :malformed}

  defp jwe_kid(%{"kid" => kid}) when is_binary(kid) and kid != "" do
    {:ok, kid}
  end

  defp jwe_kid(_header), do: {:error, :malformed}

  defp protected_header(encoded) do
    with {:ok, json} <- decode64(encoded),
         {:ok, header} <- decode_json_map(json) do
      {:ok, header}
    else
      _ -> {:error, :malformed}
    end
  end

  defp decode_json_map(bytes) do
    decoders = [
      object_start: fn _old_acc -> %{} end,
      object_push: fn key, value, object ->
        if Map.has_key?(object, key),
          do: throw(:duplicate_json_member),
          else: Map.put(object, key, value)
      end,
      object_finish: fn object, old_acc -> {object, old_acc} end
    ]

    case JSON.decode(bytes, nil, decoders) do
      {%{} = map, nil, ""} -> {:ok, map}
      _other -> {:error, :malformed}
    end
  rescue
    _error -> {:error, :malformed}
  catch
    :duplicate_json_member -> {:error, :malformed}
  end

  defp decode64(encoded) do
    with {:ok, decoded} <- Base.url_decode64(encoded, padding: false),
         true <- Base.url_encode64(decoded, padding: false) == encoded do
      {:ok, decoded}
    else
      _other -> {:error, :malformed}
    end
  end

  defp decoded_response(params) do
    with state when is_binary(state) and state != "" <- param(params, "state"),
         {:ok, vp_token} <- decode_vp_token(param(params, "vp_token")) do
      {:ok, state, vp_token}
    else
      _ -> {:error, :malformed}
    end
  end

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

  # Validate the JWE alg/enc from the compact response's protected header — the
  # first segment is base64url-encoded JSON — before decrypting, rather than
  # introspecting the decoded %JOSE.JWE{} struct.
  @accepted_response_encs ~w(A128GCM A256GCM)

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

  defp param(params, key), do: Map.get(params, key) || Map.get(params, String.to_existing_atom(key))

  defp fetch_param(params, name) do
    case Map.fetch(params, name) do
      {:ok, value} -> {:ok, value}
      :error -> Map.fetch(params, String.to_existing_atom(name))
    end
  end

  defp verify_response(store, state, vp_token) do
    PresentationSession.verify_response(
      store,
      {:state, state},
      vp_token,
      now: System.system_time(:second)
    )
  rescue
    ArgumentError -> {:error, :malformed}
  end

  defp check_https(conn, config), do: RequestContext.check_https(conn, config)

  defp presentation_session_store(config) do
    case Config.presentation_session_store(config) do
      store when is_atom(store) and not is_nil(store) -> {:ok, store}
      _ -> {:error, :misconfigured}
    end
  end

  defp invalid_request(conn, config) do
    OAuthError.render(
      conn,
      OAuthError.new(:invalid_request, nil, status: 400),
      config: config
    )
  end
end
