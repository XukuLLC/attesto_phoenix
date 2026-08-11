defmodule AttestoPhoenix.Controller.PresentationResponseController do
  @moduledoc """
  Public OID4VP direct-post response endpoint.

  The endpoint accepts either an encrypted `direct_post.jwt` `response` JWE or
  the DCQL response map directly as JSON/the JSON string carried by an
  `application/x-www-form-urlencoded` `vp_token` field. All decryption and
  verification failures use the same public error response.
  """

  use Phoenix.Controller, formats: [:json]

  alias Attesto.PresentationSession
  alias AttestoPhoenix.{Config, OAuthError, RequestContext}
  alias Plug.Conn.Unfetched

  @doc "Verify and atomically complete an OID4VP presentation session."
  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, _params) do
    config = Config.resolve!()
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
    with :ok <- compact_jwe(encrypted_response),
         :ok <- encrypted_response_algorithms(encrypted_response),
         {:ok, kid} <- jwe_kid(encrypted_response),
         {:ok, jwk_map} <- PresentationSession.response_encryption_jwk(store, kid),
         %JOSE.JWK{} = private_jwk <- JOSE.JWK.from_map(jwk_map),
         {plaintext, %JOSE.JWE{}} <- JOSE.JWE.block_decrypt(private_jwk, encrypted_response),
         {:ok, %{} = params} <- JSON.decode(plaintext),
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

  defp jwe_kid(encrypted_response) do
    with [protected_b64 | _] <- String.split(encrypted_response, "."),
         {:ok, json} <- Base.url_decode64(protected_b64, padding: false),
         {:ok, %{"kid" => kid}} when is_binary(kid) and kid != "" <- JSON.decode(json) do
      {:ok, kid}
    else
      _ -> {:error, :malformed}
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

  defp compact_jwe(encrypted_response) do
    case String.split(encrypted_response, ".") do
      [_protected, _encrypted_key, _iv, _ciphertext, _tag] -> :ok
      _parts -> {:error, :malformed}
    end
  end

  # Validate the JWE alg/enc from the compact response's protected header — the
  # first segment is base64url-encoded JSON — before decrypting, rather than
  # introspecting the decoded %JOSE.JWE{} struct.
  @accepted_response_encs ~w(A128GCM A256GCM)

  defp encrypted_response_algorithms(encrypted_response) do
    with [protected_b64 | _] <- String.split(encrypted_response, "."),
         {:ok, json} <- Base.url_decode64(protected_b64, padding: false),
         {:ok, %{"alg" => "ECDH-ES", "enc" => enc} = header} when enc in @accepted_response_encs <-
           JSON.decode(json),
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

  defp decode_vp_token(%{} = vp_token), do: {:ok, vp_token}

  defp decode_vp_token(vp_token) when is_binary(vp_token) do
    case JSON.decode(vp_token) do
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
