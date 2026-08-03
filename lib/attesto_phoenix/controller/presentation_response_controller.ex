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
         {:ok, state, vp_token} <- response(Map.get(conn, :body_params), config),
         {:ok, _results} <- verify_response(store, state, vp_token) do
      json(conn, %{})
    else
      _error -> invalid_request(conn, config)
    end
  end

  defp response(%Unfetched{}, _config), do: {:error, :malformed}

  defp response(params, config) when is_map(params) do
    case fetch_param(params, "response") do
      {:ok, encrypted_response} -> decrypt_response(encrypted_response, config)
      :error -> plaintext_response(params, config)
    end
  end

  defp response(_params, _config), do: {:error, :malformed}

  defp plaintext_response(params, config) do
    with "direct_post" <- Config.presentation_response_mode(config),
         {:ok, state, vp_token} <- decoded_response(params) do
      {:ok, state, vp_token}
    else
      _ -> {:error, :malformed}
    end
  end

  defp decrypt_response(encrypted_response, config) when is_binary(encrypted_response) do
    with :ok <- compact_jwe(encrypted_response),
         :ok <- encrypted_response_algorithms(encrypted_response),
         %JOSE.JWK{} = private_jwk <- JOSE.JWK.from_pem(config.keystore.signing_pem()),
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

  defp decrypt_response(_encrypted_response, _config), do: {:error, :malformed}

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
  defp encrypted_response_algorithms(encrypted_response) do
    with [protected_b64 | _] <- String.split(encrypted_response, "."),
         {:ok, json} <- Base.url_decode64(protected_b64, padding: false),
         {:ok, %{"alg" => "ECDH-ES", "enc" => "A128GCM"}} <- JSON.decode(json) do
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
