defmodule AttestoPhoenix.Controller.OID4VCIHelpers do
  @moduledoc false

  alias Attesto.CredentialEncryption
  alias AttestoPhoenix.{Config, OAuthError}
  alias Plug.Conn
  alias Plug.Conn.Unfetched

  @max_request_bytes 2_000_000

  def maybe_put_option(opts, _key, nil), do: opts
  def maybe_put_option(opts, key, value), do: Keyword.put(opts, key, value)

  def body_params(%Conn{body_params: %Unfetched{}}, fallback), do: fallback
  def body_params(%Conn{body_params: body_params}, _fallback) when is_map(body_params), do: body_params

  @spec read_credential_request(Conn.t(), map(), Config.t()) ::
          {:ok, map(), boolean(), Conn.t()} | {:error, String.t(), String.t()}
  def read_credential_request(%Conn{} = conn, params, %Config{} = config) do
    if jwt_content_type?(conn) do
      read_encrypted_request(conn, config)
    else
      {:ok, body_params(conn, params), false, conn}
    end
  end

  @spec send_credential_response(Conn.t(), Config.t(), map(), map() | nil) :: Conn.t()
  def send_credential_response(%Conn{} = conn, %Config{} = config, response, nil) do
    conn
    |> OAuthError.no_store(config)
    |> Phoenix.Controller.json(response)
  end

  def send_credential_response(%Conn{} = conn, %Config{} = config, response, response_encryption) do
    case CredentialEncryption.encrypt_response(response, response_encryption) do
      {:ok, compact} ->
        conn
        |> OAuthError.no_store(config)
        |> Conn.put_resp_content_type("application/jwt")
        |> Conn.send_resp(200, compact)

      {:error, :invalid_encryption_parameters} ->
        invalid_request(
          conn,
          config,
          "invalid_encryption_parameters",
          "Invalid or unsupported Credential Response encryption parameters."
        )
    end
  end

  def invalid_request(conn, config, error, description) do
    conn
    |> OAuthError.no_store(config)
    |> Conn.put_status(:bad_request)
    |> Phoenix.Controller.json(%{"error" => error, "error_description" => description})
  end

  defp read_encrypted_request(conn, config) do
    case Config.credential_encryption_keystore(config) do
      nil ->
        {:error, "invalid_encryption_parameters",
         "This credential issuer does not support encrypted credential requests."}

      keystore ->
        with {:ok, raw_body, conn} <- read_full_body(conn, <<>>, @max_request_bytes),
             {:ok, decoded} <- CredentialEncryption.decrypt_request(raw_body, keystore) do
          {:ok, decoded, true, conn}
        else
          {:error, :size_limit} ->
            {:error, "invalid_encryption_parameters", "Encrypted credential request exceeds the maximum allowed size."}

          {:error, :invalid_encryption_parameters} ->
            {:error, "invalid_encryption_parameters", "Invalid or unsupported encrypted credential request."}

          {:error, :invalid_credential_request} ->
            {:error, "invalid_credential_request", "Invalid credential request."}
        end
    end
  end

  defp read_full_body(conn, acc, max_bytes) do
    case Conn.read_body(conn, length: max_bytes, read_length: max_bytes) do
      {:ok, chunk, conn} ->
        total = acc <> chunk
        if byte_size(total) <= max_bytes, do: {:ok, total, conn}, else: {:error, :size_limit}

      {:more, chunk, conn} ->
        total = acc <> chunk

        if byte_size(total) < max_bytes,
          do: read_full_body(conn, total, max_bytes),
          else: {:error, :size_limit}

      {:error, _reason} ->
        {:error, :invalid_encryption_parameters}
    end
  end

  defp jwt_content_type?(conn) do
    case Conn.get_req_header(conn, "content-type") do
      [value] when is_binary(value) ->
        media_type = value |> String.split(";") |> hd() |> String.trim() |> String.downcase()
        media_type == "application/jwt"

      _ ->
        false
    end
  end
end
