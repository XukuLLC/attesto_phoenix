defmodule AttestoPhoenix.Controller.CredentialController do
  @moduledoc """
  OID4VCI Credential Endpoint (`draft-ietf-oauth-openid4vci` §8.2).

  This endpoint authenticates the access token, enforces the credential
  configuration entitlement carried by that token, verifies the wallet's
  holder-key proof against a server-issued c_nonce, and issues an SD-JWT VC.
  The host supplies only the credential type and claim values through
  `:build_credential`; the library owns proof verification, holder binding,
  signing, and response framing.
  """

  use Phoenix.Controller, formats: [:json]

  import Plug.Conn

  alias Attesto.{CredentialProof, CredentialRequest, CredentialResponse, JWS, SdJwtVc}
  alias AttestoPhoenix.Callback
  alias AttestoPhoenix.{Config, ProtectedResource}
  alias AttestoPhoenix.OAuthError, as: PhoenixOAuthError
  alias Plug.Conn.Unfetched

  @credential_configuration_ids_claim "credential_configuration_ids"

  @doc """
  Issue the credential requested by an authenticated wallet.

  The action accepts exactly one `jwt` proof in this slice. Batch issuance,
  credential identifiers, and any proof or request failure are returned as the
  OID4VCI JSON error envelope with status 400.
  """
  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, params) do
    config = Config.resolve!()
    resource_metadata = Config.resource_metadata_url(config, conn)

    case ProtectedResource.authenticate(conn, config, resource_metadata) do
      {:ok, conn, claims} ->
        issue(conn, config, body_params(conn, params), resource_metadata, claims)

      {:halt, conn} ->
        conn
    end
  end

  defp issue(conn, config, request, resource_metadata, claims) do
    with {:ok, parsed} <- CredentialRequest.parse(request),
         {:ok, credential_configuration_id} <- selector(parsed.selector),
         :ok <- entitled?(claims, credential_configuration_id),
         {:ok, holder_jwk} <- verify_proof(config, claims, parsed.proofs) do
      build_and_issue(
        conn,
        config,
        claims["sub"],
        credential_configuration_id,
        holder_jwk,
        resource_metadata
      )
    else
      {:error, :unsupported_credential_identifier} ->
        invalid_request(conn, config, "invalid_credential_request", "credential_identifier not supported")

      {:error, :not_entitled} ->
        not_entitled(conn, config, claims, resource_metadata)

      {:error, :invalid_proof, description} ->
        invalid_request(conn, config, "invalid_proof", description)

      {:error, :invalid_credential_request, description} ->
        invalid_request(conn, config, "invalid_credential_request", description)

      {:error, _reason} ->
        invalid_request(conn, config, "invalid_credential_request", "Invalid credential request.")
    end
  end

  defp selector({:configuration_id, id}), do: {:ok, id}
  defp selector({:credential_identifier, _id}), do: {:error, :unsupported_credential_identifier}

  defp entitled?(%{@credential_configuration_ids_claim => ids}, id) when is_list(ids) do
    if id in ids, do: :ok, else: {:error, :not_entitled}
  end

  defp entitled?(_claims, _id), do: {:error, :not_entitled}

  defp verify_proof(_config, _claims, []), do: {:error, :invalid_proof, "A credential proof is required."}

  defp verify_proof(_config, _claims, proofs) when length(proofs) > 1 do
    {:error, :invalid_proof, "batch issuance not supported yet"}
  end

  defp verify_proof(config, claims, [{"jwt", jwt}]) do
    with {:ok, payload} <- JWS.peek_json(jwt, :payload),
         nonce when is_binary(nonce) and nonce != "" <- Map.get(payload, "nonce"),
         true <- nonce_valid?(config, nonce),
         {:ok, %{jwk: holder_jwk}} <- CredentialProof.verify_jwt(jwt, proof_opts(config, claims, nonce)) do
      {:ok, holder_jwk}
    else
      _ -> {:error, :invalid_proof, "Invalid credential proof."}
    end
  end

  defp verify_proof(_config, _claims, [_proof]) do
    {:error, :invalid_proof, "Only jwt credential proofs are supported."}
  end

  defp nonce_valid?(config, nonce) do
    case Config.c_nonce_store(config) do
      store when is_atom(store) ->
        function_exported?(store, :valid?, 1) and store.valid?(nonce)

      _ ->
        false
    end
  end

  defp proof_opts(config, claims, nonce) do
    [issuer: config.issuer, nonce: nonce]
    |> maybe_put_client_id(claims)
  end

  defp maybe_put_client_id(opts, %{"grant_type" => "authorization_code", "client_id" => client_id})
       when is_binary(client_id), do: Keyword.put(opts, :client_id, client_id)

  defp maybe_put_client_id(opts, _claims), do: opts

  defp build_and_issue(conn, config, subject, credential_configuration_id, holder_jwk, _resource_metadata) do
    case Config.build_credential(config, subject, credential_configuration_id, holder_jwk) do
      {:ok, %{vct: vct, claims: claims} = result}
      when is_binary(vct) and is_map(claims) ->
        issue_credential(conn, config, result, holder_jwk)

      {:error, _reason} ->
        invalid_request(conn, config, "invalid_credential_request", "credential unavailable")

      _other ->
        invalid_request(conn, config, "invalid_credential_request", "credential unavailable")
    end
  end

  defp issue_credential(conn, config, %{vct: vct, claims: claims} = result, holder_jwk) do
    credential =
      SdJwtVc.issue(
        [
          iss: config.issuer,
          vct: vct,
          pem: config.keystore.signing_pem()
        ],
        [
          claims: claims,
          cnf: %{"jwk" => holder_jwk}
        ]
        |> maybe_put_option(:exp, Map.get(result, :valid_until))
        |> maybe_put_option(:nbf, Map.get(result, :valid_from))
      )

    conn
    |> PhoenixOAuthError.no_store(config)
    |> json(CredentialResponse.build([credential]))
  end

  defp maybe_put_option(opts, _key, nil), do: opts
  defp maybe_put_option(opts, key, value), do: Keyword.put(opts, key, value)

  defp invalid_request(conn, config, error, description) do
    conn
    |> PhoenixOAuthError.no_store(config)
    |> put_status(:bad_request)
    |> json(%{"error" => error, "error_description" => description})
  end

  defp not_entitled(conn, config, claims, resource_metadata) do
    description = "The access token does not authorize this credential."
    scheme = ProtectedResource.scheme_of(claims)

    challenge =
      PhoenixOAuthError.format_challenge(
        scheme,
        [{"error", "insufficient_scope"}, {"error_description", description}] ++
          resource_metadata_param(resource_metadata)
      )

    body = %{"error" => "insufficient_scope", "error_description" => description}

    conn
    |> PhoenixOAuthError.no_store(config)
    |> apply_www_authenticate(config, challenge)
    |> send_scope_error(config, body)
  end

  defp body_params(%Plug.Conn{body_params: %Unfetched{}}, fallback), do: fallback
  defp body_params(%Plug.Conn{body_params: body_params}, _fallback) when is_map(body_params), do: body_params

  defp apply_www_authenticate(conn, %Config{www_authenticate: nil}, challenge),
    do: put_resp_header(conn, "www-authenticate", challenge)

  defp apply_www_authenticate(conn, %Config{www_authenticate: callback}, challenge),
    do: Callback.invoke(callback, [conn, challenge])

  defp send_scope_error(conn, %Config{send_error: nil}, body) do
    conn
    |> put_status(:forbidden)
    |> json(body)
  end

  defp send_scope_error(conn, %Config{send_error: callback}, body), do: Callback.invoke(callback, [conn, 403, body])

  defp resource_metadata_param(url) when is_binary(url), do: [{"resource_metadata", url}]
  defp resource_metadata_param(_url), do: []
end
