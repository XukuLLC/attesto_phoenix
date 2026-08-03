defmodule AttestoPhoenix.Controller.CredentialController do
  @moduledoc """
  OID4VCI Credential Endpoint (`draft-ietf-oauth-openid4vci` §8.2).

  This endpoint authenticates the access token, enforces the credential
  configuration entitlement carried by that token, verifies each of the
  wallet's holder-key proofs against a server-issued c_nonce, and issues one
  holder-bound credential per verified proof (the OID4VCI `proofs` batch
  form). The host supplies only the credential type and claim values through
  `:build_credential`; the library owns proof verification, holder binding,
  signing, format-specific issuance, and response framing.
  """

  use Phoenix.Controller, formats: [:json]

  import AttestoPhoenix.Controller.OID4VCIHelpers,
    only: [body_params: 2, invalid_request: 4, maybe_put_option: 3]

  import Plug.Conn

  alias Attesto.{CredentialProof, CredentialRequest, CredentialResponse, JWS, Key, MapParams, Mdoc, SdJwtVc, SigningAlg}
  alias AttestoPhoenix.Callback
  alias AttestoPhoenix.{Config, ProtectedResource}
  alias AttestoPhoenix.OAuthError, as: PhoenixOAuthError

  @credential_configuration_ids_claim "credential_configuration_ids"
  @mdoc_signing_key_error "mso_mdoc issuance requires an EC P-256 (ES256) VC signing key."
  @sd_jwt_vc_formats ~w(vc+sd-jwt dc+sd-jwt)

  @doc """
  Issue the credential(s) requested by an authenticated wallet.

  The action accepts either the single `proof` form or the batch `proofs`
  form; each holder-key proof yields its own holder-bound credential in the
  response. Every proof must verify (fresh c_nonce, correct audience, valid
  signature) or the whole request fails with the same `invalid_proof` error,
  regardless of which proof or how many failed. Credential identifiers and any
  other proof or request failure are returned as the OID4VCI JSON error
  envelope with status 400.
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
    parsed_request = Callback.map_value(%{result: CredentialRequest.parse(request)}, :result)

    with {:ok, parsed} <- parsed_request,
         {:ok, credential_configuration_id} <- selector(parsed.selector),
         :ok <- entitled?(claims, credential_configuration_id),
         {:ok, holder_jwks} <- verify_proofs(config, claims, parsed.proofs) do
      build_and_issue(
        conn,
        config,
        claims["sub"],
        credential_configuration_id,
        holder_jwks,
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

  defp verify_proofs(_config, _claims, []), do: {:error, :invalid_proof, "A credential proof is required."}

  defp verify_proofs(config, claims, proofs) do
    proofs
    |> Enum.reduce_while({:ok, []}, fn proof, {:ok, acc} ->
      case verify_proof(config, claims, proof) do
        {:ok, holder_jwk} -> {:cont, {:ok, [holder_jwk | acc]}}
        :error -> {:halt, :error}
      end
    end)
    |> case do
      {:ok, holder_jwks} -> {:ok, Enum.reverse(holder_jwks)}
      :error -> {:error, :invalid_proof, "Invalid credential proof."}
    end
  end

  defp verify_proof(config, claims, {"jwt", jwt}) do
    with {:ok, payload} <- JWS.peek_json(jwt, :payload),
         nonce when is_binary(nonce) and nonce != "" <- Map.get(payload, "nonce"),
         true <- nonce_valid?(config, nonce),
         {:ok, %{jwk: holder_jwk}} <- CredentialProof.verify_jwt(jwt, proof_opts(config, claims, nonce)) do
      {:ok, holder_jwk}
    else
      _ -> :error
    end
  end

  defp verify_proof(_config, _claims, _proof), do: :error

  defp nonce_valid?(config, nonce) do
    case Callback.config_callback(config, :c_nonce_store) do
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

  defp build_and_issue(conn, config, subject, credential_configuration_id, holder_jwks, _resource_metadata) do
    case build_credentials(config, subject, credential_configuration_id, holder_jwks) do
      {:ok, credentials} ->
        conn
        |> PhoenixOAuthError.no_store(config)
        |> json(CredentialResponse.build(credentials))

      {:error, :invalid_mdoc_signing_key} ->
        invalid_request(conn, config, "invalid_credential_request", @mdoc_signing_key_error)

      {:error, _reason} ->
        invalid_request(conn, config, "invalid_credential_request", "credential unavailable")
    end
  end

  defp build_credentials(config, subject, credential_configuration_id, holder_jwks) do
    with {:ok, credential_configuration} <-
           credential_configuration(config, credential_configuration_id) do
      build_credentials(
        config,
        subject,
        credential_configuration_id,
        holder_jwks,
        credential_configuration
      )
    end
  end

  defp build_credentials(config, subject, credential_configuration_id, holder_jwks, credential_configuration) do
    format = configuration_value(credential_configuration, :format)

    holder_jwks
    |> Enum.reduce_while({:ok, []}, fn holder_jwk, {:ok, acc} ->
      case build_credential(
             config,
             subject,
             credential_configuration_id,
             holder_jwk,
             format,
             credential_configuration
           ) do
        {:ok, credential} -> {:cont, {:ok, [credential | acc]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, credentials} -> {:ok, Enum.reverse(credentials)}
      error -> error
    end
  end

  defp build_credential(config, subject, credential_configuration_id, holder_jwk, format, _configuration)
       when format in @sd_jwt_vc_formats do
    build_credential(config, subject, credential_configuration_id, holder_jwk)
  end

  defp build_credential(config, subject, credential_configuration_id, holder_jwk, "jwt_vc_json", _configuration) do
    build_jwt_vc_credential(config, subject, credential_configuration_id, holder_jwk)
  end

  defp build_credential(config, subject, credential_configuration_id, holder_jwk, "mso_mdoc", credential_configuration) do
    build_mdoc_credential(config, subject, credential_configuration_id, holder_jwk, credential_configuration)
  end

  defp build_credential(_config, _subject, _credential_configuration_id, _holder_jwk, _format, _configuration),
    do: {:error, :unsupported_credential_format}

  defp build_credential(config, subject, credential_configuration_id, holder_jwk) do
    case Config.build_credential(config, subject, credential_configuration_id, holder_jwk) do
      {:ok, %{vct: vct, claims: claims} = result}
      when is_binary(vct) and is_map(claims) ->
        {:ok, issue_credential(config, result, holder_jwk)}

      other ->
        normalize_build_result(other)
    end
  end

  defp issue_credential(config, %{vct: vct, claims: claims} = result, holder_jwk) do
    SdJwtVc.issue(
      [
        iss: config.issuer,
        vct: vct,
        pem: Config.vc_signing_pem(config)
      ],
      [
        claims: claims,
        cnf: %{"jwk" => holder_jwk}
      ]
      |> maybe_put_option(:exp, Map.get(result, :valid_until))
      |> maybe_put_option(:nbf, Map.get(result, :valid_from))
    )
  end

  defp build_jwt_vc_credential(config, subject, credential_configuration_id, holder_jwk) do
    case Config.build_credential(config, subject, credential_configuration_id, holder_jwk) do
      {:ok, %{credential_type: credential_type, claims: claims} = result}
      when is_binary(credential_type) and is_map(claims) ->
        {:ok, issue_jwt_vc_credential(config, subject, result, holder_jwk)}

      other ->
        normalize_build_result(other)
    end
  end

  defp issue_jwt_vc_credential(config, subject, result, holder_jwk) do
    Attesto.JwtVc.issue(
      [
        iss: config.issuer,
        sub: subject,
        pem: Config.vc_signing_pem(config)
      ],
      [
        type: ["VerifiableCredential", result.credential_type],
        claims: result.claims,
        cnf: %{"jwk" => holder_jwk}
      ]
      |> maybe_put_option(:exp, Map.get(result, :valid_until))
      |> maybe_put_option(:nbf, Map.get(result, :valid_from))
    )
  end

  defp build_mdoc_credential(config, subject, credential_configuration_id, holder_jwk, credential_configuration) do
    case Config.build_credential(config, subject, credential_configuration_id, holder_jwk) do
      {:ok, %{namespaces: namespaces} = result} when is_map(namespaces) ->
        issue_mdoc_credential(config, result, holder_jwk, credential_configuration)

      other ->
        normalize_build_result(other)
    end
  end

  defp normalize_build_result({:error, reason}), do: {:error, reason}
  defp normalize_build_result(_other), do: {:error, :invalid_credential}

  defp issue_mdoc_credential(config, result, holder_jwk, credential_configuration) do
    now = System.system_time(:second)
    doc_type = Map.get(result, :doc_type) || configuration_doc_type(credential_configuration)

    with {:ok, issuer_pem} <- mdoc_signing_pem(config) do
      Mdoc.issue(
        doc_type: doc_type,
        namespaces: result.namespaces,
        device_key: holder_jwk,
        issuer_pem: issuer_pem,
        validity: %{
          signed: now,
          valid_from: Map.get(result, :valid_from, now),
          valid_until: Map.get(result, :valid_until, now)
        }
      )
    end
  end

  defp mdoc_signing_pem(config) do
    pem = Config.vc_signing_pem(config)

    pem
    |> Key.signing_jwk()
    |> SigningAlg.infer()
    |> case do
      "ES256" -> {:ok, pem}
      _other -> {:error, :invalid_mdoc_signing_key}
    end
  rescue
    _error -> {:error, :invalid_mdoc_signing_key}
  catch
    _kind, _reason -> {:error, :invalid_mdoc_signing_key}
  end

  defp credential_configuration(config, credential_configuration_id) do
    case Config.credential_configurations_supported(config) do
      configurations when is_map(configurations) ->
        case Map.fetch(configurations, credential_configuration_id) do
          {:ok, configuration} when is_map(configuration) -> {:ok, configuration}
          _other -> {:error, :unsupported_credential_configuration}
        end

      _other ->
        {:error, :unsupported_credential_configuration}
    end
  end

  defp configuration_doc_type(configuration) do
    configuration_value(configuration, :doctype) || configuration_value(configuration, :doc_type)
  end

  defp configuration_value(configuration, key), do: MapParams.fetch(configuration, key)

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
