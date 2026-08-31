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

  use AttestoPhoenix.Controller, formats: [:json]

  import AttestoPhoenix.Controller.OID4VCIHelpers,
    only: [body_params: 2, invalid_request: 4, maybe_put_option: 3]

  import Plug.Conn

  alias Attesto.{CredentialProof, CredentialRequest, CredentialResponse, JWS, Key, MapParams, Mdoc, SdJwtVc, SigningAlg}
  alias AttestoPhoenix.Callback
  alias AttestoPhoenix.{Config, ProtectedResource}
  alias AttestoPhoenix.OAuthError, as: PhoenixOAuthError

  require Logger

  @credential_configuration_ids_claim "credential_configuration_ids"
  @mdoc_signing_key_error "mso_mdoc issuance requires an EC P-256 (ES256) VC signing key."
  @sd_jwt_vc_formats ~w(vc+sd-jwt dc+sd-jwt)
  @invalid_builder_result_warning "AttestoPhoenix credential builder returned an invalid result; credential issuance denied"
  @builder_failure "AttestoPhoenix credential builder callback failed"
  @nonce_consume_failure "c_nonce_store consume/1 must return :ok or {:error, reason}"
  @nonce_validity_failure "c_nonce_store valid?/1 must return true or false"

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
    config = Config.resolve!(conn)
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
         :ok <- reject_response_encryption(parsed.response_encryption),
         {:ok, credential_configuration_id} <- selector(parsed.selector),
         :ok <- entitled?(claims, parsed.selector, credential_configuration_id),
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
      {:error, :not_entitled} ->
        not_entitled(conn, config, claims, resource_metadata)

      {:error, :unknown_credential_configuration} ->
        # OID4VCI §8.3.1: the request names a credential_configuration_id the
        # access token was not granted (or the issuer does not support).
        invalid_request(
          conn,
          config,
          "unknown_credential_configuration",
          "The access token does not authorize the requested credential_configuration_id."
        )

      {:error, :unknown_credential_identifier} ->
        # OID4VCI §8.3.1: the request names a credential_identifier that was not
        # returned in this access token's authorization_details.
        invalid_request(
          conn,
          config,
          "unknown_credential_identifier",
          "The access token does not authorize the requested credential_identifier."
        )

      {:error, :invalid_nonce, description} ->
        invalid_request(conn, config, "invalid_nonce", description)

      {:error, :invalid_proof, description} ->
        invalid_request(conn, config, "invalid_proof", description)

      {:error, :invalid_credential_request, description} ->
        invalid_request(conn, config, "invalid_credential_request", description)

      {:error, :response_encryption_not_supported, description} ->
        invalid_request(conn, config, "invalid_encryption_parameters", description)

      {:error, _reason} ->
        invalid_request(conn, config, "invalid_credential_request", "Invalid credential request.")
    end
  end

  # `Attesto.CredentialRequest.parse` accepts and normalizes a wallet's
  # `credential_response_encryption` request per OID4VCI §8.2, but this issuer
  # does not implement Credential Response encryption (a future feature) and
  # its metadata never advertises it as supported. Silently returning a
  # plaintext credential when the wallet explicitly required an encrypted
  # response would be a silent confidentiality downgrade, so fail closed with
  # a clear OID4VCI error instead.
  defp reject_response_encryption(nil), do: :ok

  defp reject_response_encryption(%{}) do
    {:error, :response_encryption_not_supported,
     "This credential issuer does not support Credential Response encryption."}
  end

  defp selector({:configuration_id, id}), do: {:ok, id}
  # OID4VCI §6.2/§8.2: when the token response returned `credential_identifiers`,
  # the wallet presents one as `credential_identifier`. This issuer maps each
  # identifier 1:1 onto its `credential_configuration_id` (see the token
  # endpoint's `credential_authorization_detail/1`), so it resolves to the same
  # id; `entitled?/2` still gates it against the access token's granted set, so
  # an identifier the token was not issued for is rejected.
  defp selector({:credential_identifier, id}), do: {:ok, id}

  # A token that carries the credential entitlement claim but not this id names a
  # credential the wallet was not authorized for: a bad request (400) whose error
  # code names which selector was unknown (OID4VCI §8.3.1). A token with no
  # entitlement claim at all is not a credential-issuance token, which is the
  # genuine insufficient-scope (403) condition.
  defp entitled?(%{@credential_configuration_ids_claim => ids}, selector, id) when is_list(ids) do
    cond do
      id in ids -> :ok
      match?({:credential_identifier, _}, selector) -> {:error, :unknown_credential_identifier}
      true -> {:error, :unknown_credential_configuration}
    end
  end

  defp entitled?(_claims, _selector, _id), do: {:error, :not_entitled}

  defp verify_proofs(_config, _claims, []), do: {:error, :invalid_proof, "A credential proof is required."}

  defp verify_proofs(config, claims, proofs) do
    proofs
    |> Enum.reduce_while({:ok, [], []}, fn proof, {:ok, jwks, nonces} ->
      case verify_proof(config, claims, proof) do
        {:ok, holder_jwk, nonce} -> {:cont, {:ok, [holder_jwk | jwks], [nonce | nonces]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      # Every proof verified against a live c_nonce. Now single-use it once for
      # the whole request (OID4VCI `proofs` share one nonce, so consuming
      # per-proof would fail the second) so a captured proof cannot be replayed.
      {:ok, holder_jwks, nonces} ->
        case consume_nonces(config, Enum.uniq(nonces)) do
          :ok -> {:ok, Enum.reverse(holder_jwks)}
          {:error, :invalid_nonce} -> invalid_nonce_error()
        end

      # OID4VCI §8.3: an invalid or expired proof nonce is `invalid_nonce`,
      # distinct from an otherwise malformed or wrongly-signed proof.
      {:error, :invalid_nonce} ->
        invalid_nonce_error()

      {:error, :invalid_proof} ->
        {:error, :invalid_proof, "Invalid credential proof."}
    end
  end

  defp invalid_nonce_error, do: {:error, :invalid_nonce, "The proof nonce is invalid or has expired."}

  # Atomically single-use the request's c_nonce(s) after the batch verifies. A
  # store that cannot `consume/1` (only `valid?/1`) must not be used for
  # issuance - fail closed rather than leave the nonce replayable.
  defp consume_nonces(config, nonces) do
    with {:ok, store} <- consuming_nonce_store(config) do
      consume_each(store, nonces)
    end
  end

  defp consuming_nonce_store(config) do
    case Callback.config_callback(config, :c_nonce_store) do
      store when is_atom(store) and not is_nil(store) ->
        if function_exported?(store, :consume, 1), do: {:ok, store}, else: {:error, :invalid_nonce}

      _store ->
        {:error, :invalid_nonce}
    end
  end

  defp consume_each(store, nonces) do
    Enum.reduce_while(nonces, :ok, fn nonce, :ok ->
      case consume_nonce!(store, nonce) do
        :ok -> {:cont, :ok}
        {:error, _reason} -> {:halt, {:error, :invalid_nonce}}
      end
    end)
  end

  defp consume_nonce!(store, nonce) do
    case store.consume(nonce) do
      :ok -> :ok
      {:error, _reason} = error -> error
      _unexpected -> raise RuntimeError, @nonce_consume_failure
    end
  rescue
    _error -> raise RuntimeError, @nonce_consume_failure
  catch
    _kind, _reason -> raise RuntimeError, @nonce_consume_failure
  end

  defp verify_proof(config, claims, {"jwt", jwt}) do
    with {:ok, payload} <- peek_proof_payload(jwt),
         {:ok, nonce} <- proof_nonce(payload),
         :ok <- check_nonce(config, nonce),
         {:ok, %{jwk: holder_jwk}} <- CredentialProof.verify_jwt(jwt, proof_opts(config, claims, nonce)) do
      {:ok, holder_jwk, nonce}
    else
      {:error, :invalid_nonce} -> {:error, :invalid_nonce}
      _other -> {:error, :invalid_proof}
    end
  end

  defp verify_proof(_config, _claims, _proof), do: {:error, :invalid_proof}

  defp peek_proof_payload(jwt) do
    case JWS.peek_json(jwt, :payload) do
      {:ok, payload} when is_map(payload) -> {:ok, payload}
      _other -> {:error, :invalid_proof}
    end
  end

  defp proof_nonce(payload) do
    case Map.get(payload, "nonce") do
      nonce when is_binary(nonce) and nonce != "" -> {:ok, nonce}
      _other -> {:error, :invalid_proof}
    end
  end

  defp check_nonce(config, nonce) do
    if nonce_valid?(config, nonce), do: :ok, else: {:error, :invalid_nonce}
  end

  defp nonce_valid?(config, nonce) do
    case Callback.config_callback(config, :c_nonce_store) do
      store when is_atom(store) ->
        if function_exported?(store, :valid?, 1) do
          nonce_valid_from_store!(store, nonce)
        else
          false
        end

      _ ->
        false
    end
  end

  defp nonce_valid_from_store!(store, nonce) do
    case store.valid?(nonce) do
      true -> true
      false -> false
      _unexpected -> raise RuntimeError, @nonce_validity_failure
    end
  rescue
    _error -> raise RuntimeError, @nonce_validity_failure
  catch
    _kind, _reason -> raise RuntimeError, @nonce_validity_failure
  end

  defp proof_opts(config, claims, nonce) do
    [issuer: config.issuer, nonce: nonce]
    |> maybe_put_client_id(claims)
    |> maybe_put_key_attestation(config)
  end

  # When the host configures trusted key-attestation keys, verify a
  # `key_attestation` header carried by the proof and (under HAIP) require one.
  defp maybe_put_key_attestation(opts, config) do
    case Config.key_attestation_trusted_jwks(config) do
      nil ->
        opts

      jwks ->
        opts
        |> Keyword.put(:key_attestation_trusted_jwks, jwks)
        |> Keyword.put(:require_key_attestation, Config.require_key_attestation?(config))
    end
  end

  # RFC 9068 §2.2 guarantees every access token JWT carries a `client_id`
  # claim, so this binds every credential-request proof's `iss` to the
  # authenticated client regardless of grant type. (Previously this only
  # fired for a `"grant_type" => "authorization_code"` claim that no token
  # minting path ever wrote, so the iss-binding check was permanently
  # dead code and a forged/absent proof `iss` was accepted.)
  defp maybe_put_client_id(opts, %{"client_id" => client_id}) when is_binary(client_id),
    do: Keyword.put(opts, :client_id, client_id)

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
    build_credential(config, subject, credential_configuration_id, holder_jwk, format)
  end

  defp build_credential(config, subject, credential_configuration_id, holder_jwk, "jwt_vc_json", _configuration) do
    build_jwt_vc_credential(config, subject, credential_configuration_id, holder_jwk)
  end

  defp build_credential(config, subject, credential_configuration_id, holder_jwk, "mso_mdoc", credential_configuration) do
    build_mdoc_credential(config, subject, credential_configuration_id, holder_jwk, credential_configuration)
  end

  defp build_credential(_config, _subject, _credential_configuration_id, _holder_jwk, _format, _configuration),
    do: {:error, :unsupported_credential_format}

  defp build_credential(config, subject, credential_configuration_id, holder_jwk, format) do
    case invoke_build_credential!(config, subject, credential_configuration_id, holder_jwk) do
      {:ok, %{vct: vct, claims: claims} = result}
      when is_binary(vct) and is_map(claims) ->
        {:ok, issue_credential(config, result, holder_jwk, format)}

      other ->
        normalize_build_result(other)
    end
  end

  defp issue_credential(config, %{vct: vct, claims: claims} = result, holder_jwk, format) do
    SdJwtVc.issue(
      [
        iss: config.issuer,
        vct: vct,
        keystore: Config.vc_keystore(config)
      ],
      [
        claims: claims,
        cnf: %{"jwk" => holder_jwk},
        typ: format
      ]
      |> maybe_put_option(:x5c, Config.vc_signing_x5c(config))
      |> maybe_put_option(:exp, Map.get(result, :valid_until))
      |> maybe_put_option(:nbf, Map.get(result, :valid_from))
    )
  end

  defp build_jwt_vc_credential(config, subject, credential_configuration_id, holder_jwk) do
    case invoke_build_credential!(config, subject, credential_configuration_id, holder_jwk) do
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
        keystore: Config.vc_keystore(config)
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
    case invoke_build_credential!(config, subject, credential_configuration_id, holder_jwk) do
      {:ok, %{namespaces: namespaces} = result} when is_map(namespaces) ->
        issue_mdoc_credential(config, result, holder_jwk, credential_configuration)

      other ->
        normalize_build_result(other)
    end
  end

  defp invoke_build_credential!(config, subject, credential_configuration_id, holder_jwk) do
    Config.build_credential(config, subject, credential_configuration_id, holder_jwk)
  rescue
    _error -> raise RuntimeError, @builder_failure
  catch
    _kind, _reason -> raise RuntimeError, @builder_failure
  end

  defp normalize_build_result({:error, reason}), do: {:error, reason}

  defp normalize_build_result(_other) do
    Logger.warning(@invalid_builder_result_warning)
    {:error, :invalid_credential}
  end

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
