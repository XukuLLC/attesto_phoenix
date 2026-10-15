defmodule AttestoPhoenix.CredentialIssuer do
  @moduledoc false

  import AttestoPhoenix.Controller.OID4VCIHelpers, only: [maybe_put_option: 3]

  alias Attesto.{Key, MapParams, Mdoc, SdJwtVc, SigningAlg}
  alias AttestoPhoenix.Config

  @sd_jwt_vc_formats ~w(vc+sd-jwt dc+sd-jwt)
  @credential_formats @sd_jwt_vc_formats ++ ["jwt_vc_json", "mso_mdoc"]

  @spec issue(Config.t(), String.t(), String.t(), map(), map()) ::
          {:ok, String.t()} | {:error, atom()}
  def issue(%Config{} = config, subject, credential_configuration_id, holder_jwk, result)
      when is_binary(subject) and subject != "" and is_binary(credential_configuration_id) and
             credential_configuration_id != "" and is_map(holder_jwk) and is_map(result) do
    with {:ok, configuration} <- credential_configuration(config, credential_configuration_id),
         {:ok, holder_jwk} <- public_holder_jwk(holder_jwk),
         format when is_binary(format) <- configuration_value(configuration, :format),
         :ok <- validate_holder_for_format(holder_jwk, format) do
      issue_format(config, subject, format, configuration, holder_jwk, result)
    else
      {:error, _reason} = error -> error
      _invalid -> {:error, :invalid_credential}
    end
  rescue
    _error -> {:error, :invalid_credential}
  catch
    _kind, _reason -> {:error, :invalid_credential}
  end

  def issue(%Config{}, _subject, _credential_configuration_id, _holder_jwk, _result), do: {:error, :invalid_credential}

  @doc false
  @spec validate_configuration(Config.t(), String.t()) :: :ok | {:error, atom()}
  def validate_configuration(%Config{} = config, credential_configuration_id)
      when is_binary(credential_configuration_id) and credential_configuration_id != "" do
    with {:ok, configuration} <- credential_configuration(config, credential_configuration_id),
         format when format in @credential_formats <-
           configuration_value(configuration, :format) do
      :ok
    else
      {:error, _reason} = error -> error
      _invalid -> {:error, :unsupported_credential_format}
    end
  end

  def validate_configuration(%Config{}, _credential_configuration_id),
    do: {:error, :unsupported_credential_configuration}

  defp issue_format(config, _subject, format, _configuration, holder_jwk, %{vct: vct, claims: claims} = result)
       when format in @sd_jwt_vc_formats and is_binary(vct) and vct != "" and is_map(claims) do
    with :ok <- validate_optional_numeric_dates(result) do
      credential =
        SdJwtVc.issue(
          [iss: config.issuer, vct: vct, keystore: Config.vc_keystore(config)],
          [claims: claims, cnf: %{"jwk" => holder_jwk}, typ: format]
          |> maybe_put_option(:x5c, Config.vc_signing_x5c(config))
          |> maybe_put_option(:iat, Map.get(result, :issued_at))
          |> maybe_put_option(:exp, Map.get(result, :valid_until))
          |> maybe_put_option(:nbf, Map.get(result, :valid_from))
        )

      {:ok, credential}
    end
  end

  defp issue_format(
         config,
         subject,
         "jwt_vc_json",
         _configuration,
         holder_jwk,
         %{credential_type: credential_type, claims: claims} = result
       )
       when is_binary(credential_type) and credential_type != "" and is_map(claims) do
    with :ok <- validate_optional_numeric_dates(result) do
      credential =
        Attesto.JwtVc.issue(
          [iss: config.issuer, sub: subject, keystore: Config.vc_keystore(config)],
          [
            type: ["VerifiableCredential", credential_type],
            claims: claims,
            cnf: %{"jwk" => holder_jwk}
          ]
          |> maybe_put_option(:exp, Map.get(result, :valid_until))
          |> maybe_put_option(:nbf, Map.get(result, :valid_from))
        )

      {:ok, credential}
    end
  end

  defp issue_format(config, _subject, "mso_mdoc", configuration, holder_jwk, %{namespaces: namespaces} = result)
       when is_map(namespaces) do
    now = System.system_time(:second)
    doc_type = Map.get(result, :doc_type) || configuration_doc_type(configuration)

    with {:ok, issuer_pem} <- mdoc_signing_pem(config),
         {:ok, x5chain} <- mdoc_signing_chain(Config.vc_signing_x5c(config)) do
      with :ok <- validate_mdoc_validity(result, now),
           true <- is_binary(doc_type) and doc_type != "" do
        Mdoc.issue(
          doc_type: doc_type,
          namespaces: namespaces,
          device_key: holder_jwk,
          issuer_pem: issuer_pem,
          x5chain: x5chain,
          validity: %{
            signed: Map.get(result, :issued_at, now),
            valid_from: Map.get(result, :valid_from, now),
            valid_until: Map.fetch!(result, :valid_until)
          }
        )
      else
        false -> {:error, :invalid_credential}
        {:error, _reason} = error -> error
      end
    else
      {:error, _reason} = error -> error
    end
  end

  defp issue_format(_config, _subject, _format, _configuration, _holder_jwk, _result), do: {:error, :invalid_credential}

  defp public_holder_jwk(holder_jwk) do
    with {:ok, alg} <- holder_algorithm(holder_jwk),
         {:ok, jwk} <- Key.verification_jwk(holder_jwk, alg: alg) do
      {_key_type, public_jwk} = JOSE.JWK.to_public_map(jwk)
      {:ok, public_jwk}
    else
      _invalid -> {:error, :invalid_holder_key}
    end
  end

  defp holder_algorithm(%{"alg" => alg}) when is_binary(alg) and alg != "", do: {:ok, alg}
  defp holder_algorithm(%{"kty" => "RSA"}), do: {:ok, "RS256"}
  defp holder_algorithm(%{"kty" => "EC", "crv" => "P-256"}), do: {:ok, "ES256"}
  defp holder_algorithm(%{"kty" => "EC", "crv" => "P-384"}), do: {:ok, "ES384"}
  defp holder_algorithm(%{"kty" => "EC", "crv" => "P-521"}), do: {:ok, "ES512"}
  defp holder_algorithm(%{"kty" => "OKP", "crv" => "Ed25519"}), do: {:ok, "EdDSA"}
  defp holder_algorithm(%{"kty" => "OKP", "crv" => "Ed448"}), do: {:ok, "EdDSA"}
  defp holder_algorithm(_holder_jwk), do: {:error, :invalid_holder_key}

  defp validate_holder_for_format(%{"kty" => "EC", "crv" => "P-256"}, "mso_mdoc"), do: :ok
  defp validate_holder_for_format(_holder_jwk, "mso_mdoc"), do: {:error, :invalid_holder_key}
  defp validate_holder_for_format(_holder_jwk, format) when format in @sd_jwt_vc_formats, do: :ok
  defp validate_holder_for_format(_holder_jwk, "jwt_vc_json"), do: :ok
  defp validate_holder_for_format(_holder_jwk, _format), do: {:error, :unsupported_credential_format}

  defp validate_optional_numeric_dates(result) do
    if Enum.all?([:issued_at, :valid_from, :valid_until], &valid_optional_numeric_date?(result, &1)) do
      :ok
    else
      {:error, :invalid_credential}
    end
  end

  defp valid_optional_numeric_date?(result, key) do
    case Map.fetch(result, key) do
      :error -> true
      {:ok, value} -> is_integer(value) and value >= 0
    end
  end

  defp validate_mdoc_validity(result, now) do
    signed = Map.get(result, :issued_at, now)
    valid_from = Map.get(result, :valid_from, now)

    result
    |> Map.fetch(:valid_until)
    |> validate_mdoc_window(signed, valid_from)
  end

  defp validate_mdoc_window({:ok, valid_until}, signed, valid_from)
       when is_integer(signed) and signed >= 0 and is_integer(valid_from) and valid_from >= 0 and
              is_integer(valid_until) and valid_until >= 0 and signed <= valid_from and valid_from < valid_until,
       do: :ok

  defp validate_mdoc_window(_valid_until, _signed, _valid_from), do: {:error, :invalid_credential}

  defp mdoc_signing_chain(nil), do: {:ok, nil}
  defp mdoc_signing_chain([]), do: {:ok, nil}

  defp mdoc_signing_chain(chain) when is_list(chain) do
    Enum.reduce_while(chain, {:ok, []}, fn
      certificate, {:ok, certificates} when is_binary(certificate) ->
        case Base.decode64(certificate) do
          {:ok, der} when byte_size(der) > 0 -> {:cont, {:ok, [der | certificates]}}
          _other -> {:halt, {:error, :invalid_credential}}
        end

      _certificate, _acc ->
        {:halt, {:error, :invalid_credential}}
    end)
    |> case do
      {:ok, certificates} -> {:ok, Enum.reverse(certificates)}
      error -> error
    end
  end

  defp mdoc_signing_chain(_chain), do: {:error, :invalid_credential}

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
end
