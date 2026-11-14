defmodule AttestoPhoenix.AuthorizationServer.SubjectIdentifier do
  @moduledoc """
  The `sub` a client is shown for a resource owner (OpenID Connect Core §8), as
  conn-free core.

  A client's subject type comes from the host's `:client_subject_type`
  callback: `"public"` (the default, and the only type when the callback is
  not configured) shows the host's own subject identifier; `"pairwise"` shows
  the value `Attesto.PairwiseSubject.derive/3` computes from the client's
  sector identifier, the host subject and `:pairwise_subject_salt`.

  Every response that tells a client who the resource owner is goes through
  this module, so one client sees one `sub` for one End-User everywhere: the
  access token, ID Token, the UserInfo response, the introspection response and
  the back-channel logout token. For access tokens issued to a pairwise client,
  `access_token_opts/2` directs `Attesto.Token.mint/3` to emit the pairwise
  `sub` alongside the AES-256-GCM sealed host subject, which `verify_opts/1`
  unseals for same-deployment protected resources and introspection.

  A client resolved from a Client ID Metadata Document is always `public`.

  The sector identifier is the single host shared by the client's registered
  redirect URIs. `sector_identifier_uri` is not supported, so a pairwise
  client whose redirect URIs span hosts has no sector identifier and gets
  `{:error, :multiple_hosts}` here; callers fail closed on any error and never
  fall back to the host subject.
  """

  alias Attesto.PairwiseSubject
  alias AttestoPhoenix.AuthorizationServer.RequestPolicy
  alias AttestoPhoenix.Callback
  alias AttestoPhoenix.ClientIdMetadata
  alias AttestoPhoenix.ClientIdMetadata.Client, as: CIMDClient
  alias AttestoPhoenix.Config

  @type error ::
          :pairwise_not_configured
          | :client_unavailable
          | :no_redirect_uris
          | :invalid_redirect_uri
          | :multiple_hosts
          | :unsupported_pairwise_grant

  @pairwise_allowed_grants ~w(authorization_code refresh_token)

  @doc false
  @spec pairwise_allowed_grant_types() :: [String.t()]
  def pairwise_allowed_grant_types, do: @pairwise_allowed_grants

  @doc false
  @spec pairwise_grants_allowed?(term()) :: boolean()
  def pairwise_grants_allowed?(grant_types) when is_list(grant_types) and grant_types != [] do
    Enum.all?(grant_types, &(&1 in @pairwise_allowed_grants))
  end

  def pairwise_grants_allowed?(_grant_types), do: false

  @doc """
  Whether any client of this configuration can be pairwise: the host
  configured `:client_subject_type`.
  """
  @spec pairwise_possible?(Config.t()) :: boolean()
  def pairwise_possible?(%Config{} = config), do: not is_nil(Config.client_subject_type_fun(config))

  @doc "The subject types this configuration issues, for discovery."
  @spec subject_types_supported(Config.t()) :: [String.t()]
  def subject_types_supported(%Config{} = config) do
    if pairwise_possible?(config), do: PairwiseSubject.subject_types(), else: ["public"]
  end

  @doc """
  The subject type of a loaded `client`: `"public"` or `"pairwise"`.

  Raises `RuntimeError` when the host callback returns anything else.
  """
  @spec subject_type(Config.t(), term()) :: String.t()
  def subject_type(%Config{}, %CIMDClient{}), do: "public"

  def subject_type(%Config{} = config, client) do
    case Config.client_subject_type_fun(config) do
      nil ->
        "public"

      callback ->
        case Callback.invoke(callback, [client]) do
          type when type in ["public", :public, nil] -> "public"
          type when type in ["pairwise", :pairwise] -> "pairwise"
          _other -> raise RuntimeError, ":client_subject_type callback violated its return contract"
        end
    end
  end

  @doc """
  The `sub` to show a loaded `client` for the host's `subject`.
  """
  @spec for_client(Config.t(), term(), String.t()) :: {:ok, String.t()} | {:error, error()}
  def for_client(%Config{} = config, client, subject) when is_binary(subject) do
    case subject_type(config, client) do
      "public" -> {:ok, subject}
      "pairwise" -> pairwise(config, client, subject)
    end
  end

  @doc """
  The same, for a client known only by its `client_id`. The client is loaded
  only when a pairwise client is possible; otherwise the host subject is
  returned as is.
  """
  @spec for_client_id(Config.t(), term(), String.t()) :: {:ok, String.t()} | {:error, error()}
  def for_client_id(%Config{} = config, client_id, subject) when is_binary(subject) do
    cond do
      not pairwise_possible?(config) -> {:ok, subject}
      not (is_binary(client_id) and client_id != "") -> {:error, :client_unavailable}
      true -> load_and_derive(config, client_id, subject)
    end
  end

  defp load_and_derive(config, client_id, subject) do
    case ClientIdMetadata.load_host_client(config, client_id) do
      {:ok, client} -> for_client(config, client, subject)
      _unavailable -> {:error, :client_unavailable}
    end
  end

  defp pairwise(%Config{} = config, client, subject) do
    with {:ok, sector} <- pairwise_sector(config, client) do
      {:ok, PairwiseSubject.derive(sector, subject, config.pairwise_subject_salt)}
    end
  end

  defp pairwise_sector(%Config{pairwise_subject_salt: salt} = config, client) do
    with :ok <- check_pairwise_grants(config, client) do
      if PairwiseSubject.valid_salt?(salt) do
        sector_identifier(config, client)
      else
        {:error, :pairwise_not_configured}
      end
    end
  end

  defp check_pairwise_grants(config, client) do
    case Config.client_grant_types_fun(config) do
      nil -> :ok
      callback -> check_grant_list(Callback.invoke(callback, [client]))
    end
  end

  defp check_grant_list(grant_types) when is_list(grant_types) do
    if pairwise_grants_allowed?(grant_types) do
      :ok
    else
      {:error, :unsupported_pairwise_grant}
    end
  end

  defp check_grant_list(_other), do: :ok

  @doc """
  Extra `Attesto.Token.mint/3` options for an access token minted for `client`.
  """
  @spec access_token_opts(Config.t(), term()) :: {:ok, keyword()} | {:error, error()}
  def access_token_opts(%Config{} = config, client) do
    case subject_type(config, client) do
      "public" ->
        {:ok, []}

      "pairwise" ->
        with {:ok, sector} <- pairwise_sector(config, client) do
          {:ok, [pairwise: {sector, config.pairwise_subject_salt}]}
        end
    end
  end

  @doc """
  Extra `Attesto.Token.verify/3` options needed to unseal pairwise access tokens
  under `config`.
  """
  @spec verify_opts(Config.t()) :: keyword()
  def verify_opts(%Config{} = config) do
    if pairwise_possible?(config) and PairwiseSubject.valid_salt?(config.pairwise_subject_salt) do
      [pairwise_subject_salt: config.pairwise_subject_salt]
    else
      []
    end
  end

  @doc """
  The client's sector identifier: the one host its registered redirect URIs
  share (OIDC Core §8.1).
  """
  @spec sector_identifier(Config.t(), term()) :: {:ok, String.t()} | {:error, error()}
  def sector_identifier(%Config{} = config, client) do
    config |> RequestPolicy.registered_redirect_uris(client) |> PairwiseSubject.sector_identifier()
  end
end
