defmodule AttestoPhoenix.Revocation do
  @moduledoc """
  Cut off a subject, a client, or a session: delete their unredeemed
  authorization codes and revoke their refresh-token families.

      Repo.transaction(fn ->
        MyApp.Accounts.disable!(user)
        {:ok, _counts} = AttestoPhoenix.Revocation.revoke_subject(config, user.id)
      end)

  Each function calls the configured `:code_store`'s
  `c:Attesto.CodeStore.delete_unclaimed/1` and the configured
  `:refresh_store`'s `c:Attesto.RefreshStore.revoke_families/1`. With the
  bundled Ecto stores both run on the configured repo and open no outer
  transaction of their own, so a call made inside the host's transaction
  commits or rolls back with it. Put the call in the same transaction as the
  change that makes the subject or client ineligible; otherwise a grant issued
  between the two is missed.

  ## Lock order

  Lock authorization-code rows before refresh families. The bundled stores
  then lock families in ascending family-id order and rows in ascending id
  order within each family, taking the family advisory lock before its rows.
  Hosts combining these operations must use the same order, including across
  multiple calls in one transaction. Scheduled sweeps release each step's
  locks before the next step. `Sweeper.sweep_once/2` instead remains inside
  the caller's transaction; do not run it concurrently with grant writes.

  ## What is and is not revoked

    * Unredeemed authorization codes are deleted; redeeming one afterwards
      fails as an unknown code.
    * Refresh-token families are revoked for good: every token removed and the
      family marked so no successor can be inserted.
    * Access tokens already issued are **not** revoked. A self-contained JWT
      access token stays valid until it expires unless the protected resource
      consults introspection or a denylist. Keep `:access_token_ttl` short, or
      have the resource check the subject's status, when immediate cut-off
      matters.

  ## Stores

  A store that is not configured contributes `0`. A configured store that does
  not implement the callback raises `ArgumentError`: reporting success while
  that store's grants stay live would be worse than failing.
  """

  alias Attesto.RevocationCriteria
  alias AttestoPhoenix.AuthorizationServer.Token
  alias AttestoPhoenix.Callback
  alias AttestoPhoenix.Config

  @type counts :: %{
          codes: non_neg_integer(),
          device_codes: non_neg_integer(),
          ciba_requests: non_neg_integer(),
          pre_authorized_codes: non_neg_integer(),
          refresh_families: non_neg_integer()
        }

  @store_specs [
    {:code_store, :delete_unclaimed},
    {:device_code_store, :delete_unconsumed},
    {:ciba_store, :delete_unconsumed},
    {:pre_authorized_code_store, :delete_unconsumed},
    {:refresh_store, :revoke_families}
  ]

  @doc """
  Delete the unredeemed codes and revoke the refresh families issued for
  `subject`, to any client.
  """
  @spec revoke_subject(Config.t(), String.t()) :: {:ok, counts()}
  def revoke_subject(%Config{} = config, subject), do: revoke(config, subject: subject)

  @doc """
  Delete the unredeemed codes and revoke the refresh families issued to
  `client_id`, for any subject.
  """
  @spec revoke_client(Config.t(), String.t()) :: {:ok, counts()}
  def revoke_client(%Config{} = config, client_id), do: revoke(config, client_id: client_id)

  @doc """
  Delete the unredeemed codes and revoke the refresh families issued under the
  host session `sid` (the `:sid` the host's authentication callback returned).
  """
  @spec revoke_session(Config.t(), String.t()) :: {:ok, counts()}
  def revoke_session(%Config{} = config, sid), do: revoke(config, sid: sid)

  @doc """
  The general form: `criteria` is a keyword list of `:subject`, `:client_id`
  and/or `:sid`, ANDed (see `Attesto.RevocationCriteria`).
  """
  @spec revoke(Config.t(), RevocationCriteria.criteria()) :: {:ok, counts()}
  def revoke(%Config{} = config, criteria) do
    # Validate criteria and every configured store callback up front so a fault
    # in a later store can never leave earlier stores partially revoked.
    _validated = RevocationCriteria.new!(criteria)
    stores = validate_stores!(config)

    Config.with_request_config(config, fn ->
      {:ok, codes} = invoke_store(stores[:code_store], :delete_unclaimed, criteria)
      {:ok, device_codes} = invoke_store(stores[:device_code_store], :delete_unconsumed, criteria)
      {:ok, ciba_requests} = invoke_store(stores[:ciba_store], :delete_unconsumed, criteria)
      {:ok, pre_authorized_codes} = invoke_store(stores[:pre_authorized_code_store], :delete_unconsumed, criteria)

      # A refresh context records the session under this module's own key, not
      # the code's `sid` claim.
      {:ok, families} = invoke_store(stores[:refresh_store], :revoke_families, refresh_criteria(criteria))

      {:ok,
       %{
         codes: codes,
         device_codes: device_codes,
         ciba_requests: ciba_requests,
         pre_authorized_codes: pre_authorized_codes,
         refresh_families: families
       }}
    end)
  end

  defp refresh_criteria(criteria) do
    if Keyword.has_key?(criteria, :sid) and not Keyword.has_key?(criteria, :sid_claim),
      do: Keyword.put(criteria, :sid_claim, Token.refresh_session_id_claim()),
      else: criteria
  end

  defp validate_stores!(config) do
    Map.new(@store_specs, fn {store_key, function} ->
      {store_key, validated_store!(config, store_key, function)}
    end)
  end

  defp validated_store!(config, store_key, function) do
    case Callback.config_callback(config, store_key) do
      nil ->
        nil

      store ->
        if Code.ensure_loaded?(store) and function_exported?(store, function, 1) do
          store
        else
          raise ArgumentError,
                "AttestoPhoenix.Revocation: #{inspect(store_key)} #{inspect(store)} does not implement " <>
                  "#{function}/1, so its grants cannot be revoked by criteria."
        end
    end
  end

  defp invoke_store(nil, _function, _criteria), do: {:ok, 0}
  defp invoke_store(store, function, criteria), do: apply(store, function, [criteria])
end
