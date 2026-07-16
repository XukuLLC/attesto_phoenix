defmodule AttestoPhoenix.AuthorizationServer.Token.Request do
  @moduledoc """
  A parsed token request, all plain data lifted at the controller edge.

  `AttestoPhoenix.Controller.TokenController` authenticates the client
  (RFC 6749 §2.3), parses the request body and the relevant `Plug.Conn` facts,
  and builds this struct so that `AttestoPhoenix.AuthorizationServer.Token` can
  process the grant against data only - never a conn.

  ## Fields

    * `:config` - the validated `%AttestoPhoenix.Config{}` carrying host policy.
    * `:client` - the authenticated client (RFC 6749 §2.3), opaque to the core.
    * `:client_auth_method` - HOW the client authenticated
      (`:client_secret_basic` / `:client_secret_post` / `:private_key_jwt`, or
      `:none` for the public-client path). The core gates confidential-only
      grants (`client_credentials`, token-exchange) on this, rejecting `:none`.
    * `:grant_type` - the requested grant type string (RFC 6749 §1.3).
    * `:params` - the request body parameters.
    * `:sender_constraint_input` - the conn-free sender-constraint facts
      (`t:AttestoPhoenix.AuthorizationServer.SenderConstraint.input/0`): the
      presented DPoP proof (RFC 9449), the presented client certificate DER
      (RFC 8705), and the canonical request URL/method the proof is bound to.
    * `:client_ip` - the request client IP for audit-event metadata, or `nil`.
    * `:request_client_id` - the authenticated OAuth `client_id` from
      `AttestoPhoenix.ClientAuthentication.Result`. It is authoritative for
      access-token `client_id` claims and is also the audit fallback when the
      host exposes no `:client_id` callback. The field name is retained for
      compatibility with direct callers that already build this struct. Direct
      callers are a trusted boundary and MUST populate it only from completed
      client authentication, never from an unverified request-body parameter.
      When omitted for backward compatibility, `Token.issue/2` resolves the
      host `:client_id` callback once before processing and never re-resolves it
      during the grant.
  """

  alias AttestoPhoenix.AuthorizationServer.SenderConstraint
  alias AttestoPhoenix.Config

  @type t :: %__MODULE__{
          config: Config.t(),
          client: term(),
          client_auth_method: :client_secret_basic | :client_secret_post | :private_key_jwt | :none,
          grant_type: String.t(),
          params: map(),
          sender_constraint_input: SenderConstraint.input(),
          client_ip: String.t() | nil,
          request_client_id: String.t() | nil
        }

  @enforce_keys [:config, :client, :client_auth_method, :grant_type, :params, :sender_constraint_input]
  defstruct [
    :config,
    :client,
    :client_auth_method,
    :grant_type,
    :params,
    :sender_constraint_input,
    :client_ip,
    :request_client_id
  ]
end
