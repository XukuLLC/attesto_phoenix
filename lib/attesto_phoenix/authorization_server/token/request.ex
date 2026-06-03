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
    * `:grant_type` - the requested grant type string (RFC 6749 §1.3).
    * `:params` - the request body parameters.
    * `:sender_constraint_input` - the conn-free sender-constraint facts
      (`t:AttestoPhoenix.AuthorizationServer.SenderConstraint.input/0`): the
      presented DPoP proof (RFC 9449), the presented client certificate DER
      (RFC 8705), and the canonical request URL/method the proof is bound to.
    * `:client_ip` - the request client IP for audit-event metadata, or `nil`.
    * `:request_client_id` - the `client_id` derived from the request body or
      the Basic credentials, used as the denial-event `client_id` fallback when
      the host exposes no `:client_id` callback.
  """

  alias AttestoPhoenix.AuthorizationServer.SenderConstraint
  alias AttestoPhoenix.Config

  @type t :: %__MODULE__{
          config: Config.t(),
          client: term(),
          grant_type: String.t(),
          params: map(),
          sender_constraint_input: SenderConstraint.input(),
          client_ip: String.t() | nil,
          request_client_id: String.t() | nil
        }

  @enforce_keys [:config, :client, :grant_type, :params, :sender_constraint_input]
  defstruct [
    :config,
    :client,
    :grant_type,
    :params,
    :sender_constraint_input,
    :client_ip,
    :request_client_id
  ]
end
