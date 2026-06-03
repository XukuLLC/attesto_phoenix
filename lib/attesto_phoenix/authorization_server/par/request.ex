defmodule AttestoPhoenix.AuthorizationServer.PAR.Request do
  @moduledoc """
  A parsed Pushed Authorization Request (RFC 9126), all plain data lifted at
  the controller edge.

  `AttestoPhoenix.Controller.PARController` authenticates the client
  (RFC 6749 §2.3), parses the request body and the relevant `Plug.Conn` facts,
  and builds this struct so that `AttestoPhoenix.AuthorizationServer.PAR` can
  store the request against data only - never a conn.

  ## Fields

    * `:client` - the authenticated client (RFC 6749 §2.3), opaque to the core.
      The stored record's `client_id` is resolved from it through the host's
      `:client_id` callback, never trusted from the request body.
    * `:params` - the submitted authorization request parameters (RFC 9126 §2.1
      / RFC 6749 §4.1.1). Client-authentication credentials are stripped before
      storage; everything else is kept opaque for the authorization endpoint to
      validate when the `request_uri` is later resolved.
    * `:dpop_input` - the conn-free DPoP facts the controller lifts off the
      request: the presented `DPoP` request-header value(s) (RFC 9449 §4.1), and
      the canonical request URL/method the proof is bound to (RFC 9449 §4.2 /
      §4.3). See `t:AttestoPhoenix.AuthorizationServer.PAR.dpop_input/0`.
  """

  alias AttestoPhoenix.AuthorizationServer.PAR

  @type t :: %__MODULE__{
          client: term(),
          params: map(),
          dpop_input: PAR.dpop_input()
        }

  @enforce_keys [:client, :params, :dpop_input]
  defstruct [:client, :params, :dpop_input]
end
