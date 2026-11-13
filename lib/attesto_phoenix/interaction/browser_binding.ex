defmodule AttestoPhoenix.Interaction.BrowserBinding do
  @moduledoc """
  Keep a random browser binding in the host session for interaction park/resume.

  Mount after the session has been fetched and before the authorize route:

      pipeline :browser do
        plug :fetch_session
        plug AttestoPhoenix.Interaction.BrowserBinding
      end

  Configure `:interaction_browser_binding` with
  `&AttestoPhoenix.Interaction.BrowserBinding.binding/1` (or the equivalent MFA
  callback). The plug generates a 32-byte secret using `Attesto.Secret` when
  the session has no binding; later calls keep the existing value. `binding/1`
  only reads it, so a callback cannot silently create a different binding.

  Preserve this value through the host's login. Plug's
  `configure_session(conn, renew: true)` keeps the session data while renewing
  the session; `drop: true` discards it. If the value is lost, the next browser
  request gets a different binding and resume is refused through the
  wrong-browser path, spending the parked request. The browser must start a
  new authorization request.
  """

  @behaviour Plug

  import Kernel, except: [binding: 1]

  alias Attesto.Secret
  alias Plug.Conn

  @session_key :attesto_phoenix_interaction_browser_binding

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(conn, _opts) do
    case binding(conn) do
      value when is_binary(value) and value != "" -> conn
      _absent -> Conn.put_session(conn, @session_key, Secret.generate(32))
    end
  end

  @doc """
  Read the browser binding from the fetched session, or return `nil` if absent.

  Use as the `:interaction_browser_binding` callback. Mount this plug before
  the authorize route so the binding is present before the first park.
  """
  @spec binding(Conn.t()) :: String.t() | nil
  def binding(conn), do: Conn.get_session(conn, @session_key)
end
