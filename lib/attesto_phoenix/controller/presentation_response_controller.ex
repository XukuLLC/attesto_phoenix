defmodule AttestoPhoenix.Controller.PresentationResponseController do
  @moduledoc """
  Public OID4VP direct-post response endpoint.

  The endpoint accepts either an encrypted `direct_post.jwt` `response` JWE or
  the DCQL response map directly as JSON/the JSON string carried by an
  `application/x-www-form-urlencoded` `vp_token` field. This controller owns the
  HTTP framing only (`require_https`, `no-store` headers, and error rendering)
  and delegates decryption, session verification, and single-use `response_code`
  issuance to `AttestoPhoenix.Verifier.complete_presentation_response/2`.
  """

  use AttestoPhoenix.Controller, formats: [:json]

  alias AttestoPhoenix.{Config, OAuthError, RequestContext, Verifier}
  alias AttestoPhoenix.Verifier.PresentationResponse

  @doc "Verify and atomically complete an OID4VP presentation session."
  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, _params) do
    config = Config.resolve!(conn)
    conn = OAuthError.no_store(conn, config)

    with :ok <- RequestContext.check_https(conn, config),
         {:ok, response} <- PresentationResponse.from_params(Map.get(conn, :body_params)),
         {:ok, body} <- Verifier.complete_presentation_response(config, response) do
      json(conn, body)
    else
      _error -> invalid_request(conn, config)
    end
  end

  defp invalid_request(conn, config) do
    OAuthError.render(
      conn,
      OAuthError.new(:invalid_request, nil, status: 400),
      config: config
    )
  end
end
