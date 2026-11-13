defmodule AttestoPhoenix.Controller.PresentationResponseController do
  @moduledoc """
  OID4VP response endpoints for wallet direct POST and DC API page submissions.

  `create_dc_api/2` accepts the page's `DigitalCredential.data` object at a
  session-specific URL and returns a single-use `response_code`. The page's
  origin is configured at boot; HTTP origin headers and body fields never
  select the verification context. Hosts must bind creation, submission, and
  result consumption to their initiating browser session and apply CSRF
  protection to their browser integration.

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

  @doc "Verify the encrypted DC API response posted back by the initiating page."
  @spec create_dc_api(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create_dc_api(conn, %{"id" => id}) do
    config = Config.resolve!(conn)
    conn = OAuthError.no_store(conn, config)

    with :ok <- RequestContext.check_https(conn, config),
         {:ok, body} <- Verifier.complete_dc_api_response(config, id, Map.get(conn, :body_params)) do
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
