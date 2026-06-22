if Code.ensure_loaded?(OpenApiSpex) do
  defmodule AttestoPhoenix.OpenAPI.TokenEndpoint do
    @moduledoc """
    OpenApiSpex operation and schema values for the OAuth 2.0 token endpoint.

    This module is available only when the host depends on `:open_api_spex`.
    `attesto_phoenix` declares that dependency as optional, so authorization
    servers that do not publish an OpenAPI document do not compile or ship
    OpenApiSpex.

    The first documented request is the RFC 6749 §4.4 `client_credentials`
    exchange, because it is the common machine-to-machine token endpoint
    integration. The response and error schemas cover Bearer tokens, DPoP-bound
    tokens, and the OAuth / DPoP error envelope emitted by
    `AttestoPhoenix.Controller.TokenController`.

    ## Host wiring

    Add `operation/1` to the host's `OpenApiSpex.PathItem` for `POST
    /oauth/token` and merge `schemas/0` into the host's components.
    """

    alias OpenApiSpex.{Header, MediaType, Operation, Parameter, Reference, RequestBody, Response, Schema}

    @form_urlencoded "application/x-www-form-urlencoded"
    @json "application/json"

    @request_schema "AttestoTokenClientCredentialsRequest"
    @token_response_schema "AttestoTokenResponse"
    @bearer_response_schema "AttestoBearerTokenResponse"
    @dpop_response_schema "AttestoDPoPTokenResponse"
    @error_schema "AttestoTokenError"

    @doc """
    Returns the OpenApiSpex operation for `POST /oauth/token`.

    Options:

      * `:tags` - operation tags, defaulting to `["OAuth 2.0"]`.
      * `:operation_id` - operation id, defaulting to
        `"attestoPhoenixTokenCreate"`.
      * `:summary` - summary text.
      * `:description` - description text.
      * `:security` - OpenAPI security requirements supplied by the host.

    The operation intentionally does not name host security-scheme components.
    Client authentication is described in the request body and prose, while a
    host that defines HTTP Basic or other client-auth security schemes can pass
    `security: ...`.
    """
    @spec operation(keyword()) :: Operation.t()
    def operation(opts \\ []) do
      %Operation{
        tags: Keyword.get(opts, :tags, ["OAuth 2.0"]),
        operationId: Keyword.get(opts, :operation_id, "attestoPhoenixTokenCreate"),
        summary: Keyword.get(opts, :summary, "Issue an OAuth access token"),
        description: Keyword.get(opts, :description, operation_description()),
        parameters: [dpop_header_parameter()],
        requestBody: request_body(),
        responses: responses(),
        security: Keyword.get(opts, :security)
      }
    end

    @doc """
    Returns reusable component schemas referenced by `operation/1`.
    """
    @spec schemas() :: %{String.t() => Schema.t()}
    def schemas do
      %{
        @request_schema => client_credentials_request_schema(),
        @token_response_schema => token_response_schema(),
        @bearer_response_schema => bearer_token_response_schema(),
        @dpop_response_schema => dpop_token_response_schema(),
        @error_schema => token_error_schema()
      }
    end

    @doc """
    Returns the token request body for the media types accepted by the token
    controller.
    """
    @spec request_body() :: RequestBody.t()
    def request_body do
      %RequestBody{
        description: "OAuth 2.0 token request body (RFC 6749 §3.2).",
        required: true,
        content: %{
          @form_urlencoded => %MediaType{schema: schema_ref(@request_schema)},
          @json => %MediaType{schema: schema_ref(@request_schema)}
        }
      }
    end

    @doc """
    Returns token endpoint responses keyed by HTTP status.
    """
    @spec responses() :: %{integer() => Response.t()}
    def responses do
      %{
        200 => token_success_response(),
        400 => token_error_response("OAuth token endpoint error.", %{"DPoP-Nonce" => dpop_nonce_header()}),
        401 =>
          token_error_response("Client authentication or DPoP challenge.", %{
            "WWW-Authenticate" => www_authenticate_header(),
            "DPoP-Nonce" => dpop_nonce_header()
          })
      }
    end

    defp operation_description do
      """
      Issues an OAuth 2.0 access token. This operation documents the
      `client_credentials` grant request, including HTTP Basic client
      authentication, body client credentials, `private_key_jwt`, optional
      `scope`, and an optional DPoP proof header.
      """
    end

    defp dpop_header_parameter do
      %Parameter{
        name: :DPoP,
        in: :header,
        required: false,
        description: "DPoP proof JWT for sender-constrained token requests (RFC 9449 §4.2).",
        schema: %Schema{type: :string}
      }
    end

    defp token_success_response do
      %Response{
        description: "Access token response (RFC 6749 §5.1; RFC 9449 for DPoP).",
        content: %{
          @json => %MediaType{schema: schema_ref(@token_response_schema)}
        }
      }
    end

    defp token_error_response(description, headers) do
      %Response{
        description: description,
        headers: headers,
        content: %{
          @json => %MediaType{schema: schema_ref(@error_schema)}
        }
      }
    end

    defp client_credentials_request_schema do
      %Schema{
        title: @request_schema,
        type: :object,
        required: [:grant_type],
        properties: %{
          grant_type: %Schema{
            type: :string,
            enum: ["client_credentials"],
            description: "OAuth grant type for RFC 6749 §4.4."
          },
          scope: %Schema{
            type: :string,
            description: "Space-delimited requested scope values (RFC 6749 §3.3)."
          },
          client_id: %Schema{
            type: :string,
            description: "Client identifier when using body client authentication."
          },
          client_secret: %Schema{
            type: :string,
            writeOnly: true,
            description: "Client secret when using client_secret_post."
          },
          client_assertion_type: %Schema{
            type: :string,
            enum: ["urn:ietf:params:oauth:client-assertion-type:jwt-bearer"],
            description: "Client assertion type for private_key_jwt."
          },
          client_assertion: %Schema{
            type: :string,
            writeOnly: true,
            description: "Signed client assertion JWT for private_key_jwt."
          }
        },
        example: %{
          "grant_type" => "client_credentials",
          "scope" => "read",
          "client_id" => "client-123",
          "client_secret" => "secret"
        }
      }
    end

    defp token_response_schema do
      %Schema{
        title: @token_response_schema,
        oneOf: [
          schema_ref(@bearer_response_schema),
          schema_ref(@dpop_response_schema)
        ]
      }
    end

    defp bearer_token_response_schema do
      %Schema{
        title: @bearer_response_schema,
        type: :object,
        required: [:access_token, :token_type],
        properties: token_response_properties("Bearer"),
        example: %{
          "access_token" => "eyJhbGciOi...",
          "token_type" => "Bearer",
          "expires_in" => 3600,
          "scope" => "read"
        }
      }
    end

    defp dpop_token_response_schema do
      %Schema{
        title: @dpop_response_schema,
        type: :object,
        required: [:access_token, :token_type, :cnf],
        properties:
          Map.put(token_response_properties("DPoP"), :cnf, %Schema{
            type: :object,
            required: [:jkt],
            properties: %{
              jkt: %Schema{
                type: :string,
                description: "JWK SHA-256 thumbprint binding the token to the DPoP proof key."
              }
            }
          }),
        example: %{
          "access_token" => "eyJhbGciOi...",
          "token_type" => "DPoP",
          "expires_in" => 3600,
          "scope" => "read",
          "cnf" => %{"jkt" => "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"}
        }
      }
    end

    defp token_response_properties(token_type) do
      %{
        access_token: %Schema{
          type: :string,
          description: "Issued access token."
        },
        token_type: %Schema{
          type: :string,
          enum: [token_type],
          description: "Token type returned by the authorization server."
        },
        expires_in: %Schema{
          type: :integer,
          minimum: 0,
          description: "Lifetime in seconds."
        },
        scope: %Schema{
          type: :string,
          description: "Space-delimited granted scope values."
        }
      }
    end

    defp token_error_schema do
      %Schema{
        title: @error_schema,
        type: :object,
        required: [:error],
        properties: %{
          error: %Schema{
            type: :string,
            enum: [
              "invalid_request",
              "invalid_client",
              "invalid_grant",
              "unauthorized_client",
              "unsupported_grant_type",
              "invalid_scope",
              "server_error",
              "temporarily_unavailable",
              "invalid_dpop_proof",
              "use_dpop_nonce"
            ],
            description: "OAuth 2.0 / DPoP error code."
          },
          error_description: %Schema{
            type: :string,
            description: "Human-readable diagnostic message."
          }
        },
        example: %{
          "error" => "invalid_request",
          "error_description" => "grant_type must be sent in the request body, not the query string"
        }
      }
    end

    defp www_authenticate_header do
      %Header{
        description: "Client-authentication challenge for 401 errors.",
        schema: %Schema{type: :string}
      }
    end

    defp dpop_nonce_header do
      %Header{
        description: "Fresh nonce returned with `use_dpop_nonce` (RFC 9449 §8).",
        schema: %Schema{type: :string}
      }
    end

    defp schema_ref(name), do: %Reference{"$ref": "#/components/schemas/#{name}"}
  end
end
