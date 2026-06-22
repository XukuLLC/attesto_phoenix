defmodule AttestoPhoenix.OpenAPI.TokenEndpointTest do
  use ExUnit.Case, async: true

  alias AttestoPhoenix.OpenAPI.TokenEndpoint
  alias OpenApiSpex.{Header, MediaType, Operation, Parameter, Reference, RequestBody, Response, Schema}

  @form_urlencoded "application/x-www-form-urlencoded"
  @json "application/json"

  test "operation returns a reusable token endpoint operation" do
    operation = TokenEndpoint.operation(tags: ["Auth"], operation_id: "oauthToken")

    assert %Operation{
             tags: ["Auth"],
             operationId: "oauthToken",
             summary: "Issue an OAuth access token",
             requestBody: %RequestBody{},
             responses: %{200 => %Response{}, 400 => %Response{}, 401 => %Response{}}
           } = operation

    assert [
             %Parameter{
               name: :DPoP,
               in: :header,
               required: false,
               schema: %Schema{type: :string}
             }
           ] = operation.parameters

    assert %MediaType{schema: %Reference{"$ref": "#/components/schemas/AttestoTokenClientCredentialsRequest"}} =
             operation.requestBody.content[@form_urlencoded]

    assert %MediaType{schema: %Reference{"$ref": "#/components/schemas/AttestoTokenClientCredentialsRequest"}} =
             operation.requestBody.content[@json]
  end

  test "client_credentials request schema documents form credentials and scope" do
    request = TokenEndpoint.schemas()["AttestoTokenClientCredentialsRequest"]

    assert %Schema{
             type: :object,
             required: [:grant_type],
             properties: properties
           } = request

    assert %Schema{type: :string, enum: ["client_credentials"]} = properties.grant_type
    assert %Schema{type: :string} = properties.scope
    assert %Schema{type: :string} = properties.client_id
    assert %Schema{type: :string, writeOnly: true} = properties.client_secret

    assert %Schema{
             type: :string,
             enum: ["urn:ietf:params:oauth:client-assertion-type:jwt-bearer"]
           } = properties.client_assertion_type

    assert %Schema{type: :string, writeOnly: true} = properties.client_assertion
  end

  test "success response schema covers Bearer and DPoP token responses" do
    schemas = TokenEndpoint.schemas()

    assert %Schema{
             oneOf: [
               %Reference{"$ref": "#/components/schemas/AttestoBearerTokenResponse"},
               %Reference{"$ref": "#/components/schemas/AttestoDPoPTokenResponse"}
             ]
           } = schemas["AttestoTokenResponse"]

    assert %Schema{
             required: [:access_token, :token_type],
             properties: bearer_properties
           } = schemas["AttestoBearerTokenResponse"]

    assert %Schema{enum: ["Bearer"]} = bearer_properties.token_type

    assert %Schema{
             required: [:access_token, :token_type, :cnf],
             properties: dpop_properties
           } = schemas["AttestoDPoPTokenResponse"]

    assert %Schema{enum: ["DPoP"]} = dpop_properties.token_type
    assert %Schema{properties: %{jkt: %Schema{type: :string}}} = dpop_properties.cnf
  end

  test "error responses document OAuth and DPoP errors plus challenge headers" do
    error_schema = TokenEndpoint.schemas()["AttestoTokenError"]
    error_codes = error_schema.properties.error.enum

    assert "invalid_request" in error_codes
    assert "invalid_client" in error_codes
    assert "invalid_dpop_proof" in error_codes
    assert "use_dpop_nonce" in error_codes

    responses = TokenEndpoint.responses()

    assert %Response{
             content: %{@json => %MediaType{schema: %Reference{"$ref": "#/components/schemas/AttestoTokenError"}}},
             headers: %{"DPoP-Nonce" => %Header{schema: %Schema{type: :string}}}
           } = responses[400]

    assert %Response{
             headers: %{
               "WWW-Authenticate" => %Header{schema: %Schema{type: :string}},
               "DPoP-Nonce" => %Header{schema: %Schema{type: :string}}
             }
           } = responses[401]
  end
end
