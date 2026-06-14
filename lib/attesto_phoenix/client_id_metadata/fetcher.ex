defmodule AttestoPhoenix.ClientIdMetadata.Fetcher do
  @moduledoc """
  Behaviour for dereferencing a Client ID Metadata Document URL - CIMD
  (`draft-ietf-oauth-client-id-metadata-document-01`, IETF OAuth WG).

  CIMD lets a client identify itself with no prior registration by using an
  HTTPS URL as its `client_id`; the authorization server dereferences that URL
  to fetch a JSON client metadata document. This behaviour is the single,
  pluggable seam through which that outbound `GET` is made. Everything else in
  the feature - URL grammar (`Attesto.ClientIdMetadata.validate_client_id/1`),
  document validation (`Attesto.ClientIdMetadata.validate_document/2`), and
  caching - is HTTP-free; the fetcher is the only component that touches a
  socket, so it is also where the draft's Security Considerations live.

  The default implementation, `AttestoPhoenix.ClientIdMetadata.Fetcher.Req`,
  performs the SSRF-guarded fetch the draft mandates: it re-validates the URL,
  resolves the host, rejects any special-use (RFC 6890) address, pins the
  connection to a validated IP to close the DNS-rebinding TOCTOU, refuses
  redirects, requires `200 OK` with a JSON content type, and caps the body.
  A host may supply its own implementation instead - for example one that calls
  a CIMD proxy service (recommended by the draft for development) or that drives
  the host's own HTTP stack - by configuring the `:fetcher` module under
  `AttestoPhoenix.Config`'s `:client_id_metadata` key.

  ## Contract

  `fetch/2` receives the already-validated CIMD `client_id` URL and a keyword
  list of options (`:resolver`, `:allow_loopback`, `:max_document_bytes`,
  `:request_timeout_ms` - see `AttestoPhoenix.ClientIdMetadata.Fetcher.Req` for
  the ones the default honors). It returns:

    * `{:ok, %{body: binary(), cache_control: keyword()}}` on a successful
      fetch - `body` is the raw JSON document (still to be decoded and validated
      by the caller, never trusted here), and `cache_control` is the parsed
      HTTP freshness directives (`RFC 9111`) the caller clamps and stores; or
    * `{:error, reason}` for any failure. An implementation MUST error closed:
      an unresolvable host, a special-use address, a non-`200` status, any
      redirect, a non-JSON content type, an over-size body, or a transport
      error all yield `{:error, reason}` and never a partial `{:ok, _}`.

  The caller MUST NOT cache an `{:error, _}` result (draft §6 / RFC 9111).
  """

  @typedoc """
  A successful fetch: the raw (undecoded, untrusted) document body and the
  parsed HTTP cache-control directives (`RFC 9111`) for the caller to clamp.
  """
  @type result :: %{body: binary(), cache_control: keyword()}

  @doc """
  Dereference a validated CIMD `client_id` URL.

  Returns `{:ok, %{body: body, cache_control: directives}}` on a `200 OK` JSON
  response within the size cap, or `{:error, reason}` for any other outcome.
  Implementations MUST honor the draft's Security Considerations (no redirects,
  no special-use addresses, body cap) and error closed.
  """
  @callback fetch(url :: String.t(), opts :: keyword()) ::
              {:ok, result()} | {:error, term()}
end
