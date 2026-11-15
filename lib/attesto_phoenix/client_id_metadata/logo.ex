if Code.ensure_loaded?(Req) do
  defmodule AttestoPhoenix.ClientIdMetadata.Logo do
    @moduledoc """
    SSRF-guarded `logo_uri` prefetch and image validation (`draft-ietf-oauth-client-id-metadata-document-03` §10.9).

    Authorization servers that wish to display a CIMD client's `logo_uri` to an
    end-user MUST prefetch the image and serve it from a trusted origin rather
    than linking directly to the client's `logo_uri`, and MUST verify that the
    downloaded bytes are a valid image.

    Supports raster formats (`image/png`, `image/jpeg`, `image/gif`,
    `image/webp`), verifying both the HTTP `Content-Type` header and the leading
    magic bytes of the fetched payload under `HostPolicy`, `FlowControl`, and
    `Fetcher.Req`'s SSRF guard and byte cap. SVG is intentionally excluded by
    default to avoid active script/entity risks when re-served.
    """

    alias Attesto.ClientIdMetadata, as: Core
    alias AttestoPhoenix.ClientIdMetadata.{Client, FlowControl, HostPolicy}
    alias AttestoPhoenix.ClientIdMetadata.Fetcher.Req, as: ReqFetcher
    alias AttestoPhoenix.Config

    @default_max_logo_bytes 524_288
    @accept_header "image/png, image/jpeg, image/gif, image/webp"
    @allowed_content_types ~w(image/png image/jpeg image/gif image/webp)

    @type logo_result :: %{
            body: binary(),
            content_type: String.t(),
            cache_control: keyword()
          }

    @doc """
    Prefetch and validate the `logo_uri` from a CIMD client map, `%Client{}`, or URL string.
    """
    @spec prefetch(String.t() | map() | Client.t(), Config.t(), keyword()) ::
            {:ok, logo_result()} | {:error, term()}
    def prefetch(%Client{metadata: metadata}, %Config{} = config, opts) when is_list(opts) do
      prefetch(metadata, config, opts)
    end

    def prefetch(%{"logo_uri" => logo_uri}, %Config{} = config, opts) when is_binary(logo_uri) and is_list(opts) do
      prefetch(logo_uri, config, opts)
    end

    def prefetch(client, %Config{}, opts) when is_map(client) and is_list(opts) do
      {:error, :missing_logo_uri}
    end

    def prefetch(logo_uri, %Config{} = config, opts) when is_binary(logo_uri) and is_list(opts) do
      Config.with_request_config(config, fn -> do_prefetch(logo_uri, config, opts) end)
    end

    defp do_prefetch(logo_uri, config, opts) do
      cimd_opts = Keyword.merge(Config.client_id_metadata(config), opts)

      if Config.client_id_metadata_enabled?(config) do
        with {:ok, uri} <- validate_logo_uri(logo_uri),
             :ok <- HostPolicy.check(uri.host, cimd_opts) do
          fetch_logo(uri, logo_uri, cimd_opts)
        end
      else
        {:error, :cimd_disabled}
      end
    end

    defp validate_logo_uri(logo_uri) do
      case Core.validate_client_id(logo_uri) do
        {:ok, uri} -> {:ok, uri}
        {:error, reason} -> {:error, {:invalid_url, reason}}
      end
    end

    defp fetch_logo(uri, logo_uri, cimd_opts) do
      {:ok, host} = HostPolicy.canonicalize(uri.host)
      max_bytes = max_logo_bytes!(cimd_opts)

      fetch_opts =
        cimd_opts
        |> Keyword.take([:allow_loopback, :request_timeout_ms, :resolver, :req_options])
        |> Keyword.put(:max_document_bytes, max_bytes)

      FlowControl.run(host, {:logo, logo_uri}, {:logo, fetch_opts}, cimd_opts, fn ->
        case ReqFetcher.fetch_resource(logo_uri, @accept_header, &image_content_type?/1, fetch_opts) do
          {:ok, %{body: body, content_type: content_type} = result} ->
            validate_image_bytes(body, content_type, result)

          {:error, _reason} = error ->
            error
        end
      end)
    end

    defp validate_image_bytes(body, content_type, result) do
      case sniff_image_type(body) do
        ^content_type -> {:ok, Map.take(result, [:body, :content_type, :cache_control])}
        _other -> {:error, :invalid_image}
      end
    end

    defp image_content_type?(value) when is_binary(value) do
      essence =
        value
        |> String.split(";", parts: 2)
        |> hd()
        |> String.trim()
        |> String.downcase()

      essence in @allowed_content_types
    end

    defp sniff_image_type(<<0x89, "PNG", 0x0D, 0x0A, 0x1A, 0x0A, _rest::binary>>), do: "image/png"
    defp sniff_image_type(<<0xFF, 0xD8, 0xFF, _rest::binary>>), do: "image/jpeg"
    defp sniff_image_type(<<"GIF87a", _rest::binary>>), do: "image/gif"
    defp sniff_image_type(<<"GIF89a", _rest::binary>>), do: "image/gif"
    defp sniff_image_type(<<"RIFF", _size::32, "WEBP", _rest::binary>>), do: "image/webp"
    defp sniff_image_type(_other), do: nil

    defp max_logo_bytes!(opts) do
      case Keyword.get(opts, :max_logo_bytes, @default_max_logo_bytes) do
        value when is_integer(value) and value > 0 -> value
        _invalid -> raise ArgumentError, ":max_logo_bytes must be a positive integer"
      end
    end
  end
end
