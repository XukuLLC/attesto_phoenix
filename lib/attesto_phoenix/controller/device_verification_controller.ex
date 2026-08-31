defmodule AttestoPhoenix.Controller.DeviceVerificationController do
  @moduledoc """
  Device verification page (RFC 8628 §3.3).

  The user-facing leg of the device grant: the user opens
  `GET /oauth/device_verification` (optionally with `?user_code=...` from the
  `verification_uri_complete`), authenticates with the host, confirms the
  `user_code`, and approves or denies. This controller owns the protocol — it
  resolves and normalizes the `user_code`, drives the host login, and performs
  the atomic store transition (`Attesto.DeviceCode.approve/3` / `deny/2`) — while
  the host owns the HTML and the login UI through two callbacks:

    * `:authenticate_device_user` — `(conn -> {:ok, subject} | {:halt, conn})`.
      Establishes the resource owner (the host's session/login). `subject` is a
      map with `:subject` (the `sub`) and optional `:scope` / `:claims`
      (carrying e.g. `acr`/`auth_time` for step-up). `{:halt, conn}` lets the
      host take over the connection to render its login UI.
    * `:render_device_verification` — `(conn, view -> conn)`. Renders the page.
      `view` is a map `%{stage, user_code, pending}` where `stage` is
      `:prompt` (ask the user to enter/confirm the code — `pending` is the
      `Attesto.DeviceCodeStore.pending_view()` or `nil`), `:approved`,
      `:denied`, or `:invalid` (unknown/expired/already-decided code).

  ## No auto-approval (RFC 8628 §3.3.1 / §5.4)

  A `user_code` arriving via `verification_uri_complete` is only ever
  pre-filled — approval requires an explicit user POST carrying
  `decision=approve`. The controller never approves from a GET or from the URL
  alone, closing the one-click remote-phishing vector.

  ## Host responsibility: CSRF + session (REQUIRED)

  The approve/deny POST is a state-changing, session-authenticated action. The
  library performs the store transition but does NOT own the browser session or
  CSRF token, so the host MUST mount these routes behind a pipeline that
  enforces CSRF protection (`protect_from_forgery`) and a same-site session —
  otherwise a logged-in victim's browser can be made to POST an attacker's
  `user_code` and approve the attacker's device (a confused-deputy / device
  login CSRF). The controller additionally requires HTTPS (a credential-bearing
  authorization action must not cross a plain-HTTP hop).
  """

  use AttestoPhoenix.Controller, formats: [:html, :json]

  alias Attesto.DeviceCode
  alias AttestoPhoenix.{Callback, Config, RequestContext}

  @spec verify(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def verify(conn, params) do
    config = Config.resolve!(conn)

    with :ok <- require_enabled(config),
         :ok <- check_https(conn, config),
         {:ok, store} <- require_store(config),
         {:ok, conn, subject} <- authenticate(conn, config) do
      handle(conn, config, store, subject, params)
    else
      {:halt, conn} -> conn
      {:error, status, body} -> conn |> put_status(status) |> json(body)
    end
  end

  defp check_https(conn, config) do
    case RequestContext.check_https(conn, config) do
      :ok -> :ok
      {:error, :insecure_transport} -> {:error, 400, %{error: "invalid_request", error_description: "TLS required"}}
    end
  end

  # GET (or POST without a decision) shows the confirm prompt; a POST carrying an
  # explicit `decision` performs the approve/deny store transition. The user_code
  # is normalized in the core before any store lookup (fail-closed).
  defp handle(conn, config, store, subject, params) do
    user_code = string_param(params["user_code"])
    decision = string_param(params["decision"])

    case {conn.method, decision} do
      {"POST", "approve"} -> approve(conn, config, store, subject, user_code)
      {"POST", "deny"} -> deny(conn, config, store, user_code)
      _ -> prompt(conn, config, store, user_code)
    end
  end

  defp approve(conn, config, store, subject, user_code) do
    case pending_scope(config, store, user_code) do
      {:ok, pending_scope} ->
        approval = %{
          subject: Map.get(subject, :subject) || Map.get(subject, :sub),
          # The granted scope is the subject's narrowed scope when the host
          # login/consent layer supplied one, otherwise the originally requested
          # scope bound to the device code — never broader than what was requested.
          scope: Map.get(subject, :scope) || pending_scope,
          claims: Map.get(subject, :claims, %{})
        }

        case approve_device_code(config, store, user_code, approval) do
          :ok -> render_stage(conn, config, :approved, user_code, nil)
          {:error, _domain_reason} -> render_stage(conn, config, :invalid, user_code, nil)
        end

      {:error, _domain_reason} ->
        render_stage(conn, config, :invalid, user_code, nil)
    end
  end

  defp deny(conn, config, store, user_code) do
    case deny_device_code(config, store, user_code) do
      :ok -> render_stage(conn, config, :denied, user_code, nil)
      {:error, _domain_reason} -> render_stage(conn, config, :invalid, user_code, nil)
    end
  end

  # No decision yet: show the confirm screen with the pending request the user is
  # about to authorize (or just the code-entry prompt when no/invalid code).
  defp prompt(conn, config, _store, nil), do: render_stage(conn, config, :prompt, nil, nil)

  defp prompt(conn, config, store, user_code) do
    case lookup_device_code(config, store, user_code) do
      {:ok, %{status: :pending} = view} -> render_stage(conn, config, :prompt, user_code, view)
      {:ok, _decided} -> render_stage(conn, config, :invalid, user_code, nil)
      :error -> render_stage(conn, config, :invalid, user_code, nil)
      {:error, :invalid_user_code} -> render_stage(conn, config, :invalid, user_code, nil)
    end
  end

  defp pending_scope(_config, _store, nil), do: {:error, :invalid_user_code}

  defp pending_scope(config, store, user_code) do
    case lookup_device_code(config, store, user_code) do
      {:ok, %{status: :pending, scope: scope}} when is_list(scope) -> {:ok, scope}
      {:ok, %{status: status}} when status in [:approved, :denied, :consumed] -> {:error, :not_pending}
      :error -> {:error, :not_found}
      {:error, :invalid_user_code} = error -> error
      {:ok, _malformed_pending_view} -> device_code_contract_error!(:lookup)
    end
  end

  defp lookup_device_code(config, store, user_code) do
    result =
      invoke_device_code!(:lookup, fn ->
        DeviceCode.lookup(store, user_code, device_code_opts(config))
      end)

    case result do
      {:ok, view} ->
        if valid_pending_view?(view), do: {:ok, view}, else: device_code_contract_error!(:lookup)

      :error ->
        :error

      {:error, :invalid_user_code} = error ->
        error

      _unexpected ->
        device_code_contract_error!(:lookup)
    end
  end

  defp valid_pending_view?(%{
         user_code: user_code,
         client_id: client_id,
         scope: scope,
         resource: resource,
         status: status,
         expires_at: expires_at
       }) do
    valid_device_identity?(user_code, client_id) and valid_string_list?(scope) and
      valid_string_list?(resource) and valid_device_status?(status) and valid_expiry?(expires_at)
  end

  defp valid_pending_view?(_view), do: false

  defp valid_device_identity?(user_code, client_id) do
    is_binary(user_code) and user_code != "" and
      (is_nil(client_id) or (is_binary(client_id) and client_id != ""))
  end

  defp valid_string_list?(value), do: is_list(value) and Enum.all?(value, &is_binary/1)
  defp valid_device_status?(status), do: status in [:pending, :approved, :denied, :consumed]
  defp valid_expiry?(expires_at), do: is_integer(expires_at) and expires_at >= 0

  defp approve_device_code(config, store, user_code, approval) do
    result =
      invoke_device_code!(:approve, fn ->
        DeviceCode.approve(store, user_code, approval, device_code_opts(config))
      end)

    case result do
      :ok ->
        :ok

      {:error, reason} = error
      when reason in [:not_found, :already_decided, :expired, :invalid_user_code, :invalid_subject] ->
        error

      _unexpected ->
        device_code_contract_error!(:approve)
    end
  end

  defp deny_device_code(_config, _store, nil), do: {:error, :invalid_user_code}

  defp deny_device_code(config, store, user_code) do
    result =
      invoke_device_code!(:deny, fn ->
        DeviceCode.deny(store, user_code, device_code_opts(config))
      end)

    case result do
      :ok ->
        :ok

      {:error, reason} = error
      when reason in [:not_found, :already_decided, :expired, :invalid_user_code] ->
        error

      _unexpected ->
        device_code_contract_error!(:deny)
    end
  end

  defp device_code_opts(config) do
    [user_code_length: Keyword.fetch!(Config.device_authorization(config), :user_code_length)]
  end

  defp invoke_device_code!(operation, callback) do
    callback.()
  rescue
    _exception -> device_code_contract_error!(operation)
  catch
    _kind, _reason -> device_code_contract_error!(operation)
  end

  defp device_code_contract_error!(operation) do
    call =
      case operation do
        :lookup -> "lookup/2"
        :approve -> "approve/3"
        :deny -> "deny/2"
      end

    raise RuntimeError, "Attesto.DeviceCode.#{call} violated its return contract"
  end

  defp authenticate(conn, config) do
    case config.authenticate_device_user do
      nil ->
        {:error, 500, %{error: "server_error", error_description: "device verification login is not configured"}}

      callback ->
        case Callback.invoke(callback, [conn]) do
          {:ok, subject} when is_map(subject) -> {:ok, conn, subject}
          {:halt, halted} -> {:halt, halted}
          _ -> {:error, 500, %{error: "server_error"}}
        end
    end
  end

  defp render_stage(conn, config, stage, user_code, pending) do
    view = %{stage: stage, user_code: user_code, pending: pending}

    case config.render_device_verification do
      nil -> conn |> put_status(200) |> json(default_body(view))
      callback -> Callback.invoke(callback, [conn, view])
    end
  end

  # When no host renderer is wired, fall back to a minimal JSON body so the
  # endpoint is still functional in tests / API-only deployments.
  defp default_body(%{stage: stage, user_code: user_code}), do: %{stage: stage, user_code: user_code}

  defp require_enabled(config) do
    if Config.device_authorization_enabled?(config),
      do: :ok,
      else: {:error, 404, %{error: "not_found"}}
  end

  defp require_store(config) do
    case Config.device_code_store(config) do
      store when is_atom(store) and not is_nil(store) -> {:ok, store}
      _ -> {:error, 500, %{error: "server_error", error_description: "device authorization is not configured"}}
    end
  end

  defp string_param(value) when is_binary(value) and value != "", do: value
  defp string_param(_value), do: nil
end
