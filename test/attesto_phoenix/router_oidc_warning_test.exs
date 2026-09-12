defmodule AttestoPhoenix.RouterOIDCWarningTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias AttestoPhoenix.Config

  setup do
    previous = Application.get_env(:attesto_phoenix, Config, :missing)

    on_exit(fn ->
      case previous do
        :missing -> Application.delete_env(:attesto_phoenix, Config)
        config -> Application.put_env(:attesto_phoenix, Config, config)
      end
    end)

    :ok
  end

  test "warns when both bundled OIDC routes are removed but capability is implicit" do
    Application.put_env(:attesto_phoenix, Config, scopes_supported: ["api.read"])

    warning = capture_io(:stderr, &compile_oidc_route_opt_out/0)

    assert warning =~ "does not explicitly configure AttestoPhoenix.Config :openid_provider"
    assert warning =~ "OAuth-only hosts must set openid_provider: false"
  end

  test "does not warn when the host explicitly declares its protocol capability" do
    for enabled <- [false, true] do
      Application.put_env(:attesto_phoenix, Config, openid_provider: enabled)
      assert capture_io(:stderr, &compile_oidc_route_opt_out/0) == ""
    end
  end

  defp compile_oidc_route_opt_out do
    router = Module.concat(__MODULE__, "Router#{System.unique_integer([:positive])}")

    Code.compile_quoted(
      quote do
        defmodule unquote(router) do
          use Phoenix.Router
          use AttestoPhoenix.Router

          scope "/" do
            attesto_routes(userinfo: false, openid_configuration: false)
          end
        end
      end
    )
  end
end
