defmodule Mix.Tasks.AttestoPhoenix.BackfillRefreshIssuerTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  alias Mix.Tasks.AttestoPhoenix.BackfillRefreshIssuer

  @accepted_options ~w(
    --help
    --issuer
    --assert-single-issuer
    --apply
    --repo
    --schema-prefix
    --otp-app
    --batch-size
  )

  test "--help prints usage before application startup and configuration checks" do
    output =
      capture_io(fn ->
        assert :ok =
                 BackfillRefreshIssuer.run([
                   "--help",
                   "--otp-app",
                   "an_app_that_does_not_exist"
                 ])
      end)

    assert output =~ "mix attesto_phoenix.backfill_refresh_issuer"
    assert output =~ "dry run unless --apply is present"

    for option <- @accepted_options do
      assert output =~ option
    end
  end

  test "rejects unknown options and positional arguments with the accepted options" do
    for args <- [["--bogus"], ["unexpected"]] do
      error =
        assert_raise Mix.Error, ~r/invalid refresh issuer migration arguments/, fn ->
          BackfillRefreshIssuer.run(args)
        end

      for option <- @accepted_options do
        assert error.message =~ option
      end
    end
  end
end
