defmodule AttestoPhoenix.DevTLSTest do
  use ExUnit.Case, async: true

  alias AttestoPhoenix.DevTLS

  @moduletag :tmp_dir

  defp write_pair(dir) do
    cert = Path.join(dir, "localhost.pem")
    key = Path.join(dir, "localhost-key.pem")
    File.write!(cert, "cert")
    File.write!(key, "key")
    {cert, key}
  end

  describe "https_opts/1 with a present certificate" do
    test "returns the endpoint https keyword shape with defaults", %{tmp_dir: tmp_dir} do
      {cert, key} = write_pair(tmp_dir)

      opts = DevTLS.https_opts(certfile: cert, keyfile: key)

      assert opts[:port] == 4443
      assert opts[:cipher_suite] == :strong
      assert opts[:certfile] == cert
      assert opts[:keyfile] == key
      assert opts[:http_1_options] == [max_header_length: 65_536]
    end

    test "honours port, and max_header_length overrides", %{tmp_dir: tmp_dir} do
      {cert, key} = write_pair(tmp_dir)

      opts = DevTLS.https_opts(port: 4001, certfile: cert, keyfile: key, max_header_length: 32_768)

      assert opts[:port] == 4001
      assert opts[:http_1_options] == [max_header_length: 32_768]
    end

    test "resolves the conventional path relative to cwd when no explicit path is given", %{tmp_dir: tmp_dir} do
      File.mkdir_p!(Path.join(tmp_dir, "priv/cert"))
      {cert, key} = write_pair(Path.join(tmp_dir, "priv/cert"))

      opts =
        File.cd!(tmp_dir, fn ->
          DevTLS.https_opts(port: 4443)
        end)

      assert opts[:certfile] == cert
      assert opts[:keyfile] == key
    end

    test "resolves the conventional path via Application.app_dir when :otp_app is given", %{tmp_dir: tmp_dir} do
      app_dir = Application.app_dir(:attesto_phoenix)
      cert = Path.join(app_dir, "priv/cert/localhost.pem")
      key = Path.join(app_dir, "priv/cert/localhost-key.pem")
      File.mkdir_p!(Path.dirname(cert))
      File.write!(cert, "cert")
      File.write!(key, "key")

      on_exit(fn -> File.rm_rf!(Path.dirname(cert)) end)

      opts = DevTLS.https_opts(port: 4443, otp_app: :attesto_phoenix)

      assert opts[:certfile] == cert
      assert opts[:keyfile] == key

      _ = tmp_dir
    end
  end

  describe "https_opts/1 with a missing certificate" do
    test "raises an ArgumentError pointing at the generator", %{tmp_dir: tmp_dir} do
      cert = Path.join(tmp_dir, "nope.pem")
      key = Path.join(tmp_dir, "nope-key.pem")

      assert_raise ArgumentError, ~r/mix attesto_phoenix\.gen\.dev_https/, fn ->
        DevTLS.https_opts(certfile: cert, keyfile: key)
      end
    end

    test "the error names the missing file and never mentions falling back to http", %{tmp_dir: tmp_dir} do
      {cert, _key} = write_pair(tmp_dir)
      missing_key = Path.join(tmp_dir, "absent-key.pem")

      err =
        assert_raise ArgumentError, fn ->
          DevTLS.https_opts(certfile: cert, keyfile: missing_key)
        end

      assert err.message =~ missing_key
      refute err.message =~ "http fallback"
    end
  end
end
