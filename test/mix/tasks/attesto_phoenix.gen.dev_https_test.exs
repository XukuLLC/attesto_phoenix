defmodule Mix.Tasks.AttestoPhoenix.Gen.DevHttpsTest do
  use ExUnit.Case, async: true

  alias Mix.Tasks.AttestoPhoenix.Gen.DevHttps

  @moduletag :tmp_dir

  describe "gitignore_pattern/1" do
    test "renders a leading/trailing-slash directory pattern" do
      assert DevHttps.gitignore_pattern("priv/cert") == "/priv/cert/"
    end

    test "normalizes existing slashes" do
      assert DevHttps.gitignore_pattern("/priv/cert/") == "/priv/cert/"
    end
  end

  describe "ensure_gitignored/2" do
    test "creates .gitignore and appends the pattern when absent", %{tmp_dir: tmp_dir} do
      path = Path.join(tmp_dir, ".gitignore")

      assert DevHttps.ensure_gitignored("priv/cert", path) == :appended
      contents = File.read!(path)
      assert contents =~ "/priv/cert/"
      assert contents =~ "mkcert"
    end

    test "appends onto an existing .gitignore without clobbering it", %{tmp_dir: tmp_dir} do
      path = Path.join(tmp_dir, ".gitignore")
      File.write!(path, "/_build/\n/deps/\n")

      assert DevHttps.ensure_gitignored("priv/cert", path) == :appended
      contents = File.read!(path)
      assert contents =~ "/_build/"
      assert contents =~ "/deps/"
      assert contents =~ "/priv/cert/"
    end

    test "is idempotent: a second call does not duplicate the pattern", %{tmp_dir: tmp_dir} do
      path = Path.join(tmp_dir, ".gitignore")

      assert DevHttps.ensure_gitignored("priv/cert", path) == :appended
      assert DevHttps.ensure_gitignored("priv/cert", path) == :already

      occurrences =
        path |> File.read!() |> String.split("\n") |> Enum.count(&(String.trim(&1) == "/priv/cert/"))

      assert occurrences == 1
    end

    test "recognizes a pre-existing bare (no-slash) spelling", %{tmp_dir: tmp_dir} do
      path = Path.join(tmp_dir, ".gitignore")
      File.write!(path, "priv/cert\n")

      assert DevHttps.ensure_gitignored("priv/cert", path) == :already
      refute File.read!(path) =~ "/priv/cert/"
    end
  end

  describe "next_steps/1" do
    test "renders the DevTLS one-liner and the https issuer note" do
      out = DevHttps.next_steps("priv/cert")

      assert out =~ "AttestoPhoenix.DevTLS.https_opts(port: 4443)"
      assert out =~ "https://localhost:4443"
      assert out =~ "priv/cert/localhost.pem"
      assert out =~ "priv/cert/localhost-key.pem"
      assert out =~ "RFC 8414"
    end
  end

  describe "mkcert_install_guidance/0" do
    test "names mkcert and the brew/repo install paths" do
      out = DevHttps.mkcert_install_guidance()

      assert out =~ "brew install mkcert"
      assert out =~ "github.com/FiloSottile/mkcert"
    end
  end
end
