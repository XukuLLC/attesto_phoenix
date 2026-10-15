defmodule AttestoPhoenix.HTTPAcceptTest do
  use ExUnit.Case, async: true

  alias AttestoPhoenix.HTTPAccept

  @media_type "application/token-introspection+jwt"

  test "matches exact media types case-insensitively and honors q" do
    assert HTTPAccept.accepts?(["text/plain, APPLICATION/TOKEN-INTROSPECTION+JWT;q=0.5"], @media_type)
    refute HTTPAccept.accepts?(["#{@media_type};q=0"], @media_type)
    refute HTTPAccept.accepts?(["#{@media_type}ish"], @media_type)
  end

  test "handles quoted separators and multiple header fields" do
    assert HTTPAccept.accepts?(["text/plain", ~s(#{@media_type};profile="a,b;c")], @media_type)
  end

  test "ignores malformed ranges without raising" do
    for malformed <- [
          ";",
          "#{@media_type};q",
          "#{@media_type};q=",
          "#{@media_type};q=bogus",
          "#{@media_type};q=1.1",
          "#{@media_type};q=0.5junk",
          "#{@media_type};q=0.5;q=0.7",
          ~s(#{@media_type};profile="unterminated)
        ] do
      refute HTTPAccept.accepts?([malformed], @media_type)
    end
  end
end
