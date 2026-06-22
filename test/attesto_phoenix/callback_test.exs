defmodule AttestoPhoenix.CallbackTest do
  @moduledoc """
  Unit tests for `AttestoPhoenix.Callback.to_fun2/1`, the adapter that turns any
  configured callback form (anonymous function, `{module, function}` pair, or
  `{module, function, extra_args}` triple) into the bare 2-arity function
  `Attesto.DPoP.verify_proof/2` demands for its `:replay_check`.
  """
  use ExUnit.Case, async: true

  alias AttestoPhoenix.Callback

  defmodule Stub do
    @moduledoc false
    def check(jti, ttl), do: {:check, jti, ttl}
    def check_with_extra(jti, ttl, tag), do: {:check, jti, ttl, tag}
  end

  describe "to_fun2/1" do
    test "wraps an anonymous function transparently" do
      fun = Callback.to_fun2(fn jti, ttl -> {jti, ttl} end)

      assert is_function(fun, 2)
      assert fun.("jti-1", 60) == {"jti-1", 60}
    end

    test "adapts a {module, function} pair into a 2-arity function" do
      fun = Callback.to_fun2({Stub, :check})

      assert is_function(fun, 2)
      assert fun.("jti-2", 90) == {:check, "jti-2", 90}
    end

    test "adapts a {module, function, extra_args} triple, appending the extra args" do
      fun = Callback.to_fun2({Stub, :check_with_extra, [:tag]})

      assert is_function(fun, 2)
      assert fun.("jti-3", 120) == {:check, "jti-3", 120, :tag}
    end
  end
end
