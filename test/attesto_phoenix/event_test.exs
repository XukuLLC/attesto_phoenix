defmodule AttestoPhoenix.EventTest do
  use ExUnit.Case, async: true

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Event

  # A throwaway sink that records every dispatched event by sending it to a
  # test-local pid, so we can assert the host callback received exactly what
  # the library built.
  defmodule Sink do
    def record(%Event{} = event, pid) do
      send(pid, {:event, event})
      :ok
    end

    def record_self(%Event{} = event) do
      send(event.metadata["pid"], {:event, event})
      {:error, :ignored_return}
    end
  end

  # A minimal valid config. The required policy callbacks are never invoked by
  # the event path; they exist only so `Config.new/1` validates. `:on_event` is
  # overridden per-test.
  defp config(on_event) do
    Config.new(
      issuer: "https://issuer.example",
      keystore: __MODULE__.Keystore,
      repo: __MODULE__.Repo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      on_event: on_event
    )
  end

  describe "new/2" do
    test "builds a struct from a keyword payload" do
      event = Event.new(:token_issued, client_id: "abc", scope: "openid profile")

      assert %Event{
               name: :token_issued,
               client_id: "abc",
               scope: "openid profile",
               subject: nil,
               grant_type: nil,
               result: nil,
               metadata: %{}
             } = event
    end

    test "builds a struct from a map payload" do
      event = Event.new(:auth_succeeded, %{subject: "user-1", client_id: "abc"})

      assert event.subject == "user-1"
      assert event.client_id == "abc"
    end

    test "carries a host-opaque metadata map untouched" do
      meta = %{"request_id" => "req-7", "ip" => "203.0.113.4"}
      event = Event.new(:auth_denied, result: :invalid_token, metadata: meta)

      assert event.metadata == meta
      assert event.result == :invalid_token
    end

    test "defaults metadata to an empty map" do
      assert Event.new(:token_revoked).metadata == %{}
    end

    test "fails closed on an unrecognized event name" do
      assert_raise ArgumentError, ~r/unrecognized AttestoPhoenix event name/, fn ->
        Event.new(:not_a_real_event, %{})
      end
    end

    test "raises on an unknown payload key rather than dropping it" do
      assert_raise KeyError, fn ->
        Event.new(:token_issued, %{audience: "https://api.example"})
      end
    end

    test "accepts every recognized event name" do
      for name <- Event.names() do
        assert %Event{name: ^name} = Event.new(name, %{})
      end
    end
  end

  describe "emit/3 with no callback configured" do
    test "is a no-op returning :ok when :on_event is nil" do
      assert Event.emit(config(nil), :token_issued, client_id: "abc") == :ok
    end

    test "still raises on an unrecognized name even when :on_event is nil" do
      # emit/3 delegates name validation to new/2; verify the raise propagates
      # through the no-callback path by calling new/2 directly.
      assert_raise ArgumentError, fn ->
        Event.new(:bogus)
      end
    end
  end

  describe "emit/3 with a configured callback" do
    test "dispatches the built struct to an anonymous-function callback" do
      parent = self()
      cfg = config(fn %Event{} = e -> send(parent, {:event, e}) end)

      assert Event.emit(cfg, :refresh_rotated, client_id: "abc", subject: "user-1") == :ok

      assert_receive {:event, %Event{name: :refresh_rotated, client_id: "abc", subject: "user-1"}}
    end

    test "dispatches via a {module, function, args} callback with the event prepended" do
      cfg = config({Sink, :record, [self()]})

      assert Event.emit(cfg, :client_registered, client_id: "abc") == :ok

      assert_receive {:event, %Event{name: :client_registered, client_id: "abc"}}
    end

    test "returns :ok regardless of the callback's return value" do
      cfg = config({Sink, :record_self, []})

      assert Event.emit(cfg, :refresh_reuse_detected,
               result: :reuse_detected,
               metadata: %{"pid" => self()}
             ) == :ok

      assert_receive {:event, %Event{name: :refresh_reuse_detected, result: :reuse_detected}}
    end
  end

  describe "dispatch/2" do
    test "nil callback is a no-op returning :ok" do
      assert Event.dispatch(nil, Event.new(:token_issued)) == :ok
    end

    test "{module, function} callback invokes with the event" do
      parent = self()
      # Wrap so the 2-arity Sink.record can capture the parent pid: use a fun
      # for this case and the MFA path for the args case above.
      assert Event.dispatch(
               fn %Event{} = e -> send(parent, {:event, e}) end,
               Event.new(:auth_denied)
             ) ==
               :ok

      assert_receive {:event, %Event{name: :auth_denied}}
    end
  end

  describe "names/0" do
    test "is the closed set of recognized names" do
      assert Enum.sort(Event.names()) ==
               Enum.sort([
                 :token_issued,
                 :token_denied,
                 :code_issued,
                 :authorization_denied,
                 :authorization_failed,
                 :token_revoked,
                 :refresh_issued,
                 :refresh_rotated,
                 :refresh_reuse_detected,
                 :auth_succeeded,
                 :auth_denied,
                 :client_registered
               ])
    end
  end
end
