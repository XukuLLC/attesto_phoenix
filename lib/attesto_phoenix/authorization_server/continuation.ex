defmodule AttestoPhoenix.AuthorizationServer.Continuation do
  @moduledoc """
  Runs a host continuation wrapper and verifies what it returns, as conn-free
  core.

  Three host hooks share one shape, `(context, continuation -> result)`:
  `:authorization_code_issuance`, `:authorization_code_completion` and
  `:refresh_completion`. The host receives a secret-free `context` and a
  zero-arity `continuation` that performs the library's work, and may run it
  inside its own database transaction and locks. This module is the one
  implementation of the rules all three follow:

    * the continuation runs at most once, only in the process that received
      it, and only while the callback is running;
    * the callback must return the continuation's result unchanged. A digest
      and outcome of that result are recorded, without keeping the result
      itself in process state, so a callback that never ran the continuation
      cannot pass off a success it assembled, and a substituted success is
      refused;
    * the single `{:ok, _}` wrapper `Repo.transaction/1` puts around a
      committed return is accepted and unwrapped;
    * a host `{:error, %AttestoPhoenix.OAuthError{}}` is honored; any other
      substituted return becomes the hook's fixed refusal;
    * nothing from the exception, the context or the result is ever logged,
      because any of them may hold host secrets.

  A caller describes its hook with a `t:profile/0` (the names used in log
  lines, what counts as success, which results are well formed, and the
  refusal to answer with) and translates the normalized result. No protocol
  decision about codes or tokens lives here.
  """

  alias AttestoPhoenix.OAuthError

  require Logger

  @typedoc """
  What distinguishes one hook from another.

    * `:callback` - the hook's name in log lines, e.g.
      `"authorization code completion callback"`.
    * `:continuation` - the continuation's name in log lines.
    * `:work` - the continuation's work as a noun, e.g.
      `"authorization code completion"`.
    * `:not_done` - what did not happen when the hook is refused before any
      work, e.g. `"no token was issued"`.
    * `:no_success` - what was withheld when a success cannot be trusted, e.g.
      `"no successful token response was returned"`.
    * `:no_response` - what was withheld after a failed continuation, e.g.
      `"completion did not succeed and no token response was returned"`.
    * `:after_success` - the consequence of the callback failing after the
      continuation succeeded, completing "...after the continuation
      succeeded; ".
    * `:state_key` - `{module, name}` naming the hook's private
      process-dictionary entry.
    * `:succeeded?` - whether a continuation result is a success.
    * `:well_formed?` - whether a result is one the continuation may produce.
    * `:refusal` - the fixed result returned for a contract violation.
  """
  @type profile :: %{
          callback: String.t(),
          continuation: String.t(),
          work: String.t(),
          not_done: String.t(),
          no_success: String.t(),
          no_response: String.t(),
          after_success: String.t(),
          state_key: {module(), atom()},
          succeeded?: (term() -> boolean()),
          well_formed?: (term() -> boolean()),
          refusal: term()
        }

  @doc """
  Invoke `callback` with `context` and a guarded continuation around
  `work`, and return the normalized result.

  `invoke` applies the host callback to `[context, continuation]`; the caller
  passes its own callback invoker so this module needs no knowledge of
  callback forms. Exceptions, throws and exits from the callback propagate
  after a secret-free log line when the continuation had already started.
  """
  @spec run(profile(), (list() -> term()), term(), (-> term())) :: term()
  def run(profile, invoke, context, work) when is_function(invoke, 1) and is_function(work, 0) do
    owner = self()
    ref = make_ref()
    gate = :atomics.new(1, signed: false)

    continuation = fn -> run_continuation(profile, owner, ref, gate, work) end

    try do
      [context, continuation]
      |> invoke.()
      |> normalize(profile, ref)
    catch
      kind, reason ->
        maybe_log_termination(profile, ref, kind)
        :erlang.raise(kind, reason, __STACKTRACE__)
    after
      :atomics.put(gate, 1, 2)
      Process.delete(key(profile, ref))
    end
  end

  # Cardinality alone bounds the callback to AT MOST one invocation. A private
  # process-dictionary entry first records a secret-free `:started` marker, then
  # carries a digest and outcome of the continuation's result, supplying the
  # missing lower bound and provenance without keeping the result in process
  # state. This state is outside the ordinary mailbox, so a host callback's
  # broad receive cannot consume it. The started marker is important: a host may
  # catch a continuation termination after partial writes, before a normal
  # result exists to replace it. The host still sees the plain result, so it can
  # branch on success/failure to decide whether to commit or roll back.
  defp run_continuation(profile, owner, ref, gate, work) do
    cond do
      self() != owner ->
        # A continuation invoked from another process is a host bug with
        # security-relevant intent. The wire answer stays generic; the operator
        # gets the reason.
        Logger.error(
          "#{profile.continuation} was invoked from a process that does not own it; " <>
            profile.not_done
        )

        profile.refusal

      :atomics.compare_exchange(gate, 1, 0, 1) != :ok ->
        Logger.error(
          "#{profile.continuation} was invoked more than once or after its scope " <>
            "ended; " <> profile.not_done
        )

        profile.refusal

      true ->
        # Set this before any work. If host code catches a raise, throw, or exit
        # from the work, normalization can distinguish a post-invocation
        # termination from a callback that never invoked us.
        Process.put(key(profile, ref), :started)
        result = work.()
        Process.put(key(profile, ref), {digest(result), outcome(profile, result)})
        result
    end
  end

  # Provenance check. The host is contractually required to return the
  # continuation's result unchanged; this verifies it actually did, rather than
  # trusting the outward tuple form. The cases:
  #
  #   * the continuation never ran - nothing was done, so a fabricated success
  #     must NOT become a response;
  #   * the continuation started but terminated before producing a result - a
  #     host may have caught the termination after partial writes, so an error
  #     may be honored but a success must never be fabricated;
  #   * the host returned exactly what the continuation produced - the normal
  #     path, including a deliberate `{:error, _}` after `Repo.rollback/1`;
  #   * the host committed the continuation inside `Repo.transaction/1` and
  #     returned the `{:ok, _}` wrapper. The commit already carried the
  #     continuation's writes, so unwrap rather than fail a request whose work
  #     is done.
  defp normalize(result, profile, ref) do
    case Process.get(key(profile, ref)) do
      {digest, outcome} when is_binary(digest) and outcome in [:succeeded, :failed] ->
        normalize_produced(result, profile, digest, outcome)

      :started ->
        normalize_started(result, profile)

      _other ->
        normalize_incomplete(result, profile)
    end
  end

  # The entry is named by the hook, so two hooks nested in one process (or a
  # diagnostic that looks for one) never read each other's state.
  defp key(%{state_key: {owner, name}}, ref), do: {owner, name, ref}

  defp digest(result), do: :crypto.hash(:sha256, :erlang.term_to_binary(result, [:deterministic]))

  defp outcome(profile, result), do: if(profile.succeeded?.(result), do: :succeeded, else: :failed)

  defp maybe_log_termination(profile, ref, kind) do
    case Process.get(key(profile, ref)) do
      {_digest, :succeeded} ->
        Logger.error("#{profile.callback} #{verb(kind)} after the continuation succeeded; " <> profile.after_success)

      :started ->
        Logger.error(
          "#{profile.callback} #{verb(kind)} after the continuation started; " <>
            "partial writes may have occurred and " <> profile.no_success
        )

      _other ->
        :ok
    end
  end

  defp verb(:error), do: "raised"
  defp verb(:throw), do: "threw"
  defp verb(:exit), do: "exited"

  defp normalize_produced(result, profile, digest, outcome) do
    cond do
      digest(result) == digest ->
        normalize_result(result, profile)

      match?({:ok, _inner}, result) and digest(elem(result, 1)) == digest ->
        maybe_log_failed_wrapper(profile, outcome)
        result |> elem(1) |> normalize_result(profile)

      true ->
        normalize_substituted(result, profile, outcome)
    end
  end

  defp maybe_log_failed_wrapper(profile, :failed) do
    Logger.warning(
      "#{profile.callback} returned a success wrapper around a failed " <>
        "continuation result; an enclosing transaction may have committed partial writes"
    )
  end

  defp maybe_log_failed_wrapper(_profile, :succeeded), do: :ok

  # The continuation ran but the host returned something else.
  #
  # Any substituted return after the continuation SUCCEEDED is the dangerous
  # case and the reason these clauses are not silent. Two host behaviours reach
  # it and this library cannot tell them apart from the inside: the host rolled
  # its transaction back, so the continuation's writes went with it and the
  # error is honest; or the host COMMITTED and then returned something else
  # anyway, so the work is done and the client was told it failed. Telling them
  # apart would require the host's transaction outcome, which is outside this
  # boundary. An OAuth error is honored and every other substituted return is
  # normalized for the wire, but all are logged at error level with the hook's
  # consequence named, so an operator can find the host bug.
  defp normalize_substituted({:error, %OAuthError{}} = error, profile, :succeeded) do
    log_substituted_after_success(profile, "returned an error")
    error
  end

  defp normalize_substituted({:error, _reason}, profile, :succeeded) do
    log_substituted_after_success(profile, "returned an error")
    profile.refusal
  end

  defp normalize_substituted(_substituted, profile, :succeeded) do
    log_substituted_after_success(profile, "returned a different result")
    profile.refusal
  end

  # The continuation itself failed and the host remapped the reason. No success
  # can be returned, so there is no retry hazard to report. Earlier continuation
  # steps may still have persisted partial state when the host did not provide a
  # transaction.
  defp normalize_substituted({:error, %OAuthError{}} = error, _profile, :failed), do: error

  defp normalize_substituted({:error, _reason}, profile, :failed) do
    Logger.error("#{profile.callback} failed")
    profile.refusal
  end

  defp normalize_substituted(_substituted, profile, :failed) do
    Logger.error(
      "#{profile.callback} did not return the continuation's result " <>
        "unchanged; " <> profile.no_response
    )

    profile.refusal
  end

  defp log_substituted_after_success(profile, action) do
    Logger.error("#{profile.callback} #{action} after the continuation succeeded; " <> profile.after_success)
  end

  # The continuation started but terminated before returning a result. A host
  # may catch that termination and return an OAuth error, but the library cannot
  # infer whether work before the termination committed. Honor a real OAuth
  # error while warning about the possible partial writes; never serve a result
  # that could be a fabricated success.
  defp normalize_started({:error, %OAuthError{}} = error, profile) do
    log_caught_termination(profile)
    error
  end

  defp normalize_started({:error, _reason}, profile) do
    log_caught_termination(profile)
    profile.refusal
  end

  defp normalize_started(_result, profile) do
    Logger.error(
      "#{profile.callback} returned a result after the continuation " <>
        "terminated; partial writes may have occurred and " <> profile.no_success
    )

    profile.refusal
  end

  defp log_caught_termination(profile) do
    Logger.warning(
      "#{profile.callback} caught a termination after the continuation " <>
        "started; partial writes may have occurred and the completion result cannot be verified"
    )
  end

  # The continuation was never invoked. Nothing was done, so the only safe
  # answers are the host's own error or a refusal - never a success the host
  # assembled itself.
  defp normalize_incomplete({:error, %OAuthError{}} = error, _profile), do: error

  defp normalize_incomplete({:error, _reason}, profile) do
    Logger.error("#{profile.callback} failed")
    profile.refusal
  end

  defp normalize_incomplete(_result, profile) do
    Logger.error("#{profile.callback} returned without invoking the continuation; " <> profile.not_done)
    profile.refusal
  end

  defp normalize_result(result, profile) do
    if profile.well_formed?.(result) do
      result
    else
      Logger.error("#{profile.work} produced an unusable result; " <> profile.not_done)
      profile.refusal
    end
  end
end
