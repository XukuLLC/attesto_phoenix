# Dialyzer warning suppressions.
#
# Every entry here guards a deliberate fail-closed clause where dialyzer's
# inferred type is narrower than the real runtime surface. The same class
# of suppression is documented in attesto's own .dialyzer_ignore.exs.
#
#   * registration_controller.ex - `registration_metadata/1` has a primary
#     clause that matches `%Plug.Conn{body_params: body} when is_map(body)`.
#     Dialyzer's success typing for the `body_params` field excludes the
#     bare-map case (it narrows to `%Plug.Conn.Unfetched{}`), so it believes
#     the `_conn` catch-all is unreachable. In practice a host pipeline that
#     runs a body parser (Plug.Parsers) replaces `body_params` with a plain
#     map before this action runs; the catch-all is the correct fallback for
#     any conn that arrives before parsing and must stay fail-closed rather
#     than crashing.
#
#   * request_context.ex - `remote_ip_string/1` has a nil guard clause for
#     `%Plug.Conn{remote_ip: nil}`. Dialyzer's typespec for `Plug.Conn`
#     restricts `remote_ip` to IP tuples, so it flags the nil clause as
#     unreachable. In practice `Plug.Test.conn/2` (and similar synthetic conn
#     builders) leave `remote_ip` as nil; the guard prevents a crash on the
#     `:inet.ntoa/1` call that follows. Removing it to satisfy dialyzer would
#     cause test and integration helpers to raise.
#
#   * authorize_controller.ex - `direct_error_description/1` has a `_`
#     catch-all returning a non-revealing generic description. Dialyzer infers
#     the `reason` reaching it is exactly the closed atom set the named clauses
#     enumerate (the validation pipeline returns only those), so it flags the
#     catch-all as unreachable. It is kept as a fail-closed guard: a direct
#     (non-redirectable) error per OIDC Core §3.1.2.6 must render a safe body,
#     never raise a FunctionClauseError, if the validation surface gains a new
#     reason atom.
#
#   * authorization_server/token.ex - `access_token_claims/1` has a `_grant`
#     catch-all returning `%{}` for a grant whose `:claims` is absent or not a
#     map. Dialyzer narrows the grant to always carry a map `:claims`; the
#     catch-all stays fail-closed so a grant minted without claims yields no
#     access-token claims rather than raising.
#
#   * config.ex - a fail-closed boot-validation guard whose checked value
#     dialyzer's success typing narrows to always satisfy the check (so it flags
#     the raise branch as unreachable). The guard stays so a runtime value that
#     violates the declared field type raises a clear ArgumentError at
#     `new/1`/`validate!/1` rather than failing late. The validations are
#     covered by config_test.exs.
#
#   * authorization_server/ciba_decision.ex - `notification_endpoint/2` keeps a
#     catch-all for malformed decision data. Dialyzer follows the normal core
#     return type and sees only binary client identifiers, but the boundary is
#     intentionally fail-closed if a custom store returns invalid persisted
#     data. Attesto 1.3's tighter CIBA result types make this existing guard
#     newly visible to Dialyzer.
#
#   * openid_configuration_controller.ex - two defensive clauses are narrower
#     than Plug/Config's success types: the disabled-registration clause and a
#     catch-all for non-list request path segments. Runtime configuration and
#     synthetic conns can still reach those boundaries, where omission or a
#     non-match is safer than raising while serving discovery metadata. The
#     Attesto 1.3 PLT refresh newly proves the normal-path types; the exact
#     warning text is filtered below so unrelated warnings in this module still
#     fail CI.
[
  {"lib/attesto_phoenix/controller/registration_controller.ex", :pattern_match_cov},
  {"lib/attesto_phoenix/request_context.ex", :pattern_match},
  {"lib/attesto_phoenix/controller/authorize_controller.ex", :pattern_match_cov},
  {"lib/attesto_phoenix/authorization_server/token.ex", :pattern_match_cov},
  {"lib/attesto_phoenix/config.ex", :pattern_match},
  {"lib/attesto_phoenix/authorization_server/ciba_decision.ex",
   "The pattern pattern <__config@1, __client_id@1> can never match the type, because it is covered by previous clauses."},
  {"lib/attesto_phoenix/controller/openid_configuration_controller.ex", "The pattern can never match the type true."},
  {"lib/attesto_phoenix/controller/openid_configuration_controller.ex",
   "The pattern variable __segments@1 can never match the type, because it is covered by previous clauses."}
]
