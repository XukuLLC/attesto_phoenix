# These narrow filters retain runtime validation at external boundaries where
# upstream success types describe only well-formed values. Callbacks, manually
# assembled structs, and Plug connections can still violate those types, so the
# fallback clauses must remain fail closed instead of raising.
[
  # OTP 29 attributes generated contract checks in these modules to line 1.
  {"lib/attesto_phoenix/config.ex", :pattern_match, 1},
  {"lib/attesto_phoenix/authorization_server/registration.ex", :pattern_match, 1},
  {"lib/attesto_phoenix/request_context.ex", :pattern_match, 1},
  {"lib/mix/tasks/attesto_phoenix.backfill_refresh_issuer.ex", :pattern_match, 1},

  # Manually assembled Config structs can violate declared struct field types.
  {"lib/attesto_phoenix/config.ex", :pattern_match_cov, {4683, 8}},
  {"lib/attesto_phoenix/config.ex", :pattern_match_cov, {5112, 8}},
  {"lib/attesto_phoenix/config.ex", :pattern_match_cov, {6564, 7}},

  # Host callbacks are not constrained at runtime by their declared success type.
  {"lib/attesto_phoenix/credential_issuer.ex", :pattern_match_cov, {643, 8}},

  # URI and Plug structs can be manually assembled with malformed field values.
  {"lib/attesto_phoenix/duplicate_parameter_guard.ex", :pattern_match, {305, 8}},
  {"lib/attesto_phoenix/duplicate_parameter_guard.ex", :pattern_match_cov, {332, 8}},
  {"lib/attesto_phoenix/duplicate_parameter_guard.ex", :pattern_match_cov, {358, 8}}
]
