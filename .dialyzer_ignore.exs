# These narrow filters retain runtime validation at external boundaries where
# upstream success types describe only well-formed values. Callbacks, manually
# assembled structs, and Plug connections can still violate those types, so the
# fallback clauses must remain fail closed instead of raising.
[
  # OTP 29 attributes generated contract checks in these modules to line 1.
  {"lib/attesto_phoenix/config.ex", :pattern_match, 1},
  {"lib/attesto_phoenix/controller/registration_controller.ex", :pattern_match, 1},
  {"lib/mix/tasks/attesto_phoenix.backfill_refresh_issuer.ex", :pattern_match, 1},

  # A Policy struct can be assembled with nil despite the declared field type.
  {"lib/attesto_phoenix/config.ex", :pattern_match, {5269, 8}},

  # Host callbacks are not constrained at runtime by their declared success type.
  {"lib/attesto_phoenix/controller/credential_controller.ex", :pattern_match_cov, {380, 8}},

  # URI and Plug structs can be manually assembled with malformed field values.
  {"lib/attesto_phoenix/controller/registration_controller.ex", :pattern_match_cov, {549, 8}},
  {"lib/attesto_phoenix/duplicate_parameter_guard.ex", :pattern_match, {279, 8}},
  {"lib/attesto_phoenix/duplicate_parameter_guard.ex", :pattern_match_cov, {304, 8}},
  {"lib/attesto_phoenix/duplicate_parameter_guard.ex", :pattern_match_cov, {330, 8}}
]
