# Contributing

Thank you for contributing to AttestoPhoenix. Open an issue before a large
change so the intended behavior and compatibility constraints can be agreed
first.

Run `mix precommit` before opening a pull request. Changes involving Ecto must
also run the database-tagged test suite. Security-sensitive changes should
include regression tests for refusal paths as well as the successful path.

## Contributor credit

Accepted external contributions are credited by GitHub handle and pull request
in the release changelog entry that first includes them. The merge also
preserves Git commit authorship or an appropriate `Co-authored-by` trailer.

Credit is added when the contribution lands, not while it is still under
review. Security reporters may request anonymous or alternate attribution.
