# Contributing

Contributions are very welcome: fixes, tests, documentation, speed, and
new algorithms. For anything larger than a fix, please open an issue first
and say what you have in mind. A new algorithm, a new backend or new
assembly is a design decision as much as code, and it is better
settled before the work than after it.

Security problems are the exception: report those as `SECURITY.md`
says, privately if they are sensitive.

## Before a pull request

```sh
cargo test-extended        # every test, the slow vector suites too
scripts/ci-check           # formatting and the style checks, as CI
cargo clippy --workspace --all-targets --profile test -- -D warnings
```

Run the tests from a checkout with `SCYTALE_VECTORS=required` set, so
that a vector suite which cannot find its files fails rather than
skipping. `scripts/ci-check` needs python3 with PyYAML.

Version numbers and releases are the maintainer's: please do not bump
a version in a pull request.

## Licence

By raising a PR, you are placing your contribution under the project's
licence: BSD-2-Clause.
