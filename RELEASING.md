# Releasing

The four crates, `scytale`, `scytale-ring`, `rustls-scytale` and
`scytale-cli`, each have their own version and are released on their
own. A release is one commit that bumps the version of each crate
going out, a tag for each, and a `cargo publish` for each, the
library first. The version changes only here, at release; a feature
or an API change does not carry a bump with it.

Tags name the crate: `scytale-v0.10.0`, `scytale-ring-v0.10.1`. Each
tag names exactly one crate and version, and `scytale-v*` matches only
the library's.

## 1. Decide what goes out, and at which version

A crate goes out when its own code changed since its last tag:

```sh
git log --oneline scytale-ring-v0.10.0.. -- scytale-ring
```

For each such crate:

- It broke: bump the minor (`0.10.3` to `0.11.0`). Before 1.0 a minor
  is the breaking step, and anything a caller could write against the
  old version that the new one refuses is a break.
- Otherwise, additions and fixes alike: bump the patch (`0.10.0` to
  `0.10.1`). A user then gets the release from `cargo update`, with
  no edit to a manifest.

The shim, the provider and the tool name the oldest library release
that has everything they use: `scytale = { path = ..., version =
"0.N.M" }`. A crate that starts using something added in a library
patch release raises that requirement, and the library goes out first
or in the same release. A new library minor breaks the requirement in
every dependant at once: cargo refuses to build the workspace until
each names the new minor, and each then goes out too, so that its
users get the new library.

`rustls-scytale` pins its `rustls` exactly while rustls 0.24 is a
development release, since each one may change the provider traits,
and its own version is then a pre-release carrying the same suffix:
`0.10.0-dev.2` for rustls `=0.24.0-dev.2`, `0.10.0-dev.2.1` for a fix
against the same rustls, `0.10.0-dev.3` when it moves to the next.
Cargo picks a pre-release only when it is named, so nobody gets one
unasked. It becomes plain `0.10.0` with rustls 0.24.0, and takes the
rules above from then on. Release it only for the rustls development
release that is current.

## 2. Bump every place the version lives

For each crate going out:

- Its `Cargo.toml`: `version`.
- A library release: the `version` in the dependants'
  `scytale = { path = ..., version = "0.N.M" }` lines, where the
  requirement no longer accepts it or a dependant needs what it adds.
- `scytale-ring`: the `ring = { package = "scytale-ring", version =
  "0.N" }` example line in `scytale-ring/README.md`, on a minor bump,
  and the "Which ring" table in the shim's README, which gains a row
  when the ring API it presents changes and otherwise has its
  versions checked.
- `rustls-scytale`: the `rustls-scytale = "0.N"` line in
  `rustls-scytale/README.md`, on a minor bump, and the "Which
  rustls" table in the provider's README, kept the same way.
- `scytale-cli`: the `.TH` line's date and `scytale 0.N` in
  `scytale-cli/scytale.1`. `cargo test -p scytale-cli` fails if this
  is missed. Then `scripts/man-md` to regenerate `scytale.1.md`.
- `Cargo.lock`: `cargo update -w` records the new versions.

`grep -rn '0\.OLD' --include=Cargo.toml --include='*.md'
--include='*.1' . | grep -v target` finds anything this list has
forgotten.

## 3. Check what the READMEs claim

- The ACVP case count in `scytale/README.md` ("The ACVP corpus is
  93 suites holding M cases") is hand-maintained and counts the cases
  the drivers answer and compare, once per suite, after every
  documented skip. Step 4 checks it from CI's logs.
- Every speed figure in `scytale/README.md` and the shim's README
  against the full benchmark pass of step 4, updated where it moved.
  No figure goes out that was not measured on the code being
  released.
- The algorithm tables, if a primitive was added: `scytale/README.md`,
  `scytale/src/lib.rs`, `SECURITY.md`, the shim's README, and the
  tool's README and manual.

## 4. Run everything

Whichever crates go out, every check runs: the dependants are the
library's most demanding tests. Every check must pass, the session
on the demo server included. A failure stops the release: it is
fixed on a branch of its own, merged, and the release starts again
from step 1. Nothing is skipped, waived or rerun until it happens to
pass.

The checks are CI's, every job of `ci.yml`, run on the release
branch's pull request with the versions bumped and the report of step
5 written, so that one push carries the whole release and CI runs
once. They pass when every job passes on that commit. `ci.yml` is the
list: the style job, every crate's tests and the vendored vectors
on the native, RISC-V and 32-bit jobs, the dispatch checks on the
emulated processors, the wasm32 and bare-metal builds, clippy, the
docs, rustls and webpki on the shim, rustls and
BoGo on the provider, the provider against OpenSSL, and the crates
packaged and built as they will be published. The README's ACVP case
count is checked from the same run: the x86-64 vendored shards print
the cases of each suite under each profile, and the profile that holds
all of them totals it.

A dependant going out without a library release must also build
against the library crates.io already has, which is what its users
get:

```sh
cargo package -p scytale-ring
```

CI does not do that one, so it runs here.

Then the two runs that only a release does, on the same commit. The
benchmarks, a full pass on the reference machine, settled first:

```sh
sudo scripts/bench-quiet
scripts/bench --save i7-1355u
```

and a real session on NIST's demo server, every suite under every
implementation this processor can run, from a release build. It is a
real session and not a sample one because only a real one can pass
the RSA decryption primitive, for the reason
`scytale-acvp/README.md` gives:

```sh
cargo build --release -p scytale-acvp
( set -a; . ~/.acvp/mwp.sh
  target/release/scytale-acvp run --every-kernel )
```

It passes when it exits 0: every vector set registered was passed by
the server, and every implementation gave the same answers. A run cut
off by the network is taken up with `scytale-acvp resume DIR`, which
judges the same session; that is not a rerun.

## 5. Report, commit, tag, push

The report is `releases/<first tag>.md`, the first tag being the
library's when it goes out, and goes in the release commit. It says:

- The crates going out and their versions, and the commit the runs
  were made on.
- That the checks are CI's run on the release pull request, where
  the result is read; it is not written back, which would take a
  second push and a second run.
- The demo-server session: its number, the vector sets registered
  and passed, the profiles walked, and the exit status. The row is
  added to the table in `scytale-acvp/README.md` too.
- The benchmarks: the saved file, its header's commit and machine
  state, and the rows that moved against the previous saved pass by
  `scripts/bench --compare`, with the reason where one is known.

One commit, subject naming each crate going out and its version
(`scytale 0.10.1, scytale-cli 0.10.2: <what the release is>`), body
saying what changed for a user of each. Then a tag for each crate:

```sh
git tag -a scytale-v0.N.M -m "scytale 0.N.M"
git push && git push --tags
```

Wait for CI on the release commit on `main` to pass on every job
before publishing.

## 6. Publish, library first

```sh
cargo publish -p scytale
cargo publish -p scytale-ring
cargo publish -p rustls-scytale
cargo publish -p scytale-cli
```

Only the crates going out, in this order. crates.io must have a new
library before the shim's, the provider's and the tool's verify
builds can resolve it. A failed publish after the library's is redone
once the library is visible; nothing needs unpublishing.

## 7. Afterwards

- The tags are the release; GitHub's release pages have not been
  used. The notes are in the commit body, and the evidence in the
  report under `releases/`.
- `docs.yml` publishes the library's documentation from `main`; check
  https://docs.rs/scytale built the new version.
- `TODO` records what the release closed and what it opened.
