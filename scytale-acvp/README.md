# scytale-acvp

The NIST ACVP suites for [scytale](../scytale), as one set of
drivers that runs two ways: offline, against the sample vector files
NIST publishes, under `cargo test`; and online, against NIST's ACVP
servers, as the `scytale-acvp` binary. Not published: it is a tool
of the repository.

The drivers reach the library only through its public API, so a run
says what a user of the crate would see. None of this is a CAVP
validation; scytale has none.

## Offline

`vectors/` holds the sample files from NIST's
[ACVP-Server](https://github.com/usnistgov/ACVP-Server) repository,
one directory per suite, each an `internalProjection.json` carrying
the prompts and the expected answers together. Every driver answers
its file as it would answer the server, and the check compares every
field of the answer with the field of that name in the file, group
by group and case by case. Suites whose stored answers came from
NIST's own randomness (ECDSA sigGen, RSA sigGen, KTS-IFC) are
verified instead: the answered signature under the answered key, and
NIST's under NIST's.

```sh
SCYTALE_VECTORS=required cargo test -p scytale-acvp
```

runs the quick form of every suite. The Monte Carlo groups, which
chain a thousand calls per case, the large-data groups, which hash
gigabytes, and the whole of SLH-DSA wait for

```sh
cargo test-extended
```

which runs `vendored_extended`, every suite in full, and prints the
count of cases compared. `SCYTALE_VECTORS=required` makes a missing
file a failure rather than a skip.

`cargo test-every-profile` answers every symmetric suite once per
feature profile this processor can run and insists the answers agree:
the check that each hardware kernel does what the portable one does.
It edits the process-wide set of features in force, so it runs alone.

## Online

The session needs the credentials NIST issues for its servers: a
client certificate and key, and the seed of the one-time password
the login takes. They are read from `ACVP_CLIENT_CERT`,
`ACVP_CLIENT_KEY` and `ACVP_TOTP_SEED`, or given as `--cert`,
`--key` and `--totp-seed`.

```sh
cargo build --release -p scytale-acvp
target/release/scytale-acvp run --sample --algorithms SHA2-256
```

builds the tool, which is run as a release build since a debug one is
many times slower over a whole session, and opens a sample session on
the demo server, answers the SHA2-256 vector set, checks it against
the answers the server hands out for a sample, posts it, and reports
the server's verdict. Without
`--sample` the server keeps its answers to itself, as it does for a
validation. Without `--algorithms` every suite in `vectors/` is
registered. `--server` names another server; the default is
`https://demo.acvts.nist.gov/acvp/v1`.

`--every-kernel` answers each vector set once per feature profile
this processor can run, from the same seed, and compares the
answers before posting one. A difference is fatal: nothing is
posted, and the run stops with exit status 2 naming the two
profiles, the group and the case. `scytale-acvp profiles` prints the
walk for this processor.

A run writes every prompt, answer, expected answer and verdict to a
directory, `acvp-<session id>` unless `--save DIR` names another.
When a run dies part way, from a network fault or a driver fault the
server found, `scytale-acvp resume DIR` takes the session up again:
the server still holds its vector sets and verdicts, so the sets it
has passed are left alone and the rest are fetched, answered and
posted as before. `--algorithms` narrows that to the suites named,
for a set that needed a driver fix, and `--every-kernel` applies as
in `run`. `scytale-acvp replay DIR` answers the saved prompts again
and compares them with the saved expected answers, offline.

`scytale-acvp registration` prints the capability objects that would
be sent; `scytale-acvp totp` the current one-time code, to check the
seed and the clock.

Exit status: 0 when every vector set passed, 1 when the server failed
a case, 2 when two implementations disagreed, 3 for anything else.

The session is the crate's `session` feature, on by default, and the
only part that links the system TLS library; `--no-default-features`
leaves the drivers, the offline check and `replay` for the targets
that cross-compile or run under emulation.

## What is registered

`registrations.json` holds the capability object of each suite,
keyed by its directory under `vectors/`: NIST's own registration for
the suite, cut down to what the library offers. Curves are P-256,
P-384 and P-521, Ed25519 and X25519; hashes are SHA-1, SHA-2, SHA-3
and the XOFs; there is no Triple DES, no ECDSA or RSA over a XOF, no
SP 800-106 randomized hashing, no ANSI X9.31 signatures, and the
post-quantum signatures offer the pure external interface only. The
AES-CTR DRBG is AES-256 only. RSA keyGen is registered for the one
method the library has, random probable primes under the exponent
65537, at 2048 to 8192 bits; NIST's sample file has no such group,
so that suite is checked offline by its own test and online by the
server. XTS 1.0 and FF3-1 have no registration: the demo server no
longer maps them, XTS having moved to revision 2.0, so their sample
files are checked offline only.

The RSA decryption primitive asks the client to refuse a given number
of the ciphertexts it hands over, which is honest only when the
ciphertext is at or above the client's own modulus. The library's
primes carry their top two bits, so its moduli sit in the upper seven
sixteenths of their width, and a sample session, which draws the
ciphertexts to refuse from the whole upper half, can hand over one
that no key of the library's making can refuse; the driver reports
that rather than refusing falsely. A real session draws them with
the top two bits set and passes.

## The transport

HTTPS through [ureq](https://crates.io/crates/ureq) over the system
TLS library, OpenSSL on Linux, with the client certificate for the
mutual TLS the servers require. A pure-Rust stack was the intent, but
NIST's servers speak TLS 1.2 only and ask for the certificate by
renegotiating once the request is in, which rustls refuses by design.
Should the servers move to TLS 1.3, the transport can run on
[rustls-scytale](../rustls-scytale), the workspace's own provider.
