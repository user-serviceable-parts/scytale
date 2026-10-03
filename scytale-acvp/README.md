# scytale-acvp

Runs [scytale](../scytale) against NIST's ACVP demo server, the
service behind the Cryptographic Algorithm Validation Program. The
tool registers what the library can do, downloads the vector sets
the server generates for it, hands them to the library to answer,
sends the answers back and reports the verdict. It is a development
tool, run on demand from a checkout, never from CI and never
published.

The vendored vector files under `scytale/tests/vectors` check the
same arithmetic offline, against one frozen sample. The live server
adds what a file cannot: vectors drawn afresh each run, the groups
where the implementation under test must generate keys and random
signatures for the server to check, and the capability registration
a validation begins with.

## Credentials

NIST issues them on request; see "Obtaining TLS credentials" in the
[ACVP repository](https://github.com/usnistgov/ACVP). You get a
client certificate for mutual TLS, issued against a CSR you send,
and a base64 TOTP seed. The tool reads them from the environment
and prints none of them, nor any token:

| Variable | Holds |
| --- | --- |
| `ACVP_CLIENT_CERT` | path to the certificate, PEM |
| `ACVP_CLIENT_KEY` | path to its private key, PEM |
| `ACVP_TOTP_SEED` | the seed, base64 as NIST sent it |
| `ACVP_SERVER` | another server; the default is `https://demo.acvts.nist.gov` |

The one-time password is RFC 6238 with HMAC-SHA-256, eight digits
and a thirty second step, computed by the library's own HMAC. The
machine's clock has to be right to within a step.

## Running

Three steps. The first and last are this tool; the middle one is
the library's test build, because the code that answers a vector
set is the code that runs the vendored suites, and it lives inside
the crate where it can reach every implementation.

```sh
cargo run -p scytale-acvp -- register --sample
# prints the session id, say 12345

SCYTALE_ACVP_SESSION=target/acvp/12345 \
    cargo test -p scytale --lib acvp::live -- --ignored --nocapture

cargo run -p scytale-acvp -- submit 12345
```

`register --sample` asks for a sample session, for which the server
also hands over its expected answers; the answering step then
reports the first differing case itself when one disagrees, which is
the quicker way to debug a failure than the server's verdict.
`--algorithm NAME` registers a subset, by the names `list` prints;
`--large-data` asks for the hash tests that run to gigabytes.
`status` reads a session's verdict again without uploading.

Exit status: 0 when every vector set passed, 1 when any did not, 2
when the run itself failed.

## The session directory

Each session is a directory under `target/acvp`:

```text
target/acvp/12345/
    session.json          url, token, vector set urls, isSample
    <vsId>.prompt.json    the vector set as downloaded
    <vsId>.expected.json  the server's answers, sample sessions only
    <vsId>.response.json  the answers, written by the library
    <vsId>.result.json    the server's verdict
```

`session.json` holds the session's token and is readable by its
owner only. The prompts can be copied to another machine and
answered there, which is how another architecture is run against
the same session.

## What is registered

Only what the library's answering step can answer, so that a gap is
a missing registration and never a failed vector set. The
registration lives in `src/registration`, one file per algorithm
family, each written from that family's specification at
<https://pages.nist.gov/ACVP/>. `cargo run -p scytale-acvp -- list`
prints the current names.
