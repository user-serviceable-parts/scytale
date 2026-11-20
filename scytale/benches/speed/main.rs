//! Throughput of the primitives, in the manner of `openssl speed`,
//! and the cost of the operations that have no throughput to
//! measure.
//!
//! ```text
//! cargo bench -p scytale                       # everything
//! cargo bench -p scytale -- gcm none           # rows matching both
//! cargo bench -p scytale -- --seconds 0.25     # a quicker sweep
//! cargo bench -p scytale -- --help
//! ```
//!
//! `BENCHMARKING.md` at the top of the repository is the guide: the
//! options, how to read the figures, and the script that settles a
//! Linux machine for a run that is to be kept.
//!
//! A bench target and not a test, so that it is built against the
//! library as any caller's code is and reached the way every other
//! Rust benchmark is. It has a harness of its own rather than the
//! usual ones for what it reports: cycles from the processor's
//! counter beside the rate, both around the same work.

use std::process::ExitCode;

// The harness times a thread by its processor clock, and wasm has no
// such clock to read, so there the target builds and measures
// nothing.
#[cfg(not(target_family = "wasm"))]
mod harness;

fn main() -> ExitCode {
    #[cfg(not(target_family = "wasm"))]
    {
        harness::main()
    }
    #[cfg(target_family = "wasm")]
    {
        ExitCode::SUCCESS
    }
}
