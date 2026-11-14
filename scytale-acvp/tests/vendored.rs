//! `cargo test -p scytale-acvp`: the check against the vendored
//! vectors, every suite in full under every kernel this processor can
//! run, each once; see `scytale_acvp::vendored`. A binary of its own,
//! without the harness: the run edits the process-wide set of
//! features, so nothing may run beside it, and its report is for
//! reading.

use std::process::ExitCode;

fn main() -> ExitCode {
    match scytale_acvp::vendored::run() {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
