//! ACVP drivers for scytale.
//!
//! Each driver in [`suite`] answers one ACVP vector set: it reads the
//! prompt as the server or a vendored `internalProjection.json` gives
//! it and returns the response document the server expects. The same
//! drivers run the vendored files under `cargo test`, where every
//! answered field is compared with the file's, and the live sessions
//! the `scytale-acvp` binary opens against NIST's servers.
//!
//! The drivers reach the library only through its public API, so a
//! run says what a user of the crate would see.
//!
//! The session against a server is the `session` feature, on by
//! default; without it the drivers, the offline check and the replay
//! remain, and nothing links the system TLS library.

#[cfg(feature = "session")]
pub mod client;
pub mod envelope;
#[cfg(feature = "session")]
pub mod http;
pub mod profile;
pub mod replay;
pub mod suite;
pub mod support;
pub mod totp;

pub use support::Error;
