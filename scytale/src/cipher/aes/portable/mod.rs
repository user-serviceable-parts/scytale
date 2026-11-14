//! Portable AES implementations, in plain Rust for any target.
//!
//! Two peers, neither of them the default: [`bitsliced`] is constant
//! time, and [`ttable`] is roughly twice as fast but indexes lookup
//! tables with bytes derived from the key, so it leaks through cache
//! timing. The dispatching cipher picks the bitsliced one when the
//! processor has no AES instructions, and the other only where the
//! program has put [`Isolated`](crate::features::Feature::Isolated)
//! in force.

pub(crate) mod bitsliced;
pub(crate) mod ttable;
