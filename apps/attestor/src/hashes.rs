//! The hashes that bind a presentation to a service and a hold, and hex helpers.
//!
//! The hashes are `fermata-verdict`'s, the Milestone 0 port of Fermata `apps/attestor/src/hashes.rs`
//! @ d7cc642 (github.com/bilgin-kocak/fermata), with the same definitions and vectors. The hex
//! helpers are Fermata's `parse_hex32` and `hex0x`, plus `to_hex` for JSON output.

pub use fermata_verdict::hashes::{
    Origin, keccak256, notary_key_hash, predicate_hash, request_hash,
};
/// Hex without a prefix: how this attestor's JSON and the Stellar CLI write byte values.
pub use fermata_verdict::to_hex;

/// 32 bytes of hex, with or without `0x`.
pub fn parse_hex32(s: &str) -> anyhow::Result<[u8; 32]> {
    Ok(fermata_verdict::parse_hex::<32>(s)?)
}

/// Hex with `0x`: the value of the `X-Fermata-Call` header and of stored presentation file names,
/// unchanged from Fermata.
pub fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}
