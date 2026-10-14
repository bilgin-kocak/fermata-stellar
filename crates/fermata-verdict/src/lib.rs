//! Fermata on Stellar: the verdict a registered verifier signs, encoded exactly as the escrow
//! contract (`contracts/escrow`) rebuilds it on-chain before calling the host's `ed25519_verify`.
//!
//! The signed message is 294 bytes, every field fixed-width and every integer big-endian:
//!
//! ```text
//! "FERMATA_STELLAR_VERDICT_V1" ‖ sha256(network passphrase) ‖ escrow contract id ‖ canonical(verdict)
//! ```
//!
//! `canonical(verdict)` is `call_id ‖ service_id ‖ request_hash ‖ predicate_hash ‖ outcome (u32) ‖
//! presentation_hash ‖ response_hash ‖ issued_at (u64)`. The network id and the contract id play
//! the roles of EIP-712's `chainId` and `verifyingContract` in Fermata's Tempo version. The golden
//! vectors in `test-vectors/verdict-v1.json` pin this encoding for both this crate and the contract.
//!
//! The crate also derives service ids and computes the registration hashes (`hashes`), so scripts
//! and, from Milestone 1, the attestor share one implementation. `session` encodes the agent's
//! tickets and the verifier's batch statements for the session contract (`contracts/session`).

pub mod hashes;
pub mod hex32;
pub mod keys;
pub mod service;
pub mod session;
pub mod session_vectors;
pub mod vectors;
pub mod verdict;

pub use service::{service_id, Owner, LABEL_LEN, SERVICE_TAG};
pub use verdict::{
    message, network_id, sign, verify, Domain, Verdict, CANONICAL_LEN, FUTURENET_PASSPHRASE,
    MAINNET_PASSPHRASE, MESSAGE_LEN, OUTCOME_DELIVERED, OUTCOME_FAILED, STANDALONE_PASSPHRASE,
    TESTNET_PASSPHRASE, VERDICT_TAG,
};

/// Errors from parsing keys, addresses and hex input, and from signature verification.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid hex: {0}")]
    Hex(String),
    #[error("expected {expected} bytes, got {got}")]
    Length { expected: usize, got: usize },
    #[error("invalid strkey {0:?}: expected {1}")]
    Strkey(String, &'static str),
    #[error("invalid secret: expected a Stellar secret seed (S…) or 64 hex characters")]
    Secret,
    #[error("invalid label {0:?}: 1 to 12 bytes of ASCII, or 24 hex characters with a 0x prefix")]
    Label(String),
    #[error("invalid Ed25519 public key")]
    PublicKey,
    #[error("signature verification failed")]
    Signature,
    #[error("{0}")]
    Origin(String),
}

/// Lower-case hex without a prefix, the form the Stellar CLI takes for `BytesN` arguments.
pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Parses hex with or without a `0x` prefix into exactly `N` bytes.
pub fn parse_hex<const N: usize>(s: &str) -> Result<[u8; N], Error> {
    let s = s.trim();
    let digits = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(digits).map_err(|e| Error::Hex(e.to_string()))?;
    let got = bytes.len();
    bytes
        .try_into()
        .map_err(|_| Error::Length { expected: N, got })
}
