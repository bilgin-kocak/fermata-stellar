//! Fermata on Stellar attestor (`fermata-attest`): proves a vendor's HTTPS response with
//! TLSNotary, binds the presentation to an open hold in the Soroban escrow, evaluates the
//! service's delivery predicate and signs the Ed25519 verdict that the escrow's `settle` accepts.
//!
//! Ported from Fermata `apps/attestor` @ d7cc642 (github.com/bilgin-kocak/fermata, Apache-2.0),
//! whose TLSNotary plumbing comes from WebProof (github.com/bilgin-kocak/webproof-solana,
//! Apache-2.0) and the upstream `attestation` example at tlsn v0.1.0-alpha.15. Each module says
//! what it keeps from Fermata and what changed; `docs/PORTING_NOTES.md` section 9 has the overview.

pub mod chain;
pub mod config;
pub mod hashes;
pub mod http_raw;
pub mod notary;
pub mod predicate;
pub mod prove;
pub mod serve;
pub mod tunnel;
pub mod verify;
