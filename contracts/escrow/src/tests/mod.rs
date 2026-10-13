//! Escrow tests. Fermata's Solidity suite (`contracts/test/*.t.sol` @ d7cc642) is ported case by
//! case: each test's doc comment names the Solidity test it ports and its number in
//! `docs/PORTING_NOTES.md`, section 6, which also explains the cases that do not apply. The
//! Stellar-specific cases (auth trees, token movements, TTL and archival, golden vectors) sit next
//! to the ports they extend.

mod setup;

mod admin;
mod hold;
mod invariants;
mod lifecycle;
mod props;
mod register;
mod settle;
mod tokens;
mod ttl;
mod vectors;
