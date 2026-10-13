//! Escrow tests. Fermata's Solidity suite (`contracts/test/*.t.sol` @ d7cc642) is ported case by
//! case: test names keep the Solidity names and numbering; `docs/PORTING_NOTES.md`, section 6,
//! maps every case to its Rust test or explains why it does not apply. Stellar-specific cases
//! (auth trees, events, TTL and archival, golden vectors) follow.

mod setup;

mod admin;
mod hold;
mod lifecycle;
mod register;
mod settle;
mod tokens;
