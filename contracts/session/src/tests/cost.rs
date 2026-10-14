//! What `settle_batch` costs in the host's cost model (soroban-env-host as pinned by soroban-sdk),
//! measured on the built wasm of both contracts (the session contract reads the escrow's
//! treasury): when a contract runs natively, as in the other tests, only host functions are
//! metered, not the wasm VM's own instructions.
//!
//! The test needs both contracts' wasm, so a plain `cargo test` skips it; CI runs it after the
//! builds:
//!
//! ```text
//! stellar contract build --package fermata-escrow
//! stellar contract build --package fermata-session
//! cargo test -p fermata-session cost -- --ignored --nocapture
//! ```
//!
//! It prints CPU instructions, memory and the size of the batch's arguments for batches of 1 to
//! `MAX_BATCH` calls, and checks them against limits read from a local network (quickstart,
//! protocol 29): 400 M instructions, 40 MiB of memory and 132,096 bytes per transaction. Testnet's
//! limits may be lower; the script `scripts/session-cases.sh` simulates batches on the network
//! it runs against.

use super::setup::*;
use crate::{SessionStatus, MAX_BATCH};

const WASM_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/wasm32v1-none/release"
);

fn wasm(name: &str) -> std::vec::Vec<u8> {
    let path = std::format!("{WASM_DIR}/{name}.wasm");
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Per transaction, on the local network the CI runs (`stellar network settings`).
const TX_MAX_INSTRUCTIONS: u64 = 400_000_000;
const TX_MEMORY_LIMIT: u64 = 40 * 1024 * 1024;
const TX_MAX_SIZE_BYTES: u32 = 132_096;

#[test]
#[ignore = "needs the wasm of both contracts (stellar contract build)"]
fn settle_batch_costs_on_the_wasm() {
    let (escrow, session) = (wasm("fermata_escrow"), wasm("fermata_session"));
    std::println!(
        "settle_batch, every call proved (k = 1), on {} bytes of wasm (the escrow's: {}):",
        session.len(),
        escrow.len()
    );
    for calls in [1, 10, 100, 250, 500, MAX_BATCH] {
        let f = Fixture::with_contracts(
            |env, args| env.register(escrow.as_slice(), args),
            |env, escrow| env.register(session.as_slice(), (escrow,)),
        );
        let id = sid(&f.env, 1);
        f.open(&id, calls, 1, calls, [0; 32]);
        let entries: std::vec::Vec<_> = (1..=calls).map(delivered).collect();
        let requests: std::vec::Vec<_> = (1..=calls).map(request).collect();
        let b = f.next_batch(&id, &requests, [0; 32], &entries);
        // The variable part of the arguments; the rest (ids, signatures, seed) is 228 bytes.
        let args = b.request_hashes.len() + b.entries.len();
        let mut budget = f.env.cost_estimate().budget();
        budget.reset_default();
        f.settle(&id, &b);
        let cpu = budget.cpu_instruction_cost();
        let mem = budget.memory_bytes_cost();
        std::println!(
            "  {calls:>5} calls: {cpu:>11} CPU instructions ({:>6} per call), {mem:>9} bytes of memory, {args:>6} bytes of request hashes and entries",
            cpu / u64::from(calls)
        );
        assert_eq!(f.get(&id).status, SessionStatus::Closed);
        assert!(
            cpu < TX_MAX_INSTRUCTIONS,
            "{calls} calls: {cpu} instructions"
        );
        assert!(
            mem < TX_MEMORY_LIMIT,
            "{calls} calls: {mem} bytes of memory"
        );
        assert!(
            args + 1_000 < TX_MAX_SIZE_BYTES,
            "{calls} calls: {args} bytes of arguments"
        );
    }
}
