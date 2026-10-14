//! The bytes the agent and the verifier sign, rebuilt on-chain. They must match
//! `crates/fermata-verdict/src/session.rs` byte for byte; `test-vectors/session-v1.json` pins them
//! (`docs/session-escrow.md`, section 10).
//!
//! Byte strings are built in this contract's linear memory and handed to the host once: the host's
//! `Bytes` is immutable, so appending piece by piece would copy the whole buffer every time.

use soroban_sdk::{address_payload::AddressPayload, Bytes, BytesN, Env};

/// Versioned domain tags.
pub const TICKET_TAG: &[u8; 25] = b"FERMATA_STELLAR_TICKET_V1";
pub const BATCH_TAG: &[u8; 24] = b"FERMATA_STELLAR_BATCH_V1";
pub const CALL_TAG: &[u8; 31] = b"FERMATA_STELLAR_SESSION_CALL_V1";

pub const TICKET_LEN: usize = 25 + 32 * 3 + 4 + 32;
/// `result (u32) ‖ presentation_hash ‖ response_hash`.
pub const ENTRY_LEN: u32 = 4 + 32 + 32;
pub const STATEMENT_LEN: usize = 24 + 32 * 5 + 4 + 4 + 32 * 3;

/// One call's entry, read from a batch's entries.
pub struct Entry {
    pub result: u32,
    pub presentation_hash: [u8; 32],
    pub response_hash: [u8; 32],
}

/// `chain(n) = sha256(chain(n−1) ‖ request_hash)`.
pub fn chain_next(env: &Env, chain: &[u8; 32], request_hash: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(chain);
    buf[32..].copy_from_slice(request_hash);
    env.crypto()
        .sha256(&Bytes::from_array(env, &buf))
        .to_array()
}

/// `"FERMATA_STELLAR_TICKET_V1" ‖ network id ‖ this contract's id ‖ session_id ‖ n ‖ chain(n)`.
pub fn ticket(env: &Env, session_id: &[u8; 32], n: u32, chain: &[u8; 32]) -> Bytes {
    let mut m = [0u8; TICKET_LEN];
    let mut w = Writer::new(&mut m);
    w.put(TICKET_TAG);
    w.put(&env.ledger().network_id().to_array());
    w.put(&contract_id(env));
    w.put(session_id);
    w.put(&n.to_be_bytes());
    w.put(chain);
    w.done();
    Bytes::from_array(env, &m)
}

/// `"FERMATA_STELLAR_BATCH_V1" ‖ network id ‖ this contract's id ‖ session_id ‖ service_id ‖
/// predicate_hash ‖ from ‖ to ‖ chain(to) ‖ seed ‖ entries_hash`.
#[allow(clippy::too_many_arguments)]
pub fn statement(
    env: &Env,
    session_id: &[u8; 32],
    service_id: &[u8; 32],
    predicate_hash: &[u8; 32],
    from: u32,
    to: u32,
    chain: &[u8; 32],
    seed: &[u8; 32],
    entries_hash: &[u8; 32],
) -> Bytes {
    let mut m = [0u8; STATEMENT_LEN];
    let mut w = Writer::new(&mut m);
    w.put(BATCH_TAG);
    w.put(&env.ledger().network_id().to_array());
    w.put(&contract_id(env));
    w.put(session_id);
    w.put(service_id);
    w.put(predicate_hash);
    w.put(&from.to_be_bytes());
    w.put(&to.to_be_bytes());
    w.put(chain);
    w.put(seed);
    w.put(entries_hash);
    w.done();
    Bytes::from_array(env, &m)
}

/// Entry `i` (0-based) of a batch's concatenated entries.
pub fn entry(entries: &Bytes, i: u32) -> Entry {
    let mut buf = [0u8; ENTRY_LEN as usize];
    entries
        .slice(i * ENTRY_LEN..(i + 1) * ENTRY_LEN)
        .copy_into_slice(&mut buf);
    let mut presentation_hash = [0u8; 32];
    let mut response_hash = [0u8; 32];
    presentation_hash.copy_from_slice(&buf[4..36]);
    response_hash.copy_from_slice(&buf[36..68]);
    Entry {
        result: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
        presentation_hash,
        response_hash,
    }
}

/// Request hash `i` (0-based) of a batch's concatenated request hashes.
pub fn request_hash(request_hashes: &Bytes, i: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    request_hashes
        .slice(i * 32..(i + 1) * 32)
        .copy_into_slice(&mut out);
    out
}

/// Whether call `n` is proved: always for k = 1; otherwise when the first four bytes of
/// `sha256(seed ‖ n)`, big-endian, are a multiple of k.
pub fn sampled(env: &Env, seed: &[u8; 32], n: u32, k: u32) -> bool {
    if k <= 1 {
        return true;
    }
    let mut buf = [0u8; 36];
    buf[..32].copy_from_slice(seed);
    buf[32..].copy_from_slice(&n.to_be_bytes());
    let digest = env
        .crypto()
        .sha256(&Bytes::from_array(env, &buf))
        .to_array();
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]).is_multiple_of(k)
}

/// `sha256("FERMATA_STELLAR_SESSION_CALL_V1" ‖ this contract's id ‖ session_id ‖ n)`.
pub fn call_id(env: &Env, session_id: &[u8; 32], n: u32) -> BytesN<32> {
    let mut m = [0u8; 31 + 32 + 32 + 4];
    let mut w = Writer::new(&mut m);
    w.put(CALL_TAG);
    w.put(&contract_id(env));
    w.put(session_id);
    w.put(&n.to_be_bytes());
    w.done();
    env.crypto().sha256(&Bytes::from_array(env, &m)).into()
}

pub fn sha256(env: &Env, bytes: &Bytes) -> [u8; 32] {
    env.crypto().sha256(bytes).to_array()
}

/// The 32-byte id inside this contract's `C…` address. `to_payload` is used only to read the
/// contract's own id for domain separation, never to authenticate an account.
fn contract_id(env: &Env) -> [u8; 32] {
    match env.current_contract_address().to_payload() {
        Some(AddressPayload::ContractIdHash(id)) => id.to_array(),
        _ => panic!("a contract address has a contract id"),
    }
}

/// Writes fixed-width fields into a buffer and checks that they fill it exactly.
struct Writer<'a> {
    buf: &'a mut [u8],
    at: usize,
}

impl<'a> Writer<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, at: 0 }
    }

    fn put(&mut self, part: &[u8]) {
        self.buf[self.at..self.at + part.len()].copy_from_slice(part);
        self.at += part.len();
    }

    fn done(self) {
        assert_eq!(self.at, self.buf.len(), "fixed-width layout");
    }
}
