//! Storage layout and TTL, as in the escrow (`contracts/escrow/src/storage.rs`):
//!
//! - Instance storage holds the escrow's address; it is extended on every state-changing call.
//! - Sessions are persistent entries, one per session id, extended at opening to cover the session
//!   until its deadline plus a grace period for `close_session`, and never again.
//!
//! An entry whose TTL runs out is archived, not deleted, and restored when touched, so a session id
//! can never be reused and a deposit can always be settled or refunded. No rule depends on TTL.

use soroban_sdk::{contracttype, Address, BytesN, Env};

use crate::Session;

/// Nominal ledger close time used to convert seconds into ledgers.
pub const LEDGER_SECONDS: u64 = 5;
pub const DAY_IN_LEDGERS: u32 = 17_280;
/// Instance storage: extend to 120 days whenever fewer than 60 days remain.
pub const SHARED_TTL_THRESHOLD: u32 = 60 * DAY_IN_LEDGERS;
pub const SHARED_TTL_EXTEND_TO: u32 = 120 * DAY_IN_LEDGERS;
/// Time left after a session's deadline for someone to call `close_session` before it archives.
pub const SESSION_GRACE_LEDGERS: u32 = 7 * DAY_IN_LEDGERS;

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Escrow,
    Session(BytesN<32>),
}

/// The ledgers a session must stay live: until its deadline (rounded up) plus the grace period.
pub fn session_ttl(seconds_to_deadline: u64) -> u32 {
    let ledgers = seconds_to_deadline.div_ceil(LEDGER_SECONDS);
    u32::try_from(ledgers)
        .unwrap_or(u32::MAX)
        .saturating_add(SESSION_GRACE_LEDGERS)
}

fn capped(env: &Env, ledgers: u32) -> u32 {
    ledgers.min(env.storage().max_ttl())
}

pub fn extend_instance(env: &Env) {
    let to = capped(env, SHARED_TTL_EXTEND_TO);
    env.storage()
        .instance()
        .extend_ttl(SHARED_TTL_THRESHOLD.min(to), to);
}

pub fn escrow(env: &Env) -> Address {
    env.storage()
        .instance()
        .get(&DataKey::Escrow)
        .expect("set at construction")
}

pub fn set_escrow(env: &Env, escrow: &Address) {
    env.storage().instance().set(&DataKey::Escrow, escrow);
}

pub fn has_session(env: &Env, session_id: &BytesN<32>) -> bool {
    env.storage()
        .persistent()
        .has(&DataKey::Session(session_id.clone()))
}

pub fn session(env: &Env, session_id: &BytesN<32>) -> Option<Session> {
    env.storage()
        .persistent()
        .get(&DataKey::Session(session_id.clone()))
}

pub fn set_session(env: &Env, session_id: &BytesN<32>, session: &Session) {
    env.storage()
        .persistent()
        .set(&DataKey::Session(session_id.clone()), session);
}

/// Keeps a new session live until its deadline plus the grace period.
pub fn extend_session(env: &Env, session_id: &BytesN<32>, seconds_to_deadline: u64) {
    let ttl = capped(env, session_ttl(seconds_to_deadline));
    env.storage()
        .persistent()
        .extend_ttl(&DataKey::Session(session_id.clone()), ttl, ttl);
}
