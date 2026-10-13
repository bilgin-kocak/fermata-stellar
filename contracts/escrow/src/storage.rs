//! Storage layout and TTL (time to live) management.
//!
//! - Instance storage (owner, treasury, fee) is one ledger entry shared with the contract; it is
//!   extended on every state-changing call.
//! - Services are persistent entries, extended at registration and on every hold, so a service
//!   always outlives its open holds.
//! - Holds are persistent entries, one per call id, extended at `hold` to cover the settlement
//!   window plus a grace period for `claim_timeout`, and never again.
//!
//! An entry whose TTL runs out is archived, not deleted: a later transaction that touches it
//! restores it (automatically since protocol 23) and sees its real state. So a call id can never
//! be reused and held funds can always be settled or refunded. TTL only affects cost and
//! convenience; no rule here depends on it, and anyone may extend any entry's TTL.

use soroban_sdk::{contracttype, Address, BytesN, Env};

use crate::{Hold, Service};

/// Nominal ledger close time used to convert a settlement window into ledgers.
pub const LEDGER_SECONDS: u32 = 5;
pub const DAY_IN_LEDGERS: u32 = 17_280;
/// Instance and service entries: extend to 120 days whenever fewer than 60 days remain.
pub const SHARED_TTL_THRESHOLD: u32 = 60 * DAY_IN_LEDGERS;
pub const SHARED_TTL_EXTEND_TO: u32 = 120 * DAY_IN_LEDGERS;
/// Time left after a hold's window for someone to call `claim_timeout` before it archives.
pub const HOLD_GRACE_LEDGERS: u32 = 7 * DAY_IN_LEDGERS;

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Owner,
    Treasury,
    FeeBps,
    Service(BytesN<32>),
    Hold(BytesN<32>),
}

/// The ledgers a hold must stay live: its window (rounded up) plus the grace period.
pub fn hold_ttl(settlement_window: u32) -> u32 {
    settlement_window.div_ceil(LEDGER_SECONDS) + HOLD_GRACE_LEDGERS
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

pub fn owner(env: &Env) -> Address {
    env.storage()
        .instance()
        .get(&DataKey::Owner)
        .expect("set at construction")
}

pub fn set_owner(env: &Env, owner: &Address) {
    env.storage().instance().set(&DataKey::Owner, owner);
}

pub fn treasury(env: &Env) -> Address {
    env.storage()
        .instance()
        .get(&DataKey::Treasury)
        .expect("set at construction")
}

pub fn set_treasury(env: &Env, treasury: &Address) {
    env.storage().instance().set(&DataKey::Treasury, treasury);
}

pub fn fee_bps(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&DataKey::FeeBps)
        .expect("set at construction")
}

pub fn set_fee_bps(env: &Env, fee_bps: u32) {
    env.storage().instance().set(&DataKey::FeeBps, &fee_bps);
}

pub fn has_service(env: &Env, service_id: &BytesN<32>) -> bool {
    env.storage()
        .persistent()
        .has(&DataKey::Service(service_id.clone()))
}

pub fn service(env: &Env, service_id: &BytesN<32>) -> Option<Service> {
    env.storage()
        .persistent()
        .get(&DataKey::Service(service_id.clone()))
}

pub fn set_service(env: &Env, service_id: &BytesN<32>, service: &Service) {
    let key = DataKey::Service(service_id.clone());
    env.storage().persistent().set(&key, service);
    extend_service(env, service_id);
}

pub fn extend_service(env: &Env, service_id: &BytesN<32>) {
    let to = capped(env, SHARED_TTL_EXTEND_TO);
    env.storage().persistent().extend_ttl(
        &DataKey::Service(service_id.clone()),
        SHARED_TTL_THRESHOLD.min(to),
        to,
    );
}

pub fn has_hold(env: &Env, call_id: &BytesN<32>) -> bool {
    env.storage()
        .persistent()
        .has(&DataKey::Hold(call_id.clone()))
}

pub fn hold(env: &Env, call_id: &BytesN<32>) -> Option<Hold> {
    env.storage()
        .persistent()
        .get(&DataKey::Hold(call_id.clone()))
}

pub fn set_hold(env: &Env, call_id: &BytesN<32>, hold: &Hold) {
    env.storage()
        .persistent()
        .set(&DataKey::Hold(call_id.clone()), hold);
}

/// Keeps a new hold live for its window plus the grace period. A no-op where the network's
/// minimum TTL for new persistent entries is already longer.
pub fn extend_hold(env: &Env, call_id: &BytesN<32>, settlement_window: u32) {
    let ttl = capped(env, hold_ttl(settlement_window));
    env.storage()
        .persistent()
        .extend_ttl(&DataKey::Hold(call_id.clone()), ttl, ttl);
}
