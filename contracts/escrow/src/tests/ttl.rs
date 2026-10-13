//! Storage TTL and state archival. The test host emulates protocol 23's automatic restoration:
//! touching an archived persistent entry restores it, exactly as a transaction on the network
//! that lists it in its footprint does.

use soroban_sdk::{
    testutils::{
        storage::{Instance as _, Persistent as _},
        Ledger as _,
    },
    BytesN,
};

use super::setup::*;
use crate::{
    hold_ttl, DataKey, Error, Status, DAY_IN_LEDGERS, MAX_WINDOW, OUTCOME_DELIVERED,
    SHARED_TTL_EXTEND_TO,
};

fn hold_ttl_of(f: &Fixture, call_id: &BytesN<32>) -> u32 {
    f.env.as_contract(&f.escrow_id(), || {
        f.env
            .storage()
            .persistent()
            .get_ttl(&DataKey::Hold(call_id.clone()))
    })
}

fn service_ttl_of(f: &Fixture, service_id: &BytesN<32>) -> u32 {
    f.env.as_contract(&f.escrow_id(), || {
        f.env
            .storage()
            .persistent()
            .get_ttl(&DataKey::Service(service_id.clone()))
    })
}

fn instance_ttl_of(f: &Fixture) -> u32 {
    f.env
        .as_contract(&f.escrow_id(), || f.env.storage().instance().get_ttl())
}

fn advance_ledgers(f: &Fixture, ledgers: u32) {
    f.env.ledger().with_mut(|l| {
        l.sequence_number += ledgers;
        l.timestamp += u64::from(ledgers) * 5;
    });
}

#[test]
fn a_hold_lives_through_its_window_and_a_grace_period() {
    let f = Fixture::new();
    let id = call(&f.env, 1);
    f.hold(&id);
    // 120 s window = 24 ledgers, plus 7 days to claim the timeout
    assert_eq!(hold_ttl(WINDOW), 24 + 7 * DAY_IN_LEDGERS);
    assert_eq!(hold_ttl_of(&f, &id), hold_ttl(WINDOW));

    // the longest window: 30 days of ledgers plus the grace period
    let long = f.escrow.register_service(
        &f.vendor,
        &label(&f.env, "long"),
        &f.payout,
        &f.token.address,
        &PRICE,
        &MAX_WINDOW,
        &public_key(&f.env, &f.verifier),
        &b32(&f.env, PREDICATE),
        &b32(&f.env, ORIGIN),
        &b32(&f.env, NOTARY),
    );
    let id2 = call(&f.env, 2);
    f.hold_on(&long, &id2);
    assert_eq!(
        hold_ttl(MAX_WINDOW),
        30 * DAY_IN_LEDGERS + 7 * DAY_IN_LEDGERS
    );
    assert_eq!(hold_ttl_of(&f, &id2), hold_ttl(MAX_WINDOW));
}

#[test]
fn instance_and_service_entries_are_extended_when_low() {
    let f = Fixture::new();
    assert_eq!(instance_ttl_of(&f), SHARED_TTL_EXTEND_TO);
    assert_eq!(service_ttl_of(&f, &f.service_id), SHARED_TTL_EXTEND_TO);

    // 30 days later more than the 60-day threshold remains: no extension (and no rent)
    advance_ledgers(&f, 30 * DAY_IN_LEDGERS);
    f.hold(&call(&f.env, 1));
    assert_eq!(
        instance_ttl_of(&f),
        SHARED_TTL_EXTEND_TO - 30 * DAY_IN_LEDGERS
    );
    assert_eq!(
        service_ttl_of(&f, &f.service_id),
        SHARED_TTL_EXTEND_TO - 30 * DAY_IN_LEDGERS
    );

    // 31 days after that, below the threshold: a hold extends both back to 120 days
    advance_ledgers(&f, 31 * DAY_IN_LEDGERS);
    f.hold(&call(&f.env, 2));
    assert_eq!(instance_ttl_of(&f), SHARED_TTL_EXTEND_TO);
    assert_eq!(service_ttl_of(&f, &f.service_id), SHARED_TTL_EXTEND_TO);
}

#[test]
fn ttl_is_capped_by_the_network_maximum() {
    let f = Fixture::new();
    f.env.ledger().set_max_entry_ttl(50_000);
    let id = call(&f.env, 1);
    f.hold(&id);
    let max = f
        .env
        .as_contract(&f.escrow_id(), || f.env.storage().max_ttl());
    assert!(max < hold_ttl(WINDOW));
    assert_eq!(hold_ttl_of(&f, &id), max);
}

/// A finalised hold is never extended again. Once archived it still blocks its call id: the
/// entry is restored on access, not recreated.
#[test]
fn an_archived_finalised_hold_still_blocks_its_call_id() {
    let f = Fixture::new();
    let id = call(&f.env, 1);
    f.hold(&id);
    f.settle(&id, OUTCOME_DELIVERED);
    advance_ledgers(&f, hold_ttl(WINDOW) + 1);
    let r = f
        .escrow
        .try_hold(&f.agent, &id, &f.service_id, &f.request());
    expect_error(r, Error::CallIdUsed);
    assert_eq!(f.status(&id), Some(Status::Released));
}

/// An open hold that archived before anyone claimed the timeout can still be refunded: held
/// funds never become unreachable.
#[test]
fn an_archived_open_hold_can_still_be_refunded() {
    let f = Fixture::new();
    let id = call(&f.env, 1);
    let before = f.token.balance(&f.agent);
    f.hold(&id);
    advance_ledgers(&f, hold_ttl(WINDOW) + 1);
    f.escrow.claim_timeout(&id);
    assert_eq!(f.token.balance(&f.agent), before);
    assert_eq!(f.status(&id), Some(Status::TimedOut));
}
