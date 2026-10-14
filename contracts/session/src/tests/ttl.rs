//! Storage TTL and state archival, as for the escrow's holds (`contracts/escrow/src/tests/ttl.rs`).
//! The test host emulates protocol 23's automatic restoration: touching an archived persistent
//! entry restores it, exactly as a transaction on the network that lists it in its footprint does.

use fermata_escrow::MAX_WINDOW;
use soroban_sdk::{
    testutils::{
        storage::{Instance as _, Persistent as _},
        Ledger as _,
    },
    BytesN,
};

use super::setup::*;
use crate::{
    session_ttl, DataKey, Error, SessionStatus, DAY_IN_LEDGERS, MAX_DURATION,
    SESSION_GRACE_LEDGERS, SHARED_TTL_EXTEND_TO,
};

fn session_ttl_of(f: &Fixture, id: &BytesN<32>) -> u32 {
    f.env.as_contract(&f.session.address, || {
        f.env
            .storage()
            .persistent()
            .get_ttl(&DataKey::Session(id.clone()))
    })
}

fn instance_ttl_of(f: &Fixture) -> u32 {
    f.env
        .as_contract(&f.session.address, || f.env.storage().instance().get_ttl())
}

fn advance_ledgers(f: &Fixture, ledgers: u32) {
    f.env.ledger().with_mut(|l| {
        l.sequence_number += ledgers;
        l.timestamp += u64::from(ledgers) * 5;
    });
}

#[test]
fn a_session_lives_until_its_deadline_and_a_grace_period() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open_plain(&id, 4);
    // A day of calls and a 120 s window: 17,304 ledgers, plus 7 days to close it.
    assert_eq!(
        session_ttl(DAY + u64::from(WINDOW)),
        17_304 + 7 * DAY_IN_LEDGERS
    );
    assert_eq!(
        session_ttl_of(&f, &id),
        session_ttl(DAY + u64::from(WINDOW))
    );

    // The longest session on the longest window: 60 days of ledgers plus the grace period.
    let long = f.escrow.register_service(
        &f.vendor,
        &BytesN::from_array(&f.env, &fermata_verdict::service::label("long").unwrap()),
        &f.payout,
        &f.token.address,
        &PRICE,
        &MAX_WINDOW,
        &b32(&f.env, f.verifier.verifying_key().to_bytes()),
        &b32(&f.env, PREDICATE),
        &b32(&f.env, [0x0a; 32]),
        &b32(&f.env, [0x0b; 32]),
    );
    let id2 = sid(&f.env, 2);
    f.session.open_session(
        &f.agent,
        &id2,
        &long,
        &4,
        &f.ticket_pk(),
        &1,
        &B,
        &f.zero(),
        &(f.now() + MAX_DURATION),
    );
    let longest = MAX_DURATION + u64::from(MAX_WINDOW);
    assert_eq!(
        session_ttl(longest),
        60 * DAY_IN_LEDGERS + SESSION_GRACE_LEDGERS
    );
    assert_eq!(session_ttl_of(&f, &id2), session_ttl(longest));
}

/// Settling does not extend a session: its TTL was set at opening to outlast its deadline.
#[test]
fn settling_does_not_extend_a_session() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open_plain(&id, 4);
    let at_open = session_ttl_of(&f, &id);
    advance_ledgers(&f, 100);
    let b = f.next_batch(&id, &[request(1)], [0; 32], &[delivered(1)]);
    f.settle(&id, &b);
    assert_eq!(session_ttl_of(&f, &id), at_open - 100);
}

#[test]
fn the_instance_is_extended_when_low() {
    let f = Fixture::new();
    assert_eq!(instance_ttl_of(&f), SHARED_TTL_EXTEND_TO);

    // 30 days later more than the 60-day threshold remains: no extension (and no rent).
    advance_ledgers(&f, 30 * DAY_IN_LEDGERS);
    f.open_plain(&sid(&f.env, 1), 1);
    assert_eq!(
        instance_ttl_of(&f),
        SHARED_TTL_EXTEND_TO - 30 * DAY_IN_LEDGERS
    );

    // 31 days after that, below the threshold: opening a session extends it back to 120 days.
    advance_ledgers(&f, 31 * DAY_IN_LEDGERS);
    f.open_plain(&sid(&f.env, 2), 1);
    assert_eq!(instance_ttl_of(&f), SHARED_TTL_EXTEND_TO);
}

#[test]
fn ttl_is_capped_by_the_network_maximum() {
    let f = Fixture::new();
    f.env.ledger().set_max_entry_ttl(50_000);
    let id = sid(&f.env, 1);
    f.open_plain(&id, 1);
    let max = f
        .env
        .as_contract(&f.session.address, || f.env.storage().max_ttl());
    assert!(max < session_ttl(DAY + u64::from(WINDOW)));
    assert_eq!(session_ttl_of(&f, &id), max);
}

/// An open session that archived before anyone closed it can still be closed: the deposit never
/// becomes unreachable.
#[test]
fn an_archived_open_session_can_still_be_closed() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open_plain(&id, 3);
    advance_ledgers(&f, session_ttl(DAY + u64::from(WINDOW)) + 1);
    f.session.close_session(&id);
    assert_eq!(f.balance(&f.agent), AGENT_FUNDS);
    assert_eq!(f.get(&id).status, SessionStatus::Closed);
}

/// A closed session is never extended again. Once archived it still blocks its id: the entry is
/// restored on access, not recreated.
#[test]
fn an_archived_closed_session_still_blocks_its_id() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open_plain(&id, 1);
    f.settle(
        &id,
        &f.next_batch(&id, &[request(1)], [0; 32], &[delivered(1)]),
    );
    advance_ledgers(&f, session_ttl(DAY + u64::from(WINDOW)) + 1);
    let r = f.session.try_open_session(
        &f.agent,
        &id,
        &f.service_id,
        &1,
        &f.ticket_pk(),
        &1,
        &B,
        &f.zero(),
        &(f.now() + DAY),
    );
    expect_error(r, Error::SessionExists);
    assert_eq!(f.get(&id).status, SessionStatus::Closed);
}
