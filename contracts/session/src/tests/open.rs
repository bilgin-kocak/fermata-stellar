//! `open_session`: the deposit, the copy of the service's terms, the agent's authorization, and
//! every limit.

use soroban_sdk::{
    testutils::{Address as _, AuthorizedFunction, AuthorizedInvocation, Events as _},
    Address, BytesN, Event, IntoVal, Symbol,
};

use super::setup::*;
use crate::{
    Error, SessionOpened, SessionStatus, MAX_BATCH, MAX_CALLS, MAX_DURATION, MAX_SAMPLE_K,
};

#[test]
fn deposits_max_calls_times_the_price() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    let before = f.balance(&f.agent);
    f.open_plain(&id, 10);
    assert_eq!(
        transfers(&f.env, &f.token.address),
        [(f.agent.clone(), f.session.address.clone(), 10 * PRICE)]
    );
    assert_eq!(f.balance(&f.agent), before - 10 * PRICE);
    assert_eq!(f.balance(&f.session.address), 10 * PRICE);
}

#[test]
fn records_the_services_terms_and_the_fee() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open(&id, 5, 1, B, [0; 32]);
    let s = f.get(&id);
    let service = f.escrow.get_service(&f.service_id).unwrap();
    assert_eq!(s.agent, f.agent);
    assert_eq!(s.service_id, f.service_id);
    assert_eq!(s.token, service.token);
    assert_eq!(s.payout, service.payout);
    assert_eq!(s.price, service.price_per_call);
    assert_eq!(s.verifier, service.verifier);
    assert_eq!(s.predicate_hash, service.predicate_hash);
    assert_eq!(s.fee_bps, FEE_BPS);
    assert_eq!(s.ticket_key, f.ticket_pk());
    assert_eq!((s.max_calls, s.sample_k, s.batch_size), (5, 1, B));
    assert_eq!(s.opened_at, START);
    assert_eq!(s.deadline, START + DAY + u64::from(WINDOW));
    assert_eq!(
        (s.settled, s.chain.clone(), s.seed.clone()),
        (0, id.clone(), f.zero())
    );
    assert_eq!(s.status, SessionStatus::Open);
}

#[test]
fn emits_session_opened() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open(&id, 3, 1, B, [0; 32]);
    let expected = SessionOpened {
        session_id: id.clone(),
        service_id: f.service_id.clone(),
        agent: f.agent.clone(),
        deposit: 3 * PRICE,
        max_calls: 3,
        price: PRICE,
        sample_k: 1,
        batch_size: B,
        deadline: START + DAY + u64::from(WINDOW),
    };
    let events = f.env.events().all().filter_by_contract(&f.session.address);
    assert_eq!(
        events.events(),
        [expected.to_xdr(&f.env, &f.session.address)]
    );
}

/// The agent authorizes `open_session` with its exact arguments, and inside it the token transfer
/// of exactly the deposit to the session contract: nobody else can open a session on its balance.
#[test]
fn needs_the_agents_authorization_of_the_exact_deposit() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    let expires_at = f.now() + DAY;
    f.session.open_session(
        &f.agent,
        &id,
        &f.service_id,
        &4,
        &f.ticket_pk(),
        &1,
        &B,
        &f.zero(),
        &expires_at,
    );
    let auths = f.env.auths();
    assert_eq!(auths.len(), 1);
    let (who, tree) = &auths[0];
    assert_eq!(who, &f.agent);
    assert_eq!(
        tree,
        &AuthorizedInvocation {
            function: AuthorizedFunction::Contract((
                f.session.address.clone(),
                Symbol::new(&f.env, "open_session"),
                (
                    f.agent.clone(),
                    id.clone(),
                    f.service_id.clone(),
                    4u32,
                    f.ticket_pk(),
                    1u32,
                    B,
                    f.zero(),
                    expires_at,
                )
                    .into_val(&f.env),
            )),
            sub_invocations: std::vec![AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    f.token.address.clone(),
                    Symbol::new(&f.env, "transfer"),
                    (f.agent.clone(), f.session.address.clone(), 4 * PRICE).into_val(&f.env),
                )),
                sub_invocations: std::vec![],
            }],
        }
    );
}

#[test]
fn without_the_agents_authorization_nothing_moves() {
    let f = Fixture::new();
    f.env.set_auths(&[]);
    let r = f.session.try_open_session(
        &f.agent,
        &sid(&f.env, 1),
        &f.service_id,
        &4,
        &f.ticket_pk(),
        &1,
        &B,
        &f.zero(),
        &(f.now() + DAY),
    );
    expect_abort(r);
    assert_eq!(f.balance(&f.session.address), 0);
}

/// `(max_calls, k, batch, seed, expires_at, session id, ticket key, why it fails)`.
type Terms = (
    u32,
    u32,
    u32,
    [u8; 32],
    u64,
    [u8; 32],
    [u8; 32],
    &'static str,
);

#[test]
fn refuses_terms_outside_the_limits() {
    let f = Fixture::new();
    let now = f.now();
    let zero = [0u8; 32];
    let seed = [0x5c; 32];
    // (max_calls, k, batch, seed, expires_at, session id, ticket key) and why each fails.
    let cases: [Terms; 14] = [
        (0, 1, B, zero, now + DAY, [1; 32], [2; 32], "no calls"),
        (
            MAX_CALLS + 1,
            1,
            B,
            zero,
            now + DAY,
            [1; 32],
            [2; 32],
            "too many calls",
        ),
        (4, 0, B, zero, now + DAY, [1; 32], [2; 32], "k = 0"),
        (
            4,
            MAX_SAMPLE_K + 1,
            B,
            seed,
            now + DAY,
            [1; 32],
            [2; 32],
            "k too large",
        ),
        (4, 1, 0, zero, now + DAY, [1; 32], [2; 32], "batch of 0"),
        (
            4,
            1,
            MAX_BATCH + 1,
            zero,
            now + DAY,
            [1; 32],
            [2; 32],
            "batch too large",
        ),
        (4, 1, B, zero, now, [1; 32], [2; 32], "expires now"),
        (4, 1, B, zero, now - 1, [1; 32], [2; 32], "expired"),
        (
            4,
            1,
            B,
            zero,
            now + MAX_DURATION + 1,
            [1; 32],
            [2; 32],
            "too long",
        ),
        (
            4,
            1,
            B,
            seed,
            now + DAY,
            [1; 32],
            [2; 32],
            "a seed with k = 1",
        ),
        (
            4,
            2,
            B,
            zero,
            now + DAY,
            [1; 32],
            [2; 32],
            "no seed with k = 2",
        ),
        (4, 1, B, zero, now + DAY, zero, [2; 32], "zero session id"),
        (4, 1, B, zero, now + DAY, [1; 32], zero, "zero ticket key"),
        (
            4,
            1,
            B,
            zero,
            now + MAX_DURATION,
            [1; 32],
            [2; 32],
            "the longest session (accepted)",
        ),
    ];
    for (max_calls, k, batch, seed, expires_at, id, key, why) in cases {
        let r = f.session.try_open_session(
            &f.agent,
            &b32(&f.env, id),
            &f.service_id,
            &max_calls,
            &b32(&f.env, key),
            &k,
            &batch,
            &b32(&f.env, seed),
            &expires_at,
        );
        if why.ends_with("(accepted)") {
            assert!(r.is_ok(), "{why}: {r:?}");
        } else {
            match r {
                Err(Ok(e)) => assert_eq!(e, Error::InvalidSession, "{why}"),
                other => panic!("{why}: expected InvalidSession, got {other:?}"),
            }
        }
    }
    // Only the accepted case moved money.
    assert_eq!(f.balance(&f.session.address), 4 * PRICE);
}

#[test]
fn refuses_a_used_session_id_even_after_it_closed() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open_plain(&id, 2);
    let again = || {
        f.session.try_open_session(
            &f.agent,
            &id,
            &f.service_id,
            &2,
            &f.ticket_pk(),
            &1,
            &B,
            &f.zero(),
            &(f.now() + DAY),
        )
    };
    expect_error(again(), Error::SessionExists);
    f.warp(DAY + u64::from(WINDOW) + 1);
    f.session.close_session(&id);
    expect_error(again(), Error::SessionExists);
}

#[test]
fn refuses_an_unknown_service() {
    let f = Fixture::new();
    let r = f.session.try_open_session(
        &f.agent,
        &sid(&f.env, 1),
        &b32(&f.env, [0x99; 32]),
        &2,
        &f.ticket_pk(),
        &1,
        &B,
        &f.zero(),
        &(f.now() + DAY),
    );
    expect_error(r, Error::UnknownService);
}

/// A service paid to the session contract itself could never pay out: refused.
#[test]
fn refuses_a_service_paid_to_this_contract() {
    let f = Fixture::new();
    let service_id = f.escrow.register_service(
        &f.vendor,
        &BytesN::from_array(&f.env, &fermata_verdict::service::label("self").unwrap()),
        &f.session.address,
        &f.token.address,
        &PRICE,
        &WINDOW,
        &b32(&f.env, f.verifier.verifying_key().to_bytes()),
        &b32(&f.env, PREDICATE),
        &b32(&f.env, [0x0a; 32]),
        &b32(&f.env, [0x0b; 32]),
    );
    let r = f.session.try_open_session(
        &f.agent,
        &sid(&f.env, 1),
        &service_id,
        &2,
        &f.ticket_pk(),
        &1,
        &B,
        &f.zero(),
        &(f.now() + DAY),
    );
    expect_error(r, Error::InvalidSession);
}

/// `max_calls × price` must fit in an i128: the escrow allows prices up to `i128::MAX / 10_000`.
#[test]
fn refuses_a_deposit_that_would_overflow() {
    let f = Fixture::new();
    let huge = i128::MAX / 10_000;
    let service_id = f.escrow.register_service(
        &f.vendor,
        &BytesN::from_array(&f.env, &fermata_verdict::service::label("huge").unwrap()),
        &f.payout,
        &f.token.address,
        &huge,
        &WINDOW,
        &b32(&f.env, f.verifier.verifying_key().to_bytes()),
        &b32(&f.env, PREDICATE),
        &b32(&f.env, [0x0a; 32]),
        &b32(&f.env, [0x0b; 32]),
    );
    let r = f.session.try_open_session(
        &f.agent,
        &sid(&f.env, 1),
        &service_id,
        &MAX_CALLS,
        &f.ticket_pk(),
        &1,
        &B,
        &f.zero(),
        &(f.now() + DAY),
    );
    expect_error(r, Error::InvalidSession);
}

/// An agent without the deposit cannot open: the token's own error, and nothing is recorded.
#[test]
fn an_agent_without_the_deposit_cannot_open() {
    let f = Fixture::new();
    let poor = Address::generate(&f.env);
    f.token_admin.mint(&poor, &(3 * PRICE - 1));
    let id = sid(&f.env, 1);
    let r = f.session.try_open_session(
        &poor,
        &id,
        &f.service_id,
        &3,
        &f.ticket_pk(),
        &1,
        &B,
        &f.zero(),
        &(f.now() + DAY),
    );
    match r {
        Err(Err(soroban_sdk::InvokeError::Contract(10))) => {}
        other => panic!("expected the token's balance error (10), got {other:?}"),
    }
    assert!(f.session.get_session(&id).is_none());
}

/// The fee is the escrow's at opening: a later change does not apply to the session.
#[test]
fn the_fee_is_snapshotted_at_opening() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open_plain(&id, 2);
    f.escrow.set_fee_bps(&500);
    assert_eq!(f.get(&id).fee_bps, FEE_BPS);
    let later = sid(&f.env, 2);
    f.open_plain(&later, 2);
    assert_eq!(f.get(&later).fee_bps, 500);
}

/// The session contract's copy of the escrow's `Service` decodes the escrow's real view.
#[test]
fn reads_the_escrows_registry_through_its_own_service_type() {
    let f = Fixture::new();
    let client = crate::EscrowClient::new(&f.env, &f.escrow.address);
    let mine = client.get_service(&f.service_id).unwrap();
    let theirs = f.escrow.get_service(&f.service_id).unwrap();
    assert_eq!(mine.owner, theirs.owner);
    assert_eq!(mine.label, theirs.label);
    assert_eq!(mine.settlement_window, theirs.settlement_window);
    assert_eq!(mine.payout, theirs.payout);
    assert_eq!(mine.token, theirs.token);
    assert_eq!(mine.verifier, theirs.verifier);
    assert_eq!(mine.price_per_call, theirs.price_per_call);
    assert_eq!(mine.predicate_hash, theirs.predicate_hash);
    assert_eq!(mine.origin_hash, theirs.origin_hash);
    assert_eq!(mine.notary_key_hash, theirs.notary_key_hash);
    assert_eq!(client.fee_bps(), FEE_BPS);
    assert_eq!(client.treasury(), f.treasury);
    assert_eq!(f.session.escrow(), f.escrow.address);
}
