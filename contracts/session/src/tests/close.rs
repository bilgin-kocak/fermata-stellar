//! `close_session`: after the deadline, what is left of the deposit goes back to the agent.

use soroban_sdk::{testutils::Events as _, Event};

use super::setup::*;
use crate::{Error, SessionClosed, SessionStatus};

fn requests(from: u32, to: u32) -> std::vec::Vec<[u8; 32]> {
    (from + 1..=to).map(request).collect()
}

#[test]
fn cannot_close_until_the_deadline_has_passed() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open_plain(&id, 4);
    expect_error(f.session.try_close_session(&id), Error::WindowOpen);
    // At the deadline itself a batch is still accepted, so the session cannot be closed yet.
    let deadline = f.get(&id).deadline;
    assert_eq!(deadline, START + DAY + u64::from(WINDOW));
    f.warp(deadline - f.now());
    expect_error(f.session.try_close_session(&id), Error::WindowOpen);
    f.warp(1);
    f.session.close_session(&id);
    assert_eq!(f.get(&id).status, SessionStatus::Closed);
}

#[test]
fn refunds_the_whole_deposit_when_nothing_was_settled() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    let before = f.balance(&f.agent);
    f.open_plain(&id, 5);
    f.warp(DAY + u64::from(WINDOW) + 1);
    f.session.close_session(&id);
    assert_eq!(
        transfers(&f.env, &f.token.address),
        [(f.session.address.clone(), f.agent.clone(), 5 * PRICE)]
    );
    let events = f.env.events().all().filter_by_contract(&f.session.address);
    let closed = SessionClosed {
        session_id: id.clone(),
        service_id: f.service_id.clone(),
        agent: f.agent.clone(),
        refund: 5 * PRICE,
    };
    assert_eq!(events.events(), [closed.to_xdr(&f.env, &f.session.address)]);
    assert_eq!(f.balance(&f.agent), before);
    assert_eq!(f.balance(&f.session.address), 0);
}

#[test]
fn refunds_the_calls_not_settled() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open_plain(&id, 10);
    let entries = [delivered(1), delivered(2), failed(3)];
    f.settle(&id, &f.next_batch(&id, &requests(0, 3), [0; 32], &entries));
    f.warp(DAY + u64::from(WINDOW) + 1);
    f.session.close_session(&id);
    assert_eq!(
        transfers(&f.env, &f.token.address),
        [(f.session.address.clone(), f.agent.clone(), 7 * PRICE)]
    );
    let s = f.get(&id);
    assert_eq!((s.settled, s.status), (3, SessionStatus::Closed));
    assert_eq!(f.balance(&f.session.address), 0);
    // Over the session: two calls paid, one failed call and seven calls never settled refunded.
    assert_eq!(f.balance(&f.payout), 2 * (PRICE - FEE));
    assert_eq!(f.balance(&f.treasury), 2 * FEE);
    assert_eq!(f.balance(&f.agent), AGENT_FUNDS - 2 * PRICE);
}

#[test]
fn anyone_can_close_and_the_money_goes_to_the_agent() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    f.open_plain(&id, 2);
    f.warp(DAY + u64::from(WINDOW) + 1);
    f.env.set_auths(&[]);
    f.session.close_session(&id);
    assert_eq!(f.balance(&f.agent), AGENT_FUNDS);
}

#[test]
fn a_closed_or_unknown_session_cannot_be_closed() {
    let f = Fixture::new();
    let id = sid(&f.env, 1);
    expect_error(f.session.try_close_session(&id), Error::NotOpen);
    f.open_plain(&id, 2);
    f.warp(DAY + u64::from(WINDOW) + 1);
    f.session.close_session(&id);
    expect_error(f.session.try_close_session(&id), Error::NotOpen);
    assert_eq!(f.balance(&f.agent), AGENT_FUNDS);
}

/// Closing one session leaves the deposits of the others untouched.
#[test]
fn closing_one_session_leaves_the_others() {
    let f = Fixture::new();
    let (a, b) = (sid(&f.env, 1), sid(&f.env, 2));
    f.open_plain(&a, 3);
    f.warp(DAY);
    f.open_plain(&b, 4);
    f.warp(u64::from(WINDOW) + 1);
    f.session.close_session(&a);
    expect_error(f.session.try_close_session(&b), Error::WindowOpen);
    assert_eq!(f.balance(&f.session.address), 4 * PRICE);
    f.settle(
        &b,
        &f.next_batch(&b, &requests(0, 1), [0; 32], &[delivered(1)]),
    );
    assert_eq!(f.balance(&f.session.address), 3 * PRICE);
}
