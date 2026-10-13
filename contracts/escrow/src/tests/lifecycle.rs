//! 10.–11. replay and the settlement window (FermataEscrow.t.sol tests 28–34).

use soroban_sdk::{testutils::Events as _, Event as _};

use super::setup::*;
use crate::{Error, Status, TimedOut, OUTCOME_DELIVERED, OUTCOME_FAILED};

/// Test 28: `test_settle_replayReverts`
#[test]
fn settle_replay_reverts() {
    let f = Fixture::new();
    let id = call(&f.env, 1);
    f.hold(&id);
    let v = f.verdict(&id, OUTCOME_DELIVERED);
    let sig = f.sign(&v);
    f.escrow.settle(&id, &v, &sig);
    expect_error(f.escrow.try_settle(&id, &v, &sig), Error::NotHeld);
    // a finalised call id can never be held again
    let r = f
        .escrow
        .try_hold(&f.agent, &id, &f.service_id, &f.request());
    expect_error(r, Error::CallIdUsed);
}

/// Test 29: `test_settleAfterTimeout_andTimeoutAfterSettle_revert`
#[test]
fn settle_after_timeout_and_timeout_after_settle_revert() {
    let f = Fixture::new();
    let env = &f.env;
    let (a, b) = (call(env, 1), call(env, 2));
    f.hold(&a);
    f.hold(&b);
    f.settle(&a, OUTCOME_DELIVERED);
    f.warp(u64::from(WINDOW) + 1);
    expect_error(f.escrow.try_claim_timeout(&a), Error::NotHeld);
    f.escrow.claim_timeout(&b);
    let v = f.verdict(&b, OUTCOME_FAILED);
    let sig = f.sign(&v);
    expect_error(f.escrow.try_settle(&b, &v, &sig), Error::NotHeld);
}

/// Test 30: `test_unknownCall_reverts`
#[test]
fn unknown_call_reverts() {
    let f = Fixture::new();
    let id = call(&f.env, 1);
    expect_error(f.escrow.try_claim_timeout(&id), Error::NotHeld);
    let v = f.verdict(&id, OUTCOME_DELIVERED);
    let sig = f.sign(&v);
    expect_error(f.escrow.try_settle(&id, &v, &sig), Error::NotHeld);
    assert_eq!(f.escrow.get_hold(&id), None);
    assert_eq!(f.escrow.settlement_deadline(&id), 0);
}

/// Test 31: `test_settle_atWindowEndSucceeds`
#[test]
fn settle_at_window_end_succeeds() {
    let f = Fixture::new();
    let id = call(&f.env, 1);
    f.hold(&id);
    f.warp(u64::from(WINDOW));
    assert_eq!(f.now(), f.escrow.settlement_deadline(&id));
    f.settle(&id, OUTCOME_DELIVERED);
    assert_eq!(f.status(&id), Some(Status::Released));
}

/// Test 32: `test_settle_afterWindowReverts`
#[test]
fn settle_after_window_reverts() {
    let f = Fixture::new();
    let id = call(&f.env, 1);
    f.hold(&id);
    f.warp(u64::from(WINDOW) + 1);
    let v = f.verdict(&id, OUTCOME_DELIVERED);
    let sig = f.sign(&v);
    expect_error(f.escrow.try_settle(&id, &v, &sig), Error::WindowClosed);
}

/// Test 33: `test_timeout_beforeOrAtWindowEndReverts`
#[test]
fn timeout_before_or_at_window_end_reverts() {
    let f = Fixture::new();
    let id = call(&f.env, 1);
    f.hold(&id);
    expect_error(f.escrow.try_claim_timeout(&id), Error::WindowOpen);
    f.warp(u64::from(WINDOW));
    expect_error(f.escrow.try_claim_timeout(&id), Error::WindowOpen);
}

/// Test 34: `test_timeout_refundsAgent_calledByStranger`: no authorization at all is needed.
#[test]
fn timeout_refunds_agent_called_by_anyone() {
    let f = Fixture::new();
    let env = &f.env;
    let agent_before = f.token.balance(&f.agent);
    let id = call(env, 1);
    f.hold(&id);
    f.warp(u64::from(WINDOW) + 1);

    env.set_auths(&[]);
    f.escrow.claim_timeout(&id);

    let events = env.events().all().filter_by_contract(&f.escrow_id());
    assert_eq!(
        events,
        [TimedOut {
            call_id: id.clone(),
            service_id: f.service_id.clone(),
            agent: f.agent.clone(),
            amount: PRICE,
        }
        .to_xdr(env, &f.escrow_id())]
    );
    assert_eq!(
        transfers(env, &f.token.address),
        std::vec![(f.escrow_id(), f.agent.clone(), PRICE)]
    );
    assert_eq!(f.token.balance(&f.agent), agent_before);
    assert_eq!(f.token.balance(&f.treasury), 0);
    assert_eq!(f.status(&id), Some(Status::TimedOut));
}
