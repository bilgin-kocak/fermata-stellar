//! 2.–3. hold (FermataEscrow.t.sol tests 8–17). The TIP-20 permit pull becomes the agent's
//! authorization of `hold`, whose tree includes the token transfer with its exact amount.

use soroban_sdk::{
    testutils::{
        Address as _, AuthorizedFunction, AuthorizedInvocation, Events as _, MockAuth,
        MockAuthInvoke,
    },
    Address, Event as _, IntoVal, Symbol,
};

use super::setup::*;
use crate::{Error, Held, HoldView, Status};

/// Test 8: `test_hold_viaPermit`, adapted: the price is pulled under the agent's authorization.
#[test]
fn hold_pulls_the_price_under_the_agents_authorization() {
    let f = Fixture::new();
    let env = &f.env;
    let id = call(env, 1);
    let agent_before = f.token.balance(&f.agent);

    f.hold(&id);

    let events = env.events().all().filter_by_contract(&f.escrow_id());
    assert_eq!(
        events,
        [Held {
            call_id: id.clone(),
            service_id: f.service_id.clone(),
            agent: f.agent.clone(),
            amount: PRICE,
            request_hash: f.request(),
        }
        .to_xdr(env, &f.escrow_id())]
    );
    // exactly one token movement, agent → escrow
    assert_eq!(
        transfers(env, &f.token.address),
        std::vec![(f.agent.clone(), f.escrow_id(), PRICE)]
    );
    // the agent authorized exactly hold(...) and, inside it, transfer(agent → escrow, PRICE)
    assert_eq!(
        env.auths(),
        std::vec![(
            f.agent.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    f.escrow_id(),
                    Symbol::new(env, "hold"),
                    (
                        f.agent.clone(),
                        id.clone(),
                        f.service_id.clone(),
                        f.request()
                    )
                        .into_val(env),
                )),
                sub_invocations: std::vec![AuthorizedInvocation {
                    function: AuthorizedFunction::Contract((
                        f.token.address.clone(),
                        Symbol::new(env, "transfer"),
                        (f.agent.clone(), f.escrow_id(), PRICE).into_val(env),
                    )),
                    sub_invocations: std::vec![],
                }],
            }
        )]
    );

    assert_eq!(f.token.balance(&f.agent), agent_before - PRICE);
    assert_eq!(f.token.balance(&f.escrow_id()), PRICE);
    assert_eq!(
        f.escrow.get_hold(&id),
        Some(HoldView {
            agent: f.agent.clone(),
            service_id: f.service_id.clone(),
            request_hash: f.request(),
            amount: PRICE,
            held_at: START,
            deadline: START + u64::from(WINDOW),
            fee_bps: FEE_BPS,
            status: Status::Held,
        })
    );
    assert_eq!(f.escrow.settlement_deadline(&id), START + u64::from(WINDOW));
}

/// The exact tree above is also sufficient: with only those two authorizations, `hold` works.
#[test]
fn hold_succeeds_with_exactly_the_documented_authorizations() {
    let f = Fixture::new();
    let env = &f.env;
    let id = call(env, 1);
    let escrow = f.escrow_id();
    env.mock_auths(&[MockAuth {
        address: &f.agent,
        invoke: &MockAuthInvoke {
            contract: &escrow,
            fn_name: "hold",
            args: (
                f.agent.clone(),
                id.clone(),
                f.service_id.clone(),
                f.request(),
            )
                .into_val(env),
            sub_invokes: &[MockAuthInvoke {
                contract: &f.token.address,
                fn_name: "transfer",
                args: (f.agent.clone(), escrow.clone(), PRICE).into_val(env),
                sub_invokes: &[],
            }],
        },
    }]);
    f.hold(&id);
    assert_eq!(f.status(&id), Some(Status::Held));
}

/// Test 9: `test_hold_revertsOnUsedCallId`
#[test]
fn hold_reverts_on_used_call_id() {
    let f = Fixture::new();
    let id = call(&f.env, 1);
    f.hold(&id);
    let r = f
        .escrow
        .try_hold(&f.agent, &id, &f.service_id, &f.request());
    expect_error(r, Error::CallIdUsed);
    // a call id is global: another service cannot reuse it either
    let other = f.register("other", &f.token.address, PRICE);
    let r = f.escrow.try_hold(&f.agent, &id, &other, &f.request());
    expect_error(r, Error::CallIdUsed);
}

/// Test 10: `test_hold_revertsOnUnknownService`
#[test]
fn hold_reverts_on_unknown_service() {
    let f = Fixture::new();
    let env = &f.env;
    let nope = f.escrow.service_id(&f.vendor, &label(env, "nope"));
    let r = f
        .escrow
        .try_hold(&f.agent, &call(env, 1), &nope, &f.request());
    expect_error(r, Error::UnknownService);
}

/// Test 11: `test_hold_revertsOnZeroCallIdOrRequest`
#[test]
fn hold_reverts_on_zero_call_id_or_request() {
    let f = Fixture::new();
    let env = &f.env;
    let zero = b32(env, [0; 32]);
    let r = f
        .escrow
        .try_hold(&f.agent, &zero, &f.service_id, &f.request());
    expect_error(r, Error::InvalidCall);
    let r = f
        .escrow
        .try_hold(&f.agent, &call(env, 1), &f.service_id, &zero);
    expect_error(r, Error::InvalidCall);
}

/// Test 12: `test_hold_thirdPartyCannotUseAgentsPermit`, adapted: without the agent's authorization a
/// third party cannot hold from the agent's balance, even if the third party signs.
#[test]
fn hold_third_party_cannot_spend_the_agents_balance() {
    let f = Fixture::new();
    let env = &f.env;
    let thief = Address::generate(env);
    let id = call(env, 1);
    let escrow = f.escrow_id();
    env.mock_auths(&[MockAuth {
        address: &thief,
        invoke: &MockAuthInvoke {
            contract: &escrow,
            fn_name: "hold",
            args: (
                f.agent.clone(),
                id.clone(),
                f.service_id.clone(),
                f.request(),
            )
                .into_val(env),
            sub_invokes: &[],
        },
    }]);
    let r = f
        .escrow
        .try_hold(&f.agent, &id, &f.service_id, &f.request());
    expect_abort(r);
    assert_eq!(f.token.balance(&escrow), 0);
    assert_eq!(f.token.balance(&f.agent), AGENT_FUNDS);
    assert_eq!(f.escrow.get_hold(&id), None);
}

/// Test 13: `test_hold_revertsWhenPermitValueDiffersFromPrice`, adapted: an authorization for another
/// amount, or one that leaves out the token transfer, does not cover the pull.
#[test]
fn hold_reverts_when_the_authorized_amount_differs_from_the_price() {
    let f = Fixture::new();
    let env = &f.env;
    let id = call(env, 1);
    let escrow = f.escrow_id();
    let hold_args: soroban_sdk::Vec<soroban_sdk::Val> = (
        f.agent.clone(),
        id.clone(),
        f.service_id.clone(),
        f.request(),
    )
        .into_val(env);
    let wrong_amount = [MockAuthInvoke {
        contract: &f.token.address,
        fn_name: "transfer",
        args: (f.agent.clone(), escrow.clone(), PRICE - 1).into_val(env),
        sub_invokes: &[],
    }];
    for sub_invokes in [&wrong_amount[..], &[]] {
        env.mock_auths(&[MockAuth {
            address: &f.agent,
            invoke: &MockAuthInvoke {
                contract: &escrow,
                fn_name: "hold",
                args: hold_args.clone(),
                sub_invokes,
            },
        }]);
        let r = f
            .escrow
            .try_hold(&f.agent, &id, &f.service_id, &f.request());
        expect_abort(r);
        assert_eq!(f.escrow.get_hold(&id), None);
    }
}

// Test 14: `test_hold_revertsOnExpiredPermitWithRealError`: not applicable. There is no permit; the
// host enforces the expiry ledger of the agent's authorization entry.
// Test 15: `test_hold_succeedsWhenPermitWasFrontRun`: not applicable. There is no permit to front-run.
// Test 16: `test_hold_approvePathWithJunkSignature`: not applicable. `hold` uses no allowance.

/// Test 17: `test_hold_revertsWithoutPermitOrAllowance`, adapted: no authorization at all, or not
/// enough balance. Nothing is recorded in either case.
#[test]
fn hold_reverts_without_authorization_or_balance() {
    let f = Fixture::new();
    let env = &f.env;
    let id = call(env, 1);
    env.set_auths(&[]);
    let r = f
        .escrow
        .try_hold(&f.agent, &id, &f.service_id, &f.request());
    expect_abort(r);
    assert_eq!(f.escrow.get_hold(&id), None);

    env.mock_all_auths();
    let broke = Address::generate(env);
    f.token.mint(&broke, PRICE - 1);
    let r = f.escrow.try_hold(&broke, &id, &f.service_id, &f.request());
    expect_token_error(r, SAC_BALANCE_ERROR);
    assert_eq!(f.escrow.get_hold(&id), None);
    assert_eq!(f.token.balance(&broke), PRICE - 1);
}
