//! 12. owner and admin (FermataEscrow.t.sol tests 35–38).

use std::panic::{catch_unwind, AssertUnwindSafe};

use soroban_sdk::{
    testutils::{
        Address as _, AuthorizedFunction, AuthorizedInvocation, Events as _, MockAuth,
        MockAuthInvoke,
    },
    Address, Env, Event as _, IntoVal, Symbol,
};

use super::setup::*;
use crate::{Error, FeeBpsUpdated, FermataEscrow, FermataEscrowClient, TreasuryUpdated};

fn deploys(build: impl FnOnce(&Env) -> Address) -> bool {
    let env = Env::default();
    catch_unwind(AssertUnwindSafe(|| build(&env))).is_ok()
}

/// Test 35: `test_constructor_validation`, adapted: a fee above 5 % and a treasury that is the escrow
/// itself are refused at deployment (zero addresses do not exist on Stellar).
#[test]
fn constructor_validation() {
    assert!(!deploys(|env| {
        let (owner, treasury) = (Address::generate(env), Address::generate(env));
        env.register(FermataEscrow, (owner, treasury, 501u32))
    }));
    assert!(!deploys(|env| {
        let owner = Address::generate(env);
        let at = Address::generate(env);
        env.register_at(&at, FermataEscrow, (owner, at.clone(), 50u32))
    }));

    let env = Env::default();
    let (owner, treasury) = (Address::generate(&env), Address::generate(&env));
    let id = env.register(FermataEscrow, (&owner, &treasury, 500u32));
    let events = env.events().all().filter_by_contract(&id);
    assert_eq!(
        events,
        [
            TreasuryUpdated {
                treasury: treasury.clone()
            }
            .to_xdr(&env, &id),
            FeeBpsUpdated { fee_bps: 500 }.to_xdr(&env, &id),
        ]
    );
    let e = FermataEscrowClient::new(&env, &id);
    assert_eq!(e.owner(), owner);
    assert_eq!(e.treasury(), treasury);
    assert_eq!(e.fee_bps(), 500);
}

/// Test 36: `test_admin_onlyOwner`: without the owner's authorization, and with someone else's,
/// the fee and the treasury cannot change.
#[test]
fn admin_only_owner() {
    let f = Fixture::new();
    let env = &f.env;
    let t2 = Address::generate(env);
    env.set_auths(&[]);
    expect_abort(f.escrow.try_set_fee_bps(&10));
    expect_abort(f.escrow.try_set_treasury(&t2));

    let stranger = Address::generate(env);
    let escrow = f.escrow_id();
    env.mock_auths(&[
        MockAuth {
            address: &stranger,
            invoke: &MockAuthInvoke {
                contract: &escrow,
                fn_name: "set_fee_bps",
                args: (10u32,).into_val(env),
                sub_invokes: &[],
            },
        },
        MockAuth {
            address: &stranger,
            invoke: &MockAuthInvoke {
                contract: &escrow,
                fn_name: "set_treasury",
                args: (t2.clone(),).into_val(env),
                sub_invokes: &[],
            },
        },
    ]);
    expect_abort(f.escrow.try_set_fee_bps(&10));
    expect_abort(f.escrow.try_set_treasury(&t2));
    assert_eq!(f.escrow.fee_bps(), FEE_BPS);
    assert_eq!(f.escrow.treasury(), f.treasury);

    // the owner's authorization is what the call requires
    env.mock_all_auths();
    f.escrow.set_fee_bps(&10);
    assert_eq!(
        env.auths(),
        std::vec![(
            f.owner.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    escrow.clone(),
                    Symbol::new(env, "set_fee_bps"),
                    (10u32,).into_val(env),
                )),
                sub_invocations: std::vec![],
            }
        )]
    );
}

/// Test 37: `test_admin_setters`
#[test]
fn admin_setters() {
    let f = Fixture::new();
    let env = &f.env;
    let escrow = f.escrow_id();
    expect_error(f.escrow.try_set_fee_bps(&501), Error::FeeTooHigh);
    f.escrow.set_fee_bps(&500);
    assert_eq!(
        env.events().all().filter_by_contract(&escrow),
        [FeeBpsUpdated { fee_bps: 500 }.to_xdr(env, &escrow)]
    );
    expect_error(f.escrow.try_set_treasury(&escrow), Error::InvalidRecipient);
    let t2 = Address::generate(env);
    f.escrow.set_treasury(&t2);
    assert_eq!(
        env.events().all().filter_by_contract(&escrow),
        [TreasuryUpdated {
            treasury: t2.clone()
        }
        .to_xdr(env, &escrow)]
    );
    assert_eq!(f.escrow.treasury(), t2);
    assert_eq!(f.escrow.fee_bps(), 500);
}

/// Test 38: `test_feeSnapshot_changeAfterHoldDoesNotApply`
#[test]
fn fee_snapshot_change_after_hold_does_not_apply() {
    let f = Fixture::new();
    let env = &f.env;
    let id = call(env, 1);
    f.hold(&id);
    f.escrow.set_fee_bps(&500);
    f.settle(&id, crate::OUTCOME_DELIVERED);
    let fee = PRICE * i128::from(FEE_BPS) / 10_000; // the 50 bps in force at hold time
    assert_eq!(f.token.balance(&f.treasury), fee);
    assert_eq!(f.token.balance(&f.payout), PRICE - fee);
    // a new hold uses the new fee
    let next = call(env, 7);
    f.hold(&next);
    assert_eq!(f.escrow.get_hold(&next).unwrap().fee_bps, 500);
}
