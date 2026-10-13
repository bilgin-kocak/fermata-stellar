//! Hostile and blocked tokens: FermataEscrow.t.sol section 13 (tests 39–41), and the Tempo-only
//! `test_tempo_receivePolicyBlockedPayout_revertsThenTimesOut`.

use soroban_sdk::{testutils::IssuerFlags, BytesN};

use super::setup::*;
use crate::{Error, Status, OUTCOME_DELIVERED, OUTCOME_FAILED};

/// A SEP-41 token with balances, `arm`ed to misbehave inside `transfer`: re-enter the escrow
/// (Fermata's `ReentrantTIP20`) or trap (the Soroban counterpart of `FalseTIP20`: a SEP-41
/// transfer cannot "return false").
mod hostile {
    use soroban_sdk::{
        contract, contractimpl, contracttype, vec, Address, BytesN, Env, IntoVal, MuxedAddress,
        Symbol, Val,
    };

    pub const HONEST: u32 = 0;
    pub const REENTER: u32 = 1;
    pub const TRAP: u32 = 2;

    #[contracttype]
    #[derive(Clone)]
    enum Key {
        Balance(Address),
        Escrow,
        Target,
        Mode,
        Attempts,
        Successes,
    }

    #[contract]
    pub struct HostileToken;

    #[contractimpl]
    impl HostileToken {
        pub fn mint(env: Env, to: Address, amount: i128) {
            let balance = Self::balance(env.clone(), to.clone());
            env.storage()
                .persistent()
                .set(&Key::Balance(to), &(balance + amount));
        }

        pub fn balance(env: Env, id: Address) -> i128 {
            env.storage()
                .persistent()
                .get(&Key::Balance(id))
                .unwrap_or(0)
        }

        pub fn arm(env: Env, escrow: Address, target: BytesN<32>, mode: u32) {
            let s = env.storage().instance();
            s.set(&Key::Escrow, &escrow);
            s.set(&Key::Target, &target);
            s.set(&Key::Mode, &mode);
        }

        pub fn attempts(env: Env) -> u32 {
            env.storage().instance().get(&Key::Attempts).unwrap_or(0)
        }

        pub fn successes(env: Env) -> u32 {
            env.storage().instance().get(&Key::Successes).unwrap_or(0)
        }

        pub fn transfer(env: Env, from: Address, to: MuxedAddress, amount: i128) {
            from.require_auth();
            let mode: u32 = env.storage().instance().get(&Key::Mode).unwrap_or(HONEST);
            if mode == TRAP {
                panic!("hostile token refuses to move funds");
            }
            if mode == REENTER {
                reenter(&env);
            }
            let to = to.address();
            let from_balance = Self::balance(env.clone(), from.clone());
            assert!(from_balance >= amount, "insufficient balance");
            let s = env.storage().persistent();
            s.set(&Key::Balance(from), &(from_balance - amount));
            let to_balance = Self::balance(env.clone(), to.clone());
            s.set(&Key::Balance(to), &(to_balance + amount));
        }
    }

    /// Tries to time out the target call and to hold a fresh one from inside the transfer.
    fn reenter(env: &Env) {
        let s = env.storage().instance();
        let escrow: Address = s.get(&Key::Escrow).unwrap();
        let target: BytesN<32> = s.get(&Key::Target).unwrap();
        s.set(
            &Key::Attempts,
            &(s.get::<_, u32>(&Key::Attempts).unwrap_or(0) + 1),
        );
        let zero = BytesN::from_array(env, &[0; 32]);
        let one = BytesN::from_array(env, &[1; 32]);
        let tries = [
            (
                Symbol::new(env, "claim_timeout"),
                vec![env, target.into_val(env)],
            ),
            (
                Symbol::new(env, "hold"),
                vec![
                    env,
                    env.current_contract_address().into_val(env),
                    one.into_val(env),
                    zero.into_val(env),
                    one.into_val(env),
                ],
            ),
        ];
        for (func, args) in tries {
            let r = env.try_invoke_contract::<Val, soroban_sdk::Error>(&escrow, &func, args);
            if r.is_ok() {
                let n = s.get::<_, u32>(&Key::Successes).unwrap_or(0);
                s.set(&Key::Successes, &(n + 1));
            }
        }
    }
}

use hostile::{HostileToken, HostileTokenClient};

fn hostile_service(
    f: &Fixture,
    mode: u32,
    target: &BytesN<32>,
) -> (HostileTokenClient<'static>, BytesN<32>) {
    let id = f.env.register(HostileToken, ());
    let token = HostileTokenClient::new(&f.env, &id);
    let service = f.register("evil", &id, PRICE);
    token.mint(&f.agent, &1_000_000_000);
    token.arm(&f.escrow_id(), target, &mode);
    (token, service)
}

/// Test 39: `test_reentrantToken_cannotDoubleSpend`: the host refuses re-entry into the escrow; the
/// token's attempts inside the pull and the refund all fail, and the flow completes.
#[test]
fn reentrant_token_cannot_double_spend() {
    let f = Fixture::new();
    let id = call(&f.env, 1);
    let (evil, service) = hostile_service(&f, hostile::REENTER, &id);

    f.hold_on(&service, &id); // re-enters claim_timeout/hold during the pull
    let mut v = f.verdict(&id, OUTCOME_FAILED);
    v.service_id = service;
    let sig = f.sign(&v);
    f.escrow.settle(&id, &v, &sig); // re-enters during the refund

    assert!(evil.attempts() > 0);
    assert_eq!(evil.successes(), 0);
    assert_eq!(evil.balance(&f.escrow_id()), 0);
    assert_eq!(evil.balance(&f.agent), 1_000_000_000);
    assert_eq!(f.status(&id), Some(Status::Refunded));
}

/// Test 40: `test_tokenReturningFalse_reverts`, adapted: a token whose transfer traps makes `hold`
/// fail as a whole; nothing is recorded.
#[test]
fn trapping_token_reverts_the_hold() {
    let f = Fixture::new();
    let id = call(&f.env, 1);
    let (_, service) = hostile_service(&f, hostile::TRAP, &id);
    let r = f.escrow.try_hold(&f.agent, &id, &service, &f.request());
    expect_abort(r);
    assert_eq!(f.escrow.get_hold(&id), None);
}

/// Test 41: `test_holdsAcrossServicesAreIsolated`
#[test]
fn holds_across_services_are_isolated() {
    let f = Fixture::new();
    let env = &f.env;
    let other = Token::new(env);
    let alpha = f.register("alpha", &other.address, 7_000);
    other.mint(&f.agent, 1_000_000_000);
    let (a, b) = (call(env, 1), call(env, 2));
    f.hold(&a);
    f.hold_on(&alpha, &b);
    assert_eq!(f.token.balance(&f.escrow_id()), PRICE);
    assert_eq!(other.balance(&f.escrow_id()), 7_000);
    let mut v = f.verdict(&b, OUTCOME_DELIVERED);
    v.service_id = alpha;
    let sig = f.sign(&v);
    f.escrow.settle(&b, &v, &sig);
    assert_eq!(other.balance(&f.escrow_id()), 0);
    assert_eq!(f.token.balance(&f.escrow_id()), PRICE); // untouched
}

/// `test_tempo_receivePolicyBlockedPayout_revertsThenTimesOut`, adapted: the payout's balance on
/// the SAC is deauthorized by the issuer. A DELIVERED settle fails as a whole (the SAC refuses
/// the transfer), the hold stays open, and the agent gets the money back on timeout.
#[test]
fn blocked_payout_reverts_then_times_out_to_the_agent() {
    let f = Fixture::new();
    let id = call(&f.env, 1);
    f.hold(&id);
    f.token.sac.issuer().set_flag(IssuerFlags::RevocableFlag);
    f.token.admin.set_authorized(&f.payout, &false);

    let v = f.verdict(&id, OUTCOME_DELIVERED);
    let sig = f.sign(&v);
    expect_token_error(f.escrow.try_settle(&id, &v, &sig), SAC_BALANCE_DEAUTHORIZED);
    assert_eq!(f.status(&id), Some(Status::Held));
    assert_eq!(f.token.balance(&f.escrow_id()), PRICE);

    f.warp(u64::from(WINDOW) + 1);
    expect_error(f.escrow.try_settle(&id, &v, &sig), Error::WindowClosed);
    let agent_before = f.token.balance(&f.agent);
    f.escrow.claim_timeout(&id);
    assert_eq!(f.token.balance(&f.agent), agent_before + PRICE);
    assert_eq!(f.status(&id), Some(Status::TimedOut));
}

/// A deauthorized treasury blocks a DELIVERED settle with a fee in the same way; a FAILED
/// verdict still refunds the agent.
#[test]
fn blocked_treasury_blocks_release_but_not_refund() {
    let f = Fixture::new();
    let id = call(&f.env, 1);
    f.hold(&id);
    f.token.sac.issuer().set_flag(IssuerFlags::RevocableFlag);
    f.token.admin.set_authorized(&f.treasury, &false);
    let v = f.verdict(&id, OUTCOME_DELIVERED);
    let sig = f.sign(&v);
    expect_token_error(f.escrow.try_settle(&id, &v, &sig), SAC_BALANCE_DEAUTHORIZED);
    assert_eq!(f.token.balance(&f.payout), 0);
    let agent_before = f.token.balance(&f.agent);
    f.settle(&id, OUTCOME_FAILED);
    assert_eq!(f.token.balance(&f.agent), agent_before + PRICE);
}
