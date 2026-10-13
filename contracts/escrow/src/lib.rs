#![no_std]
//! FermataEscrow on Stellar: pay on proof.
//!
//! Holds an agent's payment for one API call until the service's registered verifier signs a
//! verdict about the vendor's response: `hold → release(proof)` pays the vendor minus a fee,
//! `hold → refund(proof)` returns the money, and with no verdict inside the settlement window
//! anyone can return the money to the agent (`claim_timeout`).
//!
//! A Soroban port of `contracts/src/FermataEscrow.sol` in github.com/bilgin-kocak/fermata
//! (@ d7cc642, MIT): same state machine, role, fee rules, checks, check order and events. The
//! differences (authorization instead of permits, events instead of memos, Ed25519 verdicts,
//! derived service ids, storage TTL) are listed with their reasons in `docs/PORTING_NOTES.md`.
//!
//! Unaudited. No upgrade entry point. The owner can change the fee (at most 5 %) and the
//! treasury, never held funds; services are immutable once registered.

mod errors;
mod events;
mod storage;
mod types;
mod verdict;

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests;

pub use errors::Error;
pub use events::{
    FeeBpsUpdated, Held, Refunded, Released, ServiceRegistered, TimedOut, TreasuryUpdated,
};
pub use storage::{
    hold_ttl, DataKey, DAY_IN_LEDGERS, HOLD_GRACE_LEDGERS, LEDGER_SECONDS, SHARED_TTL_EXTEND_TO,
    SHARED_TTL_THRESHOLD,
};
pub use types::{Hold, HoldView, Service, Status, Verdict};
pub use verdict::{SERVICE_TAG, VERDICT_TAG};

use soroban_sdk::{contract, contractimpl, token::TokenClient, Address, Bytes, BytesN, Env};

pub const OUTCOME_DELIVERED: u32 = 1;
pub const OUTCOME_FAILED: u32 = 2;
/// 5 %.
pub const MAX_FEE_BPS: u32 = 500;
/// 30 days, in seconds.
pub const MAX_WINDOW: u32 = 30 * 24 * 60 * 60;
pub const BPS: i128 = 10_000;
/// The largest price for which `price * fee_bps` cannot overflow an `i128`.
pub const MAX_PRICE: i128 = i128::MAX / BPS;

#[contract]
pub struct FermataEscrow;

#[contractimpl]
impl FermataEscrow {
    /// Runs once, atomically, at deployment.
    ///
    /// - `owner`: may change the fee and the treasury, nothing else.
    /// - `treasury`: receives the release fee.
    /// - `fee_bps`: release fee in basis points (at most `MAX_FEE_BPS`); never charged on refunds.
    pub fn __constructor(
        env: Env,
        owner: Address,
        treasury: Address,
        fee_bps: u32,
    ) -> Result<(), Error> {
        check_recipient(&env, &treasury)?;
        if fee_bps > MAX_FEE_BPS {
            return Err(Error::FeeTooHigh);
        }
        storage::set_owner(&env, &owner);
        storage::set_treasury(&env, &treasury);
        storage::set_fee_bps(&env, fee_bps);
        storage::extend_instance(&env);
        TreasuryUpdated { treasury }.publish(&env);
        FeeBpsUpdated { fee_bps }.publish(&env);
        Ok(())
    }

    // ------------------------------------------------------------------------------- vendor API

    /// Registers an immutable paid service and returns its id,
    /// `sha256("FERMATA_STELLAR_SERVICE_V1" ‖ XDR(owner) ‖ label)`. Needs `owner`'s authorization,
    /// so nobody can register under another owner's ids.
    ///
    /// - `verifier`: the Ed25519 public key whose verdicts settle this service's holds.
    /// - `predicate_hash`: sha256 of the delivery-predicate JSON the verifier enforces.
    /// - `origin_hash`, `notary_key_hash`: the origin and notary the proof must come from
    ///   (checked off-chain by the verifier).
    #[allow(clippy::too_many_arguments)]
    pub fn register_service(
        env: Env,
        owner: Address,
        label: BytesN<12>,
        payout: Address,
        token: Address,
        price_per_call: i128,
        settlement_window: u32,
        verifier: BytesN<32>,
        predicate_hash: BytesN<32>,
        origin_hash: BytesN<32>,
        notary_key_hash: BytesN<32>,
    ) -> Result<BytesN<32>, Error> {
        owner.require_auth();
        let service_id = verdict::service_id(&env, &owner, &label);
        if storage::has_service(&env, &service_id) {
            return Err(Error::ServiceExists);
        }
        if verifier == BytesN::from_array(&env, &[0; 32]) {
            return Err(Error::InvalidVerifier);
        }
        check_recipient(&env, &payout)?;
        if payout == token {
            return Err(Error::InvalidRecipient);
        }
        if price_per_call <= 0
            || price_per_call > MAX_PRICE
            || settlement_window == 0
            || settlement_window > MAX_WINDOW
        {
            return Err(Error::InvalidService);
        }

        let service = Service {
            owner: owner.clone(),
            label: label.clone(),
            settlement_window,
            payout: payout.clone(),
            token: token.clone(),
            verifier: verifier.clone(),
            price_per_call,
            predicate_hash,
            origin_hash,
            notary_key_hash,
        };
        storage::set_service(&env, &service_id, &service);
        storage::extend_instance(&env);
        ServiceRegistered {
            service_id: service_id.clone(),
            owner,
            token,
            label,
            payout,
            verifier,
            price_per_call,
            settlement_window,
        }
        .publish(&env);
        Ok(service_id)
    }

    // -------------------------------------------------------------------------------- agent API

    /// Holds the service's price from `agent` for one call. `agent` must authorize this call,
    /// including the token transfer to the escrow, which carries the exact amount.
    ///
    /// `request_hash` = sha256(service_id ‖ METHOD ‖ request-target ‖ sha256(body)), computed
    /// off-chain; the verifier checks the proved request against it.
    pub fn hold(
        env: Env,
        agent: Address,
        call_id: BytesN<32>,
        service_id: BytesN<32>,
        request_hash: BytesN<32>,
    ) -> Result<(), Error> {
        agent.require_auth();
        let zero = BytesN::from_array(&env, &[0; 32]);
        if call_id == zero || request_hash == zero {
            return Err(Error::InvalidCall);
        }
        if storage::has_hold(&env, &call_id) {
            return Err(Error::CallIdUsed);
        }
        let service = storage::service(&env, &service_id).ok_or(Error::UnknownService)?;
        let amount = service.price_per_call;

        storage::set_hold(
            &env,
            &call_id,
            &Hold {
                agent: agent.clone(),
                service_id: service_id.clone(),
                request_hash: request_hash.clone(),
                held_at: env.ledger().timestamp(),
                fee_bps: storage::fee_bps(&env),
                status: Status::Held,
            },
        );
        storage::extend_hold(&env, &call_id, service.settlement_window);
        storage::extend_service(&env, &service_id);
        storage::extend_instance(&env);
        Held {
            call_id,
            service_id,
            agent: agent.clone(),
            amount,
            request_hash,
        }
        .publish(&env);

        TokenClient::new(&env, &service.token).transfer(
            &agent,
            env.current_contract_address(),
            &amount,
        );
        Ok(())
    }

    // ------------------------------------------------------------------- settlement (anyone)

    /// Settles a hold with the service verifier's signed verdict. DELIVERED pays the vendor
    /// (price − fee) and the treasury (fee); FAILED refunds the agent in full. Only inside the
    /// settlement window; afterwards the only exit is `claim_timeout`. Callable by anyone.
    ///
    /// A signature that does not verify fails the call with the host's crypto error.
    pub fn settle(
        env: Env,
        call_id: BytesN<32>,
        verdict: Verdict,
        signature: BytesN<64>,
    ) -> Result<(), Error> {
        let hold = held(&env, &call_id)?;
        let service = storage::service(&env, &hold.service_id).ok_or(Error::UnknownService)?;
        if env.ledger().timestamp() > deadline(&hold, &service) {
            return Err(Error::WindowClosed);
        }
        check_verdict(&env, &call_id, &hold, &service, &verdict)?;
        env.crypto().ed25519_verify(
            &service.verifier,
            &verdict::message(&env, &verdict),
            &signature,
        );

        if verdict.outcome == OUTCOME_DELIVERED {
            release(&env, call_id, hold, &service, verdict.presentation_hash);
        } else {
            refund(&env, call_id, hold, &service, verdict.presentation_hash);
        }
        storage::extend_instance(&env);
        Ok(())
    }

    /// Refunds the agent when no verdict settled the hold inside its window. Callable by anyone;
    /// the money always goes to the agent.
    pub fn claim_timeout(env: Env, call_id: BytesN<32>) -> Result<(), Error> {
        let mut hold = held(&env, &call_id)?;
        let service = storage::service(&env, &hold.service_id).ok_or(Error::UnknownService)?;
        if env.ledger().timestamp() <= deadline(&hold, &service) {
            return Err(Error::WindowOpen);
        }
        let amount = service.price_per_call;
        hold.status = Status::TimedOut;
        storage::set_hold(&env, &call_id, &hold);
        TimedOut {
            call_id,
            service_id: hold.service_id,
            agent: hold.agent.clone(),
            amount,
        }
        .publish(&env);
        TokenClient::new(&env, &service.token).transfer(
            &env.current_contract_address(),
            &hold.agent,
            &amount,
        );
        storage::extend_instance(&env);
        Ok(())
    }

    // -------------------------------------------------------------------------------- owner API

    pub fn set_fee_bps(env: Env, fee_bps: u32) -> Result<(), Error> {
        storage::owner(&env).require_auth();
        if fee_bps > MAX_FEE_BPS {
            return Err(Error::FeeTooHigh);
        }
        storage::set_fee_bps(&env, fee_bps);
        storage::extend_instance(&env);
        FeeBpsUpdated { fee_bps }.publish(&env);
        Ok(())
    }

    pub fn set_treasury(env: Env, treasury: Address) -> Result<(), Error> {
        storage::owner(&env).require_auth();
        check_recipient(&env, &treasury)?;
        storage::set_treasury(&env, &treasury);
        storage::extend_instance(&env);
        TreasuryUpdated { treasury }.publish(&env);
        Ok(())
    }

    // ------------------------------------------------------------------------------------ views

    pub fn owner(env: Env) -> Address {
        storage::owner(&env)
    }

    pub fn treasury(env: Env) -> Address {
        storage::treasury(&env)
    }

    pub fn fee_bps(env: Env) -> u32 {
        storage::fee_bps(&env)
    }

    pub fn get_service(env: Env, service_id: BytesN<32>) -> Option<Service> {
        storage::service(&env, &service_id)
    }

    /// `None` for a call id that was never held.
    pub fn get_hold(env: Env, call_id: BytesN<32>) -> Option<HoldView> {
        let hold = storage::hold(&env, &call_id)?;
        let (amount, deadline) = match hold.status {
            Status::Held => {
                let service = storage::service(&env, &hold.service_id)?;
                (service.price_per_call, deadline(&hold, &service))
            }
            _ => (0, 0),
        };
        Some(HoldView {
            agent: hold.agent,
            service_id: hold.service_id,
            request_hash: hold.request_hash,
            amount,
            held_at: hold.held_at,
            deadline,
            fee_bps: hold.fee_bps,
            status: hold.status,
        })
    }

    /// The last ledger timestamp at which `settle` is accepted for a held call (0 when not held).
    pub fn settlement_deadline(env: Env, call_id: BytesN<32>) -> u64 {
        match storage::hold(&env, &call_id) {
            Some(hold) if hold.status == Status::Held => storage::service(&env, &hold.service_id)
                .map(|service| deadline(&hold, &service))
                .unwrap_or(0),
            _ => 0,
        }
    }

    /// The id `register_service` derives for `owner` and `label`.
    pub fn service_id(env: Env, owner: Address, label: BytesN<12>) -> BytesN<32> {
        verdict::service_id(&env, &owner, &label)
    }

    /// The exact bytes the verifier signs for `verdict` on this network and this contract.
    pub fn verdict_message(env: Env, verdict: Verdict) -> Bytes {
        verdict::message(&env, &verdict)
    }
}

// --------------------------------------------------------------------------------------- internals

fn held(env: &Env, call_id: &BytesN<32>) -> Result<Hold, Error> {
    match storage::hold(env, call_id) {
        Some(hold) if hold.status == Status::Held => Ok(hold),
        _ => Err(Error::NotHeld),
    }
}

fn deadline(hold: &Hold, service: &Service) -> u64 {
    hold.held_at + u64::from(service.settlement_window)
}

/// The same checks, in the same order, as `FermataEscrow._checkVerdict`.
fn check_verdict(
    env: &Env,
    call_id: &BytesN<32>,
    hold: &Hold,
    service: &Service,
    verdict: &Verdict,
) -> Result<(), Error> {
    if verdict.call_id != *call_id {
        return Err(Error::CallIdMismatch);
    }
    if verdict.service_id != hold.service_id {
        return Err(Error::ServiceMismatch);
    }
    if verdict.request_hash != hold.request_hash {
        return Err(Error::RequestMismatch);
    }
    if verdict.predicate_hash != service.predicate_hash {
        return Err(Error::PredicateMismatch);
    }
    if verdict.outcome != OUTCOME_DELIVERED && verdict.outcome != OUTCOME_FAILED {
        return Err(Error::InvalidOutcome);
    }
    if verdict.presentation_hash == BytesN::from_array(env, &[0; 32]) {
        return Err(Error::InvalidPresentation);
    }
    Ok(())
}

fn release(
    env: &Env,
    call_id: BytesN<32>,
    mut hold: Hold,
    service: &Service,
    presentation_hash: BytesN<32>,
) {
    let amount = service.price_per_call;
    // amount ≤ MAX_PRICE and fee_bps ≤ MAX_FEE_BPS, so this cannot overflow; rounds down.
    let fee = amount * i128::from(hold.fee_bps) / BPS;
    hold.status = Status::Released;
    storage::set_hold(env, &call_id, &hold);
    Released {
        call_id,
        service_id: hold.service_id,
        payout: service.payout.clone(),
        amount,
        fee,
        presentation_hash,
    }
    .publish(env);

    let token = TokenClient::new(env, &service.token);
    let escrow = env.current_contract_address();
    token.transfer(&escrow, &service.payout, &(amount - fee));
    if fee != 0 {
        token.transfer(&escrow, storage::treasury(env), &fee);
    }
}

fn refund(
    env: &Env,
    call_id: BytesN<32>,
    mut hold: Hold,
    service: &Service,
    presentation_hash: BytesN<32>,
) {
    let amount = service.price_per_call;
    hold.status = Status::Refunded;
    storage::set_hold(env, &call_id, &hold);
    Refunded {
        call_id,
        service_id: hold.service_id,
        agent: hold.agent.clone(),
        amount,
        presentation_hash,
    }
    .publish(env);
    TokenClient::new(env, &service.token).transfer(
        &env.current_contract_address(),
        &hold.agent,
        &amount,
    );
}

/// A payout or treasury must not be this contract: funds sent to it could never leave.
fn check_recipient(env: &Env, recipient: &Address) -> Result<(), Error> {
    if *recipient == env.current_contract_address() {
        return Err(Error::InvalidRecipient);
    }
    Ok(())
}
