#![no_std]
//! Fermata session escrow on Stellar: one deposit for many calls, settled in batches.
//!
//! An agent deposits `max_calls × price` for one service of the escrow (`contracts/escrow`), then
//! signs a ticket for each call that commits it to that call's exact request. The service's
//! verifier settles the calls in batches with one signed statement per batch: proved calls pay the
//! vendor if DELIVERED and are refunded if FAILED, unanswered calls are refunded, and with sampling
//! (k > 1) a proved failure refunds k calls. After the session's deadline anyone can return what is
//! left of the deposit to the agent.
//!
//! The design, its encodings and the guarantee are in `docs/session-escrow.md`; phase 1 uses only
//! k = 1 (every call proved). Services, the fee and the treasury are the escrow's, read through its
//! views. Unaudited. No upgrade entry point, no owner.

mod errors;
mod escrow;
mod events;
mod messages;
mod storage;
mod types;

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests;

pub use errors::Error;
pub use escrow::EscrowClient;
pub use events::{BatchSettled, SessionClosed, SessionOpened};
pub use messages::{BATCH_TAG, CALL_TAG, ENTRY_LEN, TICKET_TAG};
pub use storage::{
    session_ttl, DataKey, DAY_IN_LEDGERS, LEDGER_SECONDS, SESSION_GRACE_LEDGERS,
    SHARED_TTL_EXTEND_TO, SHARED_TTL_THRESHOLD,
};
pub use types::{Service, Session, SessionStatus};

use soroban_sdk::{contract, contractimpl, token::TokenClient, Address, Bytes, BytesN, Env};

/// Proved: the response passed the delivery predicate.
pub const RESULT_DELIVERED: u32 = 1;
/// Proved: the response failed the delivery predicate.
pub const RESULT_FAILED: u32 = 2;
/// Not proved (not sampled), and the vendor answered.
pub const RESULT_ANSWERED: u32 = 3;
/// The vendor did not answer, whether the call was sampled or not.
pub const RESULT_UNANSWERED: u32 = 4;

pub const MAX_CALLS: u32 = 1_000_000;
pub const MAX_SAMPLE_K: u32 = 1_000;
pub const MAX_BATCH: u32 = 1_000;
/// 30 days, in seconds: the longest a session may run before its settlement window.
pub const MAX_DURATION: u64 = 30 * 24 * 60 * 60;
pub const BPS: i128 = 10_000;

#[contract]
pub struct FermataSession;

#[contractimpl]
impl FermataSession {
    /// Runs once, at deployment. `escrow` is the Fermata escrow whose services, fee and treasury
    /// this contract uses.
    pub fn __constructor(env: Env, escrow: Address) {
        storage::set_escrow(&env, &escrow);
        storage::extend_instance(&env);
    }

    // -------------------------------------------------------------------------------- agent API

    /// Opens a session: the agent deposits `max_calls × price` for the service. `agent` must
    /// authorize this call, including the token transfer, which carries the exact deposit.
    ///
    /// - `ticket_key`: the Ed25519 key the agent signs its tickets with (not its account key).
    /// - `sample_k`: one call in k is proved; 1 proves every call.
    /// - `batch_size`: at most this many calls per batch (exactly this many when k > 1, except
    ///   the last batch).
    /// - `seed`: the verifier's seed-chain commitment when k > 1; 32 zero bytes when k = 1.
    /// - `expires_at`: when calls stop; batches are accepted until `expires_at` plus the
    ///   service's settlement window.
    #[allow(clippy::too_many_arguments)]
    pub fn open_session(
        env: Env,
        agent: Address,
        session_id: BytesN<32>,
        service_id: BytesN<32>,
        max_calls: u32,
        ticket_key: BytesN<32>,
        sample_k: u32,
        batch_size: u32,
        seed: BytesN<32>,
        expires_at: u64,
    ) -> Result<(), Error> {
        agent.require_auth();
        let zero = BytesN::from_array(&env, &[0; 32]);
        let now = env.ledger().timestamp();
        if session_id == zero
            || ticket_key == zero
            || max_calls == 0
            || max_calls > MAX_CALLS
            || sample_k == 0
            || sample_k > MAX_SAMPLE_K
            || batch_size == 0
            || batch_size > MAX_BATCH
            || expires_at <= now
            || expires_at - now > MAX_DURATION
            || (sample_k == 1) != (seed == zero)
        {
            return Err(Error::InvalidSession);
        }
        if storage::has_session(&env, &session_id) {
            return Err(Error::SessionExists);
        }
        let escrow = EscrowClient::new(&env, &storage::escrow(&env));
        let service = escrow
            .get_service(&service_id)
            .ok_or(Error::UnknownService)?;
        if service.payout == env.current_contract_address() {
            return Err(Error::InvalidSession);
        }
        let deposit = service
            .price_per_call
            .checked_mul(i128::from(max_calls))
            .ok_or(Error::InvalidSession)?;
        let deadline = expires_at + u64::from(service.settlement_window);

        storage::set_session(
            &env,
            &session_id,
            &Session {
                agent: agent.clone(),
                service_id: service_id.clone(),
                token: service.token.clone(),
                payout: service.payout,
                price: service.price_per_call,
                fee_bps: escrow.fee_bps(),
                verifier: service.verifier,
                predicate_hash: service.predicate_hash,
                ticket_key,
                max_calls,
                sample_k,
                batch_size,
                opened_at: now,
                deadline,
                settled: 0,
                chain: session_id.clone(),
                seed,
                status: SessionStatus::Open,
            },
        );
        storage::extend_session(&env, &session_id, deadline - now);
        storage::extend_instance(&env);
        SessionOpened {
            session_id,
            service_id,
            agent: agent.clone(),
            deposit,
            max_calls,
            price: service.price_per_call,
            sample_k,
            batch_size,
            deadline,
        }
        .publish(&env);

        TokenClient::new(&env, &service.token).transfer(
            &agent,
            env.current_contract_address(),
            &deposit,
        );
        Ok(())
    }

    // ------------------------------------------------------------------- settlement (anyone)

    /// Settles calls `settled + 1` through `to` with the agent's ticket for call `to` and the
    /// verifier's statement. Callable by anyone, until the session's deadline.
    ///
    /// - `request_hashes`: the calls' request hashes, 32 bytes each, concatenated in call order.
    /// - `ticket`: the agent's signature over `ticket(to)`, which commits it to all those requests.
    /// - `seed`: the batch's revealed seed when k > 1; 32 zero bytes when k = 1.
    /// - `entries`: one 68-byte entry per call, concatenated in call order.
    /// - `statement`: the verifier's signature over the batch statement.
    ///
    /// Proved DELIVERED calls and unproved answered calls are paid, minus `k − 1` calls for each
    /// proved failure (never below zero); the rest of the batch is refunded to the agent. A
    /// signature that does not verify fails the call with the host's crypto error.
    #[allow(clippy::too_many_arguments)]
    pub fn settle_batch(
        env: Env,
        session_id: BytesN<32>,
        to: u32,
        request_hashes: Bytes,
        ticket: BytesN<64>,
        seed: BytesN<32>,
        entries: Bytes,
        statement: BytesN<64>,
    ) -> Result<(), Error> {
        let mut s = open(&env, &session_id)?;
        if env.ledger().timestamp() > s.deadline {
            return Err(Error::WindowClosed);
        }
        let from = s.settled;
        let count = match to.checked_sub(from) {
            Some(c) if c > 0 && c <= s.batch_size && to <= s.max_calls => c,
            _ => return Err(Error::InvalidBatch),
        };
        if request_hashes.len() != count * 32 || entries.len() != count * ENTRY_LEN {
            return Err(Error::LengthMismatch);
        }
        let session_bytes = session_id.to_array();

        // The agent's ticket: the request hashes extend the stored chain to chain(to).
        let mut chain = s.chain.to_array();
        for i in 0..count {
            chain = messages::chain_next(&env, &chain, &messages::request_hash(&request_hashes, i));
        }
        env.crypto().ed25519_verify(
            &s.ticket_key,
            &messages::ticket(&env, &session_bytes, to, &chain),
            &ticket,
        );

        // The seed: none when nothing is sampled; otherwise the next one in the verifier's chain.
        let seed_bytes = seed.to_array();
        if s.sample_k == 1 {
            if seed_bytes != [0; 32] {
                return Err(Error::InvalidSeed);
            }
        } else if messages::sha256(&env, &Bytes::from_array(&env, &seed_bytes)) != s.seed.to_array()
        {
            return Err(Error::InvalidSeed);
        }

        // The entries: proved results only on sampled calls, ANSWERED only on unsampled ones.
        let (mut delivered, mut failed, mut answered, mut unanswered) = (0u32, 0u32, 0u32, 0u32);
        for i in 0..count {
            let e = messages::entry(&entries, i);
            let sampled = messages::sampled(&env, &seed_bytes, from + 1 + i, s.sample_k);
            let proved = e.presentation_hash != [0; 32];
            let blank = e.presentation_hash == [0; 32] && e.response_hash == [0; 32];
            match e.result {
                RESULT_DELIVERED if sampled && proved => delivered += 1,
                RESULT_FAILED if sampled && proved => failed += 1,
                RESULT_ANSWERED if !sampled && blank => answered += 1,
                RESULT_UNANSWERED if blank => unanswered += 1,
                _ => return Err(Error::InvalidEntry),
            }
        }

        // The verifier's statement.
        let entries_hash = messages::sha256(&env, &entries);
        env.crypto().ed25519_verify(
            &s.verifier,
            &messages::statement(
                &env,
                &session_bytes,
                &s.service_id.to_array(),
                &s.predicate_hash.to_array(),
                from,
                to,
                &chain,
                &seed_bytes,
                &entries_hash,
            ),
            &statement,
        );

        // What each party gets. No amount can overflow: each is at most the deposit, which was
        // checked at opening, and the escrow keeps price × fee_bps in range (MAX_PRICE,
        // MAX_FEE_BPS). The fee rounds down, as in the escrow.
        let penalty = i64::from(s.sample_k - 1) * i64::from(failed);
        let paid = (i64::from(answered) + i64::from(delivered) - penalty).max(0) as u32;
        let fee_unit = s.price * i128::from(s.fee_bps) / BPS;
        let payout_amount = i128::from(paid) * (s.price - fee_unit);
        let fee = i128::from(paid) * fee_unit;
        let refund = i128::from(count - paid) * s.price;
        let treasury = if fee != 0 {
            let treasury = EscrowClient::new(&env, &storage::escrow(&env)).treasury();
            if treasury == env.current_contract_address() {
                return Err(Error::InvalidRecipient);
            }
            Some(treasury)
        } else {
            None
        };
        // A sampled session's shorter batch is its last (its seed exposes the rest of the batch).
        let finished = to == s.max_calls || (s.sample_k > 1 && count < s.batch_size);
        let rest = if finished {
            i128::from(s.max_calls - to) * s.price
        } else {
            0
        };

        s.settled = to;
        s.chain = BytesN::from_array(&env, &chain);
        if s.sample_k > 1 {
            s.seed = seed;
        }
        if finished {
            s.status = SessionStatus::Closed;
        }
        storage::set_session(&env, &session_id, &s);
        storage::extend_instance(&env);
        BatchSettled {
            session_id: session_id.clone(),
            service_id: s.service_id.clone(),
            from,
            to,
            delivered,
            failed,
            answered,
            unanswered,
            paid,
            payout_amount,
            fee,
            refund,
            chain: s.chain.clone(),
            entries_hash: BytesN::from_array(&env, &entries_hash),
        }
        .publish(&env);
        if finished {
            SessionClosed {
                session_id,
                service_id: s.service_id.clone(),
                agent: s.agent.clone(),
                refund: rest,
            }
            .publish(&env);
        }

        let token = TokenClient::new(&env, &s.token);
        let me = env.current_contract_address();
        if payout_amount != 0 {
            token.transfer(&me, &s.payout, &payout_amount);
        }
        if let Some(treasury) = treasury {
            token.transfer(&me, &treasury, &fee);
        }
        if refund + rest != 0 {
            token.transfer(&me, &s.agent, &(refund + rest));
        }
        Ok(())
    }

    /// After the session's deadline, returns what is left of the deposit to the agent. Callable by
    /// anyone; the money always goes to the agent.
    pub fn close_session(env: Env, session_id: BytesN<32>) -> Result<(), Error> {
        let mut s = open(&env, &session_id)?;
        if env.ledger().timestamp() <= s.deadline {
            return Err(Error::WindowOpen);
        }
        let refund = i128::from(s.max_calls - s.settled) * s.price;
        s.status = SessionStatus::Closed;
        storage::set_session(&env, &session_id, &s);
        storage::extend_instance(&env);
        SessionClosed {
            session_id,
            service_id: s.service_id.clone(),
            agent: s.agent.clone(),
            refund,
        }
        .publish(&env);
        if refund != 0 {
            TokenClient::new(&env, &s.token).transfer(
                &env.current_contract_address(),
                &s.agent,
                &refund,
            );
        }
        Ok(())
    }

    // ------------------------------------------------------------------------------------ views

    pub fn escrow(env: Env) -> Address {
        storage::escrow(&env)
    }

    /// `None` for a session id that was never opened.
    pub fn get_session(env: Env, session_id: BytesN<32>) -> Option<Session> {
        storage::session(&env, &session_id)
    }

    /// The exact bytes the agent's ticket key signs for call `n` of a session, on this network and
    /// this contract.
    pub fn ticket_message(env: Env, session_id: BytesN<32>, n: u32, chain: BytesN<32>) -> Bytes {
        messages::ticket(&env, &session_id.to_array(), n, &chain.to_array())
    }

    /// The exact bytes the verifier signs for a batch statement, on this network and this contract.
    #[allow(clippy::too_many_arguments)]
    pub fn statement_message(
        env: Env,
        session_id: BytesN<32>,
        service_id: BytesN<32>,
        predicate_hash: BytesN<32>,
        from: u32,
        to: u32,
        chain: BytesN<32>,
        seed: BytesN<32>,
        entries: Bytes,
    ) -> Bytes {
        messages::statement(
            &env,
            &session_id.to_array(),
            &service_id.to_array(),
            &predicate_hash.to_array(),
            from,
            to,
            &chain.to_array(),
            &seed.to_array(),
            &messages::sha256(&env, &entries),
        )
    }

    /// The id call `n` of a session is proved against (its `X-Fermata-Call` header).
    pub fn call_id(env: Env, session_id: BytesN<32>, n: u32) -> BytesN<32> {
        messages::call_id(&env, &session_id.to_array(), n)
    }

    /// Whether call `n` is proved in a batch with this seed, sampling one call in `k`.
    pub fn sampled(env: Env, seed: BytesN<32>, n: u32, k: u32) -> bool {
        messages::sampled(&env, &seed.to_array(), n, k)
    }
}

// --------------------------------------------------------------------------------------- internals

fn open(env: &Env, session_id: &BytesN<32>) -> Result<Session, Error> {
    match storage::session(env, session_id) {
        Some(s) if s.status == SessionStatus::Open => Ok(s),
        _ => Err(Error::NotOpen),
    }
}
