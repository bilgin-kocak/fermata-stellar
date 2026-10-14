//! Events. As in the escrow, each event's topics are its name and the ids it concerns, and its
//! money moves are the token contract's own `transfer` events in the same transaction.

use soroban_sdk::{contractevent, Address, BytesN};

/// The agent deposited `deposit = max_calls × price` for the session.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionOpened {
    #[topic]
    pub session_id: BytesN<32>,
    #[topic]
    pub service_id: BytesN<32>,
    #[topic]
    pub agent: Address,
    pub deposit: i128,
    pub max_calls: u32,
    pub price: i128,
    pub sample_k: u32,
    pub batch_size: u32,
    pub deadline: u64,
}

/// Calls `from + 1` through `to` were settled: `paid` of them paid the vendor `payout_amount` in
/// all and the treasury `fee`; `refund` went back to the agent for the others.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchSettled {
    #[topic]
    pub session_id: BytesN<32>,
    #[topic]
    pub service_id: BytesN<32>,
    pub from: u32,
    pub to: u32,
    pub delivered: u32,
    pub failed: u32,
    pub answered: u32,
    pub unanswered: u32,
    pub paid: u32,
    pub payout_amount: i128,
    pub fee: i128,
    pub refund: i128,
    /// `chain(to)`.
    pub chain: BytesN<32>,
    pub entries_hash: BytesN<32>,
}

/// The session ended; `refund` (what was left of the deposit) went back to the agent.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionClosed {
    #[topic]
    pub session_id: BytesN<32>,
    #[topic]
    pub service_id: BytesN<32>,
    #[topic]
    pub agent: Address,
    pub refund: i128,
}
