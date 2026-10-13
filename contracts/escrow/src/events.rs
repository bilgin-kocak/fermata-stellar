//! Events. On Tempo every token movement carried `memo = callId`; here the escrow's events carry
//! the call id as a topic, next to the token contract's own `transfer` events in the same
//! transaction. Topics are (event name, then up to three ids), as the three indexed parameters of
//! the Solidity events.

use soroban_sdk::{contractevent, Address, BytesN};

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceRegistered {
    #[topic]
    pub service_id: BytesN<32>,
    #[topic]
    pub owner: Address,
    #[topic]
    pub token: Address,
    pub label: BytesN<12>,
    pub payout: Address,
    pub verifier: BytesN<32>,
    pub price_per_call: i128,
    pub settlement_window: u32,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Held {
    #[topic]
    pub call_id: BytesN<32>,
    #[topic]
    pub service_id: BytesN<32>,
    #[topic]
    pub agent: Address,
    pub amount: i128,
    pub request_hash: BytesN<32>,
}

/// A DELIVERED verdict paid the vendor `amount - fee` and the treasury `fee`.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Released {
    #[topic]
    pub call_id: BytesN<32>,
    #[topic]
    pub service_id: BytesN<32>,
    #[topic]
    pub payout: Address,
    pub amount: i128,
    pub fee: i128,
    pub presentation_hash: BytesN<32>,
}

/// A FAILED verdict refunded the agent in full.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Refunded {
    #[topic]
    pub call_id: BytesN<32>,
    #[topic]
    pub service_id: BytesN<32>,
    #[topic]
    pub agent: Address,
    pub amount: i128,
    pub presentation_hash: BytesN<32>,
}

/// No verdict settled the hold inside its window; the agent was refunded in full.
/// (On Tempo this was `Refunded` with a zero presentation hash.)
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimedOut {
    #[topic]
    pub call_id: BytesN<32>,
    #[topic]
    pub service_id: BytesN<32>,
    #[topic]
    pub agent: Address,
    pub amount: i128,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeeBpsUpdated {
    pub fee_bps: u32,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreasuryUpdated {
    #[topic]
    pub treasury: Address,
}
