use soroban_sdk::{contracttype, Address, BytesN};

/// Life cycle of a session. A session id is usable once, ever.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum SessionStatus {
    /// Calls may be settled until the deadline.
    Open = 1,
    /// Every call settled, a short sampled batch ended it, or it was closed after its deadline.
    /// What was left of the deposit went back to the agent.
    Closed = 2,
}

/// One deposit for up to `max_calls` calls of one service, settled in batches. The service's
/// terms are copied from the escrow's registry at opening (services are immutable there).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session {
    pub agent: Address,
    pub service_id: BytesN<32>,
    pub token: Address,
    pub payout: Address,
    /// The service's price per call; the deposit is `max_calls × price`.
    pub price: i128,
    /// The escrow's fee at opening; later fee changes do not apply to this session.
    pub fee_bps: u32,
    /// The Ed25519 key whose batch statements settle this session (the service's verifier).
    pub verifier: BytesN<32>,
    pub predicate_hash: BytesN<32>,
    /// The agent's Ed25519 key for tickets (not its account key).
    pub ticket_key: BytesN<32>,
    pub max_calls: u32,
    /// One call in `sample_k` is proved; 1 proves every call.
    pub sample_k: u32,
    /// The batch size B: at most B calls per batch, exactly B for sampled sessions except the last.
    pub batch_size: u32,
    pub opened_at: u64,
    /// The last ledger timestamp at which a batch is accepted: `expires_at + settlement_window`.
    pub deadline: u64,
    /// Calls settled so far; the next batch starts at call `settled + 1`.
    pub settled: u32,
    /// `chain(settled)`; `session_id` before the first batch.
    pub chain: BytesN<32>,
    /// The last revealed seed (the commitment before the first batch); zero when `sample_k` is 1.
    pub seed: BytesN<32>,
    pub status: SessionStatus,
}

/// The escrow's `Service`, as its `get_service` view returns it. Field names and types must stay
/// identical to `fermata_escrow::Service` (contract types are encoded as maps keyed by field
/// name); a test reads a real escrow through this type.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Service {
    pub owner: Address,
    pub label: BytesN<12>,
    pub settlement_window: u32,
    pub payout: Address,
    pub token: Address,
    pub verifier: BytesN<32>,
    pub price_per_call: i128,
    pub predicate_hash: BytesN<32>,
    pub origin_hash: BytesN<32>,
    pub notary_key_hash: BytesN<32>,
}
