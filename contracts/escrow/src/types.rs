use soroban_sdk::{contracttype, Address, BytesN};

/// Life cycle of a call. A call id is usable once, ever: once a hold exists for it, its record is
/// never removed (an expired one is archived and restored on access, never deleted).
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Status {
    Held = 1,
    Released = 2,
    Refunded = 3,
    TimedOut = 4,
}

/// A vendor's paid endpoint. Immutable once registered: the held amount, the verifier key and the
/// pinned hashes are read from it when a hold settles.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Service {
    pub owner: Address,
    /// The 12-byte label the id was derived from (on Tempo it was the id's last 12 bytes).
    pub label: BytesN<12>,
    /// Seconds after `hold` during which `settle` is accepted; afterwards only `claim_timeout`.
    pub settlement_window: u32,
    pub payout: Address,
    pub token: Address,
    /// The Ed25519 public key whose verdicts this service accepts.
    pub verifier: BytesN<32>,
    pub price_per_call: i128,
    /// sha256 of the delivery-predicate JSON the verifier enforces.
    pub predicate_hash: BytesN<32>,
    /// Hash of the upstream origin the proof must be against (checked off-chain by the verifier).
    pub origin_hash: BytesN<32>,
    /// Hash of the accepted notary key (checked off-chain by the verifier).
    pub notary_key_hash: BytesN<32>,
}

/// Storage record of a hold. Kept in full after finalisation (Tempo cleared `service_id` and
/// `request_hash` only to earn storage credits, which Stellar does not have).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hold {
    pub agent: Address,
    pub service_id: BytesN<32>,
    pub request_hash: BytesN<32>,
    pub held_at: u64,
    /// The fee in force at `hold`; later fee changes do not apply to this call.
    pub fee_bps: u32,
    pub status: Status,
}

/// What `get_hold` returns. As on Tempo, `amount` and `deadline` are 0 unless the call is Held.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HoldView {
    pub agent: Address,
    pub service_id: BytesN<32>,
    pub request_hash: BytesN<32>,
    pub amount: i128,
    pub held_at: u64,
    pub deadline: u64,
    pub fee_bps: u32,
    pub status: Status,
}

/// The verifier's decision about one call: the fields of Fermata's EIP-712 `Verdict`, in order.
/// `outcome` is a `u32` because Soroban has no `u8` value type.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Verdict {
    pub call_id: BytesN<32>,
    pub service_id: BytesN<32>,
    pub request_hash: BytesN<32>,
    pub predicate_hash: BytesN<32>,
    pub outcome: u32,
    pub presentation_hash: BytesN<32>,
    pub response_hash: BytesN<32>,
    pub issued_at: u64,
}
