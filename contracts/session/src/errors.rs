use soroban_sdk::contracterror;

/// Contract errors. Codes are public ABI and never reused. They start at 201, apart from the
/// escrow's (101–117) and the Stellar Asset Contract's own codes (1–15, e.g. 10 = insufficient
/// balance), which a failed token transfer propagates unchanged.
///
/// A ticket or statement signature that does not verify is not a contract error: the host's
/// `ed25519_verify` traps with a crypto error, as in the escrow.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// Opening terms outside the limits (calls, k, batch size, expiry, deposit), a zero session
    /// id or ticket key, a seed that does not match k, or a service whose payout is this contract.
    InvalidSession = 201,
    SessionExists = 202,
    /// The escrow has no service with this id.
    UnknownService = 203,
    /// No open session with this id.
    NotOpen = 204,
    /// The session's deadline has passed; only `close_session` remains.
    WindowClosed = 205,
    /// The session's deadline has not passed yet.
    WindowOpen = 206,
    /// A batch that settles no call, goes past `max_calls`, is longer than B, or (sampled) is not
    /// the next B calls.
    InvalidBatch = 207,
    /// Request hashes or entries whose length is not the batch's number of calls.
    LengthMismatch = 208,
    /// A seed that is not the next one in the verifier's chain, or a non-zero seed when k = 1.
    InvalidSeed = 209,
    /// A result that the sample or the hashes do not allow.
    InvalidEntry = 210,
    /// The escrow's treasury is this contract: fees sent there could never leave.
    InvalidRecipient = 211,
}
