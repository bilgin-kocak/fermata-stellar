use soroban_sdk::contracterror;

/// Contract errors. The names follow `FermataEscrow.sol`; codes are public ABI and never reused.
///
/// Codes start at 101 so they cannot be confused with the Stellar Asset Contract's own error codes
/// (1–15, e.g. 10 = insufficient balance), which a failed token transfer inside `hold`, `settle`
/// or `claim_timeout` propagates unchanged.
///
/// Not carried over, because Soroban reports them itself: `NotOwner` (a failed `require_auth` is a
/// host auth error), `InvalidSignature` and `WrongVerifier` (`ed25519_verify` traps with a host
/// crypto error), `TransferFailed` (SEP-41 transfers trap instead of returning `false`),
/// `RecipientBlocked` (a SAC transfer to a blocked recipient fails on its own), `ZeroAddress`
/// (a Stellar `Address` cannot be zero) and `ServiceIdNotOwned` (ids are derived from the
/// authenticated owner).
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// A fee above `MAX_FEE_BPS`.
    FeeTooHigh = 101,
    /// A payout or treasury that would lock the funds (this escrow, or the service's token).
    InvalidRecipient = 102,
    /// A verifier key of 32 zero bytes.
    InvalidVerifier = 103,
    /// A price outside `1..=MAX_PRICE` or a settlement window outside `1..=MAX_WINDOW`.
    InvalidService = 104,
    ServiceExists = 105,
    UnknownService = 106,
    /// A zero call id or request hash.
    InvalidCall = 107,
    CallIdUsed = 108,
    NotHeld = 109,
    WindowClosed = 110,
    WindowOpen = 111,
    CallIdMismatch = 112,
    ServiceMismatch = 113,
    RequestMismatch = 114,
    PredicateMismatch = 115,
    InvalidOutcome = 116,
    InvalidPresentation = 117,
}
