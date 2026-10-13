//! The bytes a verifier signs, rebuilt on-chain, and service-id derivation. Both must match
//! `crates/fermata-verdict` byte for byte; `test-vectors/verdict-v1.json` pins them.

use soroban_sdk::{address_payload::AddressPayload, xdr::ToXdr, Address, Bytes, BytesN, Env};

use crate::Verdict;

/// Versioned domain tag; the first 26 bytes of every verdict message.
pub const VERDICT_TAG: &[u8; 26] = b"FERMATA_STELLAR_VERDICT_V1";
/// Versioned domain tag for service ids.
pub const SERVICE_TAG: &[u8; 26] = b"FERMATA_STELLAR_SERVICE_V1";

/// `"FERMATA_STELLAR_VERDICT_V1" ‖ network id ‖ this contract's id ‖ canonical(verdict)`: 294
/// bytes, every field fixed-width, integers big-endian. The network id (sha256 of the network
/// passphrase) and the contract id play the roles of EIP-712's `chainId` and `verifyingContract`,
/// so a verdict signed for another network or another escrow does not verify here.
pub fn message(env: &Env, verdict: &Verdict) -> Bytes {
    let mut m = Bytes::from_array(env, VERDICT_TAG);
    m.append(&env.ledger().network_id().into());
    m.append(&contract_id(env).into());
    m.append(&verdict.call_id.clone().into());
    m.append(&verdict.service_id.clone().into());
    m.append(&verdict.request_hash.clone().into());
    m.append(&verdict.predicate_hash.clone().into());
    m.extend_from_array(&verdict.outcome.to_be_bytes());
    m.append(&verdict.presentation_hash.clone().into());
    m.append(&verdict.response_hash.clone().into());
    m.extend_from_array(&verdict.issued_at.to_be_bytes());
    m
}

/// The 32-byte id inside this contract's `C…` address. `to_payload` is used only to read the
/// contract's own id for domain separation, never to authenticate an account.
fn contract_id(env: &Env) -> BytesN<32> {
    match env.current_contract_address().to_payload() {
        Some(AddressPayload::ContractIdHash(id)) => id,
        _ => panic!("a contract address has a contract id"),
    }
}

/// `sha256("FERMATA_STELLAR_SERVICE_V1" ‖ XDR(ScVal::Address(owner)) ‖ label)`. Derived from the
/// authenticated owner, so nobody can register under another owner's id (on Tempo: the id's
/// 20-byte owner prefix, checked against `msg.sender`).
pub fn service_id(env: &Env, owner: &Address, label: &BytesN<12>) -> BytesN<32> {
    let mut preimage = Bytes::from_array(env, SERVICE_TAG);
    preimage.append(&owner.clone().to_xdr(env));
    preimage.append(&label.clone().into());
    env.crypto().sha256(&preimage).into()
}
