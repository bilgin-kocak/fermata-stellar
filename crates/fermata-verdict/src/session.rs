//! Sessions: the agent's tickets and the verifier's batch statements, encoded exactly as the
//! session contract (`contracts/session`) rebuilds them on-chain before calling the host's
//! `ed25519_verify` (`docs/session-escrow.md`, section 10). `test-vectors/session-v1.json` pins
//! every encoding here.
//!
//! - `chain(0) = session_id`, `chain(n) = sha256(chain(n−1) ‖ request_hash of call n)`.
//! - A ticket for call n commits the agent to calls 1 through n, each to its exact request:
//!   `"FERMATA_STELLAR_TICKET_V1" ‖ network id ‖ contract id ‖ session_id ‖ n (u32) ‖ chain(n)`.
//! - A batch statement is the verifier's account of calls `from + 1` through `to`:
//!   `"FERMATA_STELLAR_BATCH_V1" ‖ network id ‖ contract id ‖ session_id ‖ service_id ‖
//!   predicate_hash ‖ from (u32) ‖ to (u32) ‖ chain(to) ‖ seed ‖ entries_hash`.
//!
//! The contract id is the session contract's; integers are big-endian; every field is fixed-width.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{verdict::concat_into, Domain, Error};

/// Versioned domain tag; the first 25 bytes of every ticket.
pub const TICKET_TAG: &[u8; 25] = b"FERMATA_STELLAR_TICKET_V1";
/// Versioned domain tag; the first 24 bytes of every batch statement.
pub const BATCH_TAG: &[u8; 24] = b"FERMATA_STELLAR_BATCH_V1";
/// Versioned domain tag for the id a session call is proved against.
pub const CALL_TAG: &[u8; 31] = b"FERMATA_STELLAR_SESSION_CALL_V1";

/// Tag, network id, contract id, session id, n (u32), chain(n).
pub const TICKET_LEN: usize = TICKET_TAG.len() + 32 * 3 + 4 + 32;
/// Result (u32), presentation hash, response hash.
pub const ENTRY_LEN: usize = 4 + 32 + 32;
/// Tag, network id, contract id, session id, service id, predicate hash, from and to (u32),
/// chain(to), seed, entries hash.
pub const STATEMENT_LEN: usize = BATCH_TAG.len() + 32 * 5 + 4 + 4 + 32 * 3;

/// Proved: the response passed the delivery predicate.
pub const RESULT_DELIVERED: u32 = 1;
/// Proved: the response failed the delivery predicate.
pub const RESULT_FAILED: u32 = 2;
/// Unproved (not sampled), and the vendor answered.
pub const RESULT_ANSWERED: u32 = 3;
/// The vendor did not answer (no transcript), proved or not.
pub const RESULT_UNANSWERED: u32 = 4;

/// One call's result in a batch. Proved results carry the presentation and response hashes;
/// unproved ones carry zeros.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub result: u32,
    #[serde(with = "crate::hex32")]
    pub presentation_hash: [u8; 32],
    #[serde(with = "crate::hex32")]
    pub response_hash: [u8; 32],
}

impl Entry {
    /// A proved call: DELIVERED or FAILED, with its presentation and response hashes.
    pub fn proved(delivered: bool, presentation_hash: [u8; 32], response_hash: [u8; 32]) -> Self {
        Self {
            result: if delivered {
                RESULT_DELIVERED
            } else {
                RESULT_FAILED
            },
            presentation_hash,
            response_hash,
        }
    }

    pub fn answered() -> Self {
        Self {
            result: RESULT_ANSWERED,
            presentation_hash: [0; 32],
            response_hash: [0; 32],
        }
    }

    pub fn unanswered() -> Self {
        Self {
            result: RESULT_UNANSWERED,
            presentation_hash: [0; 32],
            response_hash: [0; 32],
        }
    }

    pub fn is_proved(&self) -> bool {
        self.result == RESULT_DELIVERED || self.result == RESULT_FAILED
    }

    /// `result (u32) ‖ presentation_hash ‖ response_hash`: 68 bytes.
    pub fn bytes(&self) -> [u8; ENTRY_LEN] {
        let mut out = [0u8; ENTRY_LEN];
        concat_into(
            &mut out,
            &[
                &self.result.to_be_bytes(),
                &self.presentation_hash,
                &self.response_hash,
            ],
        );
        out
    }
}

/// `chain(n)` from `chain(n−1)` and the request hash of call n.
pub fn chain_next(chain: &[u8; 32], request_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(chain);
    h.update(request_hash);
    h.finalize().into()
}

/// Extends `chain` over the request hashes of the next calls, in order.
pub fn extend_chain(chain: &[u8; 32], request_hashes: &[[u8; 32]]) -> [u8; 32] {
    request_hashes
        .iter()
        .fold(*chain, |c, request_hash| chain_next(&c, request_hash))
}

/// `chain(n)` for the first n calls of a session, whose request hashes are given in order.
pub fn chain(session_id: &[u8; 32], request_hashes: &[[u8; 32]]) -> [u8; 32] {
    extend_chain(session_id, request_hashes)
}

/// The 157 bytes the agent's ticket key signs for call `n` of `session_id` on `domain` (the
/// session contract's network and id).
pub fn ticket_message(
    domain: &Domain,
    session_id: &[u8; 32],
    n: u32,
    chain: &[u8; 32],
) -> [u8; TICKET_LEN] {
    let mut out = [0u8; TICKET_LEN];
    concat_into(
        &mut out,
        &[
            TICKET_TAG,
            &domain.network_id,
            &domain.contract_id,
            session_id,
            &n.to_be_bytes(),
            chain,
        ],
    );
    out
}

/// Ed25519 signature over [`ticket_message`]. Deterministic, so vectors are reproducible.
pub fn sign_ticket(
    key: &SigningKey,
    domain: &Domain,
    session_id: &[u8; 32],
    n: u32,
    chain: &[u8; 32],
) -> [u8; 64] {
    key.sign(&ticket_message(domain, session_id, n, chain))
        .to_bytes()
}

/// Verifies a ticket as the Soroban host does (`verify_strict`).
pub fn verify_ticket(
    public_key: &[u8; 32],
    domain: &Domain,
    session_id: &[u8; 32],
    n: u32,
    chain: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), Error> {
    verify_strict(
        public_key,
        &ticket_message(domain, session_id, n, chain),
        signature,
    )
}

/// sha256 of the entries' bytes, concatenated in call order.
pub fn entries_hash(entries: &[Entry]) -> [u8; 32] {
    let mut h = Sha256::new();
    for entry in entries {
        h.update(entry.bytes());
    }
    h.finalize().into()
}

/// The verifier's account of calls `from + 1` through `to` of a session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    #[serde(with = "crate::hex32")]
    pub session_id: [u8; 32],
    #[serde(with = "crate::hex32")]
    pub service_id: [u8; 32],
    #[serde(with = "crate::hex32")]
    pub predicate_hash: [u8; 32],
    pub from: u32,
    pub to: u32,
    /// `chain(to)`.
    #[serde(with = "crate::hex32")]
    pub chain: [u8; 32],
    /// The batch's revealed seed; 32 zero bytes when nothing is sampled (k = 1).
    #[serde(with = "crate::hex32")]
    pub seed: [u8; 32],
    #[serde(with = "crate::hex32")]
    pub entries_hash: [u8; 32],
}

/// The 288 bytes a verifier signs for a batch statement on `domain`.
pub fn statement_message(domain: &Domain, s: &Statement) -> [u8; STATEMENT_LEN] {
    let mut out = [0u8; STATEMENT_LEN];
    concat_into(
        &mut out,
        &[
            BATCH_TAG,
            &domain.network_id,
            &domain.contract_id,
            &s.session_id,
            &s.service_id,
            &s.predicate_hash,
            &s.from.to_be_bytes(),
            &s.to.to_be_bytes(),
            &s.chain,
            &s.seed,
            &s.entries_hash,
        ],
    );
    out
}

/// Ed25519 signature over [`statement_message`].
pub fn sign_statement(key: &SigningKey, domain: &Domain, s: &Statement) -> [u8; 64] {
    key.sign(&statement_message(domain, s)).to_bytes()
}

/// Verifies a statement as the Soroban host does (`verify_strict`).
pub fn verify_statement(
    public_key: &[u8; 32],
    domain: &Domain,
    s: &Statement,
    signature: &[u8; 64],
) -> Result<(), Error> {
    verify_strict(public_key, &statement_message(domain, s), signature)
}

/// Whether call `n` is proved in a batch with seed `seed`, sampling one call in `k`: always for
/// k = 1; otherwise when the first four bytes of `sha256(seed ‖ n)`, big-endian, are a multiple
/// of k.
pub fn sampled(seed: &[u8; 32], n: u32, k: u32) -> bool {
    if k <= 1 {
        return true;
    }
    let mut h = Sha256::new();
    h.update(seed);
    h.update(n.to_be_bytes());
    let digest: [u8; 32] = h.finalize().into();
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]).is_multiple_of(k)
}

/// The id call `n` of a session is proved against (its `X-Fermata-Call` header):
/// `sha256("FERMATA_STELLAR_SESSION_CALL_V1" ‖ contract id ‖ session_id ‖ n)`.
pub fn call_id(contract_id: &[u8; 32], session_id: &[u8; 32], n: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CALL_TAG);
    h.update(contract_id);
    h.update(session_id);
    h.update(n.to_be_bytes());
    h.finalize().into()
}

/// The verifier's seed chain for a session of `batches` batches: `seeds[0]` is the commitment
/// `sha256^m(secret)` that goes into `open_session`, and batch j reveals `seeds[j]`, so that
/// `sha256(seeds[j]) = seeds[j − 1]`. `seeds[batches]` is the secret itself.
pub fn seed_chain(secret: &[u8; 32], batches: u32) -> Vec<[u8; 32]> {
    let mut seeds = Vec::with_capacity(batches as usize + 1);
    let mut s = *secret;
    seeds.push(s);
    for _ in 0..batches {
        s = Sha256::digest(s).into();
        seeds.push(s);
    }
    seeds.reverse();
    seeds
}

fn verify_strict(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<(), Error> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| Error::PublicKey)?;
    key.verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| Error::Signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TESTNET_PASSPHRASE;

    fn domain() -> Domain {
        Domain::new(TESTNET_PASSPHRASE, [0x5e; 32])
    }

    #[test]
    fn lengths() {
        assert_eq!(TICKET_LEN, 157);
        assert_eq!(ENTRY_LEN, 68);
        assert_eq!(STATEMENT_LEN, 288);
    }

    #[test]
    fn ticket_layout() {
        let d = domain();
        let m = ticket_message(&d, &[0x5a; 32], 7, &[0x0c; 32]);
        assert_eq!(&m[..25], TICKET_TAG);
        assert_eq!(&m[25..57], &d.network_id);
        assert_eq!(&m[57..89], &d.contract_id);
        assert_eq!(&m[89..121], &[0x5a; 32]);
        assert_eq!(&m[121..125], &7u32.to_be_bytes());
        assert_eq!(&m[125..], &[0x0c; 32]);
    }

    #[test]
    fn statement_layout() {
        let d = domain();
        let s = Statement {
            session_id: [1; 32],
            service_id: [2; 32],
            predicate_hash: [3; 32],
            from: 4,
            to: 9,
            chain: [5; 32],
            seed: [6; 32],
            entries_hash: [7; 32],
        };
        let m = statement_message(&d, &s);
        assert_eq!(&m[..24], BATCH_TAG);
        assert_eq!(&m[24..56], &d.network_id);
        assert_eq!(&m[56..88], &d.contract_id);
        assert_eq!(&m[88..120], &[1; 32]);
        assert_eq!(&m[120..152], &[2; 32]);
        assert_eq!(&m[152..184], &[3; 32]);
        assert_eq!(&m[184..188], &4u32.to_be_bytes());
        assert_eq!(&m[188..192], &9u32.to_be_bytes());
        assert_eq!(&m[192..224], &[5; 32]);
        assert_eq!(&m[224..256], &[6; 32]);
        assert_eq!(&m[256..], &[7; 32]);
    }

    #[test]
    fn chain_folds_in_order() {
        let (a, b) = ([0xaa; 32], [0xbb; 32]);
        let one = chain_next(&[0x5a; 32], &a);
        assert_eq!(chain(&[0x5a; 32], &[a, b]), chain_next(&one, &b));
        assert_ne!(chain(&[0x5a; 32], &[a, b]), chain(&[0x5a; 32], &[b, a]));
        assert_eq!(chain(&[0x5a; 32], &[]), [0x5a; 32]);
        assert_eq!(extend_chain(&one, &[b]), chain(&[0x5a; 32], &[a, b]));
    }

    #[test]
    fn tickets_and_statements_sign_and_verify() {
        let d = domain();
        let key = SigningKey::from_bytes(&[9; 32]);
        let pk = key.verifying_key().to_bytes();
        let sig = sign_ticket(&key, &d, &[0x5a; 32], 3, &[0x0c; 32]);
        assert_eq!(
            verify_ticket(&pk, &d, &[0x5a; 32], 3, &[0x0c; 32], &sig),
            Ok(())
        );
        // Another call number, chain, session or domain does not verify.
        assert!(verify_ticket(&pk, &d, &[0x5a; 32], 4, &[0x0c; 32], &sig).is_err());
        assert!(verify_ticket(&pk, &d, &[0x5a; 32], 3, &[0x0d; 32], &sig).is_err());
        assert!(verify_ticket(&pk, &d, &[0x5b; 32], 3, &[0x0c; 32], &sig).is_err());
        let other = Domain::new(TESTNET_PASSPHRASE, [0x5f; 32]);
        assert!(verify_ticket(&pk, &other, &[0x5a; 32], 3, &[0x0c; 32], &sig).is_err());

        let s = Statement {
            session_id: [1; 32],
            service_id: [2; 32],
            predicate_hash: [3; 32],
            from: 0,
            to: 2,
            chain: [5; 32],
            seed: [0; 32],
            entries_hash: entries_hash(&[Entry::answered(), Entry::unanswered()]),
        };
        let sig = sign_statement(&key, &d, &s);
        assert_eq!(verify_statement(&pk, &d, &s, &sig), Ok(()));
        let mut changed = s.clone();
        changed.to = 3;
        assert!(verify_statement(&pk, &d, &changed, &sig).is_err());
    }

    #[test]
    fn entries_hash_covers_order_and_content() {
        let a = Entry::proved(true, [1; 32], [2; 32]);
        let b = Entry::proved(false, [1; 32], [2; 32]);
        assert_ne!(entries_hash(&[a, b]), entries_hash(&[b, a]));
        assert_ne!(entries_hash(&[a]), entries_hash(&[b]));
        assert_eq!(a.bytes()[..4], 1u32.to_be_bytes());
        assert!(a.is_proved() && !Entry::answered().is_proved());
    }

    #[test]
    fn sampling() {
        let seed = [0x5c; 32];
        assert!((1..=100).all(|n| sampled(&seed, n, 1)));
        let hits = (1..=4_000).filter(|&n| sampled(&seed, n, 4)).count();
        // One call in four, give or take: a sanity check of the rule, not a statistical test.
        assert!((850..=1_150).contains(&hits), "{hits}");
        // Another seed samples other calls.
        let other: Vec<u32> = (1..=64).filter(|&n| sampled(&[0x5d; 32], n, 4)).collect();
        let mine: Vec<u32> = (1..=64).filter(|&n| sampled(&seed, n, 4)).collect();
        assert_ne!(mine, other);
    }

    #[test]
    fn seed_chain_reveals_backwards() {
        let seeds = seed_chain(&[0x5c; 32], 3);
        assert_eq!(seeds.len(), 4);
        assert_eq!(seeds[3], [0x5c; 32]);
        for j in 1..seeds.len() {
            assert_eq!(<[u8; 32]>::from(Sha256::digest(seeds[j])), seeds[j - 1]);
        }
    }

    #[test]
    fn call_ids_are_distinct() {
        let c = [0x5e; 32];
        assert_ne!(call_id(&c, &[1; 32], 1), call_id(&c, &[1; 32], 2));
        assert_ne!(call_id(&c, &[1; 32], 1), call_id(&c, &[2; 32], 1));
        assert_ne!(call_id(&c, &[1; 32], 1), call_id(&[0x5f; 32], &[1; 32], 1));
    }
}
