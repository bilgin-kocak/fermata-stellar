//! The verdict and the exact bytes a verifier signs.
//!
//! Ported from Fermata `apps/attestor/src/eip712.rs` @ d7cc642 (github.com/bilgin-kocak/fermata,
//! MIT): the `Verdict` fields, their order, the outcome values and the JSON shape are kept. The
//! EIP-712 digest and the secp256k1 signature are replaced by an Ed25519 signature over a
//! domain-separated, fixed-width message that Soroban verifies natively
//! (`docs/PORTING_NOTES.md`, section 3).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Error;

/// Versioned domain tag; the first 26 bytes of every verdict message.
pub const VERDICT_TAG: &[u8; 26] = b"FERMATA_STELLAR_VERDICT_V1";
/// Six 32-byte fields, `outcome` (u32) and `issued_at` (u64).
pub const CANONICAL_LEN: usize = 6 * 32 + 4 + 8;
/// Tag, network id, contract id, canonical verdict.
pub const MESSAGE_LEN: usize = VERDICT_TAG.len() + 32 + 32 + CANONICAL_LEN;

pub const OUTCOME_DELIVERED: u32 = 1;
pub const OUTCOME_FAILED: u32 = 2;

pub const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
pub const MAINNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";
pub const FUTURENET_PASSPHRASE: &str = "Test SDF Future Network ; October 2022";
pub const STANDALONE_PASSPHRASE: &str = "Standalone Network ; February 2017";

/// The verifier's decision about one call: the fields of Fermata's EIP-712 `Verdict`, in order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    #[serde(with = "crate::hex32")]
    pub call_id: [u8; 32],
    #[serde(with = "crate::hex32")]
    pub service_id: [u8; 32],
    #[serde(with = "crate::hex32")]
    pub request_hash: [u8; 32],
    #[serde(with = "crate::hex32")]
    pub predicate_hash: [u8; 32],
    /// 1 = DELIVERED, 2 = FAILED. A `u32` because Soroban has no `u8` value type.
    pub outcome: u32,
    #[serde(with = "crate::hex32")]
    pub presentation_hash: [u8; 32],
    #[serde(with = "crate::hex32")]
    pub response_hash: [u8; 32],
    /// Unix seconds. Signed, not checked on-chain (as on Tempo).
    pub issued_at: u64,
}

impl Verdict {
    /// The eight fields concatenated in declaration order, integers big-endian (204 bytes).
    pub fn canonical_bytes(&self) -> [u8; CANONICAL_LEN] {
        let outcome = self.outcome.to_be_bytes();
        let issued_at = self.issued_at.to_be_bytes();
        let mut out = [0u8; CANONICAL_LEN];
        concat_into(
            &mut out,
            &[
                &self.call_id,
                &self.service_id,
                &self.request_hash,
                &self.predicate_hash,
                &outcome,
                &self.presentation_hash,
                &self.response_hash,
                &issued_at,
            ],
        );
        out
    }
}

/// Where a verdict is valid: one network and one escrow contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Domain {
    /// sha256(network passphrase), what `env.ledger().network_id()` returns on-chain.
    pub network_id: [u8; 32],
    /// The 32-byte id inside the escrow's `C…` address.
    pub contract_id: [u8; 32],
}

impl Domain {
    pub fn new(network_passphrase: &str, contract_id: [u8; 32]) -> Self {
        Self {
            network_id: network_id(network_passphrase),
            contract_id,
        }
    }
}

/// sha256(network passphrase): Stellar's network id.
pub fn network_id(network_passphrase: &str) -> [u8; 32] {
    Sha256::digest(network_passphrase.as_bytes()).into()
}

/// The 294 bytes a verifier signs for `verdict` on `domain`.
pub fn message(domain: &Domain, verdict: &Verdict) -> [u8; MESSAGE_LEN] {
    let canonical = verdict.canonical_bytes();
    let mut out = [0u8; MESSAGE_LEN];
    concat_into(
        &mut out,
        &[
            VERDICT_TAG,
            &domain.network_id,
            &domain.contract_id,
            &canonical,
        ],
    );
    out
}

/// Ed25519 signature over [`message`]. Deterministic (RFC 8032), so vectors are reproducible.
pub fn sign(key: &SigningKey, domain: &Domain, verdict: &Verdict) -> [u8; 64] {
    key.sign(&message(domain, verdict)).to_bytes()
}

/// Verifies as the Soroban host does: the key must decode to a curve point and the signature must
/// pass `verify_strict` (canonical `S`, no small-order key).
pub fn verify(
    public_key: &[u8; 32],
    domain: &Domain,
    verdict: &Verdict,
    signature: &[u8; 64],
) -> Result<(), Error> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| Error::PublicKey)?;
    let signature = Signature::from_bytes(signature);
    key.verify_strict(&message(domain, verdict), &signature)
        .map_err(|_| Error::Signature)
}

pub(crate) fn concat_into(out: &mut [u8], parts: &[&[u8]]) {
    let mut at = 0;
    for part in parts {
        out[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    assert_eq!(at, out.len(), "fixed-width layout");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict() -> Verdict {
        Verdict {
            call_id: [0x11; 32],
            service_id: [0x22; 32],
            request_hash: [0x33; 32],
            predicate_hash: [0x44; 32],
            outcome: OUTCOME_DELIVERED,
            presentation_hash: [0x55; 32],
            response_hash: [0x66; 32],
            issued_at: 1_700_000_000,
        }
    }

    fn domain() -> Domain {
        Domain::new(TESTNET_PASSPHRASE, [0x0f; 32])
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    #[test]
    fn lengths() {
        assert_eq!(CANONICAL_LEN, 204);
        assert_eq!(MESSAGE_LEN, 294);
    }

    #[test]
    fn testnet_network_id() {
        assert_eq!(
            hex::encode(network_id(TESTNET_PASSPHRASE)),
            "cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd472"
        );
    }

    /// The offsets documented in docs/PORTING_NOTES.md, section 3.
    #[test]
    fn message_layout() {
        let v = verdict();
        let d = domain();
        let m = message(&d, &v);
        assert_eq!(&m[0..26], b"FERMATA_STELLAR_VERDICT_V1");
        assert_eq!(&m[26..58], &d.network_id);
        assert_eq!(&m[58..90], &d.contract_id);
        assert_eq!(&m[90..122], &v.call_id);
        assert_eq!(&m[122..154], &v.service_id);
        assert_eq!(&m[154..186], &v.request_hash);
        assert_eq!(&m[186..218], &v.predicate_hash);
        assert_eq!(&m[218..222], &[0, 0, 0, 1]);
        assert_eq!(&m[222..254], &v.presentation_hash);
        assert_eq!(&m[254..286], &v.response_hash);
        assert_eq!(&m[286..294], &1_700_000_000u64.to_be_bytes());
    }

    #[test]
    fn sign_then_verify() {
        let (v, d, k) = (verdict(), domain(), key());
        let sig = sign(&k, &d, &v);
        assert_eq!(verify(&k.verifying_key().to_bytes(), &d, &v, &sig), Ok(()));
        // deterministic
        assert_eq!(sig, sign(&k, &d, &v));
    }

    #[test]
    fn every_field_and_the_domain_are_signed() {
        let (v, d, k) = (verdict(), domain(), key());
        let pk = k.verifying_key().to_bytes();
        let sig = sign(&k, &d, &v);
        let tampered: [fn(&mut Verdict); 8] = [
            |v| v.call_id[0] ^= 1,
            |v| v.service_id[0] ^= 1,
            |v| v.request_hash[0] ^= 1,
            |v| v.predicate_hash[0] ^= 1,
            |v| v.outcome = OUTCOME_FAILED,
            |v| v.presentation_hash[0] ^= 1,
            |v| v.response_hash[0] ^= 1,
            |v| v.issued_at += 1,
        ];
        for tamper in tampered {
            let mut t = v.clone();
            tamper(&mut t);
            assert_eq!(verify(&pk, &d, &t, &sig), Err(Error::Signature));
        }
        let other_network = Domain::new(MAINNET_PASSPHRASE, d.contract_id);
        assert_eq!(verify(&pk, &other_network, &v, &sig), Err(Error::Signature));
        let other_contract = Domain::new(TESTNET_PASSPHRASE, [0x10; 32]);
        assert_eq!(
            verify(&pk, &other_contract, &v, &sig),
            Err(Error::Signature)
        );
        let other_key = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
        assert_eq!(verify(&other_key, &d, &v, &sig), Err(Error::Signature));
    }

    /// `S + L` verifies under plain Ed25519 implementations that skip the range check;
    /// `verify_strict` (and the Soroban host) must reject it.
    #[test]
    fn non_canonical_s_is_rejected() {
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        let (v, d, k) = (verdict(), domain(), key());
        let mut sig = sign(&k, &d, &v);
        // S lives in the upper 32 bytes, little-endian; add L.
        let mut carry = 0u16;
        for i in 0..32 {
            let sum = sig[32 + i] as u16 + L[i] as u16 + carry;
            sig[32 + i] = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(
            verify(&k.verifying_key().to_bytes(), &d, &v, &sig),
            Err(Error::Signature)
        );
    }

    #[test]
    fn json_shape() {
        let v = verdict();
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(json["call_id"], "11".repeat(32));
        assert_eq!(json["outcome"], 1);
        assert_eq!(json["issued_at"], 1_700_000_000u64);
        let back: Verdict = serde_json::from_value(json).unwrap();
        assert_eq!(back, v);
        // Fermata's 0x-prefixed form is accepted too.
        let mut prefixed = serde_json::to_value(&v).unwrap();
        prefixed["call_id"] = format!("0x{}", "11".repeat(32)).into();
        assert_eq!(serde_json::from_value::<Verdict>(prefixed).unwrap(), v);
    }
}
