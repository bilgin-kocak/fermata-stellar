//! The hashes that tie a proof to an on-chain service and hold.
//!
//! Ported from Fermata `apps/attestor/src/hashes.rs` @ d7cc642 (github.com/bilgin-kocak/fermata,
//! MIT) with the definitions unchanged: the escrow stores these as opaque 32-byte values, so moving
//! from Tempo to Stellar does not change them. The vectors below are the ones Fermata's Solidity,
//! Rust and TypeScript tests share. Errors are this crate's `Error` instead of `anyhow`.

use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::Error;

/// `requestHash = sha256(serviceId ‖ METHOD ‖ request-target ‖ sha256(body))`, no separators.
/// `method` is upper-cased; `target` is verbatim from the request line (origin-form with `?query`).
pub fn request_hash(service_id: &[u8; 32], method: &str, target: &str, body: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(service_id);
    h.update(method.to_ascii_uppercase().as_bytes());
    h.update(target.as_bytes());
    h.update(Sha256::digest(body));
    h.finalize().into()
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

/// `predicateHash = sha256(predicate JSON bytes exactly as registered)`.
pub fn predicate_hash(predicate_bytes: &[u8]) -> [u8; 32] {
    sha256(predicate_bytes)
}

/// `notaryKeyHash = keccak256(notary verifying key, 33-byte compressed SEC1)`.
pub fn notary_key_hash(key: &[u8]) -> [u8; 32] {
    keccak256(key)
}

/// An HTTPS origin in canonical form: `https://` + lower-case DNS host + `:port` unless 443.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    pub host: String,
    pub port: u16,
}

impl Origin {
    /// Parses `https://host[:port][/]`. Anything else (other schemes, paths, user info) is rejected.
    pub fn parse(s: &str) -> Result<Self, Error> {
        let rest = s
            .strip_prefix("https://")
            .ok_or_else(|| Error::Origin(format!("origin must start with https://: {s}")))?;
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        if rest.is_empty() || rest.contains(['/', '?', '#', '@']) {
            return Err(Error::Origin(format!("not a bare origin: {s}")));
        }
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) => (
                h,
                p.parse::<u16>()
                    .map_err(|_| Error::Origin(format!("bad port in {s}")))?,
            ),
            None => (rest, 443),
        };
        Self::new(host, port)
    }

    pub fn new(host: &str, port: u16) -> Result<Self, Error> {
        let host = host.to_ascii_lowercase();
        if host.is_empty()
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        {
            return Err(Error::Origin(format!(
                "origin host must be a DNS name: {host:?}"
            )));
        }
        Ok(Self { host, port })
    }

    /// The value a request to this origin carries in its `Host` header.
    pub fn host_header(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    pub fn canonical(&self) -> String {
        format!("https://{}", self.host_header())
    }

    /// `originHash = keccak256(canonical origin string)`.
    pub fn hash(&self) -> [u8; 32] {
        keccak256(self.canonical().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_hash_vector() {
        // Same vector as Fermata's contracts/test/Vectors.t.sol and packages/sdk/test/requestHash.test.ts.
        let mut sid = [0u8; 32];
        sid[31] = 1;
        let h = request_hash(&sid, "post", "/v1/quote", br#"{"symbol":"BTC-USD"}"#);
        assert_eq!(
            hex::encode(h),
            "e8b23a0b9ea8101a4a0173a94062d4c5a197bc08b706e069c58eafccc47444b7"
        );
    }

    #[test]
    fn origin_canonical_forms() {
        let o = Origin::parse("https://Vendor.Fermata.Test:8443/").unwrap();
        assert_eq!(o.canonical(), "https://vendor.fermata.test:8443");
        assert_eq!(o.host_header(), "vendor.fermata.test:8443");
        assert_eq!(
            Origin::parse("https://api.example.com:443")
                .unwrap()
                .canonical(),
            "https://api.example.com"
        );
        assert_eq!(
            Origin::parse("https://api.example.com")
                .unwrap()
                .host_header(),
            "api.example.com"
        );
        for bad in [
            "http://a.com",
            "https://a.com/x",
            "https://a.com?q",
            "https://u@a.com",
            "https://",
            "https://a.com:99999",
        ] {
            assert!(Origin::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn hash_vectors() {
        // Shared with Fermata's packages/sdk/test/hashes.test.ts (values from `cast keccak`).
        let o = Origin::parse("https://vendor.fermata.test:8443").unwrap();
        assert_eq!(
            hex::encode(o.hash()),
            "99d1433da9b4903068a8548272ad3128e24be018828f8b1f14282b37b8261f29"
        );
        let key = hex::decode("02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27")
            .unwrap();
        assert_eq!(
            hex::encode(notary_key_hash(&key)),
            "138b5a9c7e4489edde45496ce6770b6d91d5a0bcebb81ead85a3704242008aff"
        );
    }

    #[test]
    fn predicate_hash_of_the_demo_predicate() {
        // predicates/quote-v1.json is Fermata's apps/attestor/predicates/quote-v1.json, byte for byte;
        // this is the predicateHash in Fermata's contracts/test/fixtures/attest-vector.json.
        let bytes = include_bytes!("../../../predicates/quote-v1.json");
        assert_eq!(
            hex::encode(predicate_hash(bytes)),
            "f9607cf217c0df0ef28de1cfbf3aa69c87f8a70d61a4557f5a7815958754c3e6"
        );
    }
}
