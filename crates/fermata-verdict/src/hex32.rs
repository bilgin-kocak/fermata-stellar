//! Serde helper for 32-byte values as hex strings.
//!
//! Adapted from Fermata `apps/attestor/src/eip712.rs` @ d7cc642 (github.com/bilgin-kocak/fermata,
//! MIT): output drops the `0x` prefix (the Stellar CLI's form for `BytesN`); input accepts both.

use serde::{Deserialize, Deserializer, Serializer};

pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(bytes))
}

pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
    let s = String::deserialize(d)?;
    crate::parse_hex::<32>(&s).map_err(serde::de::Error::custom)
}
