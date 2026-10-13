//! Service ids.
//!
//! On Tempo a service id was `owner address (20 bytes) ‖ label (12 bytes)`, and the escrow checked
//! the prefix against the caller so nobody could register under another vendor's id. A Stellar
//! address does not fit next to a label in 32 bytes, so the escrow derives the id instead:
//!
//! ```text
//! service_id = sha256("FERMATA_STELLAR_SERVICE_V1" ‖ XDR(ScVal::Address(owner)) ‖ label[12])
//! ```
//!
//! The contract computes it from the authenticated owner (`owner.to_xdr(&env)` gives the same
//! XDR bytes), so the property is kept: only the owner can register its ids.

use sha2::{Digest, Sha256};

use crate::{keys, parse_hex, Error};

/// Versioned domain tag for service ids.
pub const SERVICE_TAG: &[u8; 26] = b"FERMATA_STELLAR_SERVICE_V1";
/// Labels are 12 bytes, as on Tempo.
pub const LABEL_LEN: usize = 12;

/// XDR discriminants (Stellar-transaction.x / Stellar-contract.x).
const SCV_ADDRESS: u32 = 18;
const SC_ADDRESS_TYPE_ACCOUNT: u32 = 0;
const SC_ADDRESS_TYPE_CONTRACT: u32 = 1;
const PUBLIC_KEY_TYPE_ED25519: u32 = 0;

/// The registrant of a service: a Stellar account or a contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner {
    Account([u8; 32]),
    Contract([u8; 32]),
}

impl Owner {
    /// Parses a `G…` account or `C…` contract address.
    pub fn parse(address: &str) -> Result<Self, Error> {
        let address = address.trim();
        match address.chars().next() {
            Some('G') => Ok(Self::Account(keys::public_key(address)?)),
            Some('C') => Ok(Self::Contract(keys::contract_id(address)?)),
            _ => Err(Error::Strkey(address.into(), "a G… or C… address")),
        }
    }

    pub fn address(&self) -> String {
        match self {
            Self::Account(key) => keys::account_address(key),
            Self::Contract(id) => keys::contract_address(id),
        }
    }

    /// XDR of `ScVal::Address(owner)`: the bytes `owner.to_xdr(&env)` returns in a contract.
    pub fn sc_val_xdr(&self) -> Vec<u8> {
        let mut out = SCV_ADDRESS.to_be_bytes().to_vec();
        match self {
            Self::Account(key) => {
                out.extend_from_slice(&SC_ADDRESS_TYPE_ACCOUNT.to_be_bytes());
                out.extend_from_slice(&PUBLIC_KEY_TYPE_ED25519.to_be_bytes());
                out.extend_from_slice(key);
            }
            Self::Contract(id) => {
                out.extend_from_slice(&SC_ADDRESS_TYPE_CONTRACT.to_be_bytes());
                out.extend_from_slice(id);
            }
        }
        out
    }
}

/// A 12-byte label from ASCII text of 1 to 12 bytes (zero-padded on the right) or from
/// `0x` followed by 24 hex characters.
pub fn label(s: &str) -> Result<[u8; LABEL_LEN], Error> {
    if let Some(digits) = s.strip_prefix("0x") {
        return parse_hex::<LABEL_LEN>(digits).map_err(|_| Error::Label(s.into()));
    }
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > LABEL_LEN || !s.is_ascii() || bytes.contains(&0) {
        return Err(Error::Label(s.into()));
    }
    let mut out = [0u8; LABEL_LEN];
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(out)
}

/// The label as text when it is printable ASCII followed by zero padding.
pub fn label_text(label: &[u8; LABEL_LEN]) -> Option<String> {
    let end = label.iter().position(|&b| b == 0).unwrap_or(LABEL_LEN);
    let (text, padding) = label.split_at(end);
    let printable = !text.is_empty() && text.iter().all(|b| b.is_ascii_graphic() || *b == b' ');
    (printable && padding.iter().all(|&b| b == 0))
        .then(|| String::from_utf8(text.to_vec()).expect("ASCII"))
}

/// `sha256(SERVICE_TAG ‖ XDR(ScVal::Address(owner)) ‖ label)`.
pub fn service_id(owner: &Owner, label: &[u8; LABEL_LEN]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SERVICE_TAG);
    h.update(owner.sc_val_xdr());
    h.update(label);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_xdr_layouts() {
        let account = Owner::Account([0x22; 32]).sc_val_xdr();
        assert_eq!(account.len(), 44);
        assert_eq!(&account[..12], &[0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 0]);
        let contract = Owner::Contract([0x0f; 32]).sc_val_xdr();
        assert_eq!(contract.len(), 40);
        assert_eq!(&contract[..8], &[0, 0, 0, 18, 0, 0, 0, 1]);
    }

    #[test]
    fn labels() {
        assert_eq!(&label("quote").unwrap()[..6], b"quote\0");
        assert_eq!(label("123456789012").unwrap(), *b"123456789012");
        assert!(label("1234567890123").is_err());
        assert!(label("").is_err());
        assert!(label("é").is_err());
        assert_eq!(
            label("0x71756f746500000000000000").unwrap(),
            label("quote").unwrap()
        );
        assert_eq!(
            label_text(&label("quote").unwrap()).as_deref(),
            Some("quote")
        );
        assert_eq!(label_text(&[0xff; 12]), None);
    }

    #[test]
    fn ids_depend_on_owner_and_label() {
        let a = Owner::Account([1; 32]);
        let b = Owner::Account([2; 32]);
        let c = Owner::Contract([1; 32]);
        let quote = label("quote").unwrap();
        let other = label("other").unwrap();
        assert_ne!(service_id(&a, &quote), service_id(&b, &quote));
        assert_ne!(service_id(&a, &quote), service_id(&a, &other));
        // the same 32 bytes as an account and as a contract give different ids
        assert_ne!(service_id(&a, &quote), service_id(&c, &quote));
    }

    #[test]
    fn owner_parse_round_trip() {
        for owner in [Owner::Account([3; 32]), Owner::Contract([4; 32])] {
            assert_eq!(Owner::parse(&owner.address()), Ok(owner));
        }
        assert!(Owner::parse("Mxyz").is_err());
    }
}
