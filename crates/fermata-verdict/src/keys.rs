//! Keys and addresses: Stellar strkeys (`G…`, `S…`, `C…`) and raw hex.

use ed25519_dalek::SigningKey;
use stellar_strkey::{ed25519, Contract, Strkey};

use crate::{parse_hex, Error};

/// A verifier signing key from a Stellar secret seed (`S…`, as `stellar keys secret` prints it)
/// or from 64 hex characters.
pub fn signing_key(secret: &str) -> Result<SigningKey, Error> {
    let secret = secret.trim();
    let seed = if secret.starts_with('S') {
        match Strkey::from_string(secret) {
            Ok(Strkey::PrivateKeyEd25519(ed25519::PrivateKey(seed))) => seed,
            _ => return Err(Error::Secret),
        }
    } else {
        parse_hex::<32>(secret).map_err(|_| Error::Secret)?
    };
    Ok(SigningKey::from_bytes(&seed))
}

/// A 32-byte Ed25519 public key from a `G…` address or 64 hex characters.
pub fn public_key(s: &str) -> Result<[u8; 32], Error> {
    let s = s.trim();
    if s.starts_with('G') {
        match Strkey::from_string(s) {
            Ok(Strkey::PublicKeyEd25519(ed25519::PublicKey(key))) => Ok(key),
            _ => Err(Error::Strkey(s.into(), "a G… account address")),
        }
    } else {
        parse_hex::<32>(s)
    }
}

/// A contract id from a `C…` address or 64 hex characters.
pub fn contract_id(s: &str) -> Result<[u8; 32], Error> {
    let s = s.trim();
    if s.starts_with('C') {
        match Strkey::from_string(s) {
            Ok(Strkey::Contract(Contract(id))) => Ok(id),
            _ => Err(Error::Strkey(s.into(), "a C… contract address")),
        }
    } else {
        parse_hex::<32>(s)
    }
}

/// The `G…` address of an Ed25519 public key.
pub fn account_address(public_key: &[u8; 32]) -> String {
    ed25519::PublicKey(*public_key)
        .to_string()
        .as_str()
        .to_owned()
}

/// The `C…` address of a contract id.
pub fn contract_address(id: &[u8; 32]) -> String {
    Contract(*id).to_string().as_str().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strkey_round_trips() {
        let pk = [0x22; 32];
        let g = account_address(&pk);
        assert!(g.starts_with('G'));
        assert_eq!(public_key(&g), Ok(pk));
        assert_eq!(public_key(&hex::encode(pk)), Ok(pk));

        let id = [0x0f; 32];
        let c = contract_address(&id);
        assert!(c.starts_with('C'));
        assert_eq!(contract_id(&c), Ok(id));
        assert_eq!(contract_id(&format!("0x{}", hex::encode(id))), Ok(id));
    }

    #[test]
    fn secret_forms_agree() {
        let seed = [9u8; 32];
        let s = stellar_strkey::ed25519::PrivateKey(seed)
            .to_string()
            .as_str()
            .to_owned();
        assert!(s.starts_with('S'));
        let a = signing_key(&s).unwrap();
        let b = signing_key(&hex::encode(seed)).unwrap();
        assert_eq!(a.to_bytes(), b.to_bytes());
        assert_eq!(signing_key("Sbogus"), Err(Error::Secret));
        assert_eq!(signing_key("1234"), Err(Error::Secret));
    }

    #[test]
    fn wrong_strkey_kinds_are_rejected() {
        let c = contract_address(&[1; 32]);
        let g = account_address(&[1; 32]);
        assert!(public_key(&c).is_err());
        assert!(contract_id(&g).is_err());
    }
}
