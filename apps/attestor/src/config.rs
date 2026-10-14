//! Loading trust roots, keys and the content-addressed predicate store.
//!
//! Copied unchanged from Fermata `apps/attestor/src/config.rs` @ d7cc642
//! (github.com/bilgin-kocak/fermata, Apache-2.0).

use std::{collections::HashMap, path::Path};

use anyhow::{Context, Result, anyhow};
use tlsn::webpki::CertificateDer;

use crate::hashes::{parse_hex32, predicate_hash};

/// All certificates in a PEM file (a vendor's dev CA, or a bundle).
pub fn load_roots(path: &Path) -> Result<Vec<CertificateDer>> {
    let pem = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let text = String::from_utf8_lossy(&pem);
    let mut out = Vec::new();
    for block in text
        .split("-----END CERTIFICATE-----")
        .filter(|b| b.contains("-----BEGIN CERTIFICATE-----"))
    {
        let block = format!("{block}-----END CERTIFICATE-----\n");
        out.push(
            CertificateDer::from_pem_slice(block.as_bytes())
                .map_err(|_| anyhow!("bad PEM in {}", path.display()))?,
        );
    }
    anyhow::ensure!(!out.is_empty(), "no certificate in {}", path.display());
    Ok(out)
}

/// The trust roots for vendor certificates: the PEM files in `ca` (dev CAs), plus Mozilla's root
/// program when `mozilla` is set (real vendors). At least one source is required.
pub fn trust_roots(ca: &[std::path::PathBuf], mozilla: bool) -> Result<Vec<CertificateDer>> {
    let mut roots = Vec::new();
    for path in ca {
        roots.extend(load_roots(path)?);
    }
    if mozilla {
        roots.extend(tlsn::webpki::RootCertStore::mozilla().roots);
    }
    anyhow::ensure!(
        !roots.is_empty(),
        "no trust roots: pass --ca <pem> and/or --roots mozilla"
    );
    Ok(roots)
}

/// A 32-byte hex key from an environment variable.
pub fn key_from_env(var: &str) -> Result<[u8; 32]> {
    parse_hex32(&std::env::var(var).with_context(|| format!("{var} is not set"))?)
        .with_context(|| format!("{var} is not a 32-byte hex key"))
}

/// Predicates by sha256 of their exact bytes: a directory of `*.json` files, or single files.
///
/// A hash it does not know triggers one rescan of the same paths (at most once a second), so a
/// predicate written for a newly onboarded service is picked up without a restart. The store is
/// content-addressed: a new file can only add a predicate, never change an existing one's bytes.
#[derive(Debug, Default)]
pub struct PredicateStore {
    by_hash: std::sync::RwLock<HashMap<[u8; 32], Vec<u8>>>,
    paths: Vec<std::path::PathBuf>,
    last_scan: std::sync::Mutex<Option<std::time::Instant>>,
}

impl PredicateStore {
    pub fn load(paths: &[impl AsRef<Path>]) -> Result<Self> {
        let store = Self {
            paths: paths.iter().map(|p| p.as_ref().to_path_buf()).collect(),
            ..Self::default()
        };
        store.scan()?;
        Ok(store)
    }

    fn scan(&self) -> Result<()> {
        for p in &self.paths {
            if p.is_dir() {
                for entry in std::fs::read_dir(p)? {
                    let path = entry?.path();
                    if path.extension().is_some_and(|e| e == "json") {
                        self.add(std::fs::read(&path)?);
                    }
                }
            } else {
                self.add(std::fs::read(p).with_context(|| format!("reading {}", p.display()))?);
            }
        }
        *self.last_scan.lock().unwrap() = Some(std::time::Instant::now());
        Ok(())
    }

    pub fn add(&self, bytes: Vec<u8>) -> [u8; 32] {
        let h = predicate_hash(&bytes);
        self.by_hash.write().unwrap().insert(h, bytes);
        h
    }

    pub fn get(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        if let Some(b) = self.by_hash.read().unwrap().get(hash) {
            return Some(b.clone());
        }
        let due = self
            .last_scan
            .lock()
            .unwrap()
            .is_none_or(|t| t.elapsed() >= std::time::Duration::from_secs(1));
        if due && !self.paths.is_empty() {
            let _ = self.scan();
            return self.by_hash.read().unwrap().get(hash).cloned();
        }
        None
    }

    pub fn len(&self) -> usize {
        self.by_hash.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_up_a_new_predicate_file_on_a_miss() {
        let dir = std::env::temp_dir().join(format!("fermata-pred-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.json"), br#"{"version":1,"status":[200]}"#).unwrap();
        let store = PredicateStore::load(&[&dir]).unwrap();
        assert_eq!(store.len(), 1);
        let b = br#"{"version":1,"status":[201]}"#;
        std::fs::write(dir.join("b.json"), b).unwrap();
        let h = predicate_hash(b);
        *store.last_scan.lock().unwrap() = None; // as if a second had passed
        assert_eq!(store.get(&h).as_deref(), Some(&b[..]));
        assert_eq!(store.len(), 2);
        // An unknown hash right after a scan does not rescan (rate limit) and is simply absent.
        assert!(store.get(&[9u8; 32]).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
