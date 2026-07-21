//! Asymmetric signing key management for JWT (RS256) and JWKS publication.
//!
//! Keys are generated once and persisted as PKCS#1 PEM in the data directory,
//! so restarts don't invalidate live tokens. The public half is published via
//! a standards-compliant JWKS document that Infinity Edge (and any third-party
//! resource server) can fetch to validate tokens without a shared secret.
//!
//! [`KeyRing`] additionally supports manual key rotation: the previously
//! active key is retired (kept on disk and published in the JWKS) rather than
//! discarded, so tokens signed before a rotation keep validating until they
//! naturally expire.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{CoreError, Result};

/// A single JWK entry (public RSA key) as published in the JWKS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub r#use: String,
    pub alg: String,
    pub kid: String,
    pub n: String,
    pub e: String,
}

/// The JWKS document served at `/.well-known/jwks.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// In-memory signing material derived from an RSA private key.
#[derive(Clone)]
pub struct SigningKey {
    pub kid: String,
    pub private_pem: String,
    pub jwk: Jwk,
}

impl SigningKey {
    /// Load an existing key from `path`, or generate + persist a new 2048-bit key.
    pub fn load_or_generate(path: &Path) -> Result<Self> {
        if path.exists() {
            let pem = std::fs::read_to_string(path)?;
            let key = RsaPrivateKey::from_pkcs1_pem(&pem)
                .map_err(|e| CoreError::Crypto(format!("parse private key: {e}")))?;
            Self::from_private(key, pem)
        } else {
            let (key, pem) = generate_key()?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, &pem)?;
            Self::from_private(key, pem)
        }
    }

    fn from_private(key: RsaPrivateKey, pem: String) -> Result<Self> {
        let public = RsaPublicKey::from(&key);
        let n = public.n().to_bytes_be();
        let e = public.e().to_bytes_be();
        let n_b64 = URL_SAFE_NO_PAD.encode(&n);
        let e_b64 = URL_SAFE_NO_PAD.encode(&e);

        // Stable key id = URL-safe base64 of SHA-256(n || e).
        let mut hasher = Sha256::new();
        hasher.update(&n);
        hasher.update(&e);
        let kid = URL_SAFE_NO_PAD.encode(hasher.finalize())[..16].to_string();

        let jwk = Jwk {
            kty: "RSA".into(),
            r#use: "sig".into(),
            alg: "RS256".into(),
            kid: kid.clone(),
            n: n_b64,
            e: e_b64,
        };
        Ok(Self { kid, private_pem: pem, jwk })
    }

    /// Publish the public key as a single-entry JWKS document.
    pub fn jwks(&self) -> Jwks {
        Jwks { keys: vec![self.jwk.clone()] }
    }
}

fn generate_key() -> Result<(RsaPrivateKey, String)> {
    let mut rng = rand::thread_rng();
    let key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| CoreError::Crypto(format!("generate key: {e}")))?;
    let pem = key
        .to_pkcs1_pem(LineEnding::LF)
        .map_err(|e| CoreError::Crypto(format!("encode key: {e}")))?
        .to_string();
    Ok((key, pem))
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Retired-key filename convention: `<stem>.retired-<unix_ts>.<ext>`, stored
/// alongside the active key file so a restart rediscovers them.
fn retired_file_name(stem: &str, ext: &str, retired_at: i64) -> String {
    format!("{stem}.retired-{retired_at}.{ext}")
}

fn split_stem_ext(path: &Path) -> (String, String) {
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("signing_key").to_string();
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("pem").to_string();
    (stem, ext)
}

/// The active signing key plus any keys retired by a rotation that are still
/// within their retention window (i.e. a token signed under them might still
/// be unexpired).
pub struct KeyRing {
    pub active: SigningKey,
    /// Retired keys, newest first, each still eligible for verification.
    pub previous: Vec<SigningKey>,
}

impl KeyRing {
    /// Load the active key at `path` (generating one if absent), plus any
    /// retired keys found alongside it. Retired keys older than
    /// `retention_secs` are pruned from disk — they're outside the window in
    /// which any token they signed could still be valid.
    pub fn load_or_generate(path: &Path, retention_secs: i64) -> Result<Self> {
        let active = SigningKey::load_or_generate(path)?;
        let previous = Self::load_previous(path, retention_secs)?;
        Ok(Self { active, previous })
    }

    fn load_previous(path: &Path, retention_secs: i64) -> Result<Vec<SigningKey>> {
        let mut previous: Vec<(i64, SigningKey)> = Vec::new();
        let Some(dir) = path.parent() else { return Ok(Vec::new()) };
        let (stem, ext) = split_stem_ext(path);
        let prefix = format!("{stem}.retired-");
        let suffix = format!(".{ext}");
        let now = now_unix();

        let Ok(entries) = std::fs::read_dir(dir) else { return Ok(Vec::new()) };
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            let Some(rest) = file_name.strip_prefix(&prefix) else { continue };
            let Some(ts_str) = rest.strip_suffix(&suffix) else { continue };
            let Ok(retired_at) = ts_str.parse::<i64>() else { continue };

            if now - retired_at > retention_secs {
                let _ = std::fs::remove_file(entry.path());
                continue;
            }
            let Ok(pem) = std::fs::read_to_string(entry.path()) else { continue };
            let Ok(key) = RsaPrivateKey::from_pkcs1_pem(&pem) else { continue };
            if let Ok(signing_key) = SigningKey::from_private(key, pem) {
                previous.push((retired_at, signing_key));
            }
        }
        // Newest retirement first, so `jwks()`/verification checks the most
        // recently active keys before older ones.
        previous.sort_by_key(|(retired_at, _)| std::cmp::Reverse(*retired_at));
        Ok(previous.into_iter().map(|(_, k)| k).collect())
    }

    /// Retire the current active key (persisted on disk so it survives a
    /// restart, still validating tokens until `retention_secs` elapses) and
    /// generate a fresh active signing key.
    pub fn rotate(&mut self, path: &Path, retention_secs: i64) -> Result<()> {
        let (stem, ext) = split_stem_ext(path);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
            let retired_path = dir.join(retired_file_name(&stem, &ext, now_unix()));
            std::fs::write(&retired_path, &self.active.private_pem)?;
        }

        let (key, pem) = generate_key()?;
        std::fs::write(path, &pem)?;
        self.active = SigningKey::from_private(key, pem)?;
        // Reload from disk, which picks up the file just written above and
        // prunes anything already past `retention_secs`.
        self.previous = Self::load_previous(path, retention_secs)?;
        Ok(())
    }

    /// Publish every still-valid key (active first) as a JWKS document, so
    /// resource servers and Infinity Edge can verify tokens signed under a
    /// key that has since been rotated out.
    pub fn jwks(&self) -> Jwks {
        let mut keys = vec![self.active.jwk.clone()];
        keys.extend(self.previous.iter().map(|k| k.jwk.clone()));
        Jwks { keys }
    }

    /// All JWKs (active first, then retired-but-still-valid) for local token
    /// verification against this server's own key material.
    pub fn verification_keys(&self) -> impl Iterator<Item = &Jwk> {
        std::iter::once(&self.active.jwk).chain(self.previous.iter().map(|k| &k.jwk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_key_path() -> std::path::PathBuf {
        std::env::temp_dir()
            .join(format!("infinity-core-keys-test-{}", uuid::Uuid::new_v4()))
            .join("signing_key.pem")
    }

    #[test]
    fn rotate_retires_active_key_but_keeps_it_valid() {
        let path = temp_key_path();
        let mut ring = KeyRing::load_or_generate(&path, 3600).unwrap();
        let old_kid = ring.active.kid.clone();
        assert!(ring.previous.is_empty());

        ring.rotate(&path, 3600).unwrap();

        assert_ne!(ring.active.kid, old_kid, "rotation must generate a fresh active key");
        assert_eq!(ring.previous.len(), 1);
        assert_eq!(ring.previous[0].kid, old_kid, "the retired key must still be published");

        // Both keys must appear in the JWKS and in the local verification set.
        let kids: Vec<_> = ring.jwks().keys.into_iter().map(|k| k.kid).collect();
        assert!(kids.contains(&old_kid));
        assert!(kids.contains(&ring.active.kid));

        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn load_or_generate_survives_restart() {
        let path = temp_key_path();
        let first = KeyRing::load_or_generate(&path, 3600).unwrap();
        let second = KeyRing::load_or_generate(&path, 3600).unwrap();
        assert_eq!(first.active.kid, second.active.kid, "restart must reuse the persisted key");

        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn expired_retired_keys_are_pruned() {
        let path = temp_key_path();
        let mut ring = KeyRing::load_or_generate(&path, 3600).unwrap();
        ring.rotate(&path, 3600).unwrap();
        assert_eq!(ring.previous.len(), 1);

        // Simulate the retired key having aged past its retention window by
        // rewriting its filename with a timestamp far in the past.
        let dir = path.parent().unwrap();
        let old_entry = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .find(|e| e.file_name().to_string_lossy().contains(".retired-"))
            .unwrap();
        let stale_name = "signing_key.retired-1.pem";
        std::fs::rename(old_entry.path(), dir.join(stale_name)).unwrap();

        let reloaded = KeyRing::load_or_generate(&path, 3600).unwrap();
        assert!(reloaded.previous.is_empty(), "keys past retention must be pruned on load");
        assert!(!dir.join(stale_name).exists(), "pruned key file must be deleted from disk");

        std::fs::remove_dir_all(dir).ok();
    }
}
