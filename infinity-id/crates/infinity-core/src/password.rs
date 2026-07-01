//! Password hashing using Argon2id — the OWASP-recommended memory-hard KDF.
//!
//! Argon2id is resistant to both GPU cracking and side-channel attacks, and is
//! the modern default that outclasses bcrypt/PBKDF2 used by legacy IdPs.

use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

use crate::error::{CoreError, Result};

/// Build an Argon2id hasher with hardened parameters (19 MiB, 2 passes).
fn hasher() -> Argon2<'static> {
    // 19456 KiB memory, 2 iterations, 1 lane — OWASP minimum for Argon2id.
    let params = Params::new(19_456, 2, 1, None).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hash a plaintext password, returning a PHC-format string safe to store.
pub fn hash_password(plaintext: &str) -> Result<String> {
    if plaintext.len() < 8 {
        return Err(CoreError::Invalid("password must be at least 8 characters".into()));
    }
    let salt = SaltString::generate(&mut OsRng);
    let hash = hasher()
        .hash_password(plaintext.as_bytes(), &salt)
        .map_err(|e| CoreError::Crypto(e.to_string()))?
        .to_string();
    Ok(hash)
}

/// Verify a plaintext password against a stored PHC hash. Constant-time.
pub fn verify_password(plaintext: &str, phc_hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(phc_hash).map_err(|e| CoreError::Crypto(e.to_string()))?;
    Ok(hasher().verify_password(plaintext.as_bytes(), &parsed).is_ok())
}

/// Perform a throwaway verification against a fixed hash.
///
/// Called when a login references an unknown user so that response timing does
/// not reveal whether the account exists (user-enumeration hardening).
pub fn dummy_verify(plaintext: &str) {
    use std::sync::OnceLock;
    static DUMMY: OnceLock<String> = OnceLock::new();
    let hash = DUMMY.get_or_init(|| {
        hash_password("infinity-enumeration-guard").expect("dummy hash")
    });
    let _ = verify_password(plaintext, hash);
}

/// Constant-time byte-slice equality (avoids leaking match position via timing).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let h = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &h).unwrap());
        assert!(!verify_password("wrong password", &h).unwrap());
    }

    #[test]
    fn rejects_short() {
        assert!(hash_password("short").is_err());
    }
}
