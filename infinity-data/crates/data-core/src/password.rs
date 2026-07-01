use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

use crate::error::{CoreError, Result};

fn hasher() -> Argon2<'static> {
    let params = Params::new(19_456, 2, 1, None).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub fn hash_password(plaintext: &str) -> Result<String> {
    if plaintext.len() < 8 {
        return Err(CoreError::Invalid("password must be at least 8 characters".into()));
    }
    let salt = SaltString::generate(&mut OsRng);
    Ok(hasher()
        .hash_password(plaintext.as_bytes(), &salt)
        .map_err(|e| CoreError::Crypto(e.to_string()))?
        .to_string())
}

pub fn verify_password(plaintext: &str, phc_hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(phc_hash).map_err(|e| CoreError::Crypto(e.to_string()))?;
    Ok(hasher().verify_password(plaintext.as_bytes(), &parsed).is_ok())
}

pub fn dummy_verify(plaintext: &str) {
    use std::sync::OnceLock;
    static DUMMY: OnceLock<String> = OnceLock::new();
    let hash = DUMMY.get_or_init(|| hash_password("infinity-data-enumeration-guard").expect("dummy hash"));
    let _ = verify_password(plaintext, hash);
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) { diff |= x ^ y; }
    diff == 0
}
