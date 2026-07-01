//! Multi-factor authentication: TOTP (RFC 6238) + single-use recovery codes.
//!
//! TOTP interoperates with Google Authenticator, Authy, 1Password, etc.
//! Recovery codes are shown once and stored only as SHA-256 hashes.

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use rand::Rng;
use sha2::{Digest, Sha256};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::error::{CoreError, Result};

/// Generate a fresh base32-encoded TOTP secret to store per user.
pub fn generate_secret() -> String {
    match Secret::generate_secret().to_encoded() {
        Secret::Encoded(s) => s,
        // `to_encoded` always yields the Encoded variant; this arm is unreachable.
        Secret::Raw(_) => unreachable!("to_encoded always returns Encoded"),
    }
}

fn totp(secret_b32: &str, issuer: &str, account: &str) -> Result<TOTP> {
    let bytes = Secret::Encoded(secret_b32.to_string())
        .to_bytes()
        .map_err(|e| CoreError::Mfa(format!("decode secret: {e:?}")))?;
    TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes, Some(issuer.to_string()), account.to_string())
        .map_err(|e| CoreError::Mfa(e.to_string()))
}

/// Build the `otpauth://` provisioning URI for QR-code enrolment.
pub fn provisioning_uri(secret_b32: &str, issuer: &str, account: &str) -> Result<String> {
    Ok(totp(secret_b32, issuer, account)?.get_url())
}

/// Verify a 6-digit TOTP code (±1 step of clock skew tolerance).
pub fn verify_totp(secret_b32: &str, code: &str, issuer: &str, account: &str) -> Result<bool> {
    let t = totp(secret_b32, issuer, account)?;
    t.check_current(code).map_err(|e| CoreError::Mfa(e.to_string()))
}

/// A generated recovery code plus the hash that should be persisted.
pub struct RecoveryCode {
    pub plaintext: String,
    pub hash: String,
}

/// Generate `count` single-use recovery codes formatted `xxxxx-xxxxx`.
pub fn generate_recovery_codes(count: usize) -> Vec<RecoveryCode> {
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..count)
        .map(|_| {
            let raw: String = (0..10)
                .map(|i| {
                    let c = ALPHABET[rng.gen_range(0..ALPHABET.len())] as char;
                    if i == 5 { format!("-{c}") } else { c.to_string() }
                })
                .collect();
            let plaintext = raw;
            let hash = hash_recovery_code(&plaintext);
            RecoveryCode { plaintext, hash }
        })
        .collect()
}

/// Stable hash used to store/compare recovery codes.
pub fn hash_recovery_code(code: &str) -> String {
    let mut h = Sha256::new();
    h.update(code.trim().as_bytes());
    STANDARD_NO_PAD.encode(h.finalize())
}
