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

/// Verify a TOTP code and, on success, return the matched time-step.
///
/// Only steps strictly newer than the caller's high-water mark are accepted
/// (pass `last_step + 1` as `min_step`), so a single code cannot be replayed
/// within its ±1-step skew window once it has been consumed. Returns `None`
/// when the code does not match an allowed step.
pub fn verify_totp_step(
    secret_b32: &str,
    code: &str,
    issuer: &str,
    account: &str,
    min_step: u64,
) -> Result<Option<u64>> {
    const STEP: u64 = 30;
    let t = totp(secret_b32, issuer, account)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| CoreError::Mfa(e.to_string()))?
        .as_secs();
    let current = now / STEP;
    let candidate = code.trim();
    // Check newest step first so the stored high-water mark advances maximally.
    for cand in [current + 1, current, current.saturating_sub(1)] {
        if cand < min_step {
            continue;
        }
        let expected = t.generate(cand * STEP);
        if crate::password::constant_time_eq(expected.as_bytes(), candidate.as_bytes()) {
            return Ok(Some(cand));
        }
    }
    Ok(None)
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
