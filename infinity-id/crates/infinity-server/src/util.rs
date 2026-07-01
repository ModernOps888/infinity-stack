use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Generate a cryptographically-random opaque token (32 bytes, base64url).
pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// SHA-256 hex digest — used to store opaque tokens/sessions at rest.
pub fn sha256_hex(input: &str) -> String {
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Verify a PKCE `code_verifier` against a stored challenge (S256 or plain).
pub fn verify_pkce(verifier: &str, challenge: &str, method: Option<&str>) -> bool {
    match method.unwrap_or("plain") {
        "S256" => {
            let mut h = Sha256::new();
            h.update(verifier.as_bytes());
            let computed = URL_SAFE_NO_PAD.encode(h.finalize());
            computed == challenge
        }
        _ => verifier == challenge,
    }
}
