//! JWT issuing and validation (RS256).
//!
//! Access tokens are short-lived OIDC-style JWTs carrying subject, audience,
//! scopes and roles. Validation is done with the public key only, so resource
//! servers never need a shared secret.

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};
use crate::keys::SigningKey;

/// Standard + custom claims for an Infinity ID access token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject — the user (or client) id.
    pub sub: String,
    /// Issuer — the Infinity ID base URL.
    pub iss: String,
    /// Audience — the intended resource server / client.
    pub aud: String,
    /// Expiry (unix seconds).
    pub exp: i64,
    /// Issued-at (unix seconds).
    pub iat: i64,
    /// Not-before (unix seconds).
    pub nbf: i64,
    /// Space-delimited OAuth2 scopes.
    #[serde(default)]
    pub scope: String,
    /// Assigned RBAC roles.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Preferred username / email for convenience.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    /// Token type marker (`access` or `id`).
    #[serde(default)]
    pub typ: String,
}

/// Sign a set of claims into a compact JWT using the active signing key.
pub fn issue(key: &SigningKey, claims: &Claims) -> Result<String> {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key.kid.clone());
    let enc = EncodingKey::from_rsa_pem(key.private_pem.as_bytes())
        .map_err(|e| CoreError::Token(format!("encoding key: {e}")))?;
    encode(&header, claims, &enc).map_err(|e| CoreError::Token(e.to_string()))
}

/// Validate a JWT against RSA public components `(n, e)` (base64url) and issuer.
pub fn validate_with_components(
    token: &str,
    n_b64: &str,
    e_b64: &str,
    issuer: &str,
    audience: Option<&str>,
) -> Result<Claims> {
    let dec = DecodingKey::from_rsa_components(n_b64, e_b64)
        .map_err(|e| CoreError::Token(format!("decoding key: {e}")))?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[issuer]);
    match audience {
        Some(a) => validation.set_audience(&[a]),
        None => validation.validate_aud = false,
    }
    let data = decode::<Claims>(token, &dec, &validation)
        .map_err(|e| CoreError::Token(e.to_string()))?;
    Ok(data.claims)
}
