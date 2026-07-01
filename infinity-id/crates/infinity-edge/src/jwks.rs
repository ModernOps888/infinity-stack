//! JWKS fetch + token validation for the edge gateway.

use infinity_core::token::{validate_with_components, Claims};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
struct JwkEntry {
    kid: String,
    n: String,
    e: String,
}

#[derive(Debug, Deserialize)]
struct JwkDoc {
    keys: Vec<JwkEntry>,
}

/// Cached public keys used to validate incoming access tokens.
pub struct JwksCache {
    keys: Vec<JwkEntry>,
    issuer: String,
}

impl JwksCache {
    /// Fetch the JWKS from Infinity ID.
    pub async fn fetch(url: &str, issuer: &str) -> anyhow::Result<Self> {
        let doc: JwkDoc = reqwest::get(url).await?.json().await?;
        Ok(Self { keys: doc.keys, issuer: issuer.to_string() })
    }

    /// Validate a token against any known key; returns claims on success.
    ///
    /// When `audience` is `Some`, the token's `aud` must match — this stops a
    /// token minted for one relying party from being replayed at another.
    pub fn validate(&self, token: &str, audience: Option<&str>) -> Option<Claims> {
        for key in &self.keys {
            if let Ok(claims) =
                validate_with_components(token, &key.n, &key.e, &self.issuer, audience)
            {
                let _ = &key.kid;
                // Only genuine access tokens may authorize upstream calls —
                // reject id_tokens (which are exposed to browsers/SPAs).
                if claims.typ != "access" {
                    return None;
                }
                return Some(claims);
            }
        }
        None
    }
}
