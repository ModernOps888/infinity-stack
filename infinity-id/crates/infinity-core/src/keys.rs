//! Asymmetric signing key management for JWT (RS256) and JWKS publication.
//!
//! Keys are generated once and persisted as PKCS#1 PEM in the data directory,
//! so restarts don't invalidate live tokens. The public half is published via
//! a standards-compliant JWKS document that Infinity Edge (and any third-party
//! resource server) can fetch to validate tokens without a shared secret.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

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

/// In-memory signing material derived from the RSA private key.
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
            let mut rng = rand::thread_rng();
            let key = RsaPrivateKey::new(&mut rng, 2048)
                .map_err(|e| CoreError::Crypto(format!("generate key: {e}")))?;
            let pem = key
                .to_pkcs1_pem(LineEnding::LF)
                .map_err(|e| CoreError::Crypto(format!("encode key: {e}")))?
                .to_string();
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

    /// Publish the public key as a JWKS document.
    pub fn jwks(&self) -> Jwks {
        Jwks { keys: vec![self.jwk.clone()] }
    }
}
