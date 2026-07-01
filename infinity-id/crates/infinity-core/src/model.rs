//! Shared domain types serialized across the API and persistence layers.

use serde::{Deserialize, Serialize};

/// A user account. Never serializes secrets (password hash, MFA secret).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub username: String,
    pub display_name: Option<String>,
    pub roles: Vec<String>,
    pub mfa_enabled: bool,
    pub disabled: bool,
    pub created_at: String,
}

/// An OAuth2 / OIDC client application registered with Infinity ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    pub client_id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    /// Public clients (SPA/mobile) use PKCE and have no secret.
    pub public: bool,
    pub created_at: String,
}

/// An RBAC role bundling a set of permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    pub description: String,
    pub permissions: Vec<String>,
}

/// An immutable audit-log record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub ip: Option<String>,
    pub detail: Option<String>,
    pub created_at: String,
}
