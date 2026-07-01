-- Infinity ID initial schema (SQLite; Postgres-compatible types kept simple).
-- All timestamps are RFC3339 TEXT in UTC.

CREATE TABLE IF NOT EXISTS roles (
    name        TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    permissions TEXT NOT NULL DEFAULT '[]' -- JSON array of "resource:action"
);

CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    username      TEXT NOT NULL UNIQUE,
    display_name  TEXT,
    password_hash TEXT NOT NULL,
    mfa_enabled   INTEGER NOT NULL DEFAULT 0,
    mfa_secret    TEXT,
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role    TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role)
);

CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id    TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    secret_hash  TEXT,                 -- NULL for public (PKCE) clients
    redirect_uris TEXT NOT NULL DEFAULT '[]',
    grant_types  TEXT NOT NULL DEFAULT '[]',
    scopes       TEXT NOT NULL DEFAULT '[]',
    public       INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_codes (
    code                  TEXT PRIMARY KEY,
    client_id             TEXT NOT NULL,
    user_id               TEXT NOT NULL,
    redirect_uri          TEXT NOT NULL,
    scope                 TEXT NOT NULL DEFAULT '',
    code_challenge        TEXT,
    code_challenge_method TEXT,
    expires_at            TEXT NOT NULL,
    created_at            TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    client_id  TEXT NOT NULL,
    scope      TEXT NOT NULL DEFAULT '',
    expires_at TEXT NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS recovery_codes (
    id        TEXT PRIMARY KEY,
    user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,   -- opaque session token (hashed)
    user_id    TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         TEXT PRIMARY KEY,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    target     TEXT,
    ip         TEXT,
    detail     TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);
