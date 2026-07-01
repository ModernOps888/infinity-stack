-- Infinity Data initial schema (SQLite). Runtime sqlx queries only.
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    username      TEXT NOT NULL UNIQUE,
    display_name  TEXT,
    password_hash TEXT NOT NULL,
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS roles (
    name        TEXT PRIMARY KEY,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_name  TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    PRIMARY KEY (role_name, permission)
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_name TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_name)
);

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    prefix       TEXT NOT NULL,
    key_hash     TEXT NOT NULL UNIQUE,
    created_at   TEXT NOT NULL,
    last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS collections (
    name       TEXT PRIMARY KEY,
    dim        INTEGER NOT NULL,
    metric     TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vector_points (
    collection_name TEXT NOT NULL REFERENCES collections(name) ON DELETE CASCADE,
    id              TEXT NOT NULL,
    vector_json     TEXT NOT NULL,
    metadata_json   TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    PRIMARY KEY (collection_name, id)
);

CREATE TABLE IF NOT EXISTS analytics_tables (
    name       TEXT PRIMARY KEY,
    columns    TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS table_rows (
    id         TEXT PRIMARY KEY,
    table_name TEXT NOT NULL REFERENCES analytics_tables(name) ON DELETE CASCADE,
    row_json   TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id            TEXT PRIMARY KEY,
    actor_user_id TEXT,
    event         TEXT NOT NULL,
    target        TEXT,
    detail_json   TEXT,
    ip            TEXT,
    user_agent    TEXT,
    created_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_table_rows_table ON table_rows(table_name);
CREATE INDEX IF NOT EXISTS idx_vector_points_collection ON vector_points(collection_name);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
