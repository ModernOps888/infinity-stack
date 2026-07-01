-- Infinity Stream initial schema (SQLite). Timestamps are RFC3339 TEXT UTC.
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS topics (
    name TEXT PRIMARY KEY,
    partitions INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS consumer_offsets (
    topic TEXT NOT NULL,
    consumer_group TEXT NOT NULL,
    partition INTEGER NOT NULL,
    offset INTEGER NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (topic, consumer_group, partition)
);

CREATE TABLE IF NOT EXISTS search_indexes (
    name TEXT PRIMARY KEY,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS search_docs (
    index_name TEXT NOT NULL,
    doc_id TEXT NOT NULL,
    fields_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (index_name, doc_id)
);

CREATE INDEX IF NOT EXISTS idx_search_docs_index ON search_docs(index_name);
CREATE INDEX IF NOT EXISTS idx_offsets_topic ON consumer_offsets(topic);
