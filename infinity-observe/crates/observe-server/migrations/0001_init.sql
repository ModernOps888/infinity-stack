-- Infinity Observe initial schema (SQLite). Timestamps are RFC3339 UTC TEXT.

CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    username      TEXT NOT NULL UNIQUE,
    display_name  TEXT,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'viewer',
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS ingest_keys (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    key_hash     TEXT NOT NULL UNIQUE,
    prefix       TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    revoked_at   TEXT,
    last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_ingest_key_hash ON ingest_keys(key_hash);

CREATE TABLE IF NOT EXISTS logs (
    id         TEXT PRIMARY KEY,
    timestamp  TEXT NOT NULL,
    level      TEXT NOT NULL,
    service    TEXT NOT NULL,
    message    TEXT NOT NULL,
    attributes TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_logs_time ON logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_service_time ON logs(service, timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_level_time ON logs(level, timestamp);

CREATE TABLE IF NOT EXISTS metrics (
    id        TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    name      TEXT NOT NULL,
    value     REAL NOT NULL,
    tags      TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_metrics_name_time ON metrics(name, timestamp);
CREATE INDEX IF NOT EXISTS idx_metrics_time ON metrics(timestamp);

CREATE TABLE IF NOT EXISTS spans (
    id             TEXT PRIMARY KEY,
    trace_id       TEXT NOT NULL,
    span_id        TEXT NOT NULL,
    parent_span_id TEXT,
    name           TEXT NOT NULL,
    service        TEXT NOT NULL,
    start_time     TEXT NOT NULL,
    end_time       TEXT NOT NULL,
    duration_ms    REAL NOT NULL,
    status         TEXT,
    attributes     TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_spans_trace ON spans(trace_id, start_time);
CREATE INDEX IF NOT EXISTS idx_spans_service_time ON spans(service, start_time);
CREATE INDEX IF NOT EXISTS idx_spans_time ON spans(start_time);

CREATE TABLE IF NOT EXISTS alert_rules (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL,
    target      TEXT NOT NULL DEFAULT '',
    threshold   REAL NOT NULL,
    window_secs INTEGER NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id          TEXT PRIMARY KEY,
    rule_id     TEXT NOT NULL,
    rule_name   TEXT NOT NULL,
    severity    TEXT NOT NULL,
    message     TEXT NOT NULL,
    fired_at    TEXT NOT NULL,
    resolved_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_fired ON alerts(fired_at);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id, fired_at);
