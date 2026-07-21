<div align="center">

# ∞ Infinity Stack

### Open-source, Rust-native replacements for over-monetized SaaS infrastructure.

Predictable performance. Memory safety. No GC pauses. Self-hostable. No per-seat tax.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](./infinity-id/LICENSE)
[![Rust](https://img.shields.io/badge/built%20with-Rust-000000?logo=rust)](https://www.rust-lang.org/)

</div>

---

Rust's memory safety, C-like performance, and lack of garbage collection (predictable tail latency) make it the ideal tool to commoditize expensive cloud infrastructure. Infinity Stack spans four heavily-monopolized verticals — **identity, observability, data, and streaming** — each a self-hostable, security-hardened Rust service with an embedded admin dashboard.

## The products

| Product | Replaces | Status |
|---|---|---|
| **[∞ Infinity ID](./infinity-id/)** | Auth0 · Okta · OneLogin · Clerk | 🟢 **Flagship — runnable, hardened** |
| [Infinity Observe](./infinity-observe/) | Datadog · Splunk · New Relic · Sentry | 🟢 Runnable · hardened (alpha) |
| [Infinity Data](./infinity-data/) | Snowflake · Databricks · Pinecone | 🟢 Runnable · hardened (alpha) |
| [Infinity Stream](./infinity-stream/) | Kafka/Confluent · Elasticsearch · Algolia | 🟢 Runnable · hardened (alpha) |

Every service ships hardened by default — Argon2id password storage, opaque server-side sessions with `HttpOnly`/`SameSite=Strict` (+ `Secure`) cookies and a 2-hour default TTL, RBAC, O(1) indexed API-key auth with constant-time confirmation, per-account lockout + per-IP rate limiting (memory-bounded), hardened HTTP security headers, and fully parameterized SQL. Each tool has passed automated security review with findings remediated and verified — most recently a 4th round that upgraded `sqlx` 0.7 → 0.8 across all four workspaces (clearing several transitive rustls/webpki advisories and a yanked `spin` dependency) and removed the unused `rsa` dependency from Observe, Data and Stream; ID keeps `rsa` for JWKS key generation and documents the one remaining advisory as an accepted, monitored risk. This round also added a GitHub Actions CI matrix (check/test/clippy/audit per service) and, for Infinity ID, signing-key rotation so a manual JWKS rotation never invalidates a live session or access token.

---

## ⭐ Infinity ID — the flagship

A secure-by-design IAM platform in a single fast binary: **OpenID Connect, OAuth 2.0, TOTP MFA, RBAC, an auth-aware edge gateway, and an embedded admin dashboard** — with every security feature included (no "SSO tax").

![Infinity ID dashboard](./infinity-id/docs/img/overview.png)

```bash
cd infinity-id
INFINITY_ADMIN_PASSWORD='ChooseAStrongOne#2025' cargo run --bin infinity-id
# open http://localhost:8080
```

👉 **See the full [Infinity ID README](./infinity-id/) for features, security model, API reference, and Docker deployment.**

---

## Design principles

- **Secure by design** — hardened defaults, not security-as-an-upsell.
- **Single binary, self-hostable** — SQLite for local, object storage / Postgres for scale.
- **Cost transparency** — your bill scales with hardware, not a vendor's margin.
- **All Rust** — safety and predictable latency without a garbage collector.

## Repository layout

```
infinity-stack/
├─ infinity-id/         # identity + OAuth2/OIDC + edge gateway + dashboard (flagship)
├─ infinity-observe/    # observability — logs, metrics, traces, alerts + dashboard
├─ infinity-data/       # vector DB + analytics tables + dashboard
└─ infinity-stream/     # durable topics + BM25 search + dashboard
```

## License

[Apache-2.0](./infinity-id/LICENSE) © Infinity Stack.
