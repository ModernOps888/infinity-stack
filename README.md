<div align="center">

# ∞ Infinity Stack

### Open-source, Rust-native replacements for over-monetized SaaS infrastructure.

Predictable performance. Memory safety. No GC pauses. Self-hostable. No per-seat tax.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](./infinity-id/LICENSE)
[![Rust](https://img.shields.io/badge/built%20with-Rust-000000?logo=rust)](https://www.rust-lang.org/)

</div>

---

Rust's memory safety, C-like performance, and lack of garbage collection (predictable tail latency) make it the ideal tool to commoditize expensive cloud infrastructure. Infinity Stack targets four heavily-monopolized verticals — starting with a production-grade **identity provider**.

## The products

| Product | Replaces | Status |
|---|---|---|
| **[∞ Infinity ID](./infinity-id/)** | Auth0 · Okta · OneLogin · Clerk | 🟢 **Flagship — runnable, hardened** |
| [Infinity Observe](./infinity-observe/) | Datadog · Splunk · New Relic · Sentry | 🟡 Scaffold / roadmap |
| [Infinity Data](./infinity-data/) | Snowflake · Databricks · Pinecone | 🟡 Scaffold / roadmap |
| [Infinity Stream](./infinity-stream/) | Kafka/Confluent · Elasticsearch · Algolia | 🟡 Scaffold / roadmap |

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
├─ infinity-id/         # ← deep build (identity + edge gateway + dashboard)
├─ infinity-observe/    # observability (stub)
├─ infinity-data/       # analytics + vector DB (stub)
└─ infinity-stream/     # streaming + search (stub)
```

## License

[Apache-2.0](./infinity-id/LICENSE) © Infinity Stack.
