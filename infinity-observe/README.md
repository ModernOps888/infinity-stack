# Infinity Observe

> Rust-native observability platform — a cost-transparent alternative to **Datadog, Splunk, New Relic and Sentry**.
>
> **Status: early scaffold / roadmap.** Part of the [Infinity Stack](../README.md) family. The flagship, production-oriented product today is **[Infinity ID](../infinity-id/)**.

## Why

Consumption-based observability pricing (per-host, per-GB-ingested, per-event) causes runaway "bill shock" as microservices scale. Infinity Observe decouples compute from storage and writes compressed columnar data to cheap object storage, so telemetry cost scales with hardware, not with a vendor's margin.

## Target architecture

```
OTel/agents ──▶ ingest (tokio, zero-copy parse) ──▶ Parquet on S3/GCS/MinIO
                                                        │
                       vectorized query (DataFusion/Arrow) ◀── dashboards/API
```

- **Compute:** async ingest pipeline (`tokio`) for logs, metrics and traces (OpenTelemetry-native).
- **Storage:** columnar Apache Parquet on commodity object storage — no expensive local NVMe arrays.
- **Query:** vectorized engine on Apache Arrow / DataFusion for sub-second search over S3.

## Workspace layout

```
crates/observe-core     # domain types, config, shared primitives
crates/observe-server   # ingest + query API + dashboard
crates/observe-agent    # lightweight collector/forwarder
```

## Build

```bash
cargo build --release
```

## Roadmap

- [ ] OTLP/HTTP + OTLP/gRPC ingest endpoints
- [ ] Parquet writer + object-storage backend (S3/GCS/MinIO)
- [ ] DataFusion query layer + PromQL-style API
- [ ] Alerting & dashboards
- [ ] Multi-tenant RBAC (via **Infinity ID**)

Licensed under Apache-2.0.
