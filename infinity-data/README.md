# Infinity Data

> Rust-native, S3-backed hybrid analytics + vector database — an alternative to **Snowflake, Databricks and Pinecone**.
>
> **Status: early scaffold / roadmap.** Part of the [Infinity Stack](../README.md) family. The flagship, production-oriented product today is **[Infinity ID](../infinity-id/)**.

## Why

Data warehouses lock you in and bill exponentially for compute (DBUs, credits) and memory-bound vector indexing at billion-scale. Infinity Data leans on the modern Rust data ecosystem to deliver distributed analytics and vector search on cheap object storage with predictable cost.

## Target architecture

```
SQL / vector query ─▶ cost-based planner ─▶ distributed executors (Polars/Arrow)
                                              │
                          columnar + vector index (Tantivy) on S3 object storage
                                              │
                            Raft consensus (raft-rs) for metadata/coordination
```

- **Engine:** `Polars`/Arrow for dataframes, `Tantivy` for indexing.
- **Scale-out:** Raft (`raft-rs`) for consensus; out-of-core spilling to avoid OOM on heavy joins.
- **Hybrid:** unified analytical (OLAP) + vector (ANN) query surface.

## Workspace layout

```
crates/data-core     # types, planner primitives, config
crates/data-server   # coordinator + executor + query API
crates/data-cli      # client / admin CLI
```

## Build

```bash
cargo build --release
```

## Roadmap

- [ ] Parquet/Arrow storage layer on object storage
- [ ] SQL front-end + cost-based optimizer
- [ ] Vector index (HNSW) with disk spill
- [ ] Raft-based distributed coordination
- [ ] Auth & RBAC via **Infinity ID**

Licensed under Apache-2.0.
