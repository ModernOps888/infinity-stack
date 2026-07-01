# Infinity Stream

> Rust-native real-time streaming + search engine — an alternative to **Confluent/Kafka, Elasticsearch, Algolia and Pusher**.
>
> **Status: early scaffold / roadmap.** Part of the [Infinity Stack](../README.md) family. The flagship, production-oriented product today is **[Infinity ID](../infinity-id/)**.

## Why

Kafka carries heavy JVM/RAM overhead and DevOps burden; Elasticsearch is resource-hungry; Algolia and Pusher bill aggressively on usage spikes. Infinity Stream unifies an append-only log, inverted-index search, and real-time pub/sub in one lean Rust binary.

## Target architecture

```
producers ─▶ append-only log (io_uring, zero-copy) ─▶ consumers
                     │
          inverted index (search)      WebSocket pub/sub (presence)
```

- **Streaming:** append-only log using `io_uring` for asynchronous, zero-copy disk I/O.
- **Search:** built-in inverted indexing (Lucene replacement).
- **Realtime:** WebSocket pub/sub and presence.
- **Goal:** wire-protocol parity (speak the Kafka TCP protocol) so existing consumers point at Infinity Stream with zero code changes.

## Workspace layout

```
crates/stream-core     # log/index primitives, config
crates/stream-server   # broker + search + WebSocket API
crates/stream-cli      # producer/consumer/admin CLI
```

## Build

```bash
cargo build --release
```

## Roadmap

- [ ] Segmented append-only log with offset index
- [ ] Kafka wire-protocol compatibility layer
- [ ] Inverted-index search + query API
- [ ] WebSocket pub/sub + presence
- [ ] Auth & ACLs via **Infinity ID**

Licensed under Apache-2.0.
