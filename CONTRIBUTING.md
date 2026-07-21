# Contributing to Infinity Stack

Thanks for considering a contribution. Infinity Stack is a Cargo-workspace-per-service monorepo (`infinity-id`, `infinity-observe`, `infinity-data`, `infinity-stream`) — each service builds, tests, and runs independently.

## Getting set up

You'll need a stable Rust toolchain (see each service's `Cargo.toml` for the edition). No other services or databases are required — each ships with SQLite by default.

```bash
cd infinity-id        # or infinity-observe / infinity-data / infinity-stream
cargo run --bin infinity-id
```

See the Quickstart section of the service's own README for its default port and admin credentials.

## Before opening a PR

Run the same checks CI runs (see `.github/workflows/ci.yml`), from inside the service directory you changed:

```bash
cargo check --workspace --all-targets
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo audit
```

A PR that only touches one service only needs that service's checks to pass.

## Guidelines

- Keep PRs scoped to one service where possible — the CI matrix runs each service independently, and focused PRs are easier to review.
- New dependencies should be justified in the PR description; `cargo audit` must stay clean (or the advisory must be documented in that service's `.cargo/audit.toml` with reasoning, matching the existing pattern).
- Security-relevant changes (auth, session handling, RBAC, crypto) should call out the threat being addressed or mitigated in the PR description — see each README's "Security" table for the existing threat model.
- Update the relevant README (API reference, config table, roadmap checkbox) alongside behavior changes.

## Reporting security issues

Please do not open a public issue for a suspected vulnerability. Open a private security advisory via the repository's **Security** tab instead.
