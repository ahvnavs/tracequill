# Changelog

All notable changes to 墨影録 (Bokuei-roku) will be documented in this file.

## [Unreleased] - Phase 0 & Phase 1 Removals

In accordance with [docs/PLAN.md](file:///home/ahvnav/warehouse/tracequill/docs/PLAN.md) (approved Phase 0 and Phase 1 scope), all out-of-scope, speculative, non-epistemic, and dead components have been removed.

### Removed
- **Plugin System & Extensibility**:
  - Deleted `plugins/` directory (AI classifier, blockchain ledger anchor, quantum entropy generator).
  - Deleted plugin loader `internal/plugins/` and its unit tests.
  - Removed plugin documentation and references from `README.md`.
- **Federation Registry & Network Server**:
  - Deleted central registry HTTP server `internal/registry/`.
  - Removed `registry.db` handling and network federation CLI commands (`registry`, `push`, `pull`).
  - *Kept*: Signed cryptographic batch sealing and verification (`export`, `import`, `keygen` in `internal/fed/`).
- **Synthetic Multi-Host Demo Generator**:
  - Deleted `internal/demo/` and the `bokuei demo` CLI command.
  - Replaced test dependencies on synthetic generators with static deterministic test fixture `testdata/fixtures/minimal_estate.json` via helper `internal/testutil`.
- **Scoring & Microbenchmark Harness**:
  - Deleted `internal/score/` and `bench/` directories.
- **Rule Pruning**:
  - Stripped speculative machine-learning and crypto heuristics (`model_weights_updated`, `checkpoint_hash_changed`, `dataset_split_changed`) from [rules/causes.json](file:///home/ahvnav/warehouse/tracequill/rules/causes.json) and [rules/inference_pack.json](file:///home/ahvnav/warehouse/tracequill/rules/inference_pack.json).
- **Unused Dependencies**:
  - Removed `rand` crate dependency from [crates/tq-agent/Cargo.toml](file:///home/ahvnav/warehouse/tracequill/crates/tq-agent/Cargo.toml) (replaced salt generation with direct `/dev/urandom` kernel CSPRNG reads in [crates/tq-agent/src/env.rs](file:///home/ahvnav/warehouse/tracequill/crates/tq-agent/src/env.rs)).
  - Cleaned Go module dependencies with `go mod tidy` (`modernc.org/sqlite` and `github.com/spf13/cobra`).
- **Documentation**:
  - Cleaned [README.md](file:///home/ahvnav/warehouse/tracequill/README.md) to eliminate dangling references to plugins, registry, and demo generators.
