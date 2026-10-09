# 墨影録 (Bokuei-roku) — Repository Inventory and Transition Plan

This document establishes the audit, classification, toolchain report, dependency reduction proposal, and epistemic risk analysis for transitioning the codebase to **墨影録 (Bokuei-roku)** (`bokuei` / `bokuei-agent`).

---

## 1. INVENTORY

### Go Packages (`github.com/bokuei/bokuei`)
- `cmd/bokuei`: Root CLI entrypoint and subcommand dispatch for all Bokuei commands.
- `internal/claims`: Normative Claim struct definition, canonical JSON serializer, SHA-256 ID computation, and reference graph validator.
- `internal/store`: Append-only SQLite ledger management, trigger enforcement, atomic ingest transactions, and evidence payload storage.
- `internal/views`: Disposable derived views orchestrator (`view_entities`, `view_effective_state`, `view_unknowns`) and complete ledger rebuild mechanism.
- `internal/resolve`: Cross-source entity resolution, disjoint-set (Union-Find) clustering, and `cannot_link` negative constraint propagation.
- `internal/effective`: Decayed belief strength calculation, half-life model, retraction processing (`tq.meta.retracts`), and claim precedence resolution.
- `internal/infer`: Forward-chaining rule engine over active claims with provenance tracking and cycle detection.
- `internal/diff`: State comparison between runs or points in time with explicit three-state epistemic handling (`not comparable`) and root-cause ranking.
- `internal/impact`: Depth-bounded reverse dependency BFS traversal, confidence band aggregation, blind-spot identification, and safety verdicts.
- `internal/nbq`: Next-Best-Question uncertainty scoring (`uncertainty * (1 + downstream) * (1 + blind_adjacent)`) and interactive verification claim ingestion.
- `internal/server`: HTTP server serving REST endpoints (`/api/*`) and embedded zero-dependency web UI for visual inspection.
- `internal/demo`: Synthetic multi-host estate generator simulating 3 hosts over 3 days of operations.
- `internal/fed`: Ed25519 key generation, signed claim batch export/import, and selective pseudonymization filtering.
- `internal/registry`: Standalone HTTP federation batch registry server with SQLite storage and append-only constraints.
- `internal/plugins`: Declarative TOML plugin manifest loader and schema validator for third-party extensions.
- `internal/score`: Benchmark scoring harness evaluating inference and impact accuracy across synthetic seeds 1-20.

### Rust Crates (`crates/`)
- `crates/tq-claims`: Rust implementation of normative Claim data structures, canonical byte serializer, and SHA-256 claim ID generator.
- `crates/tq-agent`: Process tracer (`ptrace` + `/proc` polling fallback) and host inventory collector (`/proc/cpuinfo`, `/proc/meminfo`, `/proc/net/tcp`, `/var/lib/dpkg/status`, Python package metadata) producing the `bokuei-agent` binary.

### CLI Commands (`bokuei`)
- `bokuei claims list`: Queries and displays raw ledger claims with optional filtering by type, entity, or observer.
- `bokuei run`: Spawns and traces an arbitrary user command using `bokuei-agent` and records observed process and file activity into the ledger.
- `bokuei collect`: Executes system-level host inventory collection and appends host claims to the ledger.
- `bokuei rebuild`: Drops and reconstructs all derived SQL views (`view_entities`, `view_effective_state`, `view_unknowns`) from the raw immutable ledger.
- `bokuei explain <entity_id>`: Displays entity provenance, contributing claims, confidence scores, and forward inferences.
- `bokuei unknowns`: Queries and prints all explicit blind spots (`tq.coverage.blocked` and unobserved state).
- `bokuei rules list`: Lists all loaded forward-chaining inference rules and cause-ranking heuristics.
- `bokuei history <entity_id>`: Shows chronological timeline of claims and effective state transitions for an entity.
- `bokuei diff <run_a> <run_b>`: Compares two runs or state snapshots, reporting changed, identical, and epistemic "not comparable" attributes.
- `bokuei explain-diff <run_a> <run_b>`: Evaluates state differences against cause-ranking rules to rank probable root causes.
- `bokuei impact <entity_id>`: Evaluates upstream and downstream dependency blast radius, computing safety verdicts and blind spots.
- `bokuei ask`: Identifies and outputs the Next-Best-Question to reduce epistemic uncertainty with highest impact.
- `bokuei answer --question <id> --value <val>`: Records a manual human verification claim into the ledger to resolve an unknown.
- `bokuei serve`: Starts the local HTTP daemon serving the inspection API and embedded dashboard UI.
- `bokuei demo`: Generates synthetic multi-host demo claims across simulated time spans into `ledger.db`.
- `bokuei score`: Computes precision, recall, and epistemic fidelity scores against the synthetic benchmark ground truth.
- `bokuei keygen`: Generates an Ed25519 private/public keypair for batch signing.
- `bokuei export`: Exports a signed, optionally pseudonymized JSON batch of claims from the local ledger.
- `bokuei import`: Verifies signatures and ingests an exported JSON batch of claims into the local ledger.
- `bokuei registry`: Starts a standalone HTTP federation batch registry server.
- `bokuei push`: Signs and uploads a batch of local claims to a remote registry endpoint.
- `bokuei pull`: Downloads and ingests batches of claims from a remote registry endpoint.

### HTTP Endpoints (`internal/server/server.go`)
- `GET /`: Serves the embedded HTML/CSS/JS single-page operator dashboard.
- `GET /api/claims`: Returns paginated raw claims filtered by entity or type.
- `GET /api/entity`: Returns resolved entity details, aliases, and effective attributes.
- `GET /api/explain`: Returns dependency provenance and rule triggers for an entity.
- `GET /api/diff`: Computes and returns JSON diff between two runs or timestamps.
- `GET /api/history`: Returns timeline of claim assertions for a given entity.
- `GET /api/impact`: Returns reverse dependency traversal graph, safety verdict, and blind spots.
- `GET /api/unknowns`: Lists all active coverage gaps and unobserved dependencies.
- `GET /api/ask`: Computes and returns the top-ranked Next-Best-Question.
- `POST /api/answer`: Accepts an operator's verification answer and commits it as an assertion claim.
- `GET /api/coverage`: Summarizes host sensor visibility, ptrace availability, and blind spots.
- `GET /api/score`: Returns benchmark fidelity metrics.
- `GET /api/map`: Returns entity-relationship graph data formatted for visualization.

### Registry Endpoints (`internal/registry/server.go`)
- `GET /v1/batches`: Lists or streams signed claim batches stored in the federation registry.
- `POST /v1/batches`: Accepts and verifies a newly submitted signed claim batch.

### Plugins (`plugins/`)
- `plugins/ai.toml`: Domain schema extension for ML model checkpoints, tensor shapes, and GPU memory.
- `plugins/blockchain.toml`: Domain schema extension for consensus protocols, peer counts, and block heights.
- `plugins/quantum.toml`: Domain schema extension for qubit counts, coherence times, and quantum gates.

### Rules Files (`rules/`)
- `rules/identity.json`: 5 deterministic identity correlation rules (hostname, machine-id, DNS name, artifact SHA-256, process start+exe).
- `rules/causes.json`: 13 ranked cause heuristics (dataset change, CUDA driver, GPU device, package version, loaded library, executable binary, kernel, CPU feature, nondeterminism seed, env var, service migration, network endpoint, command arg).
- `rules/inference_pack.json`: 6 forward inference rules (Python ML job, PostgreSQL, Redis, Nginx, Blockchain node, Generic Python service).

### Documentation Files (`docs/`)
- `docs/CLAIM_SPEC.md`: Normative specification of claim schema, canonical JSON encoding, and test vectors.
- `docs/DECISIONS.md`: Architectural Decision Records (ADRs) on append-only SQLite, three-state epistemics, and language boundary.
- `docs/INVENTION_LOG.md`: Historical record of algorithmic innovations, NBQ design, and epistemic diff equations.
- `docs/LICENSING.md`: Software licensing rationale and third-party attribution declarations.
- `docs/THREAT_MODEL.md`: Security analysis regarding read-only safety, ptrace risks, and cryptographic tamper resistance.

### Tests
- Go `internal/claims/claim_test.go`: Validates canonical serialization and SHA-256 ID against the 5 normative spec vectors.
- Go `internal/claims/cross_language_test.go`: Validates claim ID equivalence and JSON interchange with `tq-claims`.
- Go `internal/store/ledger_test.go`: Tests append-only trigger enforcement, read-only guarantees, and concurrent ingest.
- Go `internal/views/views_test.go`: Tests derived view reconstruction from raw immutable ledger records.
- Go `internal/resolve/resolver_test.go`: Tests entity clustering and `cannot_link` negative constraint resolution.
- Go `internal/effective/effective_test.go`: Tests exponential decay weighting, retraction precedence, and effective state views.
- Go `internal/infer/infer_test.go`: Tests forward-chaining rule engine, loop detection, and inference provenance.
- Go `internal/diff/diff_test.go`: Tests state diffing and three-state epistemics ("not comparable" vs changed/removed).
- Go `internal/impact/impact_test.go`: Tests depth-20 reverse dependency graph traversal and blind-spot propagation.
- Go `internal/nbq/nbq_test.go`: Tests Next-Best-Question scoring algorithm and verification ingest.
- Go `internal/server/server_test.go`: Tests HTTP API endpoints and embedded web UI asset delivery.
- Go `internal/demo/generator_test.go`: Tests synthetic 3-host 3-day data generator consistency.
- Go `internal/fed/fed_test.go`: Tests Ed25519 signing, verification, and batch export/import round-tripping.
- Go `internal/score/score_test.go`: Tests synthetic benchmark scoring harness calculations.
- Rust `crates/tq-claims/src/lib.rs` (`test_spec_vectors`): Validates Rust canonical serialization against the 5 normative vectors.
- Rust `crates/tq-agent/tests/integration_tests.rs`: Tests 11 agent workflows (collector, ptrace tracing, /proc polling fallback, redaction).

---

## 2. KEEP / REMOVE / ADD CLASSIFICATION

### KEEP
- `crates/tq-claims`: Essential normative Claim representation and serialization in Rust.
- `crates/tq-agent`: Essential host and process tracer (`bokuei-agent`) providing read-only host observation.
- `internal/claims`: Essential normative Claim representation, canonical hashing, and reference validation in Go.
- `internal/store`: Essential SQLite append-only ledger and evidence storage.
- `internal/views`: Essential disposable view manager (`view_entities`, `view_effective_state`, `view_unknowns`).
- `internal/resolve`: Essential entity resolution engine with `cannot_link` negative constraints.
- `internal/effective`: Essential state belief weighting, half-life decay, and retraction processing.
- `internal/diff`: Essential state diffing engine with three-state epistemics (`not comparable`).
- `internal/impact`: Essential reverse dependency blast radius and blind-spot traversal engine.
- `internal/nbq`: Essential Next-Best-Question ranking and verification assertion workflow.
- `internal/server`: Essential local HTTP server and zero-dependency web UI for operator inspection.
- `cmd/bokuei` (Core commands): `run`, `collect`, `diff`, `explain-diff`, `impact`, `ask`, `answer`, `rebuild`, `explain`, `unknowns`, `history`, `serve`, `claims`.
- `rules/identity.json`: Essential host, process, and artifact identity matching rules.
- `rules/causes.json` (Host/OS/Package rules): Keep package version, loaded library, executable binary, kernel, CPU feature, env var, network endpoint, command arg.
- `rules/inference_pack.json` (Core system rules): Keep PostgreSQL, Redis, Nginx, generic service inference.
- `docs/CLAIM_SPEC.md`, `docs/DECISIONS.md`, `docs/INVENTION_LOG.md`, `docs/LICENSING.md`, `docs/THREAT_MODEL.md`.

### REMOVE
- `plugins/` (`ai.toml`, `blockchain.toml`, `quantum.toml`): Not needed for core Linux host/run dependency intelligence.
- `internal/plugins`: Plugin loader and schema validator for speculative domain extensions.
- `internal/registry`: Standalone federation registry server and `registry.db`.
- `cmd/bokuei` (Registry commands): `registry`, `push`, `pull`.
- `internal/demo`: Heavy synthetic multi-host generator.
- `cmd/bokuei` (Demo command): `demo`.
- `internal/score`: Benchmark scoring harness across synthetic seeds.
- `cmd/bokuei` (Score command): `score`.
- `rules/causes.json` (ML & Crypto cause rules): Remove `cause-dataset-change`, `cause-ai-model-hash`, `cause-cuda-driver`, `cause-gpu-device`, `cause-nondeterminism-seed`.
- `rules/inference_pack.json` (ML & Crypto inference rules): Remove `blockchain-node`, `python-ml-job`.
- `bench/results.json`: Output artifact of the synthetic benchmark harness.

### ADD
- `testdata/fixtures/minimal_estate.json`: Tiny static fixture replacing the synthetic multi-host demo generator to provide fast, deterministic test data for UI and diff validation.
- `internal/evidence`: Clarify extraction and read-only storage of raw proof artifacts (/proc snippets, package records).

---

## 3. TOOLCHAIN REPORT

### Toolchain Versions
- **Go version**: `go version go1.26.0 linux/amd64` (installed at `/usr/lib/go-1.26/bin/go`).
  *(Note: The system PATH points to Go 1.26.0; the fallback compiler at `/usr/bin/go` is `gccgo 14.3.0` which corresponds to Go 1.18).*
- **Rustc version**: `rustc 1.99.0 (b940084d7 2026-09-28)`.
- **Cargo version**: `cargo 1.99.0 (5f94df478 2026-08-27)`.

### Go Language & Stdlib Feature Audit
- The installed active Go toolchain is **Go 1.26.0**, which supports all modern Go language features.
- Analysis of code against Go 1.21+ features:
  - `min` / `max` builtins: Not used in Go source code (SQL queries use SQL `max()`, and internal helpers implement custom comparisons).
  - `clear` builtin: Not used.
  - `slices` package: Not used.
  - `maps` package: Not used.
  - `log/slog` package: Not used (code uses standard `log` and `fmt`).
  - `range-over-int`: Not used; traditional standard `for i := 0; i < n; i++` loops are used.
  - `loopvar` per-iteration variable semantics: All goroutines and closures capture variables explicitly or pass as parameters.
- **Dependency Toolchain Requirements**:
  - `modernc.org/sqlite` requires Go 1.20+.
- **Conclusion**:
  - The installed Go compiler (1.26.0) is fully capable of building and running the codebase without requiring any toolchain upgrade.
  - If a user were running in an environment with only the legacy `/usr/bin/go` (gccgo Go 1.18), `modernc.org/sqlite` would fail to compile; in that scenario, the recommendation would be to install Go 1.22+ into a user directory (`~/.local/go`) without sudo.

---

## 4. DEPENDENCY-REDUCTION PROPOSAL

### `go.mod` Reduction Proposal
Current dependencies in `go.mod`:
- `github.com/dustin/go-humanize v1.0.1`: Used only in CLI output formatting and synthetic demo reporting. **Can be replaced** with a 10-line helper function for byte/number formatting, eliminating the external dependency.
- `github.com/google/uuid v1.6.0`: Used for generating run IDs and entity IDs. **Can be replaced** by cryptographically secure random 16-byte hex strings using stdlib `crypto/rand` or canonical content hashes.
- `github.com/spf13/cobra v1.8.0` & `github.com/spf13/pflag v1.0.5`: High quality, robust CLI command tree. **Keep** for CLI usability and standard POSIX flag parsing.
- `modernc.org/sqlite v1.29.5` (and its sub-dependencies `libc`, `mathutil`, `memory`): Pure Go SQLite engine required for CGO-free append-only ledger operation. **Keep**.

**Summary**: By removing `github.com/dustin/go-humanize` and `github.com/google/uuid`, `go.mod` becomes strictly limited to Cobra (CLI) and pure-Go SQLite.

### `Cargo.toml` (`crates/tq-agent`) Reduction Proposal
Current dependencies in `crates/tq-agent/Cargo.toml`:
- `serde`, `serde_json`: Essential for canonical claim output. **Keep**.
- `sha2`: Essential for hashing file contents and computing claim IDs. **Keep**.
- `nix`: Used for Linux `ptrace`, `waitpid`, and signal handling. **Keep**.
- `regex`: Used for parsing `/proc/net/tcp` and package manifests. **Keep**.
- `toml`: Used for parsing `bokuei.toml` configuration. If config is simplified or formatted as JSON, this can be dropped, but keeping it for config ergonomics is reasonable.
- `rand`: Used only to generate salt for environment variable hashing. **Can be dropped** and replaced by reading 16 bytes directly from `/dev/urandom` or stdlib features, removing an entire dependency tree (`rand_core`, `rand_chacha`, etc.).

---

## 5. RISK LIST: PLACES WHERE CODE COULD CLAIM CERTAINTY IT DOESN'T HAVE

The core tenet of 墨影録 is three-state epistemics: *absence of evidence is never evidence of absence*. The following locations in the codebase carry the risk of claiming false certainty or collapsing unobserved state into "absent":

1. **CPU Feature Flag Truncation (`crates/tq-agent/src/collector.rs`)**:
   - *Risk*: When parsing `/proc/cpuinfo`, the collector captures only the first 10 CPU flags (`take(10)`).
   - *Epistemic Danger*: An impact check checking for AVX-512, AES-NI, or virtualization extensions will observe them as absent rather than "unobserved" or truncated, falsely concluding the host lacks these capabilities.
   - *Correction*: Capture all flags or emit a `coverage.blocked: cpu_flags_truncated` claim.

2. **GPU & Accelerator Blindness (`crates/tq-agent/src/collector.rs`)**:
   - *Risk*: The agent checks for NVIDIA GPUs by probing `/proc/driver/nvidia` or running `nvidia-smi`. If missing, it emits `coverage.blocked: gpu_metrics:nvidia_smi_not_found`. However, it does not probe AMD (`/sys/class/kfd`, `rocm-smi`) or Intel accelerators.
   - *Epistemic Danger*: The system might lead an operator to believe no accelerator exists, when in fact non-NVIDIA accelerators are completely invisible to the agent.
   - *Correction*: Explicitly emit `coverage.blocked` for unsupported accelerator types when PCI devices indicate graphics controllers exist.

3. **Polling Mode I/O Loss (`crates/tq-agent/src/tracer.rs`)**:
   - *Risk*: When `ptrace` is unavailable (e.g. unprivileged container or `yama/ptrace_scope=1`), the tracer falls back to polling `/proc/<pid>/fd` every 5ms.
   - *Epistemic Danger*: Short-lived files opened and closed between 5ms ticks (e.g. temporary config files, lock files, credentials) are completely missed. If the impact engine treats the resulting trace as complete, it will claim a file has no dependents when it actually does.
   - *Correction*: The diff and impact engines must strictly degrade confidence to "not comparable" / "blind spot" for any run where `coverage.blocked: file_io:ptrace_denied` is present.

4. **Hostname-Only Entity Resolution (`internal/resolve/resolver.go`)**:
   - *Risk*: `rules/identity.json` includes hostname matching with high weight.
   - *Epistemic Danger*: In containerized environments or virtual machines, multiple disparate instances often share default hostnames (e.g., `localhost`, `ubuntu`, `runner`). The resolver could conflate independent hosts into a single entity.
   - *Correction*: Enforce negative constraint (`cannot_link`) whenever `machine-id` or boot IDs differ, even if hostnames match.

5. **Effective State Precedence over Silence (`internal/effective/effective.go`)**:
   - *Risk*: When computing effective state at a point in time, if a daemon stops reporting an attribute, the half-life decay slowly diminishes belief strength, but the attribute remains "present" with decaying confidence until expiration.
   - *Epistemic Danger*: If a service is abruptly killed without emitting a tombstone/retraction, the system reports it as likely running for several hours.
   - *Correction*: Cross-reference process existence claims: if the host was observed without the PID, immediately report the process status as "not visible / dead" rather than decaying.

6. **Network Connection Visibility (`crates/tq-agent/src/collector.rs`)**:
   - *Risk*: `/proc/net/tcp` snapshots only existing connections at the instant of collection. Transient UDP packets, raw sockets, or fast TCP connections are invisible.
   - *Epistemic Danger*: An impact analysis on a firewall rule change could claim no process connects to a port simply because no connection was active during the snapshot.
   - *Correction*: Mark network port dependencies derived solely from `/proc/net/tcp` snapshots with explicit temporal uncertainty bounds.
