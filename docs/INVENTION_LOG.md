# INVENTION LOG

This document tracks dated design decisions, alternatives considered, and conceptual lineage borrowed from prior art. Bokuei does not claim novelty or originality for foundational mechanisms; it synthesizes established techniques into a verifiable claim/evidence engine.

## Conceptual Lineage & Borrowings

- **Nix / Guix**: Pure function build graph, derivation references (`ref://artifact/...`), deterministic input hashing, and explicit tracking of closure dependencies.
- **rr (Record and Replay Framework)**: Strict determinism invariants, separation of nondeterministic inputs from recorded event streams, and replayable execution semantics.
- **CRIU (Checkpoint/Restore In Userspace)**: Techniques for process introspection, file descriptor inspection, memory mapping tracking, and non-invasive state capture.
- **ReproZip**: Runtime provenance tracing of dependencies, distinguishing between read files, written files, loaded dynamic libraries, and system packages.
- **MLflow**: Experiment run tracking abstractions (`ref://run/...`), tracking inputs, parameters, outputs, and execution environments.
- **in-toto & SLSA**: Cryptographic attestation, signed append-only metadata chains, supply chain evidence, and provenance verification.
- **FORGE**: Formalized claim-evidence representation, distinction between raw observation records and derived beliefs, and explicit tracking of epistemic uncertainty (unknowns and blind spots).

## Dated Entries

### 2026-10-07: Phase 1 Claim/Evidence Ledger Architecture
- **Decision**: Define a strict JSON canonicalization specification (sorted keys, no whitespace, UTF-8, integer/string numbers) shared between the Go core and Rust agent.
- **Alternative considered**: Protocol Buffers or Cap'n Proto. Rejected for ledger storage because human-readable, verifiable JSON with deterministic canonical formatting allows direct SQLite inspection and zero-dependency cross-language verification.
- **Decision**: SQLite triggers to enforce ledger append-only semantics directly at the database engine level.
- **Alternative considered**: Application-level enforcement only. Rejected because any external tool, direct connection, or script must be unable to mutate or delete historical claims.
- **Decision**: Explicit three-state ontology (`observed`, `not visible`, `observed absent`).
- **Lineage**: Epistemic logic and open-world assumption in formal knowledge representation.

### 2026-10-07: Phase 2 Capture Agent & System Telemetry Architecture
- **Decision**: Split execution into low-overhead Rust tracer (`bokuei-agent`) that emits only signed/hashed NDJSON batches and pure-Go ledger engine (`bokuei`) that ingests batches into SQLite.
- **Lineage**: Follows ReproZip and CRIU for ptrace syscall interception (`open`, `openat`, `openat2`, `execve`, `execveat`), with Maps inspection from `/proc/<pid>/maps` at exec and exit.
- **Decision**: Graceful fallback to `/proc` polling when `ptrace` is denied (e.g. Yama ptrace_scope=2 or unprivileged containers). Emits `coverage.observed` with `mode=polling` and `coverage.blocked` for file I/O, strictly refusing to fabricate unobserved file accesses.
- **Lineage**: Open-world assumption; absence of evidence is not evidence of absence.
- **Decision**: Read-only host collection directly from filesystem and kernel sources (`/proc/cpuinfo`, `/proc/meminfo`, `/proc/net/tcp`, `/var/lib/dpkg/status`, `*.dist-info/METADATA`). Python packages inspected via opened metadata files without ever executing package managers like `pip`.
- **Decision**: Secret protection by default: argv[1..] redacted unless `--record-args`, `/proc/*/environ` is never opened, and environment variables record names only with allowlisted values (`PATH`, `LANG`, etc.) or per-run salted SHA-256 hashes.

### 2026-10-07: Phase 3 Effective Strength, Entity Resolution, and Rule Inference
- **Decision**: Source-group independence and strength formulation: multiple claims from the same source group do not artificially inflate strength beyond the max reliability of that group (`r_g = max(reliability)`). Cross-group combination uses independent evidence fusion: `strength = 1 - product(1 - r_g)`.
- **Decision**: Half-life time decay (`strength *= 0.5^(age_days / halflife)`). Human verification provides 1.0 strength with zero decay until explicitly retracted via `tq.meta.retracts`.
- **Lineage**: Dempster-Shafer theory of evidence, belief decay models in epistemics, and in-toto human attestation guarantees.
- **Decision**: Entity clustering via Union-Find over positive alias edges in descending strength order, hard `cannot_link` constraints, merge threshold 0.60, and rejecting single weak edge merges (< 0.60). Entity IDs are canonically computed as `sha256(smallest_member_ref)`.
- **Lineage**: Constrained clustering (COP-Kmeans), record linkage, and deterministic canonical naming.
- **Decision**: Data-driven JSON inference rules supporting `equals`, `in`, `exists`, and `port-listens`. All inferred claims record `claim_support` lineage and maintain strict idempotency.
- **Lineage**: Datalog and expert system forward chaining.

### 2026-10-08: Phase 4 Differential Causality, Temporal Reconstruction, and Epistemic Diffing
- **Decision**: Three-state diff transitions: when an attribute is observed in state A but unobserved/unmonitored in state B, report as **`not comparable`**, NEVER `removed` or `absent`. Absence of evidence is not evidence of absence.
- **Lineage**: Open-world assumption in formal knowledge representation; distinguishes epistemic blind spots from state deletion.
- **Decision**: Temporal diff reconstruction (`bokuei diff <time_a> <time_b>`): supports relative durations (`1h`, `24h`, `7d`) and RFC3339 timestamps by evaluating effective derived states using all claims observed with `observed_at <=` the cutoff timestamp.
- **Lineage**: Point-in-time temporal databases and bitemporal ledger semantics.
- **Decision**: Data-driven cause ranking via `rules/causes.json`: ordered candidate root causes based on domain category weights (dataset changes, CUDA/GPU drivers, package versions, kernel, CPU features, nondeterminism seeds, env vars, endpoints). Base weights are strictly ordering weights, not fabricated probabilities. Every ranked cause lists the exact supporting claims from the ledger.
- **Lineage**: Root cause analysis (RCA) and diagnostic rule-based expert systems.
- **Decision**: Strict narrative generation in `explain-diff`: narrative sentences are constructed solely from rule template text and verified supporting claims, with zero ungrounded text or hallucinations.

### 2026-10-08: Phase 5 Impact Analysis, Blind-Spot Verdicts, and Next-Best-Question (NBQ)
- **Decision**: Multi-hop reverse impact propagation bounded at depth 20: uses predicate impact directions (backward for loaded libraries/read datasets/host runs; forward for created artifacts and listeners) to compute the complete reachable dependent set across runs, hosts, and services.
- **Lineage**: Taint analysis, program slicing, and supply-chain dependency graphs (SLSA, in-toto).
- **Decision**: Epistemic blind-spot propagation: when the dependency path touches unmonitored zones, unmodeled endpoints, or runs with blocked file I/O telemetry, dependents in those scopes are marked unknown and the verdict defaults to `Do not proceed until questions answered`.
- **Lineage**: FORGE epistemic uncertainty modeling and safety barrier models.
- **Decision**: Active inquiry / Next-Best-Question scoring: `score = uncertainty * (1 + downstream) * (1 + blind_adjacent)`. Direct human verification answers append immutable `human` claims with `human.verified_by` and strictly reduce measured unknowns without modifying historical claims.
- **Lineage**: Active learning, expected value of information (EVOI), and human-in-the-loop verification.
### 2026-10-08: Phase 6 Standard-Library Web Server, Embedded UI & Epistemic Map
- **Decision**: Zero external dependencies in web architecture: HTTP server implemented using Go standard-library `net/http` and `embed.FS` (`go:embed web/*`), serving a single-page vanilla HTML/CSS/JS frontend without node, npm, Webpack/Vite, CDN links, or remote fonts.
- **Lineage**: Self-contained operational tools (e.g. SQLite web, Prometheus embedded UI) designed for air-gapped forensic environments.
- **Decision**: Historical effective state point-in-time time-slider immutability: `/api/map?at=<timestamp>` dynamically evaluates effective states in-memory without invoking mutations, view drops, or ledger insertions. Claims ledger bytes and hashes remain strictly byte-identical before and after time-travel navigation.
- **Lineage**: Pure functional state queries over append-only event logs (CQRS / event sourcing).
- **Decision**: Native SVG spring-electrical force graph without graph libraries: nodes, edges, stale dashed outlines, and hatched "not visible" regions are computed using an embedded 2D repulsion-spring physics simulation in vanilla JS.
- **Lineage**: Fruchterman-Reingold force-directed placement algorithms implemented directly in SVG DOM.


