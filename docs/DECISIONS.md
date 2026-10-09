# DECISIONS

This document logs architectural and design decisions, dependency justifications, read-only system queries, and disambiguations for 墨影録 (Bokuei-roku).

## 1. Toolchain & Runtime Environment

- **Go**: Pure Go 1.22+ (`go1.26.0` on Ubuntu 26.04 / WSL2), without CGO (`CGO_ENABLED=0`).
  - Dependencies: `modernc.org/sqlite` (pure Go SQLite engine) and `github.com/spf13/cobra` (CLI framework).
- **Rust**: Rust 1.99.0+ / Edition 2021.
  - Dependencies:
    - `serde` (with `derive` feature): Used for strict, typed serialization/deserialization of claims and batches.
    - `serde_json`: Used for JSON formatting and canonical serialization without arbitrary map reordering.
    - `sha2`: Used for RFC/NIST standard SHA-256 computation of canonical claim IDs and evidence payloads.
    - `nix` & `libc`: Used on Linux targets for low-level system call interception (`ptrace`), signal handling, waitpid, process inspection.
    - `toml`: Used for parsing user configuration from `bokuei.toml`.
    - `base64`: Used for encoding raw supporting evidence payloads within JSON claim batches.
    - `chrono`: Used for RFC3339 UTC timestamps (`observed_at`).
    - `tempfile`: Used for isolated, hermetic unit & integration testing of filesystem and procfs parsers.

## 2. Allowed Read-Only Host Queries

Bokuei executes only the target command passed by the user to `run`, plus explicitly documented read-only queries. It never modifies, restarts, installs, or configures anything on observed systems.
Allowed read-only inspection commands:
- `nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader,nounits` (GPU telemetry)
- `uname -a` / `uname -r` (Kernel inspection)
- `lscpu` or reading `/proc/cpuinfo` (CPU capability inspection)
- `dpkg-query -W` / `rpm -qa` (System package registry read-only query)

## 3. Claim Serialization & Hashing Specification

To ensure byte-identical cross-language hashing between Go and Rust:
- Keys in JSON objects must be lexicographically sorted (Unicode codepoint order).
- No extraneous whitespace between keys, colons, commas, or brackets.
- UTF-8 encoding without BOM.
- Numbers: strictly integers or stringified decimals (no raw float types to avoid platform float inaccuracies).
- Empty arrays serialize as `[]`, and optional omitted fields are serialized deterministically per `docs/CLAIM_SPEC.md`.
- `claim_id` is defined as `sha256(canonical_claim_bytes)` expressed as a 64-character lowercase hex string.

## 4. Ledger Immutability & Rebuildability

- The `claims` table is append-only. Triggers `trg_claims_no_update` and `trg_claims_no_delete` reject any `UPDATE` or `DELETE` with an abort signal.
- Ingestion is idempotent: inserting an existing `claim_id` is a no-op (`INSERT OR IGNORE`).
- State-change deduplication: Observations identical to the latest recorded state of the entity ref for a predicate generate 0 new claims.
- All `view_*` tables are strictly disposable and derived from the `claims` and `claim_support` ledger.

## 5. Visibility and Three-State Worldview

- States: **observed**, **not visible**, **observed absent**.
- In accordance with the non-negotiable rule: Absence of evidence is never evidence of absence. Any unobserved or blocked entity/attribute is presented as "not visible", never "absent".

## 6. Derived Views & Precedence Rules (Phase 3)

- **Effective State Precedence**: `verified > contested > corroborated > inferred > observed`.
- **Strength Formulation**:
  - Within source group: `r_g = max(reliability)`.
  - Across source groups: `strength = 1 - product(1 - r_g)`.
  - Half-lives: runtime 3d, identity 30d, software 30d, project 90d, coverage 7d.
  - Human verification (`human`, `verifier`): strength = 1.0 with no decay until retracted.
  - Stale when decayed strength < 50% of undecayed strength.
- **Entity Resolution**:
  - Minimum merge threshold: 0.60. Never merge on a single weak edge (< 0.60).
  - Hard `cannot_link` negative constraints are never violated and override positive links.
  - Entity ID is canonically computed as `sha256(smallest_member_ref)`.
- **Retractions**:
  - Emitted as claims with predicate `tq.meta.retracts` targeting `claim_id` or ref. Old claims are never mutated or deleted.
- **Inference Engine**:
  - Evaluates data-driven JSON rules supporting operators `equals`, `in`, `exists`, and `port-listens`.
  - Inferred claims record `claim_support` lineage records and are strictly idempotent.

## 7. Diff, Cause Ranking, and Epistemic Comparability (Phase 4)

- **Diff Comparability Invariant**:
  - A transition from observed to not visible is strictly reported as **`not comparable`**, NEVER `removed` or `absent`.
  - Any attribute outside observed scope remains `not visible`.
- **Temporal Cutoff Resolution**:
  - Supports RFC3339 timestamps and relative durations (`1h`, `24h`, `7d`).
  - Effective views are reconstructed by scoping ledger queries to claims where `observed_at <= cutoff`.
- **Cause Ranking Weighting**:
  - Data-driven via `rules/causes.json`.
  - Categorical ordering: input/dataset change (95) > GPU/driver (90) > GPU device (88) > package version (85) > loaded library (82) > executable binary (80) > kernel (75) > CPU feature (70) > nondeterminism hint (68) > environment variable (60) > service moves (55) > network endpoint (50).
  - Weights are strictly deterministic ordering weights, not synthetic probabilities.
- **Explain-Diff Narrative Constraint**:
  - Built strictly from rule explanation templates and concrete supporting claims. Zero speculative or generated claims beyond defined rules and ledger evidence.

## 8. Impact Traversal, Blind Spots, and Next-Best-Question (Phase 5)

- **Reverse Dependency Traversal (`bokuei impact <ref>`)**:
  - Employs predicate `ImpactDirection`: backward predicates (e.g., `run.read`, `run.loaded`, `run.ran_on`) traverse from referenced dependency to dependent runs, then upward to hosts and services. Forward predicates (`run.wrote`, `host.listens`) traverse downstream.
  - Maximum traversal depth: 20.
  - Confidence bands: `known` (>= 0.85), `likely` (0.60 to <0.85), `possible` (0.30 to <0.60).
- **Epistemic Blind Spots & Verdicts**:
  - Adjacent unmonitored zones, unmodeled endpoints, and runs with restricted file I/O telemetry are flagged as blind spots.
  - Dependents residing within or communicating with blind scopes are explicitly reported as unknown.
  - Deterministic verdict rules:
    - `Do not proceed until questions answered`: Unobservable file I/O or critical blocked zone connections on the dependency path.
    - `Proceed with caution`: Blind spots or low-confidence dependents detected.
    - `Safe to proceed`: Zero blind spots and fully observed dependency graph.
- **Next-Best-Question (`bokuei ask`, `bokuei answer`)**:
  - Prioritizes epistemic reduction: `score = uncertainty * (1 + downstream) * (1 + blind_adjacent)`.
  - `uncertainty = 1 - strength` (1.0 for unresolved gaps).
  - Human answers strictly append new signed claims with `source_group = human` and `human.verified_by`. Prior claims are immutable.
  - Rebuilding derived views after answering strictly lowers the measured unknown count. Answered questions are never re-asked.

## 9. HTTP Server, Embedded Web UI, and Interactive Map (Phase 6)

- **Pure Standard-Library Web Server (`bokuei serve`)**:
  - Built strictly using Go standard library `net/http` and `embed.FS` (`go:embed web/*`).
  - Zero external frameworks, zero npm/node build steps, zero CDN references, zero remote fonts.
  - Assets strictly scanned in automated tests to prevent any external `http://` or `https://` requests.
- **Unified Internal API**:
  - HTTP endpoints (`/api/claims`, `/api/entity`, `/api/explain`, `/api/diff`, `/api/history`, `/api/impact`, `/api/unknowns`, `/api/ask`, `/api/answer`, `/api/coverage`, `/api/map`) directly call the internal engine code shared with CLI commands.
- **Historical Effective State Immutability**:
  - `/api/map?at=<timestamp>` reconstructs point-in-time effective states purely in-memory using `effective.ComputeEffectiveStates` on claims where `observed_at <= cutoff`.
  - The SQLite database file bytes and claim counts remain strictly byte-identical before and after time-slider requests.
- **Embedded Force Graph Visualization**:
  - Pure SVG native spring-electrical force layout running without D3, Cytoscape, or foreign libraries.
  - Visual cues:
    - Hosts (Cyan), Services (Purple), Runs (Emerald), Artifacts/Packages (Amber).
    - Stale entities (< 50% decayed strength): Dashed outlines.
    - Not-visible scopes & blocked zones: Hatched pattern fills (`pattern#not-visible-hatch`).
## 10. Host Capability Probing & Visibility Score (v1.1)

- **Explicit Epistemic Capabilities**:
  - Rather than assuming complete visibility, `bokuei-agent probe` affirmatively discovers what can and cannot be observed on a host.
  - Denied, restricted, or unmodeled subsystems are recorded as immutable `capability.cannot` claims with explicit reason codes, while supported subsystems are recorded as `capability.can`.
  - Probes are strictly read-only: checking `CapEff` in `/proc/self/status`, `hidepid` in `/proc/self/mountinfo`, Yama `ptrace_scope`, opening `/proc/net/nf_conntrack`, reading `/sys/class/net`, and detecting network namespaces via `/proc/self/ns/net`.
  - Non-modeled subsystems (such as firewall packet filtering rules) affirmatively emit `capability.cannot` with reason `firewall_not_modeled`.
- **Deterministic Visibility Score Formula**:
  - For a given host, the Visibility Score evaluates visibility across core observation capabilities:
    1. Process Tracing (`ptrace`) - Weight: 20
    2. Cross-User Process Inspection (`proc_other_users`) - Weight: 15
    3. Network Conntrack State (`conntrack`) - Weight: 15
    4. Network Interfaces & Sysfs (`sysfs_net`) - Weight: 15
    5. Package Database Access (`package_db`) - Weight: 15
    6. Network Namespace Coverage (`net_ns`) - Weight: 10
    7. Firewall Filter Rules (`firewall`) - Weight: 10
    Total weights = 100.
  - Each capability receives points if observed present and supported (`capability.can`):
    $$\text{Score} = \sum_{c \in \text{Capabilities}} \text{Weight}(c) \times \mathbb{I}(\text{status}(c) = \text{observed})$$
    If a capability has status "not visible" (e.g. `capability.cannot`), its contribution is 0.
  - The score strictly ranges between 0 and 100, reflecting the fraction of system telemetry visible to the agent.


