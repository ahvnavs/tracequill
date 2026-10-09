# 墨影録 (Bokuei-roku)

> Append-only claim and evidence ledger providing dependency intelligence, root-cause diffing, reverse impact tracing, and epistemic uncertainty quantification across Linux hosts and compute runs.

---

## What It Does

Bokuei records what your runs, applications, and Linux hosts actually depended on as signed, append-only cryptographic evidence. It answers three fundamental systems questions:

1. **Why did this run behave differently from last time?**  
   Computed side-by-side state diff with causal ranking (`rules/causes.json`) backed by verified ledger claims. When telemetry was blocked or unobserved, Bokuei reports transitions as **`not comparable`**, never assuming unobserved means absent.
2. **If I change this library, driver, dataset, or config, what is affected and where are we blind?**  
   Multi-hop reverse dependency traversal bounded at depth 20 with confidence bands (`known` &ge; .85, `likely` .60–<.85, `possible` .30–<.60). Flagged epistemic blind spots (unmodeled network endpoints, unmonitored zones, blocked telemetry) compute deterministic safety verdicts (`Safe to proceed`, `Proceed with caution`, `Do not proceed until questions answered`).
3. **What is the one thing I should verify next?**  
   Next-best-question (NBQ) scoring prioritizing verification that maximizes measured reduction in epistemic unknowns:  
   $$\text{score} = \text{uncertainty} \times (1 + \text{downstream}) \times (1 + \text{blind\_adjacent})$$  
   Answering questions appends signed human verification to the ledger, permanently eliminating staleness decay and collapsing active unknowns.

---

## What It Does NOT Do

Bokuei maintains strict architectural boundaries:
- **No execution replay:** Bokuei does not record CPU registers, memory dumps, or full execution traces to replay processes.
- **No environment migration:** Bokuei does not synthesize containers, VMs, or deployment images from runs.
- **No guarantee of absolute reproducibility:** Bokuei records observed provenance, hardware features, kernel versions, and sidecars, but does not claim to guarantee bit-for-bit mathematical reproducibility across arbitrary hardware or unobserved non-deterministic sources.
- **No closed-world assumption:** Unobserved or blocked state is strictly treated as **not visible**, never assumed absent or unchanged.

---

## Architecture Overview

```
                      +-----------------------------+
                      |     bokuei-agent (Rust)     |
                      |  ptrace + procfs telemetry  |
                      +--------------+--------------+
                                     | Signed Batch
                                     v
                      +-----------------------------+
                      |      bokuei core (Go)       |
                      | SQLite Append-Only Triggers |
                      |    Canonical JSON Hashing   |
                      +--------------+--------------+
                                     |
         +---------------------------+---------------------------+
         |                           |                           |
         v                           v                           v
+------------------+       +-------------------+       +-------------------+
|  Diff & Causes   |       | Reverse Impact    |       | Epistemic UI      |
|  rules/causes.json|      | Blind Spot Bounds |       | Native SVG Graph  |
|  not comparable  |       | Safety Verdicts   |       | Time-Slider State |
+------------------+       +-------------------+       +-------------------+
```

---

## Quick Start

### 1. Build
```bash
# Set up toolchain (Go 1.26 + Rust)
source toolchain_env.sh

# Build Go core & CLI
go build -o bokuei ./cmd/bokuei

# Build Rust agent
cargo build --workspace
```

### 2. Generate Synthetic Estate & Rebuild Views
```bash
./bokuei demo --hosts 3 --days 3
./bokuei rebuild
```

### 3. Trace a Command
```bash
./bokuei run -- python3 -c "import os; print('Hello Bokuei')"
```

### 4. Diff Runs & Trace Root Causes
```bash
./bokuei diff ref://run/run-001 ref://run/run-004
```

### 5. Reverse Impact Analysis
```bash
./bokuei impact ref://dataset/imagenet-subset-v1
```

### 6. Start Web UI & API Server
```bash
./bokuei serve --addr 127.0.0.1:8080
```
Open `http://127.0.0.1:8080` in your browser for the interactive SVG Map, Time Slider, Explain, Diff, Impact, and Ask views.

### 7. Federation: Keygen, Export, and Import
```bash
# Generate Ed25519 signing key (mode 0600)
./bokuei keygen --out bokuei.key

# Export new claims as a signed batch (.bq)
./bokuei export --out batch-01.bq --key bokuei.key

# Import into another ledger with cryptographic verification (supports .bq and legacy .tq)
./bokuei import batch-01.bq --db replica.db
```
