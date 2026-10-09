# 墨影録 (Bokuei-roku) Threat Model & Security Posture

## 1. Overview
Bokuei is an evidence-first dependency observation and causal intelligence system. Its threat model acknowledges that observers on shared operating systems operate with finite visibility and adversarial limits.

---

## 2. Observer Capabilities and Blind Spots

### 2.1 What a Malicious Program Can Hide from ptrace
- **Unshared Memory / JIT Execution:** `bokuei-agent` monitors system calls (`execve`, `openat`, `socket`, `connect`). An application executing dynamic code from encrypted in-memory buffers or JIT-compiled instructions without invoking file or process syscalls leaves no syscall-level evidence of its internal logic.
- **Shared Memory Communication (shm / IPC):** Processes communicating via POSIX shared memory (`shm_open`) or memory-mapped files without file descriptors during steady state can transfer state unobserved by point-in-time file I/O tracing.
- **Side Channels & Direct Hardware IO:** Memory bus timing, GPU DMA operations bypassing host kernel wrappers, and direct port I/O on privileged hardware cannot be observed by userspace ptrace tracing.
- **ptrace Evasion:** Applications with anti-debugging logic, `PTRACE_TRACEME` collisions, or processes running with setuid root privileges outside the user's ptrace capability will block tracing. Bokuei explicitly detects this condition and records a `coverage.blocked` claim, stating that dependents and child processes are **not visible**.

### 2.2 Polling-Mode Fallback Blind Spots
- When ptrace is unavailable (e.g. strict seccomp, Yama `ptrace_scope > 1`, or missing capabilities), `bokuei-agent` falls back to `/proc` polling mode.
- **Ephemeral Processes:** Short-lived subprocesses executing faster than the polling frequency (e.g., < 20ms) may exit unobserved.
- **In-flight File Access:** Reading and closing a file between procfs scan intervals will not appear in `/proc/[pid]/fd`. Bokuei explicitly refuses to fabricate file claims from polling mode and marks file I/O as **not visible**.

---

## 3. Secret-Leakage Prevention & Redaction

### 3.1 Environment Variable Handling
- Linux `/proc/[pid]/environ` can expose credentials, database passwords, and API tokens.
- **Defense-in-depth:**
  - `bokuei-agent` maintains an explicit allowlist of safe metadata variables (e.g., `PATH`, `PYTHONHASHSEED`, `CUDA_VISIBLE_DEVICES`, `OMP_NUM_THREADS`).
  - Known credential names (`TOKEN`, `KEY`, `SECRET`, `PASSWORD`, `AUTH`, `PASSWD`) are never recorded in plain text.
  - Salted hashes (`sha256(salt + value)`) are computed for change-detection without persisting the plaintext secret.

### 3.2 Command Arguments Redaction
- Command arguments frequently contain inline secrets (`--token=<secret>`).
- By default, argument recording redacts parameters matching key/password patterns unless `--record-args` is explicitly provided by the operator.

---

## 4. Cryptographic Trust and Batch Federation

### 4.1 Append-Only Immutability
- Both the main ledger (`bokuei.db`) and the federation registry (`registry.db`) enforce append-only semantics using SQLite BEFORE UPDATE and BEFORE DELETE triggers.
- In-place modifications to recorded claims or batch envelopes are rejected at the database engine level.

### 4.2 Signature Trust and Chain Continuity
- Export batches are signed using Ed25519 keys (`bokuei.key` saved with POSIX permissions `0600`).
- Batch hashes link cryptographically to the prior batch: $\text{hash} = \text{sha256}(\text{prev\_hash} \parallel \text{canonical\_claims})$.
- **Import Rules:**
  - Tampered claims or corrupted signatures are rejected with `TAMPERED_BATCH_REJECTED`.
  - Replayed sequence numbers are treated as idempotent no-ops (0 inserted).
  - Skipped sequence numbers are rejected with `SEQUENCE_GAP_REJECTED`.
  - Public keys not listed in `--trust KEYFILE` are blocked unless the operator explicitly passes `--allow-untrusted`, and untrusted signers are prominently labeled in all outputs and UI views.

---

## 5. Declarative Plugins Safety Invariant

- Plugins in `plugins/*.toml` are strictly data-only schemas.
- The parser rejects any unknown directive or code-execution primitives (`exec`, `eval`, `script`, `url`, `network`).
- Declared directory roots are validated against path traversal (`..`); any attempt to read outside declared project roots triggers immediate termination.
