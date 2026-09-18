# JVC Architecture Specification

This document details the architectural layers, invariants, and data flows of the Judicial Verification Core (JVC).

---

## 1. Architectural Layers

JVC is structured into six clean, decoupled subsystems:

```
src/jvc/
├── configuration.py   # Registry schemas, Route dataclasses, Policy definitions
├── routing.py         # Deterministic lexical router & query matching
├── contracts.py       # ICM execution contracts & declared check definitions
├── policy/            # Governance, boundaries, prewrite guards & authority
│   ├── boundaries.py  # Path normalization, containment, secret & control plane rules
│   ├── guard.py       # Prewrite lifecycle (proposed -> approved -> applied -> verified)
│   ├── locks.py       # Interprocess per-resource locks (msvcrt/flock, fail-closed)
│   └── authority.py   # HMAC capability signing, durable nonces, trust provisioning
├── execution/         # Governed execution & runner engine
│   ├── runner.py      # Environment sanitization & pinned check execution
│   └── executor.py    # GovernedExecutor: locked CAS writes, journal, bounded Git
├── recovery/          # Backup-first recovery subsystem
│   └── store.py       # Preimage backups, write-ahead journal, durable rollback
└── continuity/        # Project continuity & state management
    └── state.py       # State store, lock-serialized revisioning, handoffs
```

> NOTE (0.1.0 scope): the HTTP/JSON-RPC server (`serve`) is intentionally
> deferred and excluded from this release. There is no network-facing
> interface; the governed interface is `GovernedExecutor` and the CLI.

---

## 2. Core Subsystem Responsibilities

### A. Routing & Project Registry (`routing.py`, `configuration.py`)
- **Project Registry:** Maintained via Markdown table or JSON manifest. Enforces uniqueness of project IDs, root paths, and alias sets.
- **Deterministic Routing:** Uses tokenized, word-boundary lexical matching.
- **Rejection Logic:**
  - `UNKNOWN`: No aliases matched. No context is loaded.
  - `AMBIGUOUS`: Multiple projects matched without explicit conjunction markers (`and`, `both`, `with`, `across`). Context loading is rejected.
  - `MULTI_ROUTE`: Explicit multi-project intent detected. Both routes returned with instructions to maintain separation.
  - `ROUTED`: Exactly one project matched.

### B. Execution Contracts (`contracts.py`)
- Standardized execution parameters embedded directly in each project's `AGENTS.md` inside `<!-- ICM_EXECUTION_START -->` blocks.
- Declares working directory (`cwd`), persistence mode (`git`, `onedrive`, `local`), capability privacy class, runtime probe, preflight check, and verify check.

### C. Policy & Boundary Enforcement (`policy/`)
- **Root Containment:** Every path target is normalized and checked against `Path.resolve().relative_to(root.resolve())`. Traversal sequences (`../`), encoded forms (`%2e%2e`), absolute drives, and control characters are rejected immediately.
- **Secret Denial:** Denies access to files matching secret patterns (`.env`, `credentials.*`, `secret.*`, `token.*`, `auth.*`, `*.pem`, `*.key`, `*.ppk`, `*.p12`, `*.pfx`, `id_rsa`) regardless of caller intent.
- **Control-Plane Surface:** Protects sensitive management files (`.git/`, `.continuity/`, `_config/`, `contracts/`, `_promotions/`, `.gitattributes`). Model operations attempting to mutate these files without valid HMAC operator capabilities are rejected with `PermissionError`.
- **Interprocess Locks:** Per-target OS file locks (`policy/locks.py`) serialize the read/validate/mutate critical section across processes. The lock directory is host-owned outside all governed roots; locking failures fail closed (never silently unlocked).
- **Operator Authority:** Privileged actions require an HMAC-SHA256 capability signed with a host-owned secret. Nonces are consumed with exclusive file creation plus flush/fsync before the privileged action executes, giving single-use within one configured trust store on the local host.

### D. Governed Mutation & Recovery (`execution/executor.py`, `recovery/store.py`)
- **Lock-Serialized Preimage Checks:** If a target file exists, the caller must supply `expected_preimage_sha256`. Under the per-target interprocess lock, the executor verifies `SHA256(current_file_bytes) == expected_preimage_sha256`; concurrent writers presenting the same preimage serialize so exactly one succeeds.
- **Write-Ahead Journal:** Before mutating, a durable `PREPARED` transaction record (backup + metadata, atomic replacement, fsync) is persisted. After atomic target replacement the journal advances `APPLIED` then `VERIFIED`. `RecoveryStore.recover()` reconciles interrupted transactions on startup (`RECOVERED_UNAPPLIED` or fail-closed `RECOVERY_REQUIRED`).
- **Preimage Backup:** Before any file modification, the exact bytes are stored in the recovery store as `recovery-<project_id>-<timestamp>-<nonce>.bak` along with a JSON receipt.
- **Durable Write:** Data is written to a temporary file in the target directory, flushed, synced to disk with `os.fsync()`, atomically replaced via `os.replace()`, with best-effort parent-directory durability where supported.
- **Durable Rollback:** Restores previous content from the recovery store using the same atomic temp-file and fsync pattern, after verifying backup hash integrity and current postimage match.

### E. Bounded Git Operations (`execution/executor.py`)
- **Bounded Diff (files only):** `git_diff` requires one or more explicitly listed exact files. Repository-wide diff is not available in 0.1.0; directories are rejected so protected descendants cannot leak through expansion. Output is byte-bounded (`truncated` flag).
- **Safe Git Invocation:** Subprocesses run with a sanitized environment (`GIT_CONFIG_NOSYSTEM=1`, global/system config pinned empty, `GIT_TERMINAL_PROMPT=0`) and `-c core.hooksPath=""`, neutralizing ambient hooks. Repository-local executable helpers are controlled explicitly: diff uses `--no-textconv --no-ext-diff` plus per-path attribute checks; mutations (stage/commit/branch) reject repos whose local config or `.gitattributes` select clean/smudge/process/textconv/external-diff helpers.
- **Exact-File Staging:** Staging requires explicit relative file lists. Directories and wildcards are rejected; each path is additionally validated against Git index/HEAD state so deleted tracked directories cannot expand recursively.
- **Owned Commits:** Commits succeed only when the staged index matches the caller's session-owned files, preventing accidental commits of unrelated files.

### F. Continuity & Resumable State (`continuity/state.py`)
- Tracks project progress in `.continuity/state.json` with an integer `metadata_revision`.
- Every checkpoint, handoff reconciliation, or decision verifies the previous revision and handoff SHA-256 under a per-state interprocess lock before advancing, so concurrent updaters serialize and losers receive revision conflicts.
