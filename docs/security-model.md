# Security Model & Threat Boundary

This document defines the trust boundaries, threat model, guarantees, and explicit limitations of JVC.

---

## 1. Threat Assumptions

JVC operates under a two-plane security architecture:

### A. Trusted Host / Operator Plane
- **Entity:** The human system administrator or privileged host process.
- **Authority:** Controls the machine environment, Python virtual environment, host operating system, and provisions the 256-bit HMAC secret key.
- **Capabilities:** Authorizes privileged control-plane modifications and registers new project routes.
- **Owns:** The recovery store, the capability trust (confirmation) store, and the interprocess lock directory. All three MUST resolve outside every governed project root; the executor refuses to start otherwise.

### B. Untrusted / Lower-Trust Agent Plane
- **Entity:** AI coding agents, external tool runners, model-facing APIs.
- **Authority:** Constrained strictly to registered project repositories.
- **Capabilities:** Read authorized code, perform lock-serialized preimage-checked writes to permitted files, stage exact owned files, and run declared preflights.
- **Constraints:** Cannot bypass root containment, cannot access secret-bearing patterns, cannot mutate control-plane files, cannot reach host-owned trust/recovery/lock stores, and cannot inject arbitrary shell commands.

---

## 2. Core Security Invariants

### 1. Canonical Root Containment
All file operations are resolved to absolute canonical paths and validated via:
`candidate.resolve().relative_to(root.resolve())`
Any path with parent traversal (`../`), encoded forms (`%2e%2e`), Windows volume specifiers, or control characters is rejected with `ValueError` before any I/O occurs.

### 2. Mandatory Secret Denial
Files matching credential patterns (`.env`, `credentials.*`, `secret.*`, `token.*`, `auth.*`, `id_rsa`, `*.pem`, `*.key`, `*.ppk`, `*.p12`, `*.pfx`) are blocked from read, write, staging, and diff operations.

### 3. Lock-Serialized Preimage Checks (Not Lock-Free CAS)
To prevent lost updates or concurrent write collisions:
- For existing files, the caller must specify `expected_preimage_sha256`.
- Under a per-target **interprocess** OS file lock, the executor verifies `SHA256(current_file_bytes) == expected_preimage_sha256`.
- Two processes presenting the same preimage serialize: exactly one succeeds; the other observes a stale/conflict failure.
- If no supported locking primitive exists, the operation fails closed instead of writing unlocked.
- The same pattern serializes continuity revision updates (losers receive revision conflicts).

### 4. Safe Git Invocation (Explicit Helper Policy)
When running Git commands:
- `core.hooksPath=""` is explicitly passed, preventing malicious scripts in `.git/hooks/` from executing.
- Ambient environment variables (`GIT_DIR`, `GIT_WORK_TREE`, `GIT_EXTERNAL_DIFF`, etc.) are stripped; system/global Git config layers are pinned empty and `GIT_TERMINAL_PROMPT=0` is set.
- These measures alone do NOT neutralize repository-local helpers, so JVC additionally enforces:
  - **Diff (read-only):** `--no-textconv --no-ext-diff` plus per-path rejection of attribute-selected filter/diff drivers.
  - **Mutations (stage/commit/branch):** repository-local config defining includes, clean/smudge/process filters, textconv, external diff, fsmonitor, or custom attributes files is rejected; `.gitattributes` files selecting executable helpers are rejected.
  - **`.gitattributes` is a protected control-plane surface:** ordinary governed writes cannot create or modify it.

### 5. Bounded Git Inspection (Not a Confidentiality Scanner)
- `git diff` accepts only explicitly listed exact files. Repository-wide diff is not available in 0.1.0 and directories are rejected, so protected descendants cannot leak through directory expansion.
- Every Git read surface (`diff`, `status`, `log`) enforces an explicit byte bound and reports `truncated: true` instead of returning unbounded content.

### 6. Line-Ending Determinism
JVC pins the system/global Git configuration layers empty, which also disables ambient system `core.autocrlf`. Repositories that rely on ambient system-level line-ending conversion may show phantom dirty entries under JVC inspection. Governed repositories should set `core.autocrlf` (or `core.eol` / `.gitattributes` text rules) explicitly in their own configuration.

### 6. Capability Single-Use Within One Trust Store
- The consumed-nonce record is flushed and fsynced BEFORE the privileged action executes (exclusive creation still decides the single winner among concurrent consumers).
- The guarantee holds **within one configured trust store on the local host**. Separate or restored stores do not share state; installation-wide single-use across arbitrary stores is NOT claimed.

---

## 3. Explicit Limitations

> [!WARNING]
> JVC is **not** an operating system hypervisor or process sandbox. If an external process runs arbitrary commands directly through a shell with existing user-level OS privileges, JVC cannot prevent it.
>
> JVC's guarantees apply to operations mediated through its governed interface (`GovernedExecutor` and CLI). There is no network-facing interface in 0.1.0 (the HTTP server is deferred).
>
> JVC does not claim cross-machine atomic compare-and-swap, universal installation-wide replay prevention, or secret detection beyond its explicit filename/pattern denylist.
