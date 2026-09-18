# JVC (Judicial Verification Core)

> **Status:** pre-release candidate (0.1.0). No public repository, license selection, or security reporting channel has been established yet.

**JVC** is a local policy-controlled routing and execution layer for agent workflows operating across multiple projects.

It makes project selection, allowed operations, declared checks, file mutation, Git mutation, recovery, and resumable state explicit and auditable.

---

## Why JVC?

When autonomous AI coding agents interact with local repositories, typical tool execution lacks boundary control:
- Agents can wander into unrelated repositories or private directories.
- Stale or concurrent file writes can overwrite human edits silently.
- Ambient Git configurations and malicious hooks can trigger arbitrary execution.
- Broad `git diff` operations can accidentally expose local secrets or protected files.
- Failures leave worktrees in dirty, unrecoverable states without proven rollbacks.

JVC addresses these challenges by introducing a **deterministic governance layer** between tool-calling agents and the underlying filesystem and Git runtime.

> [!NOTE]
> JVC is **not** an operating-system level sandbox against arbitrary processes that already possess unrestricted shell or filesystem access. Its guarantees apply to actions mediated through its governed interface and host-owned trust policies.

---

## Core Features (v0.1.0)

1. **Deterministic Project Routing:** Lexical, word-boundary alias matching with explicit rejection of unknown and ambiguous requests.
2. **Execution Contracts:** Declarative contracts embedded in `AGENTS.md` specifying working directories, persistence modes, runtimes, and declared checks.
3. **Declared Preflight & Verification Checks:** Pinned subprocess commands validating project environment and behavioral assertions with exit code and output criteria.
4. **Project-Root Containment:** Strict boundary validation preventing path traversal (`../`), encoded aliases, and symlink/reparse point escapes.
5. **Protected Control Surfaces:** Host-owned surfaces (`.git/`, `.continuity/`, `_config/`, `contracts/`, `_promotions/`, `.gitattributes`) cannot be modified by unprivileged model operations.
6. **Lock-Serialized Preimage Checks:** Every write validates that the target file's current SHA-256 matches the expected preimage under a per-target interprocess lock, so concurrent writers serialize instead of overwriting one another.
7. **Backup-First Recovery & Write-Ahead Journal:** Pre-write snapshots are preserved in an isolated recovery store with a durable transaction journal (`PREPARED` → `APPLIED` → `VERIFIED`), enabling verified rollback and deterministic restart recovery.
8. **Bounded Git Operations:** Governed `status`, file-scoped `diff`, `log`, exact-file `stage`, owned `commit`, and safe `branch` operations with explicit helper/executable-filter policy. Repository-wide diff is not available in 0.1.0.
9. **Resumable Continuity State:** Lock-serialized revision control for project state, decision records, checkpoints, and handoff integrity tracking.
10. **Host-Owned Trust Anchors:** Cryptographic HMAC capability tokens with single-use nonces (within one configured trust store) and expiration timestamps for gated administrative actions. Trust stores live outside governed roots.

---

## Quickstart

### Installation

```bash
pip install .
```

### 1. Verify Project Routing

```bash
jvc route "fix button on web client" --registry references/PROJECT_ROUTES.md
```

### 2. Declared Checks (Trusted Host API)

Declared preflight/verify checks execute only through the trusted pinned manifest path (`GovernedExecutor.run_declared_check`), never from project-owned `AGENTS.md` content. The `jvc check` command is intentionally deferred from 0.1.0 for this reason.

### 3. Run Synthetic Demo

JVC includes a self-contained 15-step demonstration verifying all core invariants:

```bash
jvc demo
```

---

## Architecture Overview

```
                          Natural Language Request
                                    │
                                    ▼
                          ┌──────────────────┐
                          │ Deterministic    │
                          │ Project Routing  │
                          └─────────┬────────┘
                                    │
                                    ▼
                         ┌────────────────────┐
                         │ Execution Contract │
                         │ & Declared Checks  │
                         └──────────┬─────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
         ┌─────────────────────┐         ┌─────────────────────┐
         │ Filesystem Boundary │         │ Bounded Git Ops     │
         │ - Root Containment  │         │ - Exact Staging     │
         │ - Secret Denial     │         │ - Owned Commits     │
         │ - Preimage CAS      │         │ - Sanitized Hooks   │
         │ - Atomic Replace    │         │ - Branch Guards     │
         └──────────┬──────────┘         └─────────────────────┘
                    │
                    ▼
         ┌─────────────────────┐
         │ Backup-First Store  │
         │ & Durable Rollback  │
         └─────────────────────┘
```

For complete architecture details, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Security Model

JVC operates under a clear separation between **Trusted Host/Operator** and **Untrusted Agent**:
- **Trusted Operator:** Defines routes, sets policy, provisions the HMAC secret key, and approves privileged operations.
- **Untrusted Agent:** Executes within project roots, subjected to boundary checks, CAS preimage validation, and restricted Git access.

For full security policy and threat model documentation, see [SECURITY.md](SECURITY.md) and [docs/security-model.md](docs/security-model.md).

---

## Documentation

- [Quickstart Guide](docs/quickstart.md)
- [Configuration Reference](docs/configuration.md)
- [Security Model & Threat Boundary](docs/security-model.md)
- [Operator Capabilities](docs/capabilities.md)
- [Recovery & Rollback Subsystem](docs/recovery.md)
- [Releasing & Packaging](docs/releasing.md)
- [Licensing Review](docs/licensing-review.md)
