# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-09-18

### Added
- **Project Registry & Deterministic Routing:**
  - Route parsing from Markdown tables and JSON registry definitions.
  - Lexical token matching with word-boundary checks.
  - Fail-closed unknown-route and ambiguous-route rejection.
  - Multi-route resolution when explicit conjunction markers are present.
- **Execution Contracts:**
  - Standardized JSON contract embedding within `AGENTS.md`.
  - Declared preflight and verification check runner with runtime probing.
  - Cryptographic script pinning and integrity drift detection.
- **Filesystem Governance & Containment:**
  - Strict project-root containment with path traversal, URL-encoding, and control-character rejection.
  - Secret path classification (`.env`, `credentials.*`, `*.key`, `*.pem`, etc.).
  - Protected control-plane surfaces (`.git/`, `.continuity/`, `_config/`).
- **Governed Mutation & Preimage Checks:**
  - Fail-closed expected-preimage validation before write operations.
  - Per-target interprocess locks serialize concurrent writers (exactly one winner per preimage); locking failures fail closed.
  - Atomic temporary file creation with explicit flush and `fsync` before `os.replace`, plus parent-directory durability.
- **Backup-First Recovery Store:**
  - Automatic task-scoped preimage capture before mutation.
  - Write-ahead transaction journal (`PREPARED` → `APPLIED` → `VERIFIED`) with deterministic restart recovery (`RECOVERED_UNAPPLIED` or fail-closed `RECOVERY_REQUIRED`).
  - Durable rollback mechanism with atomic replacement and post-restoration verification.
  - Stale postimage detection preventing overwrites of intervening human work.
- **Bounded Git Operations:**
  - Controlled `status`, file-scoped `diff` (explicit paths only, byte-bounded; no repository-wide diff), `log`, exact-file `stage`, owned `commit`, and safe `branch` operations.
  - Explicit repository-helper policy: ambient hooks neutralized, `--no-textconv`/`--no-ext-diff` for diff, fail-closed rejection of local filter/textconv/external-diff/include configuration for mutations, `.gitattributes` protected as control plane.
- **Continuity & Resumable State:**
  - Lock-serialized revision control via metadata revision numbers.
  - Handoff integrity verification with SHA-256 validation.
  - Decision records and checkpoint tracking.
- **Operator Authority & Capability Provisioning:**
  - Host-owned HMAC-SHA256 capability signing.
  - Durable single-use nonce consumption (exclusive creation + fsync before action) within one configured trust store, plus expiration protection.
  - Trust/recovery stores required outside governed roots; key provisioning refuses unsafe placement and silent overwrite (explicit rotation path).
  - Pinned trusted executable identities.
- **Synthetic 15-Step End-to-End Demo:**
  - Fully self-contained local demonstration verifying all core invariants.
- **CLI:**
  - Consolidated `jvc` command-line utility (`route`, `validate-routes`, `check`, `demo`).

### Deferred from 0.1.0
- **HTTP/JSON-RPC server (`jvc serve`):** removed from the public 0.1.0 interface to avoid shipping a network attack surface. No network-facing code ships in this release.
- **CLI project-owned checks (`jvc check`):** removed from the public 0.1.0 interface. Project-controlled `AGENTS.md` content must not grant executable authority; declared checks run only through the trusted pinned manifest path (`GovernedExecutor.run_declared_check`).

### Hardening (second independent review)
- **Effective Git configuration audit:** all Git operations (reads and mutations) reject repository-controlled executable/redirection configuration (includes, filters, textconv, external diff, fsmonitor, signing programs, worktree redirection) with origin-aware inspection; inspection failures fail closed; signing neutralized by override flags; branch switches validate touched paths; mutations serialized under a per-project lock.
- **Canonical lock identity:** locks derive from normalized absolute resource identity (case/separator/drive folding, symlink resolution); continuity init/decision/reconcile semantics tightened (`record_decision` advances revision and validates IDs; `reconcile_handoff` enforces the recorded handoff); UNC device paths explicitly rejected.
- **Recovery gate + rollback journal:** recovery reconciles under resource locks (defers on live writers); `RECOVERY_REQUIRED` blocks fresh mutation; receipts schema-validated (missing `tx_state` never defaults to verified); backups verified at recovery; rollback journaled with persisted `ROLLED_BACK`; pruning protects unresolved transactions; `seq`-ordered receipts with collision-safe IDs.
- **Replay persistence:** nonce fsync failure denies authorization (no swallowed durability errors); directory sync documented as best-effort with observable outcomes.
- **Bounded Git reads:** index-level exact-file validation (deleted-directory pathspecs rejected); byte-exact UTF-8-safe bounds on stdout and stderr; negative bounds rejected; bounded streaming reads.
- **Trust provisioning:** placement context required; atomic rotation preserving the old key on interruption; key length/format validation; observable Windows ACL outcomes (warning policy); documented `JVC_OPERATOR_SECRET_HEX` environment protocol.
- **API separation:** `docs/public-api.md` defines model-facing vs host-only surfaces; decision IDs and guard output paths validated.
- **Release evidence:** explicit `MANIFEST.in` sdist policy; acceptance harness audits member contents of both archives, verifies build-output purges, enforces fresh environments, rebuilds the wheel from the sdist for parity, and uses canonical path comparisons.

### Hardening (third independent review)
- **Recovery correctness:** completed rollbacks no longer flagged on reopen (backup audit scoped to write receipts; rollback sources completed idempotently); all recovery decisions made under the target lock on freshly reread receipts (no stale-data overwrite); corrupt journal files block mutation store-wide until repaired.
- **HELD authorization:** single canonical capability payload shared by proposal and validation (full proposal → signature → write round trip tested).
- **Staging boundary:** index-level exact-file validation applied to `git add` paths (deleted-directory expansion rejected).
- **Canonical locks:** identity resolves symlinks/junctions before normalization (shared continuity state through aliases shares one lock).
- **Packaging:** explicit `prune tests`/`prune scripts` exclusions; sdist-to-wheel parity compares file contents, not just names.

### Hardening (fourth independent review)
- **Rollback gate:** corruption denies rollback before any journal mutation, at both executor and store level.
- **Incomplete transactions:** writers reconcile-or-deny PREPARED/APPLIED receipts for their target under their own lock before fresh mutation (no reliance on a prior recover() run).
- **Rollback selection:** chain-linked `prev_receipt_id` head selection replaces wall-clock ordering (backward-clock safe; successive A → B → C → B rolls back to C).
- **Recovery robustness:** non-object JSON receipts reported without crashing the scan.

### Hardening (fifth independent review)
- **State-aware chain selection:** only `APPLIED`/`VERIFIED` pointers count toward head exclusion — unapplied (`PREPARED`/`RECOVERED_UNAPPLIED`) and undone (`ROLLED_BACK`) successors never steal head status; `RECOVERY_REQUIRED` pointers and zero/multi-head ambiguity raise instead of falling back to timestamps.

### Hardening (sixth independent review)
- **Rollback retires pending intents:** orphaned `PREPARED` receipts reconciled against the current target first — safely unapplied ones become terminal `SUPERSEDED` (never applied, can never apply, never block); a `PREPARED` receipt whose preimage no longer matches (crash between replace and journaling) becomes `RECOVERY_REQUIRED` and denies the rollback; matching `APPLIED` finalizes; diverged `APPLIED` denies fail-closed. A completed rollback no longer causes false recovery blocking on the next write or recovery run.
