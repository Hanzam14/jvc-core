# Recovery & Rollback Subsystem

The recovery subsystem records every governed mutation in a durable write-ahead journal backed by verified backup preimages, allowing reliable, deterministic rollbacks and restart recovery.

---

## 1. Preimage Capture & Journal

Before modifying any file on disk, under the per-target interprocess lock:
1. If the file exists, its bytes are durably copied (flush + file fsync; parent-directory sync best-effort where supported) to the recovery store as:
   `recovery-<project_id>-<timestamp>-<nonce>.bak`
2. A transaction receipt is atomically written as:
   `recovery-<project_id>-<timestamp>-<nonce>.json`
   with state `PREPARED`, containing:
   - `receipt_id`
   - `project_id`
   - `path` (canonical absolute path)
   - `preimage_sha256`
   - `preimage_exists` (boolean)
3. After atomic target replacement, the receipt advances to `APPLIED` with `postimage_sha256`, then to `VERIFIED` once the on-disk target is re-read and confirmed.

---

## 2. Restart Recovery

`GovernedExecutor` runs `RecoveryStore.recover()` at startup (also available manually via `executor.recover()`). Incomplete transactions reconcile under the target's interprocess lock on freshly reread receipt state (a live writer holding the lock causes deferral, never a stale-data verdict). Outcomes:

| Restart observation | Outcome |
| --- | --- |
| `PREPARED`, target still matches preimage (or still absent for creates) | `RECOVERED_UNAPPLIED`: mutation never applied; backup retained |
| `APPLIED`, target matches recorded postimage | Finalized to `VERIFIED` |
| `PREPARED` with diverged target, `APPLIED` with mismatched target, unreadable/corrupt receipt, missing/corrupt backup | `RECOVERY_REQUIRED`: fail closed; operator decision required; nothing silently resolved or clobbered |
| Lock held by a live writer | `deferred`: retried on a later run; never mismarked |

A `RECOVERY_REQUIRED` receipt blocks fresh mutation of its target (rollback remains available as the resolution path). Any corrupt receipt file blocks all mutation through the store until repaired. Rollback itself is journaled (`ROLLBACK` receipts) with the source persisted as `ROLLED_BACK`; a crash between the two terminal writes completes idempotently on restart.

---

## 3. Durable Rollback Mechanics

To rollback a file:
```python
executor.fs_rollback(project_id, relative_path, expected_postimage_sha256)
```

Rollback enforces strict invariants:
1. **Postimage Match:** Verifies that the file on disk currently matches `expected_postimage_sha256`. If someone has made newer edits since the write, rollback fails closed to prevent clobbering newer work.
2. **Pending intents settled first:** orphaned `PREPARED` intents reconciled against the current target — safely unapplied ones become terminal `SUPERSEDED` (they can never apply once rollback moves the target); a `PREPARED` receipt whose preimage no longer matches (replacement happened but was never journaled) becomes `RECOVERY_REQUIRED` and denies the rollback. A matching `APPLIED` receipt finalizes to `VERIFIED`; an `APPLIED` receipt matching nothing on disk, or an unresolvable rollback transaction, denies the rollback fail-closed.
3. **Backup Hash Integrity:** Verifies that the backup file in the recovery store matches the recorded `preimage_sha256`.
4. **Atomic Replacement:**
   - Writes backup data to a temporary file (`.filename.<uuid>.rollback`) in the target directory.
   - Flushes buffers and calls `os.fsync()`.
   - Replaces the target using `os.replace()` and best-effort fsyncs the parent directory where supported.
5. **Deleted File Handling:** If the original file was created (preimage did not exist), rollback safely unlinks the file.
---

## 4. Retention & Pruning

Recovery artifacts are retained for 30 days by default. Old receipts and backups can be pruned:
```python
store.prune(retention_days=30)
```
