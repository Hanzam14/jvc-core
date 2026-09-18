"""Backup-first recovery store, preimage preservation, and durable rollback.

Write-ahead transaction model (0.1.0):

    PREPARED  - backup bytes durably persisted, target not yet mutated
    APPLIED   - target atomically replaced, postimage recorded, not yet verified
    VERIFIED  - postimage verified against the on-disk target
    RECOVERED_UNAPPLIED - restart found a PREPARED transaction whose target
        still matches the preimage (mutation never applied); backup retained
    RECOVERY_REQUIRED   - restart found an incomplete transaction whose
        on-disk state cannot be reconciled; human/operator decision required

``RecoveryStore.recover()`` must be called on startup (the governed executor
does this automatically) to reconcile transactions interrupted by crashes.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import secrets
import tempfile
import time
from pathlib import Path
from typing import Any

RETENTION_DAYS = 30
MAX_BACKUP_BYTES = 50 * 1024 * 1024


class RecoveryError(ValueError):
    """Raised when recovery validation or rollback fails."""


class RecoveryRequiredError(RecoveryError):
    """Raised when restart recovery finds an unreconcilable transaction."""


class InjectedFailure(RuntimeError):
    """Test-only failure injected at a journal boundary."""


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest().upper()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def durable_replace(src: Path, dst: Path, attempts: int = 4) -> None:
    """Atomically replace ``dst`` with ``src``, tolerating transient sharing violations.

    On Windows, brief external interference (antivirus/indexer handles on a
    fresh file) can surface as ``PermissionError`` from ``os.replace`` even
    when the caller holds the governing interprocess lock. Retry a bounded
    number of times with small sleeps; a persistently held handle still
    raises. Must only be called while holding the resource lock so concurrent
    JVC writers cannot interleave.
    """
    last: OSError | None = None
    for attempt in range(max(1, attempts)):
        try:
            os.replace(src, dst)
            return
        except PermissionError as exc:
            last = exc
            if attempt + 1 >= max(1, attempts):
                raise
            time.sleep(0.05)
    if last is not None:  # pragma: no cover - defensive
        raise last


def fsync_dir(directory: Path) -> None:
    """Best-effort parent-directory durability (no-op where unsupported)."""
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        try:
            os.fsync(fd)
        except OSError:
            pass
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def durable_write_bytes(path: Path, data: bytes) -> None:
    """Write bytes durably: flush + fsync + parent-directory fsync."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_raw = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temp_path = Path(temp_raw)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        durable_replace(temp_path, path)
        fsync_dir(path.parent)
    finally:
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)


def atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    """Atomically and durably replace a JSON metadata document."""
    payload = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")
    durable_write_bytes(path, payload)


class RecoveryStore:
    """Manages pre-write backup images and deterministic rollbacks."""

    #: Terminal journal states: safe to prune after retention, safe to ignore.
    TERMINAL_STATES = frozenset(
        {"VERIFIED", "RECOVERED_UNAPPLIED", "ROLLED_BACK", "SUPERSEDED"}
    )
    #: Incomplete states: reconciled under the resource lock on recovery.
    INCOMPLETE_STATES = frozenset({"PREPARED", "APPLIED"})
    #: States blocking fresh mutation of the affected resource.
    BLOCKING_STATES = frozenset({"RECOVERY_REQUIRED"})
    #: All known states; anything else (including missing) is invalid.
    #: SUPERSEDED marks a pending intent overtaken by a governed rollback:
    #: it never applied, can never apply (its preimage is gone by legitimate
    #: action, not by crash), and never blocks.
    KNOWN_STATES = frozenset(
        {"PREPARED", "APPLIED", "VERIFIED", "RECOVERED_UNAPPLIED",
         "RECOVERY_REQUIRED", "ROLLED_BACK", "SUPERSEDED"}
    )

    def __init__(
        self,
        root: Path,
        failure_points: set[str] | None = None,
    ) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        # Test-only fault injection at journal boundaries. Recognized points:
        # "after_backup", "after_target_write", "during_finalize",
        # "rollback_before_terminal".
        self.failure_points: set[str] = set(failure_points or set())

    def _failpoint(self, name: str) -> None:
        if name in self.failure_points:
            raise InjectedFailure(f"injected failure at journal boundary: {name}")

    def _new_receipt_id(self, project_id: str, kind: str = "recovery") -> str:
        """Generate a collision-safe receipt ID (exclusive, with sequence)."""
        for _ in range(100):
            rid = (
                f"{kind}-{project_id}-"
                f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-"
                f"{time.time_ns() % 1_000_000_000:09d}-"
                f"{secrets.token_hex(6)}"
            )
            if not (self.root / f"{rid}.json").exists() and not (
                self.root / f"{rid}.bak"
            ).exists():
                return rid
        raise RecoveryError("could not allocate a collision-free receipt ID")

    @staticmethod
    def validate_receipt(data: Any) -> dict[str, Any]:
        """Validate receipt schema; fail closed on anything unexpected.

        Missing ``tx_state`` is INVALID (never defaults to VERIFIED).
        """
        if not isinstance(data, dict):
            raise RecoveryError("receipt must be a JSON object")
        for key in ("receipt_id", "project_id", "path", "original_operation"):
            if not isinstance(data.get(key), str) or not data[key]:
                raise RecoveryError(f"receipt missing/invalid {key!r}")
        if data["original_operation"] not in {"FS_WRITE", "ROLLBACK"}:
            raise RecoveryError(
                f"unknown original_operation: {data['original_operation']!r}"
            )
        if not isinstance(data.get("preimage_exists"), bool):
            raise RecoveryError("receipt missing/invalid 'preimage_exists'")
        tx_state = data.get("tx_state")
        if tx_state not in RecoveryStore.KNOWN_STATES:
            raise RecoveryError(f"receipt missing/unknown tx_state: {tx_state!r}")
        return data

    def save_preimage(
        self,
        project_id: str,
        target: Path,
        content: bytes | None,
    ) -> dict[str, Any]:
        """Save preimage bytes before mutation and return receipt metadata.

        Creates a durable PREPARED transaction record BEFORE the target is
        mutated, so a crash at any later point is detectable on restart.
        """
        rid = self._new_receipt_id(project_id)
        backup_file: Path | None = None
        if content is not None:
            if len(content) > MAX_BACKUP_BYTES:
                raise RecoveryError(f"file exceeds max backup limit: {len(content)} bytes")
            backup_file = self.root / f"{rid}.bak"
            durable_write_bytes(backup_file, content)
            # Verify backup integrity immediately
            if sha256_file(backup_file) != sha256_bytes(content):
                raise RecoveryError("backup verification failed immediately after write")

        receipt = {
            "receipt_id": rid,
            "project_id": project_id,
            "path": str(target.resolve()),
            "original_operation": "FS_WRITE",
            # Chain link for clock-independent rollback selection: the
            # VERIFIED receipt this write supersedes (exact postimage match),
            # or the latest terminal receipt for a create, or null.
            "prev_receipt_id": self._find_superseded_id(
                project_id, str(target.resolve()), content
            ),
            "preimage_exists": content is not None,
            "preimage_sha256": sha256_bytes(content) if content is not None else None,
            "postimage_sha256": None,
            "backup_file": str(backup_file) if backup_file else None,
            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "seq": time.time_ns(),
            "tx_state": "PREPARED",
        }
        receipt_path = self.root / f"{rid}.json"
        atomic_write_json(receipt_path, receipt)
        self._failpoint("after_backup")
        return receipt

    def note_target_replaced(self, receipt_id: str, post_sha256: str) -> None:
        """Transition PREPARED -> APPLIED after the target was replaced."""
        receipt_path = self.root / f"{receipt_id}.json"
        if not receipt_path.is_file():
            raise RecoveryError(f"recovery receipt missing: {receipt_id}")
        try:
            data = json.loads(receipt_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RecoveryError(f"recovery receipt unreadable: {receipt_id}: {exc}") from exc
        if data.get("tx_state") != "PREPARED":
            raise RecoveryError(
                f"unexpected transaction state on {receipt_id}: {data.get('tx_state')}"
            )
        data["postimage_sha256"] = post_sha256.upper()
        data["tx_state"] = "APPLIED"
        atomic_write_json(receipt_path, data)

    def record_postimage(self, receipt_id: str, post_sha256: str) -> None:
        """Verify the on-disk target and transition APPLIED -> VERIFIED."""
        receipt_path = self.root / f"{receipt_id}.json"
        if not receipt_path.is_file():
            raise RecoveryError(f"recovery receipt missing: {receipt_id}")
        data = json.loads(receipt_path.read_text(encoding="utf-8"))
        if data.get("tx_state") not in {"PREPARED", "APPLIED"}:
            raise RecoveryError(
                f"unexpected transaction state on {receipt_id}: {data.get('tx_state')}"
            )
        data["postimage_sha256"] = post_sha256.upper()
        data["tx_state"] = "APPLIED"
        atomic_write_json(receipt_path, data)
        self._failpoint("during_finalize")
        # Verify the target on disk actually carries the recorded postimage.
        try:
            current = sha256_file(Path(str(data["path"])))
        except OSError as exc:
            data["tx_state"] = "RECOVERY_REQUIRED"
            atomic_write_json(receipt_path, data)
            raise RecoveryError(
                f"target unreadable during finalization of {receipt_id}: {exc}"
            ) from exc
        if current != data["postimage_sha256"]:
            data["tx_state"] = "RECOVERY_REQUIRED"
            atomic_write_json(receipt_path, data)
            raise RecoveryError(
                f"postimage verification failed for {receipt_id}: "
                f"expected {data['postimage_sha256']}, observed {current}"
            )
        data["tx_state"] = "VERIFIED"
        atomic_write_json(receipt_path, data)

    def _iter_receipt_files(self) -> list[Path]:
        files = sorted(self.root.glob("recovery-*.json"))
        files += sorted(self.root.glob("rollback-*.json"))
        return files

    def recover(self, lock_for: Any = None) -> dict[str, Any]:
        """Reconcile interrupted transactions after a restart.

        Incomplete transactions are reconciled UNDER THE RESOURCE LOCK for
        their target (``lock_for`` maps a target path string to a context
        manager; the executor supplies its per-target interprocess lock), so
        recovery cannot race a live writer into mis-marking a ``PREPARED``
        transaction. Pass ``lock_for=None`` only in single-process contexts
        such as unit tests.

        Returns a summary ``{"recovered": [...], "recovery_required": [...],
        "verified": n, "orphans": [...]}``. Entries requiring operator
        attention fail closed: they are marked RECOVERY_REQUIRED and never
        silently resolved. Orphan ``*.bak`` files without a matching receipt
        are reported and retained (never auto-pruned).
        """
        from contextlib import nullcontext

        from jvc.policy.locks import LockTimeoutError as _LockTimeout

        recovered: list[str] = []
        recovery_required: list[str] = []
        deferred: list[str] = []
        verified = 0
        seen_backup_ids: set[str] = set()
        for meta_file in self._iter_receipt_files():
            try:
                raw = json.loads(meta_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                # Unparseable receipt: fail closed, report by filename.
                recovery_required.append(meta_file.name)
                continue
            try:
                data = self.validate_receipt(raw)
            except RecoveryError:
                # Structurally invalid receipt: mark fail-closed in place so
                # the gate and future runs treat it as blocking. Non-object
                # JSON cannot be marked; it is reported without stopping
                # the scan.
                if isinstance(raw, dict):
                    try:
                        raw["tx_state"] = "RECOVERY_REQUIRED"
                        atomic_write_json(meta_file, raw)
                    except OSError:
                        pass
                    recovery_required.append(str(raw.get("receipt_id", meta_file.name)))
                else:
                    recovery_required.append(meta_file.name)
                continue
            rid = data["receipt_id"]
            backup_ref = data.get("backup_file")
            if backup_ref:
                seen_backup_ids.add(Path(str(backup_ref)).name)
            state = data["tx_state"]
            if state in {"RECOVERED_UNAPPLIED", "ROLLED_BACK", "SUPERSEDED", "RECOVERY_REQUIRED"}:
                # Terminal/blocking reads: no mutation, no lock needed.
                if state == "RECOVERY_REQUIRED":
                    recovery_required.append(rid)
                else:
                    recovered.append(rid)
                continue
            if (
                state == "VERIFIED"
                and data.get("original_operation") == "FS_WRITE"
                and (not data.get("preimage_exists") or self._backup_ok(data))
            ):
                # Terminal read with intact backup: no mutation, no lock.
                verified += 1
                continue
            # Anything that may mutate (incomplete states, VERIFIED rollback
            # source completion, VERIFIED with bad backup) is decided under
            # the target's resource lock on a FRESH reread: the receipt may
            # have advanced (e.g., a writer completing) while this scan
            # waited for the lock. Deciding on stale data could overwrite a
            # completed transaction with RECOVERY_REQUIRED.
            locker = lock_for(str(data["path"])) if lock_for else nullcontext()
            try:
                with locker:
                    outcome = self._decide_locked(meta_file)
            except _LockTimeout:
                # A live writer holds the lock: defer, never mismark, never
                # deadlock the scan.
                deferred.append(rid)
                continue
            if outcome == "recovered":
                recovered.append(rid)
            elif outcome == "verified":
                verified += 1
            else:
                recovery_required.append(rid)
        orphans = self._find_orphan_backups(seen_backup_ids)
        return {
            "recovered": recovered,
            "recovery_required": recovery_required,
            "deferred": deferred,
            "verified": verified,
            "orphans": orphans,
        }

    def _read_validated(self, meta_file: Path) -> dict[str, Any]:
        """Reread and schema-validate a receipt; raise RecoveryError if bad."""
        try:
            raw = json.loads(meta_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RecoveryError(f"receipt unreadable: {meta_file.name}: {exc}") from exc
        return self.validate_receipt(raw)

    def _all_valid_receipts(self) -> list[tuple[Path, dict[str, Any]]]:
        """All schema-valid receipts (any project/path/state)."""
        out: list[tuple[Path, dict[str, Any]]] = []
        for meta_file in self._iter_receipt_files():
            try:
                out.append((meta_file, self._read_validated(meta_file)))
            except (OSError, json.JSONDecodeError, RecoveryError):
                continue
        return out

    def _chain_references(
        self, project_id: str, target_resolved: str
    ) -> tuple[set[str], set[str]]:
        """Split prev-pointers into effective vs ambiguous sets.

        Only pointers from receipts that actually superseded the target count
        as effective: ``APPLIED`` (replaced, finalization pending) and
        ``VERIFIED``. Pointers from ``PREPARED``/``RECOVERED_UNAPPLIED``
        (never applied) and ``ROLLED_BACK`` (undone) never count.
        Pointers from ``RECOVERY_REQUIRED`` receipts are ambiguous lineage:
        returned separately so callers fail closed instead of guessing.
        """
        effective: set[str] = set()
        ambiguous: set[str] = set()
        for _meta_file, data in self._all_valid_receipts():
            if data.get("project_id") != project_id:
                continue
            if data.get("path") != target_resolved:
                continue
            prev = data.get("prev_receipt_id")
            if not prev:
                continue
            state = data.get("tx_state")
            if state in {"APPLIED", "VERIFIED"}:
                effective.add(str(prev))
            elif state == "RECOVERY_REQUIRED":
                ambiguous.add(str(prev))
        return effective, ambiguous

    def _find_superseded_id(
        self, project_id: str, target_resolved: str, content: bytes | None
    ) -> str | None:
        """Find the receipt ID this new write supersedes (chain link).

        Exact postimage match for edits; latest terminal receipt for creates.
        Returns None for a first write. Best-effort ordering is acceptable
        here: exact postimage matches are unambiguous, and head computation
        (not this link) plus deterministic fallback resolve the rest.
        """
        best: tuple[int, str, str] | None = None
        pre_hash = sha256_bytes(content) if content is not None else None
        all_valid = self._all_valid_receipts()
        effective, _ambiguous = self._chain_references(project_id, target_resolved)
        matches: list[tuple[int, str, str]] = []
        for _meta_file, data in all_valid:
            if data.get("project_id") != project_id:
                continue
            if data.get("path") != target_resolved:
                continue
            if data.get("original_operation") != "FS_WRITE":
                continue
            if pre_hash is not None:
                if (
                    data.get("tx_state") == "VERIFIED"
                    and data.get("postimage_sha256") == pre_hash
                ):
                    seq = data.get("seq")
                    matches.append(
                        (
                            int(seq) if isinstance(seq, int) else -1,
                            str(data["receipt_id"]),
                            str(data["receipt_id"]),
                        )
                    )
                continue
            if data.get("tx_state") in self.TERMINAL_STATES:
                seq = data.get("seq")
                key = (int(seq) if isinstance(seq, int) else -1, str(data["receipt_id"]))
                if best is None or key > (best[0], best[1]):
                    best = (key[0], key[1], str(data["receipt_id"]))
        if matches:
            # Prefer the unreferenced match (chain head): an older receipt
            # with an identical postimage was already superseded. Only
            # effective (applied-and-standing) pointers count; unapplied or
            # rolled-back successors must not steal head status. Genuinely
            # ambiguous forks link to nothing rather than guess: selection
            # fails closed on ambiguity at rollback time.
            unreferenced = [m for m in matches if m[2] not in effective]
            if len(unreferenced) == 1:
                return unreferenced[0][2]
            # Zero or several unreferenced matches: genuinely ambiguous
            # lineage. Link to nothing rather than guess; selection fails
            # closed on ambiguity at rollback time.
            return None
        return best[2] if best else None

    def _decide_locked(self, meta_file: Path) -> str:
        """Make one recovery decision on freshly reread receipt state."""
        try:
            data = self._read_validated(meta_file)
        except RecoveryError:
            try:
                with open(meta_file, encoding="utf-8") as handle:
                    raw = json.load(handle)
                if isinstance(raw, dict):
                    raw["tx_state"] = "RECOVERY_REQUIRED"
                    atomic_write_json(meta_file, raw)
            except (OSError, json.JSONDecodeError):
                pass
            return "required"
        state = data["tx_state"]
        if state == "VERIFIED":
            return self._audit_verified(meta_file, data)
        if state in {"RECOVERED_UNAPPLIED", "ROLLED_BACK", "SUPERSEDED"}:
            return "recovered"
        if state == "RECOVERY_REQUIRED":
            return "required"
        return self._reconcile_one(meta_file, data, state)

    def _audit_verified(self, meta_file: Path, data: dict[str, Any]) -> str:
        """Audit an already-terminal receipt; complete rollback sources."""
        if data.get("original_operation") == "ROLLBACK":
            # Rollback receipts carry no backup of their own; the restore was
            # verified when the receipt finalized. Idempotently complete the
            # source receipt (covers a crash between the two terminal writes).
            self._finalize_rollback(
                meta_file, data, str(data.get("rollback_of", ""))
            )
            return "verified"
        if data.get("preimage_exists") and not self._backup_ok(data):
            data["tx_state"] = "RECOVERY_REQUIRED"
            atomic_write_json(meta_file, data)
            return "required"
        return "verified"

    @staticmethod
    def _backup_ok(data: dict[str, Any]) -> bool:
        """Check a receipt's backup exists and matches (when preimage exists)."""
        if not data.get("preimage_exists"):
            return True
        backup_ref = data.get("backup_file")
        expected = data.get("preimage_sha256")
        if not backup_ref or not expected:
            return False
        backup_file = Path(str(backup_ref))
        try:
            if not backup_file.is_file():
                return False
            return sha256_file(backup_file) == expected
        except OSError:
            return False

    def _find_orphan_backups(self, seen: set[str]) -> list[str]:
        orphans: list[str] = []
        for bak in sorted(self.root.glob("*.bak")):
            if bak.name not in seen:
                orphans.append(bak.name)
        return orphans

    def corrupt_receipt_files(self) -> list[str]:
        """List receipt files that are unparseable or schema-invalid."""
        corrupt: list[str] = []
        for meta_file in self._iter_receipt_files():
            try:
                self.validate_receipt(
                    json.loads(meta_file.read_text(encoding="utf-8"))
                )
            except (OSError, json.JSONDecodeError, RecoveryError):
                corrupt.append(meta_file.name)
        return corrupt

    def has_blocking_state(self, project_id: str, target: Path) -> str | None:
        """Return a blocking reason if mutation of target must not proceed.

        Blocks on RECOVERY_REQUIRED receipts for the target AND on any
        corrupt/unreadable receipt file in the store: corruption means the
        journal's integrity is unknown, so no target governed by this store
        may be mutated until the operator repairs or removes the file and
        re-runs recovery.
        """
        corrupt = self.corrupt_receipt_files()
        if corrupt:
            return f"store-corrupt:{corrupt[0]}"
        target_resolved = str(target.resolve())
        for meta_file in self._iter_receipt_files():
            try:
                data = self.validate_receipt(
                    json.loads(meta_file.read_text(encoding="utf-8"))
                )
            except (OSError, json.JSONDecodeError, RecoveryError):
                continue
            if (
                data.get("project_id") == project_id
                and data.get("path") == target_resolved
                and data.get("tx_state") in self.BLOCKING_STATES
            ):
                return data["receipt_id"]
        return None

    def _reconcile_one(
        self, meta_file: Path, data: dict[str, Any], state: str
    ) -> str:
        if data.get("original_operation") == "ROLLBACK":
            # Rollback receipts carry no backup of their own; they restore
            # from the source FS_WRITE receipt's backup.
            return self._reconcile_rollback(meta_file, data, state)
        # Backup must be available and intact before any reconciliation that
        # could rely on it; a missing/corrupt backup fails closed here, not
        # only at rollback time.
        if data.get("preimage_exists") and not self._backup_ok(data):
            data["tx_state"] = "RECOVERY_REQUIRED"
            atomic_write_json(meta_file, data)
            return "required"
        target = Path(str(data.get("path", "")))
        preimage_exists = bool(data.get("preimage_exists"))
        preimage = data.get("preimage_sha256")
        postimage = data.get("postimage_sha256")
        try:
            target_exists = target.is_file()
            current = sha256_file(target) if target_exists else None
        except OSError:
            data["tx_state"] = "RECOVERY_REQUIRED"
            atomic_write_json(meta_file, data)
            return "required"
        if state == "PREPARED":
            # Mutation was never recorded as applied. Safe only if the target
            # still matches the preimage (or is still absent for creates).
            if (not preimage_exists and not target_exists) or (
                preimage_exists and current == preimage
            ):
                data["tx_state"] = "RECOVERED_UNAPPLIED"
                atomic_write_json(meta_file, data)
                return "recovered"
            data["tx_state"] = "RECOVERY_REQUIRED"
            atomic_write_json(meta_file, data)
            return "required"
        if state == "APPLIED":
            if postimage and current == postimage:
                data["tx_state"] = "VERIFIED"
                atomic_write_json(meta_file, data)
                return "verified"
            data["tx_state"] = "RECOVERY_REQUIRED"
            atomic_write_json(meta_file, data)
            return "required"
        data["tx_state"] = "RECOVERY_REQUIRED"
        atomic_write_json(meta_file, data)
        return "required"

    def _reconcile_rollback(
        self, meta_file: Path, data: dict[str, Any], state: str
    ) -> str:
        """Complete an interrupted rollback transaction idempotently."""
        target = Path(str(data.get("path", "")))
        restored = data.get("restored_sha256")
        source_id = str(data.get("rollback_of", ""))
        try:
            target_exists = target.is_file()
            current = sha256_file(target) if target_exists else None
        except OSError:
            data["tx_state"] = "RECOVERY_REQUIRED"
            atomic_write_json(meta_file, data)
            return "required"
        if state == "PREPARED":
            # Rollback never applied: safe only if the target still carries
            # the pre-rollback postimage.
            if current == data.get("expected_postimage_sha256"):
                data["tx_state"] = "RECOVERED_UNAPPLIED"
                atomic_write_json(meta_file, data)
                return "recovered"
            data["tx_state"] = "RECOVERY_REQUIRED"
            atomic_write_json(meta_file, data)
            return "required"
        if state == "APPLIED":
            if restored and (
                current == restored
                or (restored == "__ABSENT__" and not target_exists)
            ):
                self._finalize_rollback(meta_file, data, source_id)
                return "verified"
            data["tx_state"] = "RECOVERY_REQUIRED"
            atomic_write_json(meta_file, data)
            return "required"
        data["tx_state"] = "RECOVERY_REQUIRED"
        atomic_write_json(meta_file, data)
        return "required"

    def _finalize_rollback(
        self, meta_file: Path, data: dict[str, Any], source_id: str
    ) -> None:
        data["tx_state"] = "VERIFIED"
        atomic_write_json(meta_file, data)
        if source_id:
            source_file = self.root / f"{source_id}.json"
            if source_file.is_file():
                try:
                    source = self.validate_receipt(
                        json.loads(source_file.read_text(encoding="utf-8"))
                    )
                except (OSError, json.JSONDecodeError, RecoveryError):
                    return
                source["tx_state"] = "ROLLED_BACK"
                atomic_write_json(source_file, source)

    def reconcile_target(self, project_id: str, target: Path) -> dict[str, Any]:
        """Reconcile incomplete transactions for one target (lock held).

        The caller MUST hold the target's resource lock: any PREPARED receipt
        observed here is orphaned (live writers create PREPARED only inside
        this same lock), so reconciling inline is safe. Returns a summary
        ``{"reconciled": [...], "recovery_required": [...]}``; callers deny
        fresh mutation while either list is non-empty for the target.
        """
        target_resolved = str(target.resolve())
        reconciled: list[str] = []
        required: list[str] = []
        for meta_file in self._iter_receipt_files():
            try:
                data = self._read_validated(meta_file)
            except (OSError, json.JSONDecodeError, RecoveryError):
                continue
            if data.get("project_id") != project_id:
                continue
            if data.get("path") != target_resolved:
                continue
            if data.get("tx_state") not in self.INCOMPLETE_STATES:
                if data.get("tx_state") in self.BLOCKING_STATES:
                    required.append(data["receipt_id"])
                continue
            outcome = self._reconcile_one(meta_file, data, data["tx_state"])
            if outcome == "required":
                required.append(data["receipt_id"])
            else:
                reconciled.append(data["receipt_id"])
        return {"reconciled": reconciled, "recovery_required": required}

    def find_latest_receipt(
        self, project_id: str, target: Path, expected_postimage_sha256: str
    ) -> dict[str, Any] | None:
        """Find the head VERIFIED receipt for a file/postimage pair.

        Only VERIFIED FS_WRITE receipts qualify: incomplete or blocking
        receipts must go through ``recover()`` first, and rolled-back
        receipts no longer describe restorable state.

        Selection is clock-independent: among candidates, the receipt no
        other standing receipt points to via ``prev_receipt_id`` (the chain
        head) is chosen. Only pointers from ``APPLIED``/``VERIFIED`` receipts
        count — unapplied (``PREPARED``/``RECOVERED_UNAPPLIED``) and undone
        (``ROLLED_BACK``) successors never steal head status. A backward
        clock adjustment therefore cannot select an older same-content
        receipt (e.g., successive writes A -> B -> C -> B roll back to C,
        never A). Ambiguous lineage — zero or several heads, or a
        ``RECOVERY_REQUIRED`` pointer at the selected head — raises
        ``RecoveryRequiredError`` instead of silently choosing by timestamp.
        ``seq`` (wall clock) survives only as a field, not a decision input.
        """
        target_resolved = str(target.resolve())
        expected_post = expected_postimage_sha256.upper().strip()

        candidates: list[dict[str, Any]] = []
        for meta_file in sorted(self.root.glob(f"recovery-{project_id}-*.json")):
            try:
                data = self.validate_receipt(
                    json.loads(meta_file.read_text(encoding="utf-8"))
                )
            except (OSError, json.JSONDecodeError, RecoveryError):
                continue
            if data.get("project_id") != project_id or data.get("path") != target_resolved:
                continue
            if (
                data.get("postimage_sha256") == expected_post
                and data.get("original_operation") == "FS_WRITE"
                and data.get("tx_state") == "VERIFIED"
            ):
                candidates.append(data)
        if not candidates:
            return None
        effective, ambiguous = self._chain_references(project_id, target_resolved)
        heads = [c for c in candidates if c["receipt_id"] not in effective]
        if len(heads) != 1:
            raise RecoveryRequiredError(
                f"ambiguous rollback lineage for {target_resolved} with postimage "
                f"{expected_post}: {len(heads)} head candidates; resolve recovery first"
            )
        head = heads[0]
        if head["receipt_id"] in ambiguous:
            raise RecoveryRequiredError(
                f"ambiguous rollback lineage for {target_resolved}: a "
                f"RECOVERY_REQUIRED transaction points at the head candidate "
                f"{head['receipt_id']}; resolve recovery first"
            )
        return head

    def _supersede_pending(self, project_id: str, target: Path) -> list[str]:
        """Settle pending intents overtaken by an imminent rollback.

        Caller must hold the target's resource lock: any PREPARED receipt
        seen here is orphaned (live writers journal PREPARED only inside this
        same lock) and can never apply once rollback replaces the target, so
        it becomes terminal SUPERSEDED rather than a future false
        RECOVERY_REQUIRED. An APPLIED receipt matching the current target
        finalizes to VERIFIED; an APPLIED receipt matching nothing on disk is
        genuinely ambiguous and denies the rollback. ROLLBACK-op pendings go
        through standard reconciliation; a REQUIRED outcome denies.
        """
        target_resolved = str(target.resolve())
        try:
            current = sha256_file(target) if target.is_file() else None
        except OSError:
            current = None
        superseded: list[str] = []
        for meta_file in self._iter_receipt_files():
            try:
                data = self._read_validated(meta_file)
            except (OSError, json.JSONDecodeError, RecoveryError):
                continue
            if data.get("project_id") != project_id:
                continue
            if data.get("path") != target_resolved:
                continue
            state = data.get("tx_state")
            if state not in self.INCOMPLETE_STATES:
                continue
            if data.get("original_operation") == "ROLLBACK":
                if self._reconcile_one(meta_file, data, state) == "required":
                    raise RecoveryRequiredError(
                        f"unresolved rollback transaction blocks rollback of "
                        f"{target}: {data['receipt_id']}"
                    )
                continue
            if state == "PREPARED":
                # Reconcile against the CURRENT target before superseding:
                # holding the lock proves the writer is gone, but NOT that
                # replacement never happened (crash between os.replace and
                # journaling leaves NEW bytes under a PREPARED receipt).
                # Safely unapplied (target still at preimage, or still
                # absent for creates) becomes SUPERSEDED — it can never
                # apply once rollback moves the target. Anything else is
                # genuinely unresolved: mark fail-closed and deny rollback.
                if self._reconcile_one(meta_file, data, state) == "required":
                    raise RecoveryRequiredError(
                        f"unresolved prepared transaction blocks rollback of "
                        f"{target}: {data['receipt_id']}; resolve recovery first"
                    )
                data = self._read_validated(meta_file)
                data["tx_state"] = "SUPERSEDED"
                atomic_write_json(meta_file, data)
                superseded.append(data["receipt_id"])
                continue
            # APPLIED FS_WRITE: replacement happened; finalize iff the bytes
            # are still the ones recorded, else fail closed.
            if data.get("postimage_sha256") and current == data["postimage_sha256"]:
                data["tx_state"] = "VERIFIED"
                atomic_write_json(meta_file, data)
            else:
                data["tx_state"] = "RECOVERY_REQUIRED"
                atomic_write_json(meta_file, data)
                raise RecoveryRequiredError(
                    f"ambiguous applied transaction blocks rollback of "
                    f"{target}: {data['receipt_id']}; resolve recovery first"
                )
        return superseded

    def rollback(
        self,
        project_id: str,
        target: Path,
        expected_postimage_sha256: str,
    ) -> dict[str, Any]:
        """Durably rollback target to its previous state using the recovery store.

        Rollback is journaled: a PREPARED ROLLBACK receipt records intent
        before the target is touched, advances to APPLIED after replacement,
        and finalizes to VERIFIED with the source receipt persisted as
        ROLLED_BACK. An interrupted rollback is completed idempotently by
        ``recover()``.

        Invariants:
        - Target current hash must match expected_postimage_sha256 (CAS conflict detection).
        - Only VERIFIED FS_WRITE receipts qualify (run recover() first).
        - If file existed prior to write, backup file hash must match recorded preimage hash.
        - Restoration uses atomic temp-file creation + flush + fsync + replace.
        - If file did not exist prior to write, target is safely unlinked.
        - A corrupt journal denies rollback before any mutation.
        """
        corrupt = self.corrupt_receipt_files()
        if corrupt:
            raise RecoveryRequiredError(
                f"corrupt recovery journal blocks rollback of {target}: "
                f"repair or remove {corrupt[0]} and re-run recovery first"
            )
        if not target.is_file():
            raise RecoveryError(f"rollback target missing: {target}")

        current_hash = sha256_file(target)
        if current_hash != expected_postimage_sha256.upper().strip():
            raise RecoveryError(
                f"stale postimage on rollback target: expected {expected_postimage_sha256}, observed {current_hash}"
            )

        # Settle pending target transactions FIRST, while holding the target
        # lock (callers must hold it): orphaned PREPARED intents become
        # terminal SUPERSEDED, matching APPLIED finalizes to VERIFIED, and
        # genuinely ambiguous applied state is marked RECOVERY_REQUIRED and
        # denies here with a precise reason. Settling first keeps the
        # chain-head decision below free of unapplied/undone successors.
        superseded = self._supersede_pending(project_id, target)

        receipt = self.find_latest_receipt(project_id, target, current_hash)
        if receipt is None:
            raise RecoveryError(
                f"no matching governed recovery receipt for {target} with postimage {current_hash}"
            )

        # Journal rollback intent BEFORE touching the target.
        rb_id = self._new_receipt_id(project_id, kind="rollback")
        rb_receipt: dict[str, Any] = {
            "receipt_id": rb_id,
            "project_id": project_id,
            "path": str(target.resolve()),
            "original_operation": "ROLLBACK",
            "rollback_of": receipt["receipt_id"],
            "preimage_exists": True,
            "preimage_sha256": current_hash,
            "postimage_sha256": None,
            "expected_postimage_sha256": current_hash,
            "restored_sha256": None,
            "backup_file": None,
            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "seq": time.time_ns(),
            "tx_state": "PREPARED",
        }
        rb_path = self.root / f"{rb_id}.json"
        atomic_write_json(rb_path, rb_receipt)

        if not receipt.get("preimage_exists"):
            # File was created; rollback deletes it
            target.unlink(missing_ok=True)
            fsync_dir(target.parent)
            rb_receipt["restored_sha256"] = "__ABSENT__"
            rb_receipt["tx_state"] = "APPLIED"
            atomic_write_json(rb_path, rb_receipt)
            self._failpoint("rollback_before_terminal")
            self._finalize_rollback(rb_path, rb_receipt, str(receipt["receipt_id"]))
            return {
                "status": "ROLLED_BACK",
                "receipt_id": receipt["receipt_id"],
                "rollback_receipt_id": rb_id,
                "path": str(target),
                "action": "deleted",
                "restored_state": "absent",
            }

        backup_file = Path(str(receipt.get("backup_file", "")))
        expected_preimage = receipt.get("preimage_sha256")

        if not backup_file.is_file():
            rb_receipt["tx_state"] = "RECOVERY_REQUIRED"
            atomic_write_json(rb_path, rb_receipt)
            raise RecoveryError(f"recovery backup missing: {backup_file}")

        backup_hash = sha256_file(backup_file)
        if backup_hash != expected_preimage:
            rb_receipt["tx_state"] = "RECOVERY_REQUIRED"
            atomic_write_json(rb_path, rb_receipt)
            raise RecoveryError(
                f"recovery backup hash mismatch: expected {expected_preimage}, observed {backup_hash}"
            )

        backup_data = backup_file.read_bytes()

        # Atomic tempfile replacement with fsync
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_path_str = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".rollback", dir=target.parent
        )
        temp_path = Path(temp_path_str)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(backup_data)
                stream.flush()
                os.fsync(stream.fileno())
            durable_replace(temp_path, target)
            fsync_dir(target.parent)
        finally:
            if temp_path.exists():
                temp_path.unlink(missing_ok=True)

        final_hash = sha256_file(target)
        if final_hash != expected_preimage:
            rb_receipt["tx_state"] = "RECOVERY_REQUIRED"
            atomic_write_json(rb_path, rb_receipt)
            raise RecoveryError(
                f"rollback post-verification failed: expected {expected_preimage}, observed {final_hash}"
            )

        rb_receipt["restored_sha256"] = final_hash
        rb_receipt["tx_state"] = "APPLIED"
        atomic_write_json(rb_path, rb_receipt)
        self._failpoint("rollback_before_terminal")
        self._finalize_rollback(rb_path, rb_receipt, str(receipt["receipt_id"]))

        return {
            "status": "ROLLED_BACK",
            "receipt_id": receipt["receipt_id"],
            "rollback_receipt_id": rb_id,
            "path": str(target),
            "action": "restored",
            "restored_state": "present",
            "restored_sha256": final_hash,
        }

    def prune(self, retention_days: int = RETENTION_DAYS) -> int:
        """Prune old TERMINAL receipts and their backups.

        Only receipts in terminal states (VERIFIED, RECOVERED_UNAPPLIED,
        ROLLED_BACK) older than the retention period are removed, with
        their backup files. Incomplete (PREPARED/APPLIED), blocking
        (RECOVERY_REQUIRED), invalid, and orphan backups are NEVER pruned
        automatically: unresolved transactions must survive for recovery.
        """
        cutoff = time.time() - (retention_days * 86400)
        removed = 0
        for meta_file in self._iter_receipt_files():
            try:
                if meta_file.stat().st_mtime >= cutoff:
                    continue
                data = self.validate_receipt(
                    json.loads(meta_file.read_text(encoding="utf-8"))
                )
            except (OSError, json.JSONDecodeError, RecoveryError):
                continue
            if data["tx_state"] not in self.TERMINAL_STATES:
                continue
            backup_ref = data.get("backup_file")
            try:
                meta_file.unlink(missing_ok=True)
                removed += 1
                if backup_ref:
                    Path(str(backup_ref)).unlink(missing_ok=True)
            except OSError:
                pass
        return removed
