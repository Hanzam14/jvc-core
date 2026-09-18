"""Continuity state manager, revision CAS, checkpoints, and handoff integrity."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 2
CONTINUITY_DIR = ".continuity"
STATE_FILE = "state.json"

DECISION_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")


def _validate_decision_id(decision_id: str) -> str:
    """Validate a decision identifier before it becomes a filename.

    Identifiers become ``<decision_id>.json`` under the decisions directory;
    separators, traversal, and empty values are rejected so identifiers can
    never escape that directory or collide with control files.
    """
    if not isinstance(decision_id, str) or not DECISION_ID_RE.fullmatch(decision_id):
        raise ValueError(
            f"invalid decision_id: must match [A-Za-z0-9][A-Za-z0-9_.-]{{0,127}}: {decision_id!r}"
        )
    return decision_id


class ContinuityError(RuntimeError):
    """Raised when continuity invariants fail."""


class ConflictError(ContinuityError):
    """Raised when an optimistic concurrency revision conflict is detected."""


def utc_now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def atomic_write(path: Path, data: bytes) -> None:
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
        os.replace(temp_path, path)
    finally:
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)


@dataclass
class ContinuityState:
    schema_version: int
    project_id: str
    metadata_revision: int
    persistence: str
    privacy: str
    active_workstream: str | None = None
    handoff_sha256: str | None = None
    updated_at: str = field(default_factory=utc_now)


class ContinuityManager:
    """Manages project continuity checkpoints, revision numbers, and integrity.

    Revision read/check/write critical sections execute under a per-state
    interprocess lock, so two processes racing from the same revision
    serialize: exactly one mutation succeeds and the other observes a
    revision conflict.
    """

    def __init__(self, root: Path, lock_dir: Path | None = None) -> None:
        self.root = root.resolve()
        self.continuity_dir = self.root / CONTINUITY_DIR
        self.state_file = self.continuity_dir / STATE_FILE
        self.checkpoints_dir = self.continuity_dir / "checkpoints"
        self.decisions_dir = self.continuity_dir / "decisions"
        self.workstreams_dir = self.continuity_dir / "workstreams"
        if lock_dir is not None:
            self.lock_dir = Path(lock_dir)
        else:
            from jvc.policy.locks import default_lock_dir

            self.lock_dir = default_lock_dir()

    def _revision_lock(self, timeout: float = 30.0):
        from jvc.policy.locks import ResourceLock, lock_name_for_resource

        return ResourceLock(
            self.lock_dir,
            lock_name_for_resource("continuity", self.state_file),
            timeout=timeout,
            governed_roots=[self.root],
        )

    def is_initialized(self) -> bool:
        return self.state_file.is_file()

    def init(
        self,
        project_id: str,
        persistence: str = "git",
        privacy: str = "standard",
        lock_timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Initialize continuity state directory for a project."""
        with self._revision_lock(lock_timeout):
            return self._init_locked(project_id, persistence, privacy)

    def _init_locked(
        self, project_id: str, persistence: str, privacy: str
    ) -> dict[str, Any]:
        if self.is_initialized():
            raise ContinuityError(f"continuity already initialized in {self.root}")

        self.checkpoints_dir.mkdir(parents=True, exist_ok=True)
        self.decisions_dir.mkdir(parents=True, exist_ok=True)
        self.workstreams_dir.mkdir(parents=True, exist_ok=True)

        handoff_path = self.root / "HANDOFF.md"
        handoff_sha = (
            sha256_file(handoff_path) if handoff_path.is_file() else None
        )

        state = {
            "schema_version": SCHEMA_VERSION,
            "project_id": project_id,
            "metadata_revision": 1,
            "persistence": persistence,
            "privacy": privacy,
            "active_workstream": None,
            "handoff_sha256": handoff_sha,
            "created_at": utc_now(),
            "updated_at": utc_now(),
        }
        atomic_write(
            self.state_file,
            (json.dumps(state, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )
        return {"status": "PASS", "project_id": project_id, "revision": 1}

    def load_state(self) -> dict[str, Any]:
        if not self.is_initialized():
            raise ContinuityError("continuity is not initialized")
        try:
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ContinuityError(f"failed to read state file: {exc}") from exc

    def checkpoint(
        self,
        expected_handoff_sha256: str,
        payload: dict[str, Any],
        expected_metadata_revision: int | None = None,
        lock_timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Record a continuity checkpoint with CAS verification."""
        with self._revision_lock(lock_timeout):
            return self._checkpoint_locked(
                expected_handoff_sha256, payload, expected_metadata_revision
            )

    def _checkpoint_locked(
        self,
        expected_handoff_sha256: str,
        payload: dict[str, Any],
        expected_metadata_revision: int | None,
    ) -> dict[str, Any]:
        state = self.load_state()
        current_rev = state["metadata_revision"]

        # Optimistic concurrency check
        if (
            expected_metadata_revision is not None
            and current_rev != expected_metadata_revision
        ):
            raise ConflictError(
                f"metadata revision conflict: expected {expected_metadata_revision}, observed {current_rev}"
            )

        handoff_path = self.root / "HANDOFF.md"
        if not handoff_path.is_file():
            raise ContinuityError("HANDOFF.md is missing")

        current_handoff_sha = sha256_file(handoff_path)
        if current_handoff_sha != expected_handoff_sha256.upper().strip():
            raise ConflictError(
                f"handoff SHA-256 conflict: expected {expected_handoff_sha256}, observed {current_handoff_sha}"
            )

        new_rev = current_rev + 1
        checkpoint_id = f"checkpoint-{new_rev:06d}-{utc_now().replace(':', '')}-{secrets_token()}"
        checkpoint_file = self.checkpoints_dir / f"{checkpoint_id}.json"

        checkpoint_data = {
            "checkpoint_id": checkpoint_id,
            "project_id": state["project_id"],
            "metadata_revision": new_rev,
            "previous_revision": current_rev,
            "handoff_sha256": current_handoff_sha,
            "created_at": utc_now(),
            "payload": payload,
        }
        atomic_write(
            checkpoint_file,
            (json.dumps(checkpoint_data, indent=2, sort_keys=True) + "\n").encode(
                "utf-8"
            ),
        )

        state["metadata_revision"] = new_rev
        state["handoff_sha256"] = current_handoff_sha
        state["updated_at"] = utc_now()
        atomic_write(
            self.state_file,
            (json.dumps(state, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )

        return {
            "status": "PASS",
            "checkpoint_id": checkpoint_id,
            "metadata_revision": new_rev,
        }

    def reconcile_handoff(
        self,
        expected_handoff_sha256: str,
        observed_handoff_sha256: str,
        payload: dict[str, Any],
        expected_metadata_revision: int | None = None,
        lock_timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Adopt an updated HANDOFF.md after external edit using explicit CAS."""
        with self._revision_lock(lock_timeout):
            return self._reconcile_locked(
                expected_handoff_sha256,
                observed_handoff_sha256,
                payload,
                expected_metadata_revision,
            )

    def _reconcile_locked(
        self,
        expected_handoff_sha256: str,
        observed_handoff_sha256: str,
        payload: dict[str, Any],
        expected_metadata_revision: int | None,
    ) -> dict[str, Any]:
        state = self.load_state()
        current_rev = state["metadata_revision"]

        if (
            expected_metadata_revision is not None
            and current_rev != expected_metadata_revision
        ):
            raise ConflictError(
                f"metadata revision conflict: expected {expected_metadata_revision}, observed {current_rev}"
            )

        handoff_path = self.root / "HANDOFF.md"
        if not handoff_path.is_file():
            raise ContinuityError("HANDOFF.md is missing")

        current_handoff_sha = sha256_file(handoff_path)
        if current_handoff_sha != observed_handoff_sha256.upper().strip():
            raise ConflictError(
                f"handoff observed SHA-256 conflict: expected {observed_handoff_sha256}, actual file is {current_handoff_sha}"
            )

        # Enforce the recorded-value CAS: the caller must name the handoff
        # the state file currently records, not just the file on disk.
        recorded_handoff_sha = state.get("handoff_sha256")
        if (
            recorded_handoff_sha
            and recorded_handoff_sha != expected_handoff_sha256.upper().strip()
        ):
            raise ConflictError(
                f"handoff expected SHA-256 conflict: expected {expected_handoff_sha256}, recorded is {recorded_handoff_sha}"
            )

        new_rev = current_rev + 1
        state["metadata_revision"] = new_rev
        state["handoff_sha256"] = current_handoff_sha
        state["updated_at"] = utc_now()
        atomic_write(
            self.state_file,
            (json.dumps(state, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )

        return {
            "status": "PASS",
            "action": "reconciled",
            "metadata_revision": new_rev,
            "handoff_sha256": current_handoff_sha,
        }

    def record_decision(
        self,
        decision_id: str,
        expected_metadata_revision: int,
        payload: dict[str, Any],
        lock_timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Record a structured decision artifact."""
        with self._revision_lock(lock_timeout):
            return self._record_decision_locked(
                decision_id, expected_metadata_revision, payload
            )

    def _record_decision_locked(
        self,
        decision_id: str,
        expected_metadata_revision: int,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        _validate_decision_id(decision_id)
        state = self.load_state()
        current_rev = state["metadata_revision"]
        if current_rev != expected_metadata_revision:
            raise ConflictError(
                f"revision conflict: expected {expected_metadata_revision}, observed {current_rev}"
            )

        decision_file = self.decisions_dir / f"{decision_id}.json"
        if decision_file.exists():
            raise ContinuityError(f"decision already exists: {decision_id}")

        new_rev = current_rev + 1
        decision_data = {
            "decision_id": decision_id,
            "recorded_at": utc_now(),
            "metadata_revision": new_rev,
            "payload": payload,
        }
        atomic_write(
            decision_file,
            (json.dumps(decision_data, indent=2, sort_keys=True) + "\n").encode(
                "utf-8"
            ),
        )
        # Recording a decision mutates shared state, so the revision
        # advances: concurrent decisions from the same expected revision
        # serialize to exactly one winner plus revision conflicts.
        state["metadata_revision"] = new_rev
        state["updated_at"] = utc_now()
        atomic_write(
            self.state_file,
            (json.dumps(state, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )
        return {
            "status": "PASS",
            "decision_id": decision_id,
            "metadata_revision": new_rev,
        }

    def verify(self) -> dict[str, Any]:
        """Verify project continuity state and handoff integrity."""
        if not self.is_initialized():
            return {"status": "NOT_INITIALIZED", "detail": "continuity state missing"}

        state = self.load_state()
        handoff_path = self.root / "HANDOFF.md"
        if not handoff_path.is_file():
            return {"status": "FAIL", "detail": "HANDOFF.md missing"}

        current_handoff_sha = sha256_file(handoff_path)
        recorded_handoff_sha = state.get("handoff_sha256")
        if recorded_handoff_sha and current_handoff_sha != recorded_handoff_sha:
            return {
                "status": "DRIFT",
                "detail": "HANDOFF.md hash does not match state record",
                "recorded": recorded_handoff_sha,
                "current": current_handoff_sha,
            }

        return {
            "status": "PASS",
            "project_id": state.get("project_id"),
            "metadata_revision": state.get("metadata_revision"),
            "handoff_sha256": current_handoff_sha,
        }


def secrets_token() -> str:
    return uuid.uuid4().hex[:8]
