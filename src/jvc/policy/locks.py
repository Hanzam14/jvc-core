"""Interprocess per-resource locks for governed mutations.

Serializes the read/validate/mutate critical section of governed filesystem
writes and continuity revision updates across OS processes on one host.

Platform model (0.1.0):
- Windows-first. Mandatory OS file locking via ``msvcrt.locking`` on
  Windows, ``fcntl.flock`` on POSIX.
- The lock directory is host-owned and MUST resolve outside every governed
  project root. Lock acquisition validates this and fails closed.
- If no supported locking primitive is available, acquisition raises
  :class:`LockError` instead of silently performing an unlocked write.

The lock file itself is never reachable through an ordinary governed project
path because the lock directory is required to live outside all governed
roots (enforced at lock construction and at executor initialization).
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import time
from pathlib import Path


class LockError(RuntimeError):
    """Raised when a lock cannot be established, held, or released safely."""


class LockTimeoutError(LockError):
    """Raised when a lock cannot be acquired within the requested timeout."""


def lock_name_for(*parts: str) -> str:
    """Derive a stable lock file stem from resource identity parts."""
    digest = hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()
    return f"jvc-{digest[:48]}"


def canonical_resource_id(absolute: Path | str) -> str:
    """Return the canonical identity string for a filesystem resource.

    Fully resolves the path (existing symlinks and junctions included) and
    then applies platform normalization (case folding, separators, drive
    letters via ``os.path.normcase``). Resolution is lexical for missing
    targets, so absent-file aliases such as ``audit-absent.txt`` and
    ``AUDIT-ABSENT.TXT`` still share one identity on Windows.

    Explicitly unsupported (no equivalence claimed): 8.3 short names, UNC
    device paths (``\\\\?\\``, ``\\\\.\\`` — rejected at the boundary layer),
    and handle-based protection against later reparse-point replacement.
    """
    return os.path.normcase(os.fspath(Path(absolute).resolve()))


def lock_name_for_resource(kind: str, absolute: Path | str) -> str:
    """Derive a lock name from canonical resource identity (not spelling).

    Two spellings of the same resource — including different project IDs,
    case variants, or separator variants — map to one lock.
    """
    digest = hashlib.sha256(
        f"{kind}\x00{canonical_resource_id(absolute)}".encode("utf-8")
    ).hexdigest()
    return f"jvc-{digest[:48]}"


def _lock_mechanism() -> str:
    if os.name == "nt":
        try:
            import msvcrt  # noqa: F401

            return "msvcrt"
        except ImportError:
            return "none"
    try:
        import fcntl  # noqa: F401

        return "fcntl"
    except ImportError:
        return "none"


class ResourceLock:
    """Blocking interprocess mutex backed by an OS file lock.

    Use as a context manager::

        with ResourceLock(lock_dir, name, timeout=30):
            ...critical section...

    Failure semantics are fail-closed: any inability to create, lock, or
    maintain the lock file raises :class:`LockError`.
    """

    def __init__(
        self,
        lock_dir: Path,
        name: str,
        timeout: float = 30.0,
        governed_roots: list[Path] | None = None,
    ) -> None:
        self.lock_dir = Path(lock_dir)
        self.name = str(name)
        self.timeout = float(timeout)
        self.governed_roots = [Path(r).resolve() for r in (governed_roots or [])]
        self._path: Path | None = None
        self._handle: int | None = None
        self._mechanism = _lock_mechanism()

    @property
    def path(self) -> Path:
        if self._path is None:
            raise LockError("lock path is not established (lock not acquired)")
        return self._path

    def _validate(self) -> Path:
        if self._mechanism == "none":
            raise LockError(
                "no supported interprocess file-lock primitive on this platform; "
                "refusing unlocked mutation"
            )
        if not self.name or "/" in self.name or "\\" in self.name:
            raise LockError(f"invalid lock name: {self.name!r}")
        try:
            resolved = self.lock_dir.resolve()
        except OSError as exc:
            raise LockError(f"cannot resolve lock directory: {exc}") from exc
        if resolved.is_file() if resolved.exists() else False:
            raise LockError(f"lock directory path is a file: {resolved}")
        for root in self.governed_roots:
            try:
                resolved.relative_to(root)
            except ValueError:
                continue
            raise LockError(
                f"lock directory {resolved} is inside governed project root {root}; "
                "locks must be host-owned outside governed roots"
            )
        try:
            resolved.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise LockError(f"cannot establish lock directory {resolved}: {exc}") from exc
        candidate = resolved / f"{self.name}.lock"
        try:
            candidate_resolved = candidate.resolve()
        except OSError as exc:
            raise LockError(f"cannot resolve lock file path: {exc}") from exc
        for root in self.governed_roots:
            try:
                candidate_resolved.relative_to(root)
            except ValueError:
                continue
            raise LockError("lock file resolves inside a governed project root")
        return candidate

    def acquire(self) -> None:
        candidate = self._validate()
        try:
            fd = os.open(str(candidate), os.O_RDWR | os.O_CREAT, 0o600)
        except OSError as exc:
            raise LockError(f"cannot open lock file {candidate}: {exc}") from exc
        try:
            self._blocking_lock(fd)
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        self._path = candidate
        self._handle = fd

    def _blocking_lock(self, fd: int) -> None:
        deadline = time.monotonic() + max(0.0, self.timeout)
        if self._mechanism == "msvcrt":
            import msvcrt

            while True:
                try:
                    # Lock the first byte non-blocking; retry until timeout.
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    return
                except OSError:
                    if time.monotonic() >= deadline:
                        raise LockTimeoutError(
                            f"timed out acquiring interprocess lock {self.name!r}"
                        )
                    time.sleep(0.02)
        elif self._mechanism == "fcntl":
            import fcntl

            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return
                except OSError:
                    if time.monotonic() >= deadline:
                        raise LockTimeoutError(
                            f"timed out acquiring interprocess lock {self.name!r}"
                        )
                    time.sleep(0.02)
        else:  # pragma: no cover - guarded in _validate
            raise LockError("no supported interprocess file-lock primitive")

    def release(self) -> None:
        if self._handle is None:
            return
        fd, self._handle = self._handle, None
        try:
            if self._mechanism == "msvcrt":
                import msvcrt

                try:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                except OSError as exc:
                    raise LockError(f"failed to release lock {self.name!r}: {exc}") from exc
            elif self._mechanism == "fcntl":
                import fcntl

                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError as exc:
                    raise LockError(f"failed to release lock {self.name!r}: {exc}") from exc
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
        # The lock file itself is retained (empty sentinel); uninstalling it
        # would reintroduce races between unlink and open.

    def __enter__(self) -> "ResourceLock":
        self.acquire()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.release()


def default_lock_dir() -> Path:
    """Return the default host-owned lock directory (outside any project)."""
    return Path(tempfile.gettempdir()) / "jvc-locks"
