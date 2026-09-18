"""Governed executor implementing policy-controlled file and Git mutations."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from jvc.configuration import GovernancePolicy, ProjectRegistry, Route
from jvc.execution.runner import build_safe_subprocess_env, run_declared_check
from jvc.policy.authority import (
    assert_trust_store_outside_roots,
    create_confirmation_request,
    is_within_store,
    resolve_trusted_executable,
    sha256_bytes,
    sha256_file,
    validate_and_consume_capability,
)
from jvc.policy.boundaries import (
    assert_permitted_path,
    canonical_target,
    is_control_plane_path,
    is_secret_path,
    is_within,
)
from jvc.policy.locks import ResourceLock, default_lock_dir, lock_name_for_resource
from jvc.recovery.store import InjectedFailure, RecoveryStore, durable_replace, fsync_dir

CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

GIT_READ_MAX_BYTES = 256 * 1024

# Repository-controlled Git keys that can cause external program execution
# or worktree redirection during JVC-mediated operations. Repos defining
# them (in a repository-controlled config layer) are rejected for ALL
# governed Git operations — reads and mutations alike.
_UNSAFE_GIT_KEY_RES = [
    re.compile(r"^include(\.|$)", re.IGNORECASE),
    re.compile(r"^includeif\.", re.IGNORECASE),
    re.compile(r"^filter\..+\.(clean|smudge|process|required)$", re.IGNORECASE),
    re.compile(r"^diff\..+\.(command|textconv)$", re.IGNORECASE),
    re.compile(r"^diff\.external$", re.IGNORECASE),
    re.compile(r"^core\.fsmonitor$", re.IGNORECASE),
    re.compile(r"^core\.(attributesfile|sshcommand|worktree)$", re.IGNORECASE),
    re.compile(r"^extensions\.worktreeconfig$", re.IGNORECASE),
    re.compile(r"^gpg\.", re.IGNORECASE),
    re.compile(r"^commit\.gpgsign$", re.IGNORECASE),
    re.compile(r"^tag\.gpgsign$", re.IGNORECASE),
]

# .gitattributes tokens capable of selecting executable helpers.
_UNSAFE_ATTR_TOKEN_RE = re.compile(
    r"(filter|diff|merge)\s*=|textconv|working-tree-encoding", re.IGNORECASE
)


class GovernedExecutor:
    """Governed local executor providing boundary-controlled mutations, Git, and recovery."""

    def __init__(
        self,
        registry: ProjectRegistry | None = None,
        policy: GovernancePolicy | None = None,
        recovery_store: RecoveryStore | Path | None = None,
        confirmation_store: Path | None = None,
        trusted_executables: dict[str, dict[str, str]] | None = None,
        operator_secret: bytes | None = None,
        declared_manifest: dict[str, Any] | None = None,
        lock_dir: Path | None = None,
    ) -> None:
        self.registry = registry or ProjectRegistry([])
        self.policy = policy or GovernancePolicy()

        if isinstance(recovery_store, RecoveryStore):
            self.recovery_store = recovery_store
        elif recovery_store is not None:
            self.recovery_store = RecoveryStore(Path(recovery_store))
        else:
            self.recovery_store = RecoveryStore(Path(tempfile.gettempdir()) / "jvc-recovery")

        roots = [r.root for r in self.registry.list_routes()]
        # Host-owned stores must live outside every governed project root so
        # ordinary governed operations can never reach them.
        assert_trust_store_outside_roots(self.recovery_store.root, roots)

        if confirmation_store is not None:
            self.confirmation_store = Path(confirmation_store)
        else:
            self.confirmation_store = self.recovery_store.root / "confirmations"
        assert_trust_store_outside_roots(self.confirmation_store, roots)

        self.trusted_executables = trusted_executables or {}
        self.operator_secret = operator_secret
        self.declared_manifest = declared_manifest or {}
        self._staged_paths: dict[str, set[str]] = {}

        self.lock_dir = Path(lock_dir) if lock_dir is not None else default_lock_dir()
        self._governed_roots = [Path(r).resolve() for r in roots]

        # Reconcile transactions interrupted by an earlier crash.
        try:
            self.last_recovery = self.recovery_store.recover(lock_for=self._recover_lock)
        except Exception:
            self.last_recovery = {"recovered": [], "recovery_required": ["startup-recover-failed"], "deferred": [], "verified": 0, "orphans": []}

    def _recover_lock(self, target_str: str):  # type: ignore[no-untyped-def]
        # Short timeout: a live writer holding the lock means "defer", not
        # "wait out the whole write".
        return self._target_lock(Path(target_str), 3.0)

    def recover(self) -> dict[str, Any]:
        """Re-run restart recovery over the recovery journal."""
        self.last_recovery = self.recovery_store.recover(lock_for=self._recover_lock)
        return self.last_recovery

    def _target_lock(self, target: Path, timeout: float) -> ResourceLock:
        return ResourceLock(
            self.lock_dir,
            lock_name_for_resource("fs", target),
            timeout=timeout,
            governed_roots=self._governed_roots,
        )

    def _git_lock(self, root: Path, timeout: float = 30.0) -> ResourceLock:
        """Shared transaction lock serializing Git ownership checks + execution."""
        return ResourceLock(
            self.lock_dir,
            lock_name_for_resource("git", root),
            timeout=timeout,
            governed_roots=self._governed_roots,
        )

    def _resolve_project(self, project_id: str) -> Route:
        route = self.registry.get(project_id)
        if not route:
            raise ValueError(f"unregistered project_id: {project_id!r}")
        if not route.root.is_dir():
            raise ValueError(f"project root directory missing: {route.root}")
        return route

    def _assert_outside_host_stores(self, target: Path) -> None:
        for store in (self.confirmation_store, self.recovery_store.root):
            if is_within_store(target, store):
                raise PermissionError(
                    f"host-owned trust/recovery store is not reachable via governed paths: {target}"
                )

    def _git_exe(self) -> Path:
        if "git" in self.trusted_executables:
            return resolve_trusted_executable("git", self.trusted_executables)
        import shutil
        found = shutil.which("git")
        if not found:
            raise FileNotFoundError("git executable not found")
        return Path(found).resolve()

    def _safe_git_env(self) -> dict[str, str]:
        env = build_safe_subprocess_env([self._git_exe().parent])
        # Neutralize ambient repository-external Git configuration layers.
        # Repository-local configuration is handled separately by explicit
        # policy checks (see _assert_safe_git_repo); these variables only
        # pin the system/global layers to empty so tests and operators get
        # deterministic behavior.
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["GIT_CONFIG_GLOBAL"] = os.devnull
        env["GIT_CONFIG_SYSTEM"] = os.devnull
        env["GIT_TERMINAL_PROMPT"] = "0"
        return env

    def _git_base_args(self, root: Path, args: list[str]) -> tuple[list[str], dict[str, str]]:
        git_exe = self._git_exe()
        env = self._safe_git_env()
        # Neutralize ambient hooks and signing. Repository-controlled helpers
        # (filters, textconv, external diff, includes, fsmonitor, signing,
        # worktree redirection) are controlled by explicit pre-operation
        # policy checks, not by these flags alone.
        safe_args = [
            str(git_exe),
            "-c",
            "core.hooksPath=",
            "-c",
            "core.quotepath=false",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "tag.gpgsign=false",
            "-C",
            str(root),
            *args,
        ]
        return safe_args, env

    def _run_git(
        self,
        root: Path,
        args: list[str],
        timeout: int = 30,
    ) -> subprocess.CompletedProcess[str]:
        safe_args, env = self._git_base_args(root, args)
        return subprocess.run(
            safe_args,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )

    def _run_git_capped(
        self,
        root: Path,
        args: list[str],
        stdout_cap: int,
        stderr_cap: int = 32 * 1024,
        timeout: int = 30,
    ) -> tuple[int, bytes, bytes, bool, bool]:
        """Run git with hard byte caps on both streams.

        Reads each stream on a dedicated thread up to ``cap + 1`` bytes so a
        pathological repository cannot force unbounded buffering; a process
        blocked on a full pipe is terminated and reported truncated.
        Returns ``(returncode, stdout, stderr, out_truncated, err_truncated)``.
        Encoding is NOT applied here; callers decode explicitly as UTF-8.
        """
        import threading

        safe_args, env = self._git_base_args(root, args)
        proc = subprocess.Popen(
            safe_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        buffers: dict[str, bytearray] = {"out": bytearray(), "err": bytearray()}
        stop = threading.Event()

        def _pump(stream: Any, key: str, cap: int) -> None:
            buf = buffers[key]
            try:
                while not stop.is_set():
                    chunk = stream.read(65536)
                    if not chunk:
                        break
                    room = cap + 1 - len(buf)
                    if room > 0:
                        buf.extend(chunk[:room])
                    # Keep draining (discarding) past the cap so the child
                    # can finish promptly instead of blocking on a full pipe.
                    if len(buf) > cap:
                        while not stop.is_set():
                            if not stream.read(65536):
                                break
                        break
            except (ValueError, OSError):
                pass

        threads = [
            threading.Thread(target=_pump, args=(proc.stdout, "out", stdout_cap), daemon=True),
            threading.Thread(target=_pump, args=(proc.stderr, "err", stderr_cap), daemon=True),
        ]
        for thread in threads:
            thread.start()
        try:
            returncode = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            returncode = proc.wait(timeout=15)
        stop.set()
        for thread in threads:
            thread.join(timeout=10)
        out = bytes(buffers["out"])
        err = bytes(buffers["err"])
        return (
            returncode,
            out[: stdout_cap + 1],
            err[: stderr_cap + 1],
            len(out) > stdout_cap,
            len(err) > stderr_cap,
        )

    def _effective_git_config(self, root: Path) -> list[tuple[str, str, str]]:
        """Read effective Git configuration with origin tracking.

        Uses ``git config --list --show-origin`` so repository-controlled
        layers (``.git/config``, ``config.worktree``) are audited — not just
        ``--local``. Returns ``(origin, key, value)`` triples with lowercase
        keys. ANY inspection failure raises (fail closed); there is no
        fail-open empty-config fallback.
        """
        proc = self._run_git(root, ["config", "--list", "--show-origin"])
        if proc.returncode != 0:
            raise RuntimeError(
                f"git configuration inspection failed (fail closed): {proc.stderr.strip()}"
            )
        entries: list[tuple[str, str, str]] = []
        for line in proc.stdout.splitlines():
            if "\t" not in line or "=" not in line:
                continue
            origin, _, rest = line.partition("\t")
            key, _, value = rest.partition("=")
            entries.append((origin.strip(), key.strip().lower(), value.strip()))
        return entries

    def _assert_safe_git_repo(self, root: Path) -> None:
        """Fail closed on repository-controlled executable/redirection config.

        0.1.0 policy: detect repository configuration that can cause external
        program execution (filters, textconv, external diff, fsmonitor,
        signing programs, includes) or worktree redirection, and reject the
        governed Git operation — for reads and mutations alike. Only origins
        inside the repository's own gitdir count as repository-controlled;
        system/global layers are ignored.
        """
        resolved_root = root.resolve()
        # Worktree redirection guard: the effective worktree must be the
        # validated project root.
        top_proc = self._run_git(root, ["rev-parse", "--show-toplevel"])
        if top_proc.returncode != 0:
            raise RuntimeError(
                f"git worktree inspection failed (fail closed): {top_proc.stderr.strip()}"
            )
        toplevel = Path(top_proc.stdout.strip()).resolve()
        if os.path.normcase(str(toplevel)) != os.path.normcase(str(resolved_root)):
            raise PermissionError(
                f"git worktree redirection denied: effective toplevel {toplevel} "
                f"!= validated root {resolved_root}"
            )
        for origin, key, _value in self._effective_git_config(root):
            if origin.lower().rstrip(":") == "command line":
                # Our own -c invocation flags (hooks, quotepath, signing
                # overrides). Everything else in this sanitized environment
                # is repository-introduced: local layers, worktree layers,
                # or files pulled in via repository-controlled includes
                # (whose origins may point anywhere and are therefore
                # untrusted by construction).
                continue
            if any(rx.match(key) for rx in _UNSAFE_GIT_KEY_RES):
                raise PermissionError(
                    f"unsafe repository-controlled git configuration denied: {key} ({origin})"
                )

    def _gitattributes_files(self, root: Path) -> list[Path]:
        proc = self._run_git(root, ["ls-files", "-z", "--", ".gitattributes", "*/.gitattributes"])
        if proc.returncode != 0:
            return []
        out = [Path(p) for p in proc.stdout.split("\0") if p]
        top = root / ".gitattributes"
        if top.is_file() and top not in [root / p for p in out]:
            out.append(Path(".gitattributes"))
        return [root / p for p in out]

    def _assert_no_executable_gitattributes(self, root: Path) -> None:
        """Fail closed if any tracked .gitattributes selects executable helpers."""
        for attr_file in self._gitattributes_files(root):
            try:
                text = attr_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            # Strip comments; scan remaining attribute selections.
            meaningful = "\n".join(
                line.split("#", 1)[0] for line in text.splitlines()
            )
            if _UNSAFE_ATTR_TOKEN_RE.search(meaningful):
                raise PermissionError(
                    f"unsafe .gitattributes helper selection denied for governed mutation: {attr_file}"
                )

    def _assert_safe_git_mutation(self, root: Path) -> None:
        self._assert_safe_git_repo(root)
        self._assert_no_executable_gitattributes(root)

    def _assert_path_attrs_safe(self, root: Path, canonical_rel: str) -> None:
        """Reject per-path executable filter/diff driver selection."""
        proc = self._run_git(
            root, ["check-attr", "filter", "diff", "textconv", "merge", "--", canonical_rel]
        )
        if proc.returncode != 0:
            raise RuntimeError(f"git check-attr failed: {proc.stderr}")
        for line in proc.stdout.splitlines():
            # Format: "<path>: <attr>: <value>"
            parts = [p.strip() for p in line.split(":")]
            if len(parts) < 3:
                continue
            value = parts[-1].lower()
            if value not in {"unspecified", "unset", "unknown"}:
                raise PermissionError(
                    f"executable git attribute denied for governed operation: {line.strip()}"
                )

    @staticmethod
    def _validate_max_bytes(max_bytes: int) -> int:
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
            raise ValueError(f"max_bytes must be an integer, got {max_bytes!r}")
        if max_bytes < 0:
            raise ValueError(f"max_bytes must be >= 0, got {max_bytes}")
        return max_bytes

    @staticmethod
    def _fit_bytes(raw: bytes, max_bytes: int) -> str:
        """Decode capped bytes as UTF-8, shrinking to fit max_bytes exactly.

        Decoding is explicit UTF-8 with ``errors="replace"``; the result is
        then shrunk at a character boundary so its UTF-8 encoding NEVER
        exceeds ``max_bytes`` (no split multibyte sequences, no
        replacement-character overflow).
        """
        text = raw.decode("utf-8", errors="replace")
        encoded = text.encode("utf-8")
        while len(encoded) > max_bytes and text:
            text = text[:-1]
            encoded = text.encode("utf-8")
        return text

    def _capped_git_read(
        self,
        root: Path,
        args: list[str],
        max_bytes: int,
        timeout: int = 30,
    ) -> tuple[int, str, str, bool, bool]:
        """Run a Git read command with byte-exact bounds on both streams."""
        max_bytes = self._validate_max_bytes(max_bytes)
        returncode, out_raw, err_raw, out_trunc, err_trunc = self._run_git_capped(
            root, args, max_bytes, timeout=timeout
        )
        return (
            returncode,
            self._fit_bytes(out_raw[: max_bytes + 1], max_bytes),
            self._fit_bytes(err_raw[: 32 * 1024 + 1], 32 * 1024),
            out_trunc,
            err_trunc,
        )

    def _staged_files(self, root: Path) -> set[str]:
        r = self._run_git(root, ["diff", "--cached", "--name-only", "-z"])
        if r.returncode:
            raise RuntimeError(f"git diff --cached failed: {r.stderr}")
        return {x.replace("\\", "/") for x in r.stdout.split("\0") if x}

    def _dirty_worktree(self, root: Path) -> set[str]:
        r = self._run_git(root, ["status", "--porcelain=v1", "-z"])
        if r.returncode:
            raise RuntimeError(f"git status failed: {r.stderr}")
        out: set[str] = set()
        for rec in r.stdout.split("\0"):
            if not rec:
                continue
            entry = rec[3:] if len(rec) > 3 else rec
            if " -> " in entry:
                entry = entry.split(" -> ", 1)[1]
            if entry:
                out.add(entry.replace("\\", "/"))
        return out

    def project_status(self, project_id: str) -> dict[str, Any]:
        """Return project metadata and capability status."""
        route = self.registry.get(project_id)
        if not route:
            return {"registered": False, "project_id": project_id}

        git_applicable = (route.root / ".git").is_dir()
        return {
            "registered": True,
            "project_id": project_id,
            "root": str(route.root.resolve()),
            "status": route.status,
            "lifecycle": route.lifecycle,
            "capability_class": route.capability_class,
            "git_applicable": git_applicable,
        }

    def fs_write(
        self,
        project_id: str,
        relative_path: str,
        content: str,
        expected_preimage_sha256: str | None = None,
        confirmation_id: str | None = None,
        confirmation_token: str | None = None,
        lock_timeout: float = 30.0,
        **extra: Any,
    ) -> dict[str, Any]:
        """Perform an authorized governed file write.

        The entire read/validate/mutate critical section executes under a
        per-target interprocess lock, so two processes presenting the same
        expected preimage serialize: exactly one succeeds and the other
        observes a stale/conflict failure. Every mutation is recorded in the
        write-ahead recovery journal (PREPARED -> APPLIED -> VERIFIED).
        """
        if "permit_held_mutation" in extra or "confirm" in extra:
            raise PermissionError("caller-controlled authority escalation parameter rejected")

        route = self._resolve_project(project_id)
        is_held = route.lifecycle == "held"
        is_control_target = is_control_plane_path(relative_path)

        # Check if privileged operator authorization is required
        needs_cap = is_held or is_control_target
        authorized = False
        # Single payload construction shared by the proposal and the
        # authorization check: any divergence would make legitimately
        # signed capabilities fail validation (payload hash mismatch).
        payload = {
            "path": relative_path,
            "content_sha256": sha256_bytes(content.encode("utf-8")),
            "bytes": len(content.encode("utf-8")),
        }
        if needs_cap:
            if self.operator_secret and confirmation_id and confirmation_token:
                authorized = validate_and_consume_capability(
                    self.confirmation_store,
                    confirmation_id,
                    confirmation_token,
                    project_id,
                    "FS_WRITE",
                    relative_path,
                    payload,
                    expected_preimage_sha256,
                    self.operator_secret,
                )

            if not authorized:
                if is_control_target:
                    raise PermissionError(
                        f"REQUIRES_OPERATOR_CONTROL_PLANE_CAPABILITY: control plane target denied: {relative_path}"
                    )
                # For HELD route, request confirmation
                return create_confirmation_request(
                    self.confirmation_store,
                    project_id,
                    "FS_WRITE",
                    relative_path,
                    payload,
                    expected_preimage_sha256,
                    "HELD_ROUTE_GATE",
                    "HELD route mutation requires trusted operator capability",
                )

        target, canonical_rel = assert_permitted_path(
            route.root,
            relative_path,
            "FS_WRITE",
            is_operator_privileged=authorized,
        )
        self._assert_outside_host_stores(target)

        with self._target_lock(target, lock_timeout):
            # Reconcile-or-deny: incomplete transactions for this target
            # (orphaned by a crashed writer or a deferred recovery) are
            # reconciled inline under this same lock before any fresh
            # mutation. Anything still unresolved blocks the write; rollback
            # remains available as the resolution path.
            from jvc.recovery.store import RecoveryRequiredError

            pending = self.recovery_store.reconcile_target(project_id, target)
            if pending["recovery_required"]:
                raise RecoveryRequiredError(
                    f"RECOVERY_REQUIRED blocks mutation of {canonical_rel}: "
                    f"resolve receipt {pending['recovery_required'][0]} first"
                )
            # An unresolved RECOVERY_REQUIRED transaction blocks fresh
            # mutation of the affected resource until resolved (rollback
            # remains available as the resolution path).
            blocker = self.recovery_store.has_blocking_state(project_id, target)
            if blocker is not None:
                if blocker.startswith("store-corrupt:"):
                    raise RecoveryRequiredError(
                        f"corrupt recovery journal blocks mutation of {canonical_rel}: "
                        f"repair or remove {blocker.split(':', 1)[1]} and re-run recovery first"
                    )
                raise RecoveryRequiredError(
                    f"RECOVERY_REQUIRED blocks mutation of {canonical_rel}: "
                    f"resolve receipt {blocker} first"
                )
            # CAS verification inside the lock: the on-disk state cannot
            # change between this check and the mutation below.
            file_exists = target.is_file()
            preimage_bytes: bytes | None = None
            current_hash: str | None = None

            if file_exists:
                preimage_bytes = target.read_bytes()
                current_hash = sha256_bytes(preimage_bytes)
                if not expected_preimage_sha256:
                    raise ValueError(
                        f"expected_preimage_sha256 required for existing file: {canonical_rel}"
                    )
                if current_hash != expected_preimage_sha256.upper().strip():
                    raise ValueError(
                        f"preimage CAS conflict on {canonical_rel}: expected {expected_preimage_sha256}, observed {current_hash}"
                    )
            else:
                if expected_preimage_sha256:
                    raise ValueError(
                        f"preimage supplied for missing file: {canonical_rel}"
                    )

            # Durable PREPARED journal entry before touching the target.
            receipt = self.recovery_store.save_preimage(
                project_id, target, preimage_bytes
            )

            data = content.encode("utf-8")
            target.parent.mkdir(parents=True, exist_ok=True)

            # Durable atomic write with fsync
            fd, temp_raw = tempfile.mkstemp(
                prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
            )
            temp_path = Path(temp_raw)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                durable_replace(temp_path, target)
                fsync_dir(target.parent)
            finally:
                if temp_path.exists():
                    temp_path.unlink(missing_ok=True)

            if "after_target_write" in self.recovery_store.failure_points:
                raise InjectedFailure("injected failure at journal boundary: after_target_write")

            post_hash = sha256_file(target)
            self.recovery_store.note_target_replaced(receipt["receipt_id"], post_hash)
            self.recovery_store.record_postimage(receipt["receipt_id"], post_hash)

            return {
                "status": "PASS",
                "op_class": "FILE_EDIT" if file_exists else "FILE_CREATE",
                "project_id": project_id,
                "path": canonical_rel,
                "receipt_id": receipt["receipt_id"],
                "preimage_sha256": current_hash,
                "postimage_sha256": post_hash,
                "tx_state": "VERIFIED",
            }

    def fs_rollback(
        self,
        project_id: str,
        relative_path: str,
        expected_postimage_sha256: str,
        confirmation_id: str | None = None,
        confirmation_token: str | None = None,
        lock_timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Durably rollback target file using the recovery store.

        Rollback is the resolution path for RECOVERY_REQUIRED targets, so a
        blocking receipt does not deny it — but a corrupt journal does: no
        rollback mutation proceeds on unknown journal integrity.
        """
        route = self._resolve_project(project_id)
        target, canonical_rel = assert_permitted_path(
            route.root, relative_path, "FS_ROLLBACK"
        )
        self._assert_outside_host_stores(target)
        with self._target_lock(target, lock_timeout):
            from jvc.recovery.store import RecoveryRequiredError

            corrupt = self.recovery_store.corrupt_receipt_files()
            if corrupt:
                raise RecoveryRequiredError(
                    f"corrupt recovery journal blocks rollback of {canonical_rel}: "
                    f"repair or remove {corrupt[0]} and re-run recovery first"
                )
            return self.recovery_store.rollback(
                project_id, target, expected_postimage_sha256
            )

    def git_status(self, project_id: str, max_bytes: int = GIT_READ_MAX_BYTES) -> dict[str, Any]:
        """Inspect Git status of a registered project (output-bounded)."""
        route = self._resolve_project(project_id)
        if not (route.root / ".git").is_dir():
            return {
                "status": "NOT_APPLICABLE",
                "op_class": "READ_INSPECTION",
                "project_id": project_id,
            }
        self._assert_safe_git_repo(route.root)
        returncode, output, error, truncated, err_truncated = self._capped_git_read(
            route.root, ["status", "--porcelain=v1", "-b"], max_bytes
        )
        return {
            "status": "PASS" if returncode == 0 else "FAIL",
            "op_class": "READ_INSPECTION",
            "project_id": project_id,
            "exit_code": returncode,
            "output": output,
            "truncated": truncated,
            "max_bytes": max_bytes,
            "error": error,
            "error_truncated": err_truncated,
        }

    def _assert_exact_file_target(self, root: Path, canonical_rel: str) -> None:
        """Reject Git pathspec expansion: the path must be an exact file.

        Filesystem checks alone cannot reject a deleted directory that Git
        still represents in its index/HEAD tree (Git would interpret the
        pathspec recursively). Validation therefore runs against Git state:
        if ``rel`` is a strict prefix of any index or HEAD entry, it names a
        directory and is rejected. Exact tracked files, deleted-but-exact
        files, and unknown paths (bounded empty diff) are permitted.
        """
        for source in ("index", "head"):
            if source == "index":
                proc = self._run_git(root, ["ls-files", "-z", "--", canonical_rel])
            else:
                proc = self._run_git(
                    root, ["ls-tree", "-r", "--name-only", "-z", "HEAD", "--", canonical_rel]
                )
            if proc.returncode != 0:
                # No HEAD yet, or unreadable tree: nothing to expand here.
                continue
            entries = [e for e in proc.stdout.split("\0") if e]
            for entry in entries:
                normalized = entry.replace("\\", "/")
                if normalized != canonical_rel and (
                    normalized.startswith(canonical_rel.rstrip("/") + "/")
                    or canonical_rel.startswith(normalized + "/")
                ):
                    raise ValueError(
                        f"directory pathspec expansion is not permitted (files only): {canonical_rel}"
                    )

    def git_diff(
        self,
        project_id: str,
        path: str | list[str] | None = None,
        paths: list[str] | None = None,
        max_bytes: int = GIT_READ_MAX_BYTES,
    ) -> dict[str, Any]:
        """Inspect the Git diff of explicitly listed files (output-bounded).

        0.1.0 contract: repository-wide diff is NOT available. Callers must
        name one or more exact files; directories are rejected so protected
        descendants cannot leak through directory expansion. ``--no-textconv``
        and ``--no-ext-diff`` neutralize executable diff helpers, and any
        path selecting filter/diff drivers via attributes is rejected.
        """
        route = self._resolve_project(project_id)
        if not (route.root / ".git").is_dir():
            return {
                "status": "NOT_APPLICABLE",
                "op_class": "READ_INSPECTION",
                "project_id": project_id,
            }

        requested: list[str] = []
        if paths is not None:
            if isinstance(paths, str):
                requested.append(paths)
            else:
                requested.extend(paths)
        if path is not None:
            if isinstance(path, str):
                requested.append(path)
            else:
                requested.extend(path)
        if not requested:
            raise ValueError(
                "git diff requires one or more explicit file paths; "
                "repository-wide diff is not available in 0.1.0"
            )

        # The repository audit runs BEFORE any index/worktree-touching Git
        # command: even `ls-files` and `check-attr` can invoke a configured
        # fsmonitor hook, so no such command may precede the audit.
        self._assert_safe_git_repo(route.root)

        resolved_canonical: list[str] = []
        for item in requested:
            if not isinstance(item, str) or not item:
                raise ValueError(f"only exact relative file diff is permitted: {item!r}")
            if (
                any(c in item for c in "*?[]{}")
                or item in {".", "./"}
                or item.replace("\\", "/").rstrip("/").endswith("/.")
            ):
                raise ValueError(f"only exact relative file diff is permitted: {item}")
            target, canonical_rel = assert_permitted_path(
                route.root, item, "GIT_DIFF"
            )
            if target.is_dir():
                raise ValueError(
                    f"directory diff is not available in 0.1.0 (files only): {item}"
                )
            self._assert_exact_file_target(route.root, canonical_rel)
            self._assert_path_attrs_safe(route.root, canonical_rel)
            resolved_canonical.append(canonical_rel)

        args = ["diff", "--no-ext-diff", "--no-textconv", "--", *resolved_canonical]
        returncode, diff, error, truncated, err_truncated = self._capped_git_read(
            route.root, args, max_bytes
        )
        return {
            "status": "PASS" if returncode == 0 else "FAIL",
            "op_class": "READ_INSPECTION",
            "project_id": project_id,
            "exit_code": returncode,
            "diff": diff,
            "truncated": truncated,
            "max_bytes": max_bytes,
            "paths": resolved_canonical,
            "error": error,
            "error_truncated": err_truncated,
        }

    def git_log(
        self, project_id: str, n: int = 10, max_bytes: int = GIT_READ_MAX_BYTES
    ) -> dict[str, Any]:
        """Inspect recent git commit history (output-bounded)."""
        route = self._resolve_project(project_id)
        if not (route.root / ".git").is_dir():
            return {
                "status": "NOT_APPLICABLE",
                "op_class": "READ_INSPECTION",
                "project_id": project_id,
            }
        count = min(max(1, int(n)), 100)
        self._assert_safe_git_repo(route.root)
        returncode, log, error, truncated, err_truncated = self._capped_git_read(
            route.root, ["log", f"-n{count}", "--oneline"], max_bytes
        )
        return {
            "status": "PASS" if returncode == 0 else "FAIL",
            "op_class": "READ_INSPECTION",
            "project_id": project_id,
            "exit_code": returncode,
            "log": log,
            "truncated": truncated,
            "max_bytes": max_bytes,
            "error": error,
            "error_truncated": err_truncated,
        }

    def git_stage(
        self,
        project_id: str,
        paths: list[str],
        confirmation_id: str | None = None,
        confirmation_token: str | None = None,
    ) -> dict[str, Any]:
        """Stage exact approved files only into git index.

        Repository-defined clean/process filters cannot execute: repos whose
        local config or .gitattributes select executable helpers are
        rejected before ``git add`` runs.
        """
        route = self._resolve_project(project_id)
        if not (route.root / ".git").is_dir():
            return {
                "status": "NOT_APPLICABLE",
                "op_class": "GIT_STAGE",
                "project_id": project_id,
            }
        if not isinstance(paths, list) or not paths:
            raise ValueError("paths must be a non-empty list of exact relative files")

        with self._git_lock(route.root):
            return self._stage_locked(route, project_id, paths)

    def _stage_locked(
        self, route: Route, project_id: str, paths: list[str]
    ) -> dict[str, Any]:
        self._assert_safe_git_mutation(route.root)

        resolved_canonical: list[str] = []
        for p in paths:
            if not p or any(c in p for c in "*?[]{}") or p in {".", "./"}:
                raise ValueError(f"only exact relative file staging is permitted: {p}")
            target, canonical_rel = assert_permitted_path(
                route.root, p, "GIT_STAGE"
            )
            if target.is_dir():
                raise ValueError(f"directory staging is forbidden: {p}")
            # Index-level exact-file validation (same as diff): a deleted
            # tracked directory passes is_dir() but Git would expand the
            # pathspec recursively, staging descendants without individual
            # boundary validation.
            self._assert_exact_file_target(route.root, canonical_rel)
            self._assert_path_attrs_safe(route.root, canonical_rel)
            resolved_canonical.append(canonical_rel)

        # Disallow staging if unrelated files are already staged
        currently_staged = self._staged_files(route.root)
        already_owned = self._staged_paths.get(project_id, set())
        unrelated = currently_staged - set(resolved_canonical) - already_owned
        if unrelated:
            raise PermissionError(
                f"unrelated staged paths present in git index: {sorted(unrelated)}"
            )

        proc = self._run_git(route.root, ["add", "--", *resolved_canonical])
        if proc.returncode:
            raise RuntimeError(f"git add failed: {proc.stderr}")

        self._staged_paths.setdefault(project_id, set()).update(resolved_canonical)
        return {
            "status": "PASS",
            "op_class": "GIT_STAGE",
            "project_id": project_id,
            "staged_paths": resolved_canonical,
        }

    def git_commit(
        self,
        project_id: str,
        message: str,
        confirmation_id: str | None = None,
        confirmation_token: str | None = None,
    ) -> dict[str, Any]:
        """Create a commit containing only explicitly owned and validated staged files."""
        route = self._resolve_project(project_id)
        if not (route.root / ".git").is_dir():
            return {
                "status": "NOT_APPLICABLE",
                "op_class": "GIT_COMMIT",
                "project_id": project_id,
            }
        clean_msg = str(message).strip()
        if not clean_msg or CONTROL_RE.search(clean_msg):
            raise ValueError("invalid commit message")

        with self._git_lock(route.root):
            return self._commit_locked(route, project_id, clean_msg)

    def _commit_locked(
        self, route: Route, project_id: str, clean_msg: str
    ) -> dict[str, Any]:
        self._assert_safe_git_mutation(route.root)

        staged = self._staged_files(route.root)
        owned = self._staged_paths.get(project_id, set())
        if not staged:
            raise ValueError("no staged paths in git index to commit")

        # Verify all staged files are owned by this session
        unowned = staged - owned
        if unowned:
            raise PermissionError(
                f"unowned staged paths present in index: {sorted(unowned)}"
            )

        # Re-verify every staged file against boundary policy
        for rel in staged:
            assert_permitted_path(route.root, rel, "GIT_COMMIT")

        proc = self._run_git(route.root, ["commit", "-m", clean_msg])
        if proc.returncode:
            raise RuntimeError(f"git commit failed: {proc.stderr}")

        self._staged_paths.pop(project_id, None)
        return {
            "status": "PASS",
            "op_class": "GIT_COMMIT",
            "project_id": project_id,
            "committed_paths": sorted(staged),
            "output": proc.stdout,
        }

    def git_branch(
        self,
        project_id: str,
        branch_name: str,
        confirmation_id: str | None = None,
        confirmation_token: str | None = None,
    ) -> dict[str, Any]:
        """Create or switch to a bounded branch if the worktree is clean.

        ``git switch`` checks files out (executing smudge filters), so the
        same repository-helper policy as staging applies before switching.
        """
        route = self._resolve_project(project_id)
        if not (route.root / ".git").is_dir():
            return {
                "status": "NOT_APPLICABLE",
                "op_class": "GIT_BRANCH",
                "project_id": project_id,
            }

        branch = str(branch_name).strip()
        if not branch or branch.startswith("-") or CONTROL_RE.search(branch):
            raise ValueError("unsafe branch name")

        with self._git_lock(route.root):
            return self._branch_locked(route, project_id, branch)

    def _branch_locked(
        self, route: Route, project_id: str, branch: str
    ) -> dict[str, Any]:
        self._assert_safe_git_mutation(route.root)

        check = self._run_git(route.root, ["check-ref-format", "--branch", branch])
        if check.returncode:
            raise ValueError(f"invalid git branch ref: {branch}")

        if self._dirty_worktree(route.root):
            raise PermissionError("dirty worktree blocks branch operation")

        exists = (
            self._run_git(
                route.root,
                ["show-ref", "--verify", "--quiet", f"refs/heads/{branch}"],
            ).returncode
            == 0
        )
        if exists:
            # Switching checks files out: every file the switch would touch
            # must pass the same boundary policy as a governed write, so a
            # branch switch cannot install protected tracked files.
            self._assert_switch_targets_safe(route.root, branch)
        proc = self._run_git(
            route.root, ["switch", branch] if exists else ["switch", "-c", branch]
        )
        if proc.returncode:
            raise RuntimeError(f"git switch failed: {proc.stderr}")

        return {
            "status": "PASS",
            "op_class": "GIT_BRANCH",
            "project_id": project_id,
            "branch": branch,
            "action": "switch" if exists else "create",
        }

    def _assert_switch_targets_safe(self, root: Path, branch: str) -> None:
        """Deny branch switches that would replace protected tracked files."""
        proc = self._run_git(root, ["diff", "--name-only", "-z", "HEAD", branch, "--"])
        if proc.returncode != 0:
            raise RuntimeError(f"git switch target inspection failed: {proc.stderr}")
        for entry in proc.stdout.split("\0"):
            if not entry:
                continue
            assert_permitted_path(root, entry.replace("\\", "/"), "GIT_BRANCH")

    def run_declared_check(
        self, project_id: str, check_id: str
    ) -> dict[str, Any]:
        """Run declared check through cryptographically pinned manifest or contract."""
        route = self._resolve_project(project_id)
        spec = self.declared_manifest.get("checks", {}).get(project_id, {}).get(check_id)
        if not spec:
            raise ValueError(f"no declared check spec found for {project_id}/{check_id}")

        return run_declared_check(
            project_id=project_id,
            check_id=check_id,
            spec=spec,
            root=route.root,
            trusted_executables=self.trusted_executables,
        )
