"""Safe subprocess execution environment and declared check runner."""

from __future__ import annotations

import hmac
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from jvc.policy.authority import resolve_trusted_executable, sha256_bytes, sha256_file


class IntegrityDriftError(PermissionError):
    """Raised when a declared check's contract, manifest, executable, or script drifts."""


def get_system_root() -> Path:
    """Return the Windows system root directory or / on POSIX."""
    if os.name == "nt":
        win = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
        return Path(win).resolve()
    return Path("/")


def build_safe_subprocess_env(
    extra_paths: list[Path] | None = None,
    *,
    sanitize_ambient: bool = True,
) -> dict[str, str]:
    """Construct a minimal, sanitized environment for subprocess execution.

    Security invariants:
    - Neutralizes ambient Git variables (GIT_HOOKS_PATH, GIT_CONFIG_*, GIT_EXTERNAL_DIFF, etc.).
    - Strips API keys, tokens, auth headers, and secrets from the process environment.
    - Limits PATH strictly to system binaries and explicitly declared trusted directories.
    """
    env: dict[str, str] = {}
    win = get_system_root()

    if os.name == "nt":
        dirs = [
            win / "System32",
            win,
            win / "System32" / "Wbem",
            win / "System32" / "WindowsPowerShell" / "v1.0",
        ]
        dirs += [p.resolve() for p in (extra_paths or [])]
        unique_dirs: list[str] = []
        for p in dirs:
            s = str(p)
            if p.is_dir() and s not in unique_dirs:
                unique_dirs.append(s)

        temp_dir = Path(tempfile.gettempdir()).resolve()
        env = {
            "SystemRoot": str(win),
            "WINDIR": str(win),
            "SystemDrive": str(win.drive or "C:"),
            "TEMP": str(temp_dir),
            "TMP": str(temp_dir),
            "PATH": os.pathsep.join(unique_dirs),
            "PATHEXT": ".COM;.EXE;.BAT;.CMD",
            "COMSPEC": str(win / "System32" / "cmd.exe"),
        }
        for name in ("USERPROFILE", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", "APPDATA"):
            val = os.environ.get(name)
            if val:
                env[name] = val
    else:
        dirs = [Path("/usr/bin"), Path("/bin"), Path("/usr/local/bin")]
        dirs += [p.resolve() for p in (extra_paths or [])]
        unique_dirs = [str(p) for p in dirs if p.is_dir()]
        temp_dir = Path(tempfile.gettempdir()).resolve()
        env = {
            "PATH": os.pathsep.join(unique_dirs),
            "TEMP": str(temp_dir),
            "TMP": str(temp_dir),
            "HOME": os.environ.get("HOME", "/tmp"),
        }

    # Ensure no ambient Git, credential, or token leakage
    if sanitize_ambient:
        for k in list(env.keys()):
            upper = k.upper()
            if upper.startswith("GIT_") or any(
                term in upper for term in ("API_KEY", "TOKEN", "SECRET", "PASSWD", "PASSWORD")
            ):
                env.pop(k, None)

    return env


def run_declared_check(
    project_id: str,
    check_id: str,
    spec: dict[str, Any],
    root: Path,
    trusted_executables: dict[str, dict[str, str]],
    *,
    timeout: int | None = None,
) -> dict[str, Any]:
    """Execute a cryptographically pinned declared check.

    Invariants:
    - Verifies cwd matches declared spec.
    - Verifies trusted executable path and sha256 hash.
    - Verifies child executables if specified.
    - Verifies executed script files against pinned sha256 hashes.
    - Executes command in sanitized environment.
    - Validates exit code and expected output string.
    """
    cid = str(check_id).lower().strip()
    if cid not in {"preflight", "verify"}:
        raise ValueError(f"unknown declared check: {cid}")

    if spec.get("project_id") != project_id or spec.get("check_id") != cid:
        raise IntegrityDriftError("declared project/check identity mismatch")

    spec_cwd = Path(spec.get("cwd", "")).resolve()
    if root.resolve() != spec_cwd:
        raise IntegrityDriftError(
            f"canonical cwd mismatch: expected {spec_cwd}, observed {root.resolve()}"
        )

    exe_class = str(spec.get("executable", "")).lower()
    exe_path = resolve_trusted_executable(exe_class, trusted_executables)

    if str(exe_path).casefold() != str(Path(spec.get("executable_path", "")).resolve()).casefold():
        raise IntegrityDriftError("trusted executable path mismatch")

    if not hmac.compare_digest(sha256_file(exe_path), str(spec.get("executable_sha256", "")).upper()):
        raise IntegrityDriftError("trusted executable hash mismatch")

    # Verify child executables if any
    child_executables = spec.get("child_executables", {})
    extra_paths = [exe_path.parent]
    for child_name, child_spec in child_executables.items():
        child_exe = resolve_trusted_executable(child_name, trusted_executables)
        extra_paths.append(child_exe.parent)
        if str(child_exe).casefold() != str(Path(child_spec["path"]).resolve()).casefold():
            raise IntegrityDriftError(f"child executable path mismatch: {child_name}")
        if not hmac.compare_digest(sha256_file(child_exe), str(child_spec["sha256"]).upper()):
            raise IntegrityDriftError(f"child executable hash mismatch: {child_name}")

    # Verify executed files
    executed_files = spec.get("executed_files", {})
    for relative, expected_hash in executed_files.items():
        file_target = (root / relative).resolve()
        if not file_target.is_file():
            raise IntegrityDriftError(f"executed file missing: {relative}")
        observed_hash = sha256_file(file_target)
        if not hmac.compare_digest(observed_hash, str(expected_hash).upper()):
            raise IntegrityDriftError(
                f"executed file hash mismatch: {relative} (expected {expected_hash}, observed {observed_hash})"
            )

    argv = list(spec.get("argv", []))
    if not argv:
        raise IntegrityDriftError("manifest argv is empty")

    run_timeout = timeout or int(spec.get("timeout_seconds", 60))
    env = build_safe_subprocess_env(extra_paths)

    # Replace leading executable name if needed
    cmd = [str(exe_path), *argv[1:]]

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=run_timeout,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "FAIL",
            "op_class": "DECLARED_CHECK",
            "project_id": project_id,
            "check_id": cid,
            "argv": argv,
            "error": f"timeout after {run_timeout}s: {exc}",
            "passed": False,
        }
    except OSError as exc:
        return {
            "status": "FAIL",
            "op_class": "DECLARED_CHECK",
            "project_id": project_id,
            "check_id": cid,
            "argv": argv,
            "error": f"execution failed: {exc}",
            "passed": False,
        }

    output = (proc.stdout or "") + (proc.stderr or "")
    expected_exit = int(spec.get("expected_exit", 0))
    marker = spec.get("expected_contains")
    passed = proc.returncode == expected_exit and (marker is None or str(marker) in output)

    return {
        "status": "PASS" if passed else "FAIL",
        "op_class": "DECLARED_CHECK",
        "project_id": project_id,
        "check_id": cid,
        "argv": argv,
        "exit_code": proc.returncode,
        "expected_exit": expected_exit,
        "expected_contains": marker,
        "output": output[-12000:],
        "passed": passed,
    }
