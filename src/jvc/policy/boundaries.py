"""Filesystem governance, containment, and boundary enforcement for JVC.

Guarantees:
- Operations are strictly contained within resolved project roots.
- Traversal attempts, control characters, and encoded aliases are rejected.
- Secret-bearing paths and protected control-plane surfaces fail closed.
- Symlinks, reparse points, and junctions cannot escape the root boundary.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
ENCODED_PATH_ALIAS_RE = re.compile(r"%[0-9a-fA-F]{2}")
SECRET_RE = re.compile(
    r"^(?:\.env(?:\..*)?|credentials?(?:\..*)?|secrets?(?:\..*)?|tokens?(?:\..*)?|auth(?:\..*)?|id_rsa(?:\..*)?|id_ed25519(?:\..*)?|.*recovery[-_ ]?(?:phrase|seed).*)$",
    re.IGNORECASE,
)
SECRET_SUFFIXES = {".pem", ".key", ".ppk", ".p12", ".pfx"}

DEFAULT_CONTROL_PLANE_EXACT = {
    ".continuity/policy.json",
    ".continuity/state.json",
    ".continuity/plan-index.json",
    ".continuity/decision-index.json",
    "_config/declared-execution-manifest.json",
    "_config/governance-policy.json",
    "_config/jvc-executor-integrity.json",
    "_config/trusted-executables.json",
    "_config/continuity-contract.md",
    "_config/startup-budgets.json",
}
DEFAULT_CONTROL_PLANE_PREFIXES = (
    ".git/",
    ".continuity/",
    "_config/",
    "_promotions/",
    "contracts/",
)


def normalize_path(path: str | os.PathLike[str]) -> str:
    """Normalize a path without resolving symlinks or touching the filesystem."""
    return os.path.normcase(os.path.normpath(os.path.abspath(os.fspath(path))))


def is_within(candidate: Path, root: Path) -> bool:
    """Verify that candidate resolves strictly to root or a subdirectory of root."""
    try:
        candidate_resolved = candidate.resolve()
        root_resolved = root.resolve()
        candidate_resolved.relative_to(root_resolved)
        return True
    except (ValueError, RuntimeError):
        return False


def is_secret_path(relative_path: str) -> bool:
    """Identify filenames and patterns classified as secret-bearing."""
    clean = relative_path.replace("\\", "/").casefold().strip("/")
    if clean in {
        ".claude/settings.local.json",
        ".ssh/config",
        ".ssh/authorized_keys",
        ".ssh/id_rsa",
        ".ssh/id_ed25519",
    }:
        return True
    parts = [p for p in clean.split("/") if p]
    for part in parts:
        if SECRET_RE.fullmatch(part) or Path(part).suffix.casefold() in SECRET_SUFFIXES:
            return True
    return False


def is_control_plane_path(
    relative_path: str,
    protected_prefixes: tuple[str, ...] | None = None,
    protected_exact: set[str] | None = None,
) -> bool:
    """Classify files whose mutation alters project authority, policy, or trusted execution."""
    clean = relative_path.replace("\\", "/").casefold().strip("/")
    exact = protected_exact or DEFAULT_CONTROL_PLANE_EXACT
    prefixes = protected_prefixes or DEFAULT_CONTROL_PLANE_PREFIXES

    if clean == ".git" or clean in exact:
        return True
    if Path(clean).name == ".gitattributes":
        # .gitattributes selects executable Git filters/drivers; it is a
        # control-plane surface so ordinary governed writes cannot alter the
        # semantics of JVC-mediated Git operations.
        return True
    if any(clean.startswith(prefix) for prefix in prefixes):
        return True
    if clean.startswith("_config/") and any(
        term in Path(clean).name
        for term in ("policy", "manifest", "integrity", "trusted-executable")
    ):
        return True
    return False


def canonical_target(root: Path, relative_path: str) -> tuple[Path, str]:
    """Validate relative path, verify root containment, and return resolved Path and canonical relative posix path."""
    clean = relative_path.replace("\\", "/").strip()
    if not clean:
        raise ValueError("empty path is invalid")
    # 8.3 short-name and UNC device-path equivalence (\\?\ , \\.\) is
    # explicitly unsupported: reject such spellings rather than claiming an
    # equivalence analysis that has not been tested.
    if clean.startswith("//?/") or clean.startswith("//./"):
        raise ValueError(f"unsupported device-path form: {relative_path!r}")
    if CONTROL_RE.search(clean) or ENCODED_PATH_ALIAS_RE.search(clean):
        raise ValueError("unsafe/non-relative path: invalid characters detected")
    if Path(clean).is_absolute() or ":" in clean:
        raise ValueError("absolute paths and drive escapes are forbidden")

    target = (root / clean).resolve()
    if not is_within(target, root):
        raise ValueError(f"path escapes project root: {clean}")

    canonical_rel = target.relative_to(root.resolve()).as_posix()
    if not canonical_rel or canonical_rel == ".":
        raise ValueError("project root directory itself is not a file target")

    return target, canonical_rel


def assert_permitted_path(
    root: Path,
    relative_path: str,
    operation: str,
    *,
    is_operator_privileged: bool = False,
    protected_prefixes: tuple[str, ...] | None = None,
    protected_exact: set[str] | None = None,
) -> tuple[Path, str]:
    """Validate path and enforce boundaries before any file I/O or git operation.

    Raises:
        ValueError: On root escape, malformed characters, or directory target.
        PermissionError: On secret-bearing or control-plane targets without authorization.
    """
    target, canonical_rel = canonical_target(root, relative_path)

    if is_secret_path(canonical_rel):
        raise PermissionError(
            f"mandatory secret-bearing path denied before {operation}: {canonical_rel}"
        )

    if not is_operator_privileged and is_control_plane_path(
        canonical_rel, protected_prefixes, protected_exact
    ):
        raise PermissionError(
            f"REQUIRES_OPERATOR_CONTROL_PLANE_CAPABILITY: control-plane path denied before {operation}: {canonical_rel}"
        )

    return target, canonical_rel
