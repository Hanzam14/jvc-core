"""Parse, validate, and execute ICM day-one execution contracts."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

START_MARKER = "<!-- ICM_EXECUTION_START -->"
END_MARKER = "<!-- ICM_EXECUTION_END -->"
REQUIRED_PERSISTED_FILES = (
    "AGENTS.md",
    "CONTEXT.md",
    "HANDOFF.md",
)
ALLOWED_PERSISTENCE = {"git", "onedrive", "local"}
ALLOWED_PRIVACY = {"standard", "private-content", "restricted-tooling"}
ALLOWED_PERMISSION_CLASSES = {"read-test", "private-structure-only", "docs-only"}


class ContractError(ValueError):
    """Raised when an ICM execution contract is missing or invalid."""


@dataclass
class ExecutionContract:
    """Parsed ICM execution contract."""

    schema_version: int
    project_id: str
    cwd: str
    persistence: str
    privacy: str
    permission_class: str
    runtime: dict[str, Any]
    preflight: dict[str, Any] | None
    verify: dict[str, Any] | None
    write_policy: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "project_id": self.project_id,
            "cwd": self.cwd,
            "persistence": self.persistence,
            "privacy": self.privacy,
            "permission_class": self.permission_class,
            "runtime": self.runtime,
            "preflight": self.preflight,
            "verify": self.verify,
            "write_policy": self.write_policy,
        }


def load_contract(agents_file: Path) -> ExecutionContract:
    """Extract and parse the ICM execution contract block from an AGENTS.md file."""
    try:
        text = agents_file.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise ContractError(f"cannot read agents file {agents_file}: {exc}") from exc

    if text.count(START_MARKER) != 1 or text.count(END_MARKER) != 1:
        raise ContractError("AGENTS.md must contain exactly one ICM execution block")

    body = text.split(START_MARKER, 1)[1].split(END_MARKER, 1)[0].strip()
    if body.startswith("```json") and body.endswith("```"):
        body = body[len("```json") : -len("```")].strip()
    elif body.startswith("```") and body.endswith("```"):
        body = body[len("```") : -len("```")].strip()

    try:
        value = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ContractError(f"invalid ICM execution JSON: {exc}") from exc

    if not isinstance(value, dict):
        raise ContractError("ICM execution contract must be a JSON object")

    errors = validate_contract(value)
    if errors:
        raise ContractError(f"invalid ICM execution contract: {'; '.join(errors)}")

    return ExecutionContract(
        schema_version=value["schema_version"],
        project_id=value["project_id"],
        cwd=value["cwd"],
        persistence=value["persistence"],
        privacy=value["privacy"],
        permission_class=value["permission_class"],
        runtime=value["runtime"],
        preflight=value.get("preflight"),
        verify=value.get("verify"),
        write_policy=value["write_policy"],
    )


def validate_contract(
    contract: dict[str, Any],
    project_id: str | None = None,
    root: Path | None = None,
) -> list[str]:
    """Validate contract structure against schema requirements."""
    errors: list[str] = []
    if not isinstance(contract, dict):
        return ["contract must be a dict"]

    if type(contract.get("schema_version")) is not int or contract.get("schema_version") != 1:
        errors.append("schema_version must be 1")

    if project_id is not None:
        if contract.get("project_id") != project_id:
            errors.append(f"project_id must be {project_id!r}")
    else:
        if not isinstance(contract.get("project_id"), str) or not contract.get("project_id"):
            errors.append("project_id must be a non-empty string")

    if root is not None:
        declared_root = os.path.normcase(
            os.path.normpath(os.path.abspath(os.path.expandvars(str(contract.get("cwd", "")))))
        )
        actual_root = os.path.normcase(os.path.normpath(os.path.abspath(str(root))))
        if declared_root != actual_root:
            errors.append(f"cwd ({declared_root}) must equal the registered absolute project root ({actual_root})")
    else:
        if not isinstance(contract.get("cwd"), str) or not contract.get("cwd"):
            errors.append("cwd must be a non-empty string")

    if contract.get("persistence") not in ALLOWED_PERSISTENCE:
        errors.append("persistence must be git, onedrive, or local")
    if contract.get("privacy") not in ALLOWED_PRIVACY:
        errors.append("privacy must be standard, private-content, or restricted-tooling")
    if contract.get("permission_class") not in ALLOWED_PERMISSION_CLASSES:
        errors.append("permission_class is unsupported")
    if not isinstance(contract.get("write_policy"), str) or not contract["write_policy"].strip():
        errors.append("write_policy must be a non-empty string")

    runtime = contract.get("runtime")
    if not isinstance(runtime, dict) or runtime.get("kind") not in {"python", "none"}:
        errors.append("runtime.kind must be python or none")
    elif runtime.get("kind") == "python":
        candidates = runtime.get("candidates")
        probe = runtime.get("probe_argv")
        if not isinstance(candidates, list) or not candidates or not all(
            isinstance(item, list) and item and all(isinstance(arg, str) and arg for arg in item)
            for item in candidates
        ):
            errors.append("python runtime.candidates must be non-empty argument arrays")
        if not isinstance(probe, list) or not probe or not all(isinstance(arg, str) for arg in probe):
            errors.append("python runtime.probe_argv must be a non-empty argument array")

    for name in ("preflight", "verify"):
        if name not in contract:
            errors.append(f"{name} must be declared in contract")
            continue
        check = contract.get(name)
        if check is None:
            continue
        if not isinstance(check, dict):
            errors.append(f"{name} must be an object or null")
            continue
        argv = check.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(arg, str) and arg for arg in argv):
            errors.append(f"{name}.argv must be a non-empty argument array")
        timeout = check.get("timeout_seconds")
        if type(timeout) is not int or timeout < 1:
            errors.append(f"{name}.timeout_seconds must be a positive integer")
        expected_exit = check.get("expected_exit")
        if type(expected_exit) is not int or expected_exit != 0:
            errors.append(f"{name}.expected_exit must be 0")
        if not isinstance(check.get("expected_contains"), str):
            errors.append(f"{name}.expected_contains must be a string")

    return errors


def check_applicability(contract: dict[str, Any], name: str) -> str:
    """Return 'CONFIGURED', 'NOT_APPLICABLE', or 'MISSING'."""
    if name not in contract:
        return "MISSING"
    check = contract.get(name)
    if check is None or (isinstance(check, dict) and check.get("applicable") is False):
        perm = contract.get("permission_class")
        runtime_kind = (
            contract.get("runtime", {}).get("kind")
            if isinstance(contract.get("runtime"), dict)
            else None
        )
        if perm in {"docs-only", "private-structure-only"} or runtime_kind == "none":
            return "NOT_APPLICABLE"
        return "MISSING"
    if isinstance(check, dict):
        return "CONFIGURED"
    return "MISSING"


def is_verification_satisfied(
    result: dict[str, Any],
    *,
    allow_na: bool = False,
    expected_name: str | None = None,
) -> bool:
    """Return True if result represents successful execution or legitimate contract-permitted N/A."""
    if not isinstance(result, dict):
        return False
    if expected_name is not None and result.get("name") != expected_name:
        return False
    if not isinstance(result.get("name"), str) or not result.get("name"):
        return False
    if result.get("status") == "PASS":
        if result.get("executed") is not True:
            return False
        if result.get("applicable") is not True:
            return False
        returncode = result.get("returncode")
        if type(returncode) is not int or returncode != 0:
            return False
        if result.get("failure_kind") not in {None, "none"}:
            return False
        return True
    if (
        allow_na
        and result.get("status") == "NOT_APPLICABLE"
        and result.get("applicable") is False
        and result.get("executed") is False
    ):
        if result.get("failure_kind") not in {None, "none"}:
            return False
        return True
    return False


def _expand(value: str, root: Path) -> str:
    return os.path.expandvars(value.replace("{project_root}", str(root)))


def resolve_runtime(
    contract: dict[str, Any], root: Path, *, env: dict[str, str] | None = None
) -> dict[str, Any]:
    """Resolve an available runtime candidate based on the contract probe."""
    runtime = contract["runtime"]
    if runtime["kind"] == "none":
        return {
            "status": "PASS",
            "kind": "none",
            "argv": [],
            "detail": "no application runtime required",
        }

    attempts: list[dict[str, Any]] = []
    for raw_candidate in runtime["candidates"]:
        candidate = [_expand(arg, root) for arg in raw_candidate]
        executable = candidate[0]
        resolved = executable if Path(executable).is_file() else shutil.which(executable)
        if not resolved:
            attempts.append({"candidate": candidate, "status": "not_found"})
            continue
        argv = [resolved, *candidate[1:]]
        probe_argv = [*argv, *[_expand(arg, root) for arg in runtime["probe_argv"]]]
        try:
            result = subprocess.run(
                probe_argv,
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
                env=env,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            attempts.append({"candidate": candidate, "status": "probe_error", "detail": str(exc)})
            continue

        if result.returncode == 0:
            return {
                "status": "PASS",
                "kind": "python",
                "argv": argv,
                "detail": (result.stdout.strip() or resolved).splitlines()[-1],
                "attempts": attempts,
            }

        attempts.append(
            {
                "candidate": candidate,
                "status": "probe_failed",
                "detail": (result.stderr.strip() or result.stdout.strip())[-500:],
            }
        )

    return {
        "status": "FAIL",
        "kind": "python",
        "argv": [],
        "detail": "no candidate passed the capability probe",
        "attempts": attempts,
    }


def command_argv(check: dict[str, Any], runtime: dict[str, Any], root: Path) -> list[str]:
    """Format argv array substituting {runtime} and {project_root}."""
    argv: list[str] = []
    for arg in check["argv"]:
        if arg == "{runtime}":
            argv.extend(runtime["argv"])
        else:
            argv.append(_expand(arg, root))
    return argv


def run_check(
    contract: dict[str, Any],
    name: str,
    runtime: dict[str, Any],
    root: Path,
    *,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run a declared preflight or verify check against project root."""
    applicability = check_applicability(contract, name)
    if applicability == "NOT_APPLICABLE":
        return {
            "status": "NOT_APPLICABLE",
            "name": name,
            "executed": False,
            "applicable": False,
            "skipped": True,
            "detail": f"{name} explicitly not applicable by contract",
            "failure_kind": "none",
        }
    if applicability == "MISSING":
        return {
            "status": "MISSING",
            "name": name,
            "executed": False,
            "applicable": True,
            "skipped": True,
            "detail": f"required check {name!r} is not configured or missing",
            "failure_kind": "configuration",
        }

    check = contract[name]
    if runtime.get("status") != "PASS":
        return {
            "status": "FAIL",
            "name": name,
            "executed": False,
            "applicable": True,
            "skipped": True,
            "detail": "runtime unresolved",
            "failure_kind": "infrastructure",
        }

    argv = command_argv(check, runtime, root)
    try:
        result = subprocess.run(
            argv,
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=check["timeout_seconds"],
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "FAIL",
            "name": name,
            "executed": False,
            "applicable": True,
            "argv": argv,
            "detail": f"timeout after {check['timeout_seconds']}s: {exc}",
            "failure_kind": "infrastructure",
        }
    except OSError as exc:
        return {
            "status": "FAIL",
            "name": name,
            "executed": False,
            "applicable": True,
            "argv": argv,
            "detail": f"infrastructure error: {exc}",
            "failure_kind": "infrastructure",
        }

    combined = "\n".join(part for part in (result.stdout.strip(), result.stderr.strip()) if part)
    needle = check["expected_contains"]
    passed = result.returncode == check["expected_exit"] and (not needle or needle in combined)

    return {
        "status": "PASS" if passed else "FAIL",
        "name": name,
        "executed": True,
        "applicable": True,
        "argv": argv,
        "returncode": result.returncode,
        "detail": combined[-2000:],
        "failure_kind": "none" if passed else "behavioral",
    }


def persistence_report(contract: dict[str, Any], root: Path) -> dict[str, Any]:
    """Inspect presence and git status of required persistent onboarding files."""
    missing = [
        relative
        for relative in REQUIRED_PERSISTED_FILES
        if not (root / Path(relative)).is_file()
    ]
    hashes = {
        relative: hashlib.sha256((root / Path(relative)).read_bytes()).hexdigest()
        for relative in REQUIRED_PERSISTED_FILES
        if (root / Path(relative)).is_file()
    }
    mode = contract["persistence"]
    untracked: list[str] = []
    git_error = ""

    if mode == "git":
        for relative in REQUIRED_PERSISTED_FILES:
            result = subprocess.run(
                ["git", "-C", str(root), "ls-files", "--error-unmatch", "--", relative],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode:
                untracked.append(relative)
        probe = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            check=False,
            capture_output=True,
            text=True,
        )
        if probe.returncode:
            git_error = probe.stderr.strip() or "Git repository unavailable"

    passed = not missing and not untracked and not git_error
    return {
        "status": "PASS" if passed else "FAIL",
        "mode": mode,
        "missing": missing,
        "untracked": untracked,
        "sha256": hashes,
        "detail": git_error
        or ("required onboarding files persist" if passed else "persistence requirements failed"),
    }
