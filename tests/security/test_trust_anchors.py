"""Security tests for host-owned trust anchors and declared check tamper detection.

Review Area E: Host-owned trust provisioning and declared check integrity drift.
"""

import sys
from pathlib import Path
import pytest
from jvc.configuration import ProjectRegistry, Route
from jvc.execution.executor import GovernedExecutor
from jvc.execution.runner import IntegrityDriftError, run_declared_check
from jvc.policy.authority import sha256_bytes, sha256_file


@pytest.fixture
def check_fixture(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    scripts_dir = root / "scripts"
    scripts_dir.mkdir()

    script_file = scripts_dir / "validator.py"
    script_file.write_text("print('PASS: check verified')\n", encoding="utf-8")
    script_sha = sha256_file(script_file)

    py_exe = Path(sys.executable).resolve()
    py_sha = sha256_file(py_exe)

    spec = {
        "project_id": "trust-proj",
        "check_id": "preflight",
        "cwd": str(root.resolve()),
        "executable": "python",
        "executable_path": str(py_exe),
        "executable_sha256": py_sha,
        "argv": ["python", "scripts/validator.py"],
        "timeout_seconds": 10,
        "expected_exit": 0,
        "expected_contains": "PASS: check verified",
        "executed_files": {
            "scripts/validator.py": script_sha,
        },
    }
    trusted_executables = {
        "python": {
            "class": "python",
            "path": str(py_exe),
            "sha256": py_sha,
        }
    }
    return root, script_file, spec, trusted_executables


def test_declared_check_passes_when_integrity_matches(check_fixture):
    root, _, spec, trusted_executables = check_fixture
    res = run_declared_check(
        "trust-proj",
        "preflight",
        spec,
        root,
        trusted_executables,
    )
    assert res["status"] == "PASS"
    assert res["passed"] is True


def test_declared_check_fails_closed_on_script_tamper(check_fixture):
    root, script_file, spec, trusted_executables = check_fixture

    # Tamper with the executed script
    script_file.write_text("print('tampered')\n", encoding="utf-8")

    with pytest.raises(IntegrityDriftError, match="executed file hash mismatch"):
        run_declared_check(
            "trust-proj",
            "preflight",
            spec,
            root,
            trusted_executables,
        )


def test_declared_check_fails_closed_on_executable_tamper(check_fixture):
    root, _, spec, trusted_executables = check_fixture

    # Alter the executable pin hash
    tampered_trusted = {
        "python": {
            "class": "python",
            "path": spec["executable_path"],
            "sha256": "0" * 64,
        }
    }
    with pytest.raises(PermissionError, match="integrity mismatch"):
        run_declared_check(
            "trust-proj",
            "preflight",
            spec,
            root,
            tampered_trusted,
        )


def test_control_plane_cannot_be_silently_modified(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    route = Route(
        project_id="tamper-proj",
        aliases=("tamper",),
        root=root,
        startup=("AGENTS.md", "CONTEXT.md", "HANDOFF.md"),
        handoff="HANDOFF.md",
        status="active",
    )
    executor = GovernedExecutor(
        registry=ProjectRegistry([route]), recovery_store=tmp_path / "recovery"
    )

    # Attempt to tamper with governance policy or continuity state fails
    with pytest.raises(PermissionError, match="REQUIRES_OPERATOR_CONTROL_PLANE_CAPABILITY"):
        executor.fs_write("tamper-proj", "_config/governance-policy.json", "{}")

    with pytest.raises(PermissionError, match="REQUIRES_OPERATOR_CONTROL_PLANE_CAPABILITY"):
        executor.fs_write("tamper-proj", ".continuity/state.json", "{}")
